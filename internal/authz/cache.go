package authz

import (
	"maps"
	"reflect"
	"slices"
	"sync"

	"github.com/hashicorp/golang-lru/simplelru"
)

// cache is a thread-safe LRU cache for partial evaluation results. Errors are not cached.
type cache struct {
	mu      sync.Mutex
	pending map[cacheKey]*pendingGet
	lru     simplelru.LRUCache
}

type cacheKey struct {
	Access Access
	// ExtraColumnMappings is an array of extra column mappings, constructed w/ reflection.
	// This is to keep the cache key comparable, and thus, usable as a key in the LRU cache.
	ExtraColumnMappings any
}

// pendingGet tracks the result of a cache miss.
// This allows multiple goroutines to wait for the same cache miss fulfillment without
// causing duplicate work.
type pendingGet struct {
	value Expr
	err   error
	ready chan struct{} // ready is closed when the value and error are available.
}

func newCache(size int) *cache {
	lru, err := simplelru.NewLRU(size, nil)
	if err != nil {
		panic(err)
	}

	return &cache{lru: lru, pending: make(map[cacheKey]*pendingGet)}
}

func (c *cache) Get(access Access, extraColumnMappings map[string]ColumnRef, miss func() (Expr, error)) (Expr, error) {
	key := newCacheKey(access, extraColumnMappings)

	v := func() *pendingGet {
		c.mu.Lock()
		defer c.mu.Unlock()

		if v, ok := c.lru.Get(key); ok {
			done := make(chan struct{})
			close(done)

			return &pendingGet{
				value: v.(Expr),
				ready: done,
			}
		}

		v, ok := c.pending[key]
		if !ok {
			v = &pendingGet{value: nil, err: nil, ready: make(chan struct{})}
			c.pending[key] = v
			c.mu.Unlock()

			v.value, v.err = miss()
			close(v.ready) // signal all waiters the value is available

			c.mu.Lock()
			delete(c.pending, key)

			// do not cache errors.
			if v.err == nil {
				c.lru.Add(key, v.value)
			}
		}

		return v
	}()

	<-v.ready
	return v.value, v.err
}

func newCacheKey(access Access, extraColumnMappings map[string]ColumnRef) cacheKey {
	type KeyColumnRef struct {
		Key string
		Ref ColumnRef
	}

	s := make([]KeyColumnRef, len(extraColumnMappings))

	// Sort keys to ensure deterministic cache key and avoid cache misses due to order of insertion.
	for i, k := range slices.Sorted(maps.Keys(extraColumnMappings)) {
		s[i] = KeyColumnRef{
			Key: k,
			Ref: extraColumnMappings[k],
		}
	}

	// Then convert slice to an array of the struct type, to ensure it is comparable.

	elem := reflect.TypeOf((*KeyColumnRef)(nil)).Elem()
	arr := reflect.New(reflect.ArrayOf(len(s), elem)).Elem()
	reflect.Copy(arr, reflect.ValueOf(s))

	return cacheKey{
		Access:              access,
		ExtraColumnMappings: arr.Interface(),
	}
}
