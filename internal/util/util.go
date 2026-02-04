package util

import (
	"cmp"
	"maps"
)

func SetEqual[K comparable, V any](a, b []V, key func(V) K, eq func(a, b V) bool) bool {
	if len(a) == 1 && len(b) == 1 {
		return eq(a[0], b[0])
	}

	// NB(sr): There's a risk of false positives here, e.g. []struct{n, v string}{ {"foo", "bar"}, {"foo", "baz"} }
	// is setEqual to []struct{n, v string}{ {"foo", "baz"} }
	m := make(map[K]V, len(a))
	for _, v := range a {
		m[key(v)] = v
	}

	n := make(map[K]V, len(b))
	for _, v := range b {
		n[key(v)] = v
	}

	return maps.EqualFunc(m, n, eq)
}

func PtrEqual[T comparable](a, b *T) bool {
	return FastEqual(a, b, func(a, b *T) bool { return *a == *b })
}

func BoolPtrCompare(a, b *bool) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	case !*a && *b:
		return -1
	case *a && !*b:
		return 1
	}

	return 0
}

func PtrCompare[T cmp.Ordered](a, b *T) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	case *a < *b:
		return -1
	case *a > *b:
		return 1
	}

	return 0
}

func FastEqual[V any](a, b *V, slowEqual func(a, b *V) bool) bool {
	if a == b {
		return true
	}

	if a == nil || b == nil {
		return false
	}

	return slowEqual(a, b)
}
