package authz

import (
	"testing"
)

func TestCache(t *testing.T) {
	// reset cache
	partialCache = newCache(cacheSize)

	expr1 := sqlExprIsNotNull{Column: ColumnRef{Table: "table1", Column: "id1"}}
	expr2 := sqlExprIsNotNull{Column: ColumnRef{Table: "table2", Column: "id2"}}
	expr3 := sqlExprIsNotNull{Column: ColumnRef{Table: "table3", Column: "id3"}}
	expr4 := sqlExprIsNotNull{Column: ColumnRef{Table: "table4", Column: "id4"}}
	expr5 := sqlExprIsNotNull{Column: ColumnRef{Table: "table5", Column: "id5"}}
	expr6 := sqlExprIsNotNull{Column: ColumnRef{Table: "table6", Column: "id6"}}

	columns1 := map[string]ColumnRef{"id1": {Table: "tablea", Column: "ida"}}
	columns2 := map[string]ColumnRef{"id1": {Table: "tablea", Column: "ida"}, "id2": {Table: "tableb", Column: "idb"}}

	testCases := []struct {
		name    string
		key     Access
		columns map[string]ColumnRef
		value   Expr
		err     error
		hit     bool
	}{
		{name: "miss_1", key: Access{Principal: "p0", Resource: "r0", Permission: "perm0"}, value: expr1, hit: false},
		{name: "miss_2", key: Access{Principal: "p1", Resource: "r0", Permission: "perm0"}, value: expr2, hit: false},
		{name: "miss_3", key: Access{Principal: "p1", Resource: "r1", Permission: "perm0"}, value: expr3, hit: false},
		{name: "miss_4", key: Access{Principal: "p1", Resource: "r1", Permission: "perm1"}, value: expr4, hit: false},
		{name: "miss_5", key: Access{Principal: "p1", Resource: "r1", Permission: "perm1"}, columns: columns1, value: expr5, hit: false},
		{name: "miss_6", key: Access{Principal: "p1", Resource: "r1", Permission: "perm1"}, columns: columns2, value: expr6, hit: false},
		{name: "hit_1", key: Access{Principal: "p0", Resource: "r0", Permission: "perm0"}, value: expr1, hit: true},
		{name: "hit_2", key: Access{Principal: "p1", Resource: "r0", Permission: "perm0"}, value: expr2, hit: true},
		{name: "hit_3", key: Access{Principal: "p1", Resource: "r1", Permission: "perm0"}, value: expr3, hit: true},
		{name: "hit_4", key: Access{Principal: "p1", Resource: "r1", Permission: "perm1"}, value: expr4, hit: true},
		{name: "hit_5", key: Access{Principal: "p1", Resource: "r1", Permission: "perm1"}, columns: columns1, value: expr5, hit: true},
		{name: "hit_6", key: Access{Principal: "p1", Resource: "r1", Permission: "perm1"}, columns: columns2, value: expr6, hit: true},
	}

	for _, tc := range testCases {
		hit := true
		t.Run(tc.name, func(t *testing.T) {
			value, err := partialCache.Get(tc.key, tc.columns, func() (Expr, error) {
				hit = false
				return tc.value, tc.err
			})
			if tc.value != value {
				t.Fatalf("expected value %v, got %v", tc.value, value)
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if hit != tc.hit {
				t.Fatalf("expected hit to be %v, got %v", tc.hit, hit)
			}
		})
	}
}
