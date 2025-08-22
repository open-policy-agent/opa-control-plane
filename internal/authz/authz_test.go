package authz

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	_ "modernc.org/sqlite"
)

func TestPartial(t *testing.T) {
	db, err := sql.Open("sqlite", "file::memory:?cache=shared")
	if err != nil {
		t.Fatal(err)
	}

	defer db.Close()

	db.Exec("CREATE TABLE sources (name TEXT)")
	db.Exec("CREATE TABLE principals (id TEXT, role TEXT)")
	db.Exec("CREATE TABLE resource_permissions (name TEXT, resource TEXT, principal_id TEXT, role TEXT, permission TEXT)")

	db.Exec("INSERT INTO sources (name) VALUES ('source')")
	db.Exec("INSERT INTO principals (id, role) VALUES ('alice', 'administrator')")
	db.Exec("INSERT INTO principals (id, role) VALUES ('bob', 'viewer')")
	db.Exec("INSERT INTO resource_permissions (name, resource, principal_id, role, permission) VALUES ('source', 'sources', 'bob', 'viewer', 'sources.viewer')")

	testCases := []struct {
		name                string
		access              Access
		extraColumnMappings map[string]ColumnRef
		allow               bool
	}{
		{
			name:   "allow access",
			access: Access{Principal: "alice", Resource: "sources", Permission: "sources.create"},
			allow:  true, // alice admin has full access
		},
		{
			name:   "deny access",
			access: Access{Principal: "bob", Resource: "sources", Permission: "sources.create"},
			allow:  false, // bob viewer not allowed to create
		},
		{
			name:   "allow with extra columns",
			access: Access{Principal: "bob", Resource: "sources", Permission: "sources.viewer"},
			extraColumnMappings: map[string]ColumnRef{
				"input.name": {Table: "sources", Column: "name"},
			},
			allow: true, // bob can view resource he has permission for
		},
		{
			name:   "deny with extra columns",
			access: Access{Principal: "bob", Resource: "sources", Permission: "sources.create"},
			extraColumnMappings: map[string]ColumnRef{
				"input.name": {Table: "sources", Column: "name"},
			},
			allow: false, // bob viewer not allowed to create, only view the resource
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Partial(context.Background(), tc.access, tc.extraColumnMappings)
			if err != nil {
				t.Fatal(err)
			}

			cond, args := result.SQL(func(int) string { return "?" }, nil)
			fmt.Println("cond:", cond, "args:", args)
			rows, err := db.Query("SELECT * FROM sources WHERE "+cond, args...)
			if err != nil {
				t.Fatal(err)
			}

			if rows.Next() != tc.allow {
				t.Fatalf("expected allow %v, got %v", tc.allow, !tc.allow)
			}
		})
	}
}
