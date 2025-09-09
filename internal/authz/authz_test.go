package authz

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"testing"

	_ "modernc.org/sqlite"
)

func TestPartialStringArgs(t *testing.T) {
	result, err := Partial(context.Background(), Access{Principal: "bob", Resource: "sources", Permission: "sources.view", Name: "x123"}, map[string]ColumnRef{"input.name": {Table: "sources", Column: "name"}})
	if err != nil {
		t.Fatal(err)
	}

	cond, args := result.SQL(func(int) string { return "?" }, nil)
	expCond := `EXISTS (SELECT 1 FROM resource_permissions WHERE resource_permissions.name=sources.name AND ?=resource_permissions.resource AND ?=resource_permissions.principal_id AND ?=resource_permissions.permission) OR EXISTS (SELECT 1 FROM resource_permissions WHERE resource_permissions.name=sources.name AND ?=resource_permissions.resource AND ?=resource_permissions.principal_id AND resource_permissions.role=?) OR EXISTS (SELECT 1 FROM principals WHERE ?=principals.id AND principals.role=?) OR EXISTS (SELECT 1 FROM principals WHERE ?=principals.id AND principals.role=?)`
	if cond != expCond {
		t.Fatalf("unexpected condition\n\ngot: %q\n\nexp: %q", cond, expCond)
	}
	expArgs := []any{
		"sources",
		"bob",
		"sources.view",
		"sources",
		"bob",
		"owner",
		"bob",
		"administrator",
		"bob",
		"viewer",
	}
	if !reflect.DeepEqual(expArgs, args) {
		t.Fatalf("unexpected args\n\ngot: %v\n\nexp: %v", args, expArgs)
	}
}

func TestPartial(t *testing.T) {
	db, err := sql.Open("sqlite", "file::memory:?cache=shared")
	if err != nil {
		t.Fatal(err)
	}

	defer db.Close()

	if _, err := db.Exec("CREATE TABLE sources (name TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE principals (id TEXT, role TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE resource_permissions (name TEXT, resource TEXT, principal_id TEXT, role TEXT, permission TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO sources (name) VALUES ('source')"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO principals (id, role) VALUES ('alice', 'administrator')"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO principals (id, role) VALUES ('bob', 'viewer')"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO resource_permissions (name, resource, principal_id, role, permission) VALUES ('source', 'sources', 'bob', 'viewer', 'sources.viewer')"); err != nil {
		t.Fatal(err)
	}

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
