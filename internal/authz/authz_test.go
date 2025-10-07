package authz

import (
	"database/sql"
	"testing"

	"github.com/google/go-cmp/cmp"
	_ "modernc.org/sqlite"

	"github.com/open-policy-agent/opa-control-plane/internal/test/dbs"
)

func TestPartialStringArgs(t *testing.T) {
	// NOTE(sr): Don't use the cache here (Partial, uppercase 'P'), as it'll make running this
	// test multiple times meaningless.
	result, err := partial(t.Context(), Access{Principal: "bob", Resource: "sources", Permission: "sources.view", Name: "x123"}, map[string]ColumnRef{"input.name": {Table: "sources", Column: "name"}})
	if err != nil {
		t.Fatal(err)
	}

	cond, args := result.SQL(func(int) string { return "?" }, nil)
	expCond := `EXISTS (SELECT 1 FROM resource_permissions WHERE resource_permissions.name=sources.name AND ?=resource_permissions.resource AND ?=resource_permissions.principal_id AND ?=resource_permissions.permission) ` +
		`OR EXISTS (SELECT 1 FROM resource_permissions WHERE resource_permissions.name=sources.name AND ?=resource_permissions.resource AND ?=resource_permissions.principal_id AND resource_permissions.role=?) ` +
		`OR EXISTS (SELECT 1 FROM principals WHERE ?=principals.id AND principals.role=?) ` +
		`OR EXISTS (SELECT 1 FROM principals WHERE ?=principals.id AND principals.role=?)`
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
	}
	if diff := cmp.Diff(expArgs, args[:6]); diff != "" {
		t.Fatal("unexpected first 6 args (-want, +got)", diff)
	}

	expBob1 := []any{
		"bob", "administrator",
		"bob", "viewer",
	}
	expBob2 := []any{
		"bob", "viewer",
		"bob", "administrator",
	}
	if diff1, diff2 := cmp.Diff(expBob1, args[6:]), cmp.Diff(expBob2, args[6:]); diff1 != "" && diff2 != "" {
		t.Fatal("unexpected last 4 args (-want, +got)", diff1, diff2)
	}
}

func TestPartial(t *testing.T) {
	db, err := sql.Open("sqlite", dbs.MemoryDBName())
	if err != nil {
		t.Fatal(err)
	}

	defer db.Close()

	query := func(query string) {
		t.Helper()
		if _, err := db.ExecContext(t.Context(), query); err != nil {
			t.Fatal(err)
		}
	}
	query("CREATE TABLE sources (name TEXT)")
	query("CREATE TABLE principals (id TEXT, role TEXT)")
	query("CREATE TABLE resource_permissions (name TEXT, resource TEXT, principal_id TEXT, role TEXT, permission TEXT)")
	query("INSERT INTO sources (name) VALUES ('source')")
	query("INSERT INTO principals (id, role) VALUES ('alice', 'administrator')")
	query("INSERT INTO principals (id, role) VALUES ('bob', 'viewer')")
	query("INSERT INTO resource_permissions (name, resource, principal_id, role, permission) VALUES ('source', 'sources', 'bob', 'viewer', 'sources.viewer')")

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
			result, err := Partial(t.Context(), tc.access, tc.extraColumnMappings)
			if err != nil {
				t.Fatal(err)
			}

			cond, args := result.SQL(func(int) string { return "?" }, nil)
			t.Log("cond:", cond, "args:", args)
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
