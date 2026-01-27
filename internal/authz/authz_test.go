package authz

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	_ "modernc.org/sqlite"

	"github.com/open-policy-agent/opa-control-plane/internal/test/dbs"
	"github.com/open-policy-agent/opa-control-plane/pkg/authz"
)

func TestPartialStringArgs(t *testing.T) {
	// NOTE(sr): Don't use the cache here (Partial, uppercase 'P'), as it'll make running this
	// test multiple times meaningless.

	a := NewAccess().WithPrincipal("bob").WithResource("sources").WithPermission("sources.view").WithTenant("One").WithName("x123")
	access, ok := a.(*Access)
	if !ok {
		t.Fatal("unknown access descriptor type")
	}

	result, err := partial(t.Context(), access, map[string]authz.SQLColumnRef{"input.name": {Table: "sources", Column: "name"}})
	if err != nil {
		t.Fatal(err)
	}

	cond, args := result.SQL(func(int) string { return "?" }, nil)
	actCond := strings.Split(cond, " OR ")
	// split args according to ordering in actCond
	window := args
	var this []any
	for i := range actCond {
		size := strings.Count(actCond[i], "?")
		this, window = window[:size], window[size:]
		actCond[i] += fmt.Sprintf(" %v", this)
	}

	expCond := []string{
		`EXISTS (SELECT 1 FROM resource_permissions, tenants WHERE resource_permissions.name=sources.name AND ?=resource_permissions.resource AND ?=resource_permissions.principal_id AND ?=resource_permissions.permission AND ?=tenants.name AND resource_permissions.tenant_id=tenants.id) [sources bob sources.view One]`,
		`EXISTS (SELECT 1 FROM resource_permissions, tenants WHERE resource_permissions.name=sources.name AND ?=resource_permissions.resource AND ?=resource_permissions.principal_id AND ?=tenants.name AND resource_permissions.tenant_id=tenants.id AND resource_permissions.role=?) [sources bob One owner]`,
		`EXISTS (SELECT 1 FROM principals, tenants WHERE ?=principals.id AND principals.role=? AND ?=tenants.name AND principals.tenant_id=tenants.id) [bob viewer One]`,
		`EXISTS (SELECT 1 FROM principals, tenants WHERE ?=principals.id AND principals.role=? AND ?=tenants.name AND principals.tenant_id=tenants.id) [bob administrator One]`,
	}

	if diff := cmp.Diff(expCond, actCond, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
		t.Fatalf("unexpected condition (-want,+got):\n%s", diff)
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
	query("CREATE TABLE tenants (id INTEGER, name TEXT)")
	query("CREATE TABLE principals (id TEXT, tenant_id INTEGER, role TEXT)")
	query("CREATE TABLE resource_permissions (name TEXT, resource TEXT, principal_id INTEGER, role TEXT, permission TEXT, tenant_id INT)")
	query("INSERT INTO sources (name) VALUES ('source')")
	query("INSERT INTO tenants (id, name ) VALUES (1, 'foo')")
	query("INSERT INTO tenants (id, name ) VALUES (2, 'bar')")
	query("INSERT INTO principals (id, tenant_id, role) VALUES ('alice', 1, 'administrator')")
	query("INSERT INTO principals (id, tenant_id, role) VALUES ('bob', 1, 'viewer')")
	query("INSERT INTO resource_permissions (name, resource, principal_id, role, permission, tenant_id) VALUES ('source', 'sources', 'bob', 'viewer', 'sources.view', 1)")

	testCases := []struct {
		name                string
		access              Access
		extraColumnMappings map[string]authz.SQLColumnRef
		allow               bool
	}{
		{
			name:   "allow access",
			access: Access{principal: "alice", resource: "sources", permission: "sources.create", tenant: "foo"},
			allow:  true, // alice admin has full access
		},
		{
			name:   "allow access, other tenant",
			access: Access{principal: "alice", resource: "sources", permission: "sources.create", tenant: "bar"},
			allow:  false, // alise is admin in "foo", but nobody in "bar"
		},
		{
			name:   "deny access",
			access: Access{principal: "bob", resource: "sources", permission: "sources.create", tenant: "foo"},
			allow:  false, // bob viewer not allowed to create
		},
		{
			name:   "allow with extra columns",
			access: Access{principal: "bob", resource: "sources", permission: "sources.view", tenant: "foo"},
			extraColumnMappings: map[string]authz.SQLColumnRef{
				"input.name": {Table: "sources", Column: "name"},
			},
			allow: true, // bob can view resource he has permission for
		},
		{
			name:   "deny in other tenant",
			access: Access{principal: "bob", resource: "sources", permission: "sources.view", tenant: "bar"},
			extraColumnMappings: map[string]authz.SQLColumnRef{
				"input.name": {Table: "sources", Column: "name"},
			},
			allow: false, // bob ONLY has resource access in tenant "foo"
		},
		{
			name:   "deny with extra columns",
			access: Access{principal: "bob", resource: "sources", permission: "sources.create", tenant: "foo"},
			extraColumnMappings: map[string]authz.SQLColumnRef{
				"input.name": {Table: "sources", Column: "name"},
			},
			allow: false, // bob viewer not allowed to create, only view the resource
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			oa := OPAuthorizer{}
			result, err := oa.Partial(t.Context(), &tc.access, tc.extraColumnMappings)
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
