package authz_test

import rego.v1

test_admin_can_do_anything if {
	data.authz.allow with input.principal as "testuser"
		with data.principals.id as "testuser"
		with data.principals.role as "administrator"
		with data.principals.tenant_id as 10
		with data.tenants.id as 10
		with data.tenants.name as "ten10"
		with input.tenant as "ten10"
}

read_permissions := {
	"bundles.view",
	"sources.view",
	"stacks.view",
	"secrets.view",
	"tokens.view",
	"sources.data.read",
}

test_viewer_can_view_anything if {
	every p in read_permissions {
		data.authz.allow with input.principal as "testuser"
			with data.principals.id as "testuser"
			with data.principals.role as "viewer"
			with data.principals.tenant_id as 10
			with data.tenants.id as 10
			with data.tenants.name as "ten10"
			with input.tenant as "ten10"
			with input.permission as p
	}
}

test_viewer_cannot_create_bundles if {
	not data.authz.allow with input.principal as "testuser"
		with data.principals.id as "testuser"
		with data.principals.role as "viewer"
		with data.principals.tenant_id as 10
		with data.tenants.id as 10
		with data.tenants.name as "ten10"
		with input.tenant as "ten10"
		with input.permission as "bundles.create"
}

create_permissions := {
	"bundles.create",
	"sources.create",
	"secrets.create",
}

test_owner_can_create_bundles_sources_and_secrets if {
	every p in create_permissions {
		data.authz.allow with input.principal as "testuser"
			with data.principals.id as "testuser"
			with data.principals.role as "owner"
			with data.principals.tenant_id as 10
			with data.tenants.id as 10
			with data.tenants.name as "ten10"
			with input.tenant as "ten10"
			with input.permission as p
	}
}

test_owner_cannot_create_stacks if {
	not data.authz.allow with input.principal as "testuser"
		with data.principals.id as "testuser"
		with data.principals.role as "owner"
		with data.principals.tenant_id as 10
		with data.tenants.id as 10
		with data.tenants.name as "ten10"
		with input.permission as "stacks.create"
		with input.tenant as "ten10"
}

test_stack_owner_can_create_stacks if {
	data.authz.allow with input.principal as "testuser"
		with data.principals.id as "testuser"
		with data.principals.role as "stack_owner"
		with data.principals.tenant_id as 10
		with data.tenants.id as 10
		with data.tenants.name as "ten10"
		with input.permission as "stacks.create"
		with input.tenant as "ten10"
}

test_stack_owner_cannot_create_bundles if {
	not data.authz.allow with input.principal as "testuser"
		with data.principals.id as "testuser"
		with data.principals.role as "stack_owner"
		with data.principals.tenant_id as 10
		with data.tenants.id as 10
		with data.tenants.name as "ten10"
		with input.permission as "bundles.create"
		with input.tenant as "ten10"
}

test_owners_can_edit_bundles if {
	data.authz.allow with input.principal as "testuser"
		with data.principals.id as "testuser"
		with data.principals.role as "owner"
		with data.resource_permissions.name as "testbundle"
		with data.resource_permissions.resource as "bundles"
		with data.resource_permissions.role as "owner"
		with data.resource_permissions.principal_id as "testuser"
		with data.resource_permissions.tenant_id as 10
		with data.tenants.id as 10
		with data.tenants.name as "ten10"
		with input.permission as "bundles.manage"
		with input.name as "testbundle"
		with input.resource as "bundles"
		with input.tenant as "ten10"
}

test_explicit_permission_grant if {
	data.authz.allow with input.principal as "testuser"
		with data.principals.id as "testuser"
		with data.resource_permissions.name as "testsource"
		with data.resource_permissions.resource as "sources"
		with data.resource_permissions.permission as "sources.data.write"
		with data.resource_permissions.principal_id as "testuser"
		with data.resource_permissions.tenant_id as 10
		with data.tenants.id as 10
		with data.tenants.name as "ten10"
		with input.permission as "sources.data.write"
		with input.name as "testsource"
		with input.resource as "sources"
		with input.tenant as "ten10"
}
