package authz

import rego.v1

allow if {
	data.principals.id == input.principal
	data.principals.role == "administrator"
	in_tenant(data.principals.tenant_id)
}

allow if {
	data.principals.id == input.principal
	data.principals.role == "viewer"
	in_tenant(data.principals.tenant_id)
	input.permission in [
		"bundles.view",
		"sources.view",
		"secrets.view",
		"stacks.view",
		"tokens.view",
		"sources.data.read",
	]
}

allow if {
	data.principals.id == input.principal
	data.principals.role == "owner"
	in_tenant(data.principals.tenant_id)
	input.permission in [
		"bundles.create",
		"sources.create",
		"secrets.create",
	]
}

allow if {
	data.principals.id == input.principal
	data.principals.role == "stack_owner"
	in_tenant(data.principals.tenant_id)
	input.permission == "stacks.create"
}

allow if {
	data.resource_permissions.name == input.name
	data.resource_permissions.resource == input.resource
	data.resource_permissions.principal_id == input.principal
	in_tenant(data.resource_permissions.tenant_id)
	data.resource_permissions.role == "owner"
}

allow if {
	data.resource_permissions.name == input.name
	data.resource_permissions.resource == input.resource
	data.resource_permissions.principal_id == input.principal
	data.resource_permissions.permission == input.permission
	in_tenant(data.resource_permissions.tenant_id)
}

in_tenant(tenant_id) if {
	data.tenants.name == input.tenant
	tenant_id == data.tenants.id
}
