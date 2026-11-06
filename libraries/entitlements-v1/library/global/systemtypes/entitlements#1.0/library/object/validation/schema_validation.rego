package global.systemtypes["entitlements:1.0"].library.object.validation

import rego.v1

# This file intends to provide schema tests for the object model that the user is
#   responsible for populating.  The idea is that they can import these tests to
#   understand what, if anything, is wrong with their object model.

# top-level test
test_all if {
	count(deny) == 0
}

# top-level enumeration of problems
deny = (((((deny_actions | deny_resources) | deny_roles) | deny_role_bindings) | deny_users) | deny_groups) | deny_service_accounts

# actions
deny_actions contains msg if {
	not is_array(data.object.actions)
	msg := "data.object.actions must be an array but is not"
}

deny_actions contains msg if {
	some action in data.object.actions
	not is_string(action)
	msg := sprintf("Action %v is not a string but should be", [action])
}

test_deny_actions if {
	count(deny_actions) == 0 with data.object.actions as ["foo", "bar", "baz"]
	count(deny_actions) == 1 with data.object.actions as 7
	count(deny_actions) == 2 with data.object.actions as ["foo", 1, "bar", 2]
}

# resources
deny_resources contains msg if {
	not is_object(data.object.resources)
	msg := "data.object.resources must be an object mapping a resource name to its attributes"
}

deny_resources contains msg if {
	some name
	x := data.object.resources[name]
	not is_object(x)
	msg := sprintf("Resource %v is not an object but should be", [name])
}

test_deny_resources if {
	count(deny_resources) == 0 with data.object.resources as {"foo": {"bar": 7}, "baz": {"qux": 9}}
	count(deny_resources) == 4 with data.object.resources as [1, 2, 3]
	count(deny_resources) == 2 with data.object.resources as {"foo": {"bar": 7}, "baz": 9, "qux": 10}
}

# roles
deny_roles contains msg if {
	not is_object(data.object.roles)
	msg := "'data.object.roles' must be an object mapping a role-name to the role definition"
}

deny_roles contains msg if {
	some rolename
	role_obj := data.object.roles[rolename]

	# deny: {...} or allow: {...}
	count(role_obj) == 1
	keys := {"allow", "deny"}
	some k # can be only 1
	role_obj[k] = _
	not k in keys
	msg := sprintf("Role %v uses modality %v instead of allow/deny", [rolename, k])
}

deny_roles contains msg if {
	some rolename, allowdeny, k
	rule_obj := data.object.roles[rolename][allowdeny][k]

	# {include: ...} or {exclude: ...}
	modes := {"include", "exclude"}
	not k in modes
	msg := sprintf("Role %v has %v rule with neither 'include' nor 'exclude': %v", [rolename, allowdeny, k])
}

deny_roles contains msg if {
	some rolename, allowdeny, includeexclude, i, key
	data.object.roles[rolename][allowdeny][includeexclude][i][key]

	# {include: ...} or {exclude: ...}
	keywords := {"actions", "resources"}
	not key in keywords
	msg := sprintf("Role %v has %v rule where mode %v has index %v with a prohibited keyword %v", [rolename, allowdeny, includeexclude, i, key])
}

test_deny_roles if {
	r1 := {"DenySystemConfig": {"deny": {"include": [{
		"actions": ["update", "delete"],
		"resources": ["System.Configuration"],
	}]}}}

	count(deny_roles) == 0 with data.object.roles as r1

	r2 := {"DenySystemConfig": {"foo": {"include": [{
		"actions": ["update", "delete"], # here
		"resources": ["System.Configuration"],
	}]}}}

	count(deny_roles) == 1 with data.object.roles as r2

	r3 := {"DenySystemConfig": {"deny": {"foo": [{
		"actions": ["update", "delete"], # here
		"resources": ["System.Configuration"],
	}]}}}

	count(deny_roles) == 1 with data.object.roles as r3

	r4 := {"DenySystemConfig": {"deny": {"include": [{
		"foo": ["update", "delete"], # here
		"resources": ["System.Configuration"],
	}]}}}

	count(deny_roles) == 1 with data.object.roles as r3
}

# role_bindings
deny_role_bindings contains msg if {
	not is_object(data.object.role_bindings)
	msg := "data.object.role_bindings is not a JSON object"
}

deny_role_bindings contains msg if {
	rbobj := data.object.role_bindings[rolename]
	not rbobj.subjects.ids
	msg := sprintf("Role binding %v does not have subjects.ids path", [rolename])
}

deny_role_bindings contains msg if {
	some id in data.object.role_bindings[rolename].subjects.ids
	not is_string(id)
	msg := sprintf("Role binding %v has an id that is not a string: %v", [rolename, id])
}

test_rolebindings if {
	count(deny_role_bindings) == 0 with data.object.role_bindings as {"DenySystemConfigModification": {"subjects": {"ids": ["bob"]}}}

	count(deny_role_bindings) == 4 with data.object.role_bindings as [1, 2, 3]

	count(deny_role_bindings) == 1 with data.object.role_bindings as {"DenySystemConfigModification": {"FOO": {"ids": ["bob"]}}}

	count(deny_role_bindings) == 1 with data.object.role_bindings as {"DenySystemConfigModification": {"subjects": {"FOO": ["bob"]}}}

	count(deny_role_bindings) == 2 with data.object.role_bindings as {"DenySystemConfigModification": {"subjects": {"ids": ["bob", 7, 9]}}}
}

# users
deny_users contains msg if {
	not is_object(data.object.users)
	msg := "data.object.users should be a JSON object, but it is not."
}

test_denyusers if {
	count(deny_users) == 0 with data.object.users as {"alice": {"location": "Mars", "name": "Alice", "organization": "Styra"}}
	count(deny_users) == 1 with data.object.users as [1, 2, 3]
}

# serviceaccounts
deny_service_accounts contains msg if {
	not is_object(data.object.service_accounts)
	msg := "data.object.service_accounts must be a JSON object, but it is not"
}

test_denyserviceaccounts if {
	count(deny_service_accounts) == 0 with data.object.service_accounts as {"abc": true, "def": true}
	count(deny_service_accounts) == 1 with data.object.service_accounts as [1, 2, 3]
}

# groups
deny_groups contains msg if {
	not is_object(data.object.groups)
	msg := "data.object.groups should be a JSON object, but it is not"
}

deny_groups contains msg if {
	some groupname
	obj := data.object.groups[groupname]
	not obj.users
	msg := sprintf("Group %v has no 'users' field", [groupname])
}

deny_groups contains msg if {
	some groupname
	obj := data.object.groups[groupname]
	not is_array(obj.users)
	msg := sprintf("Group %v has a 'users' field that is not an array", [groupname])
}

deny_groups contains msg if {
	some groupname, i
	user := data.object.groups[groupname].users[i]
	not is_string(user)
	msg := sprintf("Group %v user at index %v is not a string: %v", [groupname, i, user])
}

test_denygroups if {
	count(deny_groups) == 0 with data.object.groups as {"platform-team": {"users": ["cheng", "eric"]}}
	count(deny_groups) == 4 with data.object.groups as [1, 2, 3]
	count(deny_groups) == 1 with data.object.groups as {"platform-team": {"FOO": ["cheng", "eric"]}}
	count(deny_groups) == 1 with data.object.groups as {"platform-team": {"users": {"cheng", "eric"}}} # set, not array
	count(deny_groups) == 2 with data.object.groups as {"platform-team": {"users": ["cheng", 7, 8]}} # set, not array
}
