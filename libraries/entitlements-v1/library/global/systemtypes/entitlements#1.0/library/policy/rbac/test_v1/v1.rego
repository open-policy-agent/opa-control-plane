package global.systemtypes["entitlements:1.0"].library.policy.rbac.test_v1

import rego.v1
import data.global.systemtypes["entitlements:1.0"].library.policy.rbac.v1 as actions

mock_request(action, subject, resource) = x if {
	x := {
		"action": action,
		"subject": subject,
		"resource": resource,
	}
}

mock_role_binding_by_ids(role_id, subject_ids) = {role_id: {"subjects": {"ids": subject_ids}}}

mock_allow_role(role_id, actions, resources) = {role_id: {"allow": {"include": [mock_actions_resources_selectors(actions, resources)]}}}

mock_allow_role_with_exclude(role_id, include_actions, include_resources, exclude_actions, exclude_resources) = {role_id: {"allow": {
	"include": [mock_actions_resources_selectors(include_actions, include_resources)],
	"exclude": [mock_actions_resources_selectors(exclude_actions, exclude_resources)],
}}}

mock_deny_role_with_exclude(role_id, include_actions, include_resources, exclude_actions, exclude_resources) = {role_id: {"deny": {
	"include": [mock_actions_resources_selectors(include_actions, include_resources)],
	"exclude": [mock_actions_resources_selectors(exclude_actions, exclude_resources)],
}}}

mock_actions_resources_selectors(actions, resources) = {
	"actions": actions,
	"resources": resources,
}

test_any_role_allows_access_negative if {
	# no role binding for some-user
	msg_no_role_binding_match := actions.any_role_allows_access with input as mock_request("some-action", "some-user", "some-resource")
		with data.object.role_bindings as mock_role_binding_by_ids("no-matching-role", ["some-user"])
		with data.object.roles as mock_allow_role("some-role", ["some-action"], ["some-resource"])

	msg_no_role_binding_match == set()

	# resources in role don't match request resource
	msg_no_resource_match := actions.any_role_allows_access with input as mock_request("some-action", "some-user", "some-resource")
		with data.object.role_bindings as mock_role_binding_by_ids("some-role", ["some-user"])
		with data.object.roles as mock_allow_role("some-role", ["some-action"], ["a", "b", "c", "don't match"])

	msg_no_resource_match == set()

	# action in role don't match request resource
	msg_no_action_match := actions.any_role_allows_access with input as mock_request("some-action", "some-user", "some-resource")
		with data.object.role_bindings as mock_role_binding_by_ids("some-role", ["some-user"])
		with data.object.roles as mock_allow_role("some-role", ["no-action-match"], ["**"])

	msg_no_action_match == set()
}

test_any_role_allows_access_simple if {
	msg := actions.any_role_allows_access with input as mock_request("some-action", "some-user", "some-resource")
		with data.object.role_bindings as mock_role_binding_by_ids("some-role", ["some-user"])
		with data.object.roles as mock_allow_role("some-role", ["some-action"], ["some-resource"])

	msg == {"Access is allowed by roles some-role"}
}

test_any_role_allows_access_with_group if {
	msg := actions.any_role_allows_access with input as mock_request("some-action", "some-user", "some-resource")
		with data.object.role_bindings as mock_role_binding_by_ids("some-role", ["some-group"])
		with data.object.users as {}
		with data.object.roles as object.union(
			mock_allow_role("unused-role", ["n/a"], ["n/a"]),
			mock_allow_role("some-role", ["some-action"], ["some-resource"]),
		)
		with data.object.groups as {"some-group": {"users": ["some-user"]}}

	msg == {"Access is allowed by roles some-role"}
}

test_any_role_allows_access_multiple_roles if {
	roles := object.union(
		mock_allow_role("role-a", ["a-action"], ["a-resource"]),
		mock_allow_role("role-allow-all", ["a-action", "b-action"], ["a-resource", "b-resource"]),
	)

	role_bindings := object.union(
		mock_role_binding_by_ids("role-a", ["some-user"]),
		mock_role_binding_by_ids("role-allow-all", ["some-user"]),
	)

	# two roles, one allows
	msg_one_allows := actions.any_role_allows_access with input as mock_request("b-action", "some-user", "b-resource")
		with data.object.role_bindings as role_bindings
		with data.object.roles as roles

	msg_one_allows == {"Access is allowed by roles role-allow-all"}

	# two roles, both allow
	msg_both_allows := actions.any_role_allows_access with input as mock_request("a-action", "some-user", "a-resource")
		with data.object.role_bindings as role_bindings
		with data.object.roles as roles

	msg_both_allows == {"Access is allowed by roles role-a, role-allow-all"}
}

test_any_role_denies_access_multiple_roles if {
	roles := object.union(
		mock_deny_role_with_exclude("role-a", ["a-action"], ["a-resource", "exclude-resource"], [], []),
		mock_deny_role_with_exclude("role-deny-all", ["a-action", "b-action"], ["a-resource", "b-resource"], ["exclude-action"], ["exclude-resource"]),
	)

	role_bindings := object.union(
		mock_role_binding_by_ids("role-a", ["some-user"]),
		mock_role_binding_by_ids("role-deny-all", ["some-user"]),
	)

	# two roles, one denies
	msg_one_denies := actions.any_role_denies_access with input as mock_request("a-action", "some-user", "exclude-resource")
		with data.object.role_bindings as role_bindings
		with data.object.roles as roles

	msg_one_denies == {"Access is denied by roles role-a"}

	# two roles, both deny
	msg_both_denies := actions.any_role_denies_access with input as mock_request("a-action", "some-user", "a-resource")
		with data.object.role_bindings as role_bindings
		with data.object.roles as roles

	msg_both_denies == {"Access is denied by roles role-a, role-deny-all"}
}

test_any_role_denies_access_with_group if {
	msg := actions.any_role_denies_access with input as mock_request("some-action", "some-user", "some-resource")
		with data.object.users as {}
		with data.object.role_bindings as mock_role_binding_by_ids("some-role", ["some-group"])
		with data.object.roles as object.union(
			mock_deny_role_with_exclude("unused-role", ["n/a"], ["n/a"], [], []),
			mock_deny_role_with_exclude("some-role", ["some-action"], ["some-resource"], [], []),
		)
		with data.object.groups as {"some-group": {"users": ["some-user"]}}

	msg == {"Access is denied by roles some-role"}

	# same setup as above, but deny role exclude some-action and some-resource
	no_match := actions.any_role_denies_access with input as mock_request("some-action", "some-user", "some-resource")
		with data.object.role_bindings as mock_role_binding_by_ids("some-role", ["some-group"])
		with data.object.roles as object.union(
			mock_deny_role_with_exclude("unused-role", ["n/a"], ["n/a"], [], []),
			mock_deny_role_with_exclude("some-role", ["*"], ["*"], ["some-action"], ["some-resource"]),
		)
		with data.object.groups as {"some-group": {"users": ["some-user"]}}

	no_match == set()
}

test_role_allows_access if {
	roledef := {"allow": {"include": [
		{"actions": ["*"], "resources": ["any-action"]},
		{"actions": ["read"], "resources": ["read-only", "read-only-2"]},
	]}}

	actions.role_allows_access(roledef, {"action": "read", "resource": "read-only-2"}) == true
}

test_roles_bound_to_request_subject if {
	role_bindings := {
		"role-1": {"subjects": {"ids": ["alice"]}},
		"role-2": {"subjects": {"ids": ["b", "group"]}},
		"role-3": {"subjects": {"ids": ["bob", "alice"]}},
	}

	users := {"member": {}}

	roles1 := actions.roles_bound_to_request_subject with input as {"subject": "alice"}
		with data.object.role_bindings as role_bindings
		with data.object.users as users

	roles1 == {{"roles": {"role-1", "role-3"}, "snippet": "global/systemtypes/entitlements:1.0/library/policy/rbac/v1/roles_bound_to_request_subject"}}

	roles2 := actions.roles_bound_to_request_subject with input as {"subject": "member"}
		with data.object.role_bindings as role_bindings
		with data.object.users as users
		with data.object.groups as {"group": {"users": ["member"]}}

	roles2 == {{"roles": {"role-2"}, "snippet": "global/systemtypes/entitlements:1.0/library/policy/rbac/v1/roles_bound_to_request_subject"}}

	# A non-existant member should not have any roles.
	roles3 := actions.roles_bound_to_request_subject with input as {"subject": "nonexistant"}
		with data.object.role_bindings as role_bindings
		with data.object.users as users
		with data.object.groups as {"group": {"users": ["member"]}}

	roles3 == {{"roles": set(), "snippet": "global/systemtypes/entitlements:1.0/library/policy/rbac/v1/roles_bound_to_request_subject"}}
}

test_dynamic_groups if {
	# Case where the user and the group have identical attributes
	groups1 := actions.groups_for_subject("alice") with data.object.groups as {"some-group": {"membership-attributes": {"foo": "bar"}}}
		with data.object.users as {"alice": {"foo": "bar"}}

	groups1 == {"some-group"}

	# Case where the user has more attributes than the group.
	groups2 := actions.groups_for_subject("alice") with data.object.groups as {"some-group": {"membership-attributes": {"foo": "bar"}}}
		with data.object.users as {"alice": {"foo": "bar", "baz": "quux"}}

	groups2 == {"some-group"}

	# Case where the user and the group have the same attributes but they
	# have different values.
	groups3 := actions.groups_for_subject("alice") with data.object.groups as {"some-group": {"membership-attributes": {"foo": "quux"}}}
		with data.object.users as {"alice": {"foo": "bar"}}

	groups3 == set()

	# Case where the user has more attributes than the group but one of the
	# attribute values does not match.
	groups4 := actions.groups_for_subject("alice") with data.object.groups as {"some-group": {"membership-attributes": {"foo": "spam"}}}
		with data.object.users as {"alice": {"foo": "bar", "baz": "quux"}}

	groups4 == set()

	# Case where the user has fewer attributes than the group.
	groups5 := actions.groups_for_subject("alice") with data.object.groups as {"some-group": {"membership-attributes": {"foo": "bar", "bar": "baz"}}}
		with data.object.users as {"alice": {"foo": "bar"}}

	groups5 == set()

	# Case where there are multiple groups with different membership
	# attributes.
	groups6 := actions.groups_for_subject("alice") with data.object.groups as {
		"some-group": {"membership-attributes": {"foo": "bar", "bar": "baz"}},
		"other-group": {"membership-attributes": {"foo": "bar"}},
	}
		with data.object.users as {"alice": {"foo": "bar", "bar": "baz"}}

	groups6 == {"some-group", "other-group"}

	groups7 := actions.groups_for_subject("some-user") with data.object.groups as {"some-group": {"users": ["some-user"]}}
		with data.object.users as {}

	groups7 == {"some-group"}

	groups8 := actions.groups_for_subject("robot") with data.object.groups as {"some-group": {"users": ["robot"]}}
		with data.object.users as {}
		with data.object.service_accounts as {"robot": {}}

	groups8 == {"some-group"}

	groups9 := actions.groups_for_subject("robot") with data.object.groups as {"some-group": {"membership-attributes": {"is_robot": true}}}
		with data.object.users as {}
		with data.object.service_accounts as {"robot": {"is_robot": true}}

	groups9 == {"some-group"}

	# This handles an edge case discovered while fixing STY-11504 where
	# membership-attributes needed to me made mandatory. In the naive
	# implementation of that behavior, subjects with no attributes could
	# get assigned into groups which omitted the membership-attributes
	# field, since {} == {}.
	groups10 := actions.groups_for_subject("alice") with data.object.groups as {"group1": {"users": ["alice"]}, "group2": {"membership-attributes": {"is_robot": true}}, "group3": {"users": ["bob"]}}
		with data.object.users as {"alice": {}}
		with data.object.service_accounts as {}

	groups10 == {"group1"}
}

test_dynamic_roles if {
	role_bindings := {
		"role-1": {"subjects": {"membership-attributes": {"foo": "bar"}}},
		"role-2": {"subjects": {"membership-attributes": {"foo": "baz"}}},
		"role-3": {"subjects": {"membership-attributes": {"foo": "baz", "spam": "ham"}}},
	}

	# Case where user attributes exactly match role attributes.
	roles1 := actions.roles_bound_to_subject("alice") with data.object.users as {"alice": {"foo": "bar"}}
		with data.object.role_bindings as role_bindings

	roles1 == {"role-1"}

	# Case where user attributes exactly match role attributes, also where
	# user attribute keyspace is a supset of the role attribute keyspace.
	roles2 := actions.roles_bound_to_subject("alice") with data.object.users as {"alice": {"foo": "baz", "spam": "ham"}}
		with data.object.role_bindings as role_bindings

	roles2 == {"role-3", "role-2"}

	# Case where user matches no roles.
	roles3 := actions.roles_bound_to_subject("alice") with data.object.users as {"alice": {"foo": "quux", "spam": "ham"}}
		with data.object.role_bindings as role_bindings

	roles3 == set()

	# Service accounts should be able to have roles too
	roles4 := actions.roles_bound_to_subject("robot") with data.object.service_accounts as {"robot": {"foo": "baz", "spam": "ham"}}
		with data.object.role_bindings as role_bindings

	roles4 == {"role-3", "role-2"}
}

test_subject_type if {
	users := {"alice": {"name": "Alice"}, "bob": {}}
	groups := {"sales": {}, "IT": {}}
	service_accounts := {"cicd_bot": {}}

	"user" == actions.subject_type("alice") with data.object.users as users
		with data.object.groups as groups
		with data.object.service_accounts as service_accounts

	"user" == actions.subject_type("bob") with data.object.users as users
		with data.object.groups as groups
		with data.object.service_accounts as service_accounts

	"group" == actions.subject_type("sales") with data.object.users as users
		with data.object.groups as groups
		with data.object.service_accounts as service_accounts

	"group" == actions.subject_type("IT") with data.object.users as users
		with data.object.groups as groups
		with data.object.service_accounts as service_accounts

	"service_account" == actions.subject_type("cicd_bot") with data.object.users as users
		with data.object.groups as groups
		with data.object.service_accounts as service_accounts

	"none" == actions.subject_type("nonexistant") with data.object.users as users
		with data.object.groups as groups
		with data.object.service_accounts as service_accounts

	"none" == actions.subject_type("some-user") with data.object.groups as {"some-group": {"users": ["some-user"]}}
		with data.object.users as {}
}

test_complicated_1 if {
	# This test is intended to exercise a more sophisticated, complex
	# example where multiple features are exercised in tandem.
	#
	# The sample data here is copied over from the car_info_store sample,
	# but is intentional led maintained separately, so that the sample
	# data and this test case can be updated separately. The point of
	# this is to exercise RBAC functions in a complex way, NOT to validate
	# the sample data.

	groups := {
		"senior-leadership-team": {"membership-attributes": {"team": "SLT"}},
		"store-managers": {"users": ["alice"]},
		"sales": {"membership-attributes": {"team": "sales"}},
		"back-office": {"users": ["janet", "william"]},
		"robots": {"membership-attributes": {"bot": true}},
	}

	users := {
		"alice": {
			"name": "Alice",
			"organization": "Styra",
			"location": "Mars",
			"title": "general manager",
			"is_employee": true,
			"team": "sales",
		},
		"bob": {
			"name": "Bob",
			"organization": "Styra",
			"title": "CEO",
			"is_employee": true,
			"team": "SLT",
		},
		"eric": {
			"name": "Eric",
			"title": "sales associate",
			"is_employee": true,
			"team": "sales",
		},
		"janet": {
			"name": "Janet",
			"title": "accountant",
			"is_employee": true,
		},
		"sarah": {"is_employee": true},
	}

	roles := {
		"car-creators": {"allow": {"include": [{
			"actions": ["POST"],
			"resources": ["/cars", "/cars/*"],
		}]}},
		"car-updaters": {"allow": {"include": [{
			"actions": ["POST", "PUT"],
			"resources": ["/cars", "/cars/*"],
		}]}},
		"car-readers": {"allow": {"include": [{
			"actions": ["GET"],
			"resources": ["/cars", "/cars/*"],
		}]}},
		"status-updaters": {"allow": {"include": [{
			"actions": ["PUT"],
			"resources": ["/cars/*/status"],
		}]}},
		"status-readers": {"allow": {"include": [{
			"actions": ["GET"],
			"resources": ["/cars/*/status"],
		}]}},
	}

	role_bindings := {
		"car-creators": {"subjects": {"ids": ["sales", "store-managers", "senior-leadership-team"]}},
		"status-updaters": {"subjects": {"ids": ["sales", "store-managers", "senior-leadership-team", "janet"]}},
		"status-deleters": {"subjects": {"ids": ["store-managers", "senior-leadership-team"]}},
		"car-updaters": {"subjects": {"ids": ["store-managers", "senior-leadership-team", "cicd_bot"]}},
		"car-readers": {"subjects": {
			"ids": ["robots"],
			"membership-attributes": {"is_employee": true},
		}},
		"status-readers": {"subjects": {
			"ids": ["robots"],
			"membership-attributes": {"is_employee": true},
		}},
	}

	service_accounts := {"cicd_bot": {"bot": true}}

	# Verify that the groups for all uses are correct.
	alice_groups := actions.groups_for_subject("alice") with data.object.users as users
		with data.object.groups as groups
		with data.object.roles as roles
		with data.object.role_bindings as role_bindings
		with data.object.service_accounts as service_accounts

	alice_groups == {"sales", "store-managers"}

	bob_groups := actions.groups_for_subject("bob") with data.object.users as users
		with data.object.groups as groups
		with data.object.roles as roles
		with data.object.role_bindings as role_bindings
		with data.object.service_accounts as service_accounts

	bob_groups == {"senior-leadership-team"}

	eric_groups := actions.groups_for_subject("eric") with data.object.users as users
		with data.object.groups as groups
		with data.object.roles as roles
		with data.object.role_bindings as role_bindings
		with data.object.service_accounts as service_accounts

	eric_groups == {"sales"}

	janet_groups := actions.groups_for_subject("janet") with data.object.users as users
		with data.object.groups as groups
		with data.object.roles as roles
		with data.object.role_bindings as role_bindings
		with data.object.service_accounts as service_accounts

	janet_groups == {"back-office"}

	sarah_groups := actions.groups_for_subject("sarah") with data.object.users as users
		with data.object.groups as groups
		with data.object.roles as roles
		with data.object.role_bindings as role_bindings
		with data.object.service_accounts as service_accounts

	sarah_groups == set()

	cicd_bot_groups := actions.groups_for_subject("cicd_bot") with data.object.users as users
		with data.object.groups as groups
		with data.object.roles as roles
		with data.object.role_bindings as role_bindings
		with data.object.service_accounts as service_accounts

	cicd_bot_groups == {"robots"}

	# Verify that the roles for all uses are correct.
	alice_roles := actions.roles_bound_to_subject("alice") with data.object.users as users
		with data.object.groups as groups
		with data.object.roles as roles
		with data.object.role_bindings as role_bindings
		with data.object.service_accounts as service_accounts

	alice_roles == {"car-creators", "status-updaters", "status-deleters", "car-updaters", "car-readers", "status-readers"}

	bob_roles := actions.roles_bound_to_subject("bob") with data.object.users as users
		with data.object.groups as groups
		with data.object.roles as roles
		with data.object.role_bindings as role_bindings
		with data.object.service_accounts as service_accounts

	bob_roles == {"car-creators", "status-updaters", "status-deleters", "car-updaters", "car-readers", "status-readers"}

	eric_roles := actions.roles_bound_to_subject("eric") with data.object.users as users
		with data.object.groups as groups
		with data.object.roles as roles
		with data.object.role_bindings as role_bindings
		with data.object.service_accounts as service_accounts

	eric_roles == {"car-creators", "status-updaters", "car-readers", "status-readers"}

	janet_roles := actions.roles_bound_to_subject("janet") with data.object.users as users
		with data.object.groups as groups
		with data.object.roles as roles
		with data.object.role_bindings as role_bindings
		with data.object.service_accounts as service_accounts

	janet_roles == {"car-readers", "status-readers", "status-updaters"}

	sarah_roles := actions.roles_bound_to_subject("sarah") with data.object.users as users
		with data.object.groups as groups
		with data.object.roles as roles
		with data.object.role_bindings as role_bindings
		with data.object.service_accounts as service_accounts

	sarah_roles == {"car-readers", "status-readers"}

	cicd_bot_roles := actions.roles_bound_to_subject("cicd_bot") with data.object.users as users
		with data.object.groups as groups
		with data.object.roles as roles
		with data.object.role_bindings as role_bindings
		with data.object.service_accounts as service_accounts

	cicd_bot_roles == {"car-readers", "status-readers", "car-updaters"}

	# Test a few select examples with any role allows access.
	msg1 := actions.any_role_allows_access with input as mock_request("GET", "alice", "/cars")
		with data.object.users as users
		with data.object.groups as groups
		with data.object.roles as roles
		with data.object.role_bindings as role_bindings
		with data.object.service_accounts as service_accounts

	msg1 == {"Access is allowed by roles car-readers"}

	msg2 := actions.any_role_allows_access with input as mock_request("GET", "alice", "/cars/car7")
		with data.object.users as users
		with data.object.groups as groups
		with data.object.roles as roles
		with data.object.role_bindings as role_bindings
		with data.object.service_accounts as service_accounts

	msg2 == {"Access is allowed by roles car-readers"}

	msg3 := actions.any_role_allows_access with input as mock_request("DELETE", "janet", "/cars/car7")
		with data.object.users as users
		with data.object.groups as groups
		with data.object.roles as roles
		with data.object.role_bindings as role_bindings
		with data.object.service_accounts as service_accounts

	msg3 == set()

	msg4 := actions.any_role_allows_access with input as mock_request("PUT", "cicd_bot", "/cars/car7")
		with data.object.users as users
		with data.object.groups as groups
		with data.object.roles as roles
		with data.object.role_bindings as role_bindings
		with data.object.service_accounts as service_accounts

	msg4 == {"Access is allowed by roles car-updaters"}
}

test_ucdw_1 if {
	role_bindings := {
		"role-1": {"subjects": {"membership-attributes": {"foo": "bar"}}},
		"role-2": {"subjects": {"membership-attributes": {"baz": "quux"}}},
	}

	roles := {
		"role-1": {
			"allow": {
				"include": [{"actions": ["action1", "action2"], "resources": ["resource1", "resource2"]}],
				"exclude": [{"actions": ["action3", "action4"], "resources": ["resource3", "resource4"]}],
			},
			"deny": {
				"include": [{"actions": ["action5", "action6"], "resources": ["resource5", "resource6"]}],
				"exclude": [{"actions": ["action7", "action8"], "resources": ["resource7", "resource8"]}],
			},
		},
		"role-2": {"allow": {"include": [{"actions": ["action9"], "resources": ["resource9"]}]}},
	}

	users := {
		"user1": {"foo": "bar"},
		"user2": {"baz": "quux"},
		"user3": {"foo": "bar", "baz": "quux"},
	}

	ucdw := actions.user_can_do_what with data.object.users as users
		with data.object.roles as roles
		with data.object.role_bindings as role_bindings

	print(ucdw)

	expect := {
		"user1": {
			{
				"action": "action1",
				"connective": "include",
				"outcome": "allow",
				"resource": "resource1",
			},
			{
				"action": "action1",
				"connective": "include",
				"outcome": "allow",
				"resource": "resource2",
			},
			{
				"action": "action2",
				"connective": "include",
				"outcome": "allow",
				"resource": "resource1",
			},
			{
				"action": "action2",
				"connective": "include",
				"outcome": "allow",
				"resource": "resource2",
			},
			{
				"action": "action3",
				"connective": "exclude",
				"outcome": "allow",
				"resource": "resource3",
			},
			{
				"action": "action3",
				"connective": "exclude",
				"outcome": "allow",
				"resource": "resource4",
			},
			{
				"action": "action4",
				"connective": "exclude",
				"outcome": "allow",
				"resource": "resource3",
			},
			{
				"action": "action4",
				"connective": "exclude",
				"outcome": "allow",
				"resource": "resource4",
			},
			{
				"action": "action5",
				"connective": "include",
				"outcome": "deny",
				"resource": "resource5",
			},
			{
				"action": "action5",
				"connective": "include",
				"outcome": "deny",
				"resource": "resource6",
			},
			{
				"action": "action6",
				"connective": "include",
				"outcome": "deny",
				"resource": "resource5",
			},
			{
				"action": "action6",
				"connective": "include",
				"outcome": "deny",
				"resource": "resource6",
			},
			{
				"action": "action7",
				"connective": "exclude",
				"outcome": "deny",
				"resource": "resource7",
			},
			{
				"action": "action7",
				"connective": "exclude",
				"outcome": "deny",
				"resource": "resource8",
			},
			{
				"action": "action8",
				"connective": "exclude",
				"outcome": "deny",
				"resource": "resource7",
			},
			{
				"action": "action8",
				"connective": "exclude",
				"outcome": "deny",
				"resource": "resource8",
			},
		},
		"user2": {{
			"action": "action9",
			"connective": "include",
			"outcome": "allow",
			"resource": "resource9",
		}},
		"user3": {
			{
				"action": "action1",
				"connective": "include",
				"outcome": "allow",
				"resource": "resource1",
			},
			{
				"action": "action1",
				"connective": "include",
				"outcome": "allow",
				"resource": "resource2",
			},
			{
				"action": "action2",
				"connective": "include",
				"outcome": "allow",
				"resource": "resource1",
			},
			{
				"action": "action2",
				"connective": "include",
				"outcome": "allow",
				"resource": "resource2",
			},
			{
				"action": "action3",
				"connective": "exclude",
				"outcome": "allow",
				"resource": "resource3",
			},
			{
				"action": "action3",
				"connective": "exclude",
				"outcome": "allow",
				"resource": "resource4",
			},
			{
				"action": "action4",
				"connective": "exclude",
				"outcome": "allow",
				"resource": "resource3",
			},
			{
				"action": "action4",
				"connective": "exclude",
				"outcome": "allow",
				"resource": "resource4",
			},
			{
				"action": "action5",
				"connective": "include",
				"outcome": "deny",
				"resource": "resource5",
			},
			{
				"action": "action5",
				"connective": "include",
				"outcome": "deny",
				"resource": "resource6",
			},
			{
				"action": "action6",
				"connective": "include",
				"outcome": "deny",
				"resource": "resource5",
			},
			{
				"action": "action6",
				"connective": "include",
				"outcome": "deny",
				"resource": "resource6",
			},
			{
				"action": "action7",
				"connective": "exclude",
				"outcome": "deny",
				"resource": "resource7",
			},
			{
				"action": "action7",
				"connective": "exclude",
				"outcome": "deny",
				"resource": "resource8",
			},
			{
				"action": "action8",
				"connective": "exclude",
				"outcome": "deny",
				"resource": "resource7",
			},
			{
				"action": "action8",
				"connective": "exclude",
				"outcome": "deny",
				"resource": "resource8",
			},
			{
				"action": "action9",
				"connective": "include",
				"outcome": "allow",
				"resource": "resource9",
			},
		},
	}

	ucdw == expect
}

test_wcdt_1 if {
	role_bindings := {
		"role-1": {"subjects": {"membership-attributes": {"foo": "bar"}}},
		"role-2": {"subjects": {"membership-attributes": {"baz": "quux"}}},
	}

	roles := {
		"role-1": {
			"allow": {
				"include": [{"actions": ["action1", "action2"], "resources": ["resource1", "resource2"]}],
				"exclude": [{"actions": ["action3", "action4"], "resources": ["resource3", "resource4"]}],
			},
			"deny": {
				"include": [{"actions": ["action5", "action6"], "resources": ["resource5", "resource6"]}],
				"exclude": [{"actions": ["action7", "action8"], "resources": ["resource7", "resource8"]}],
			},
		},
		"role-2": {"allow": {"include": [{"actions": ["action9"], "resources": ["resource9"]}]}},
	}

	users := {
		"user1": {"foo": "bar"},
		"user2": {"baz": "quux"},
		"user3": {"foo": "bar", "baz": "quux"},
	}

	resources := {
		"resource1": {},
		"resource2": {},
		"resource3": {},
		"resource4": {},
		"resource5": {},
		"resource6": {},
		"resource7": {},
		"resource8": {},
		"resource9": {},
	}

	test_actions := [
		"action1",
		"action2",
		"action3",
		"action4",
		"action5",
		"action6",
		"action7",
		"action8",
		"action9",
	]

	actions.snippet_who_can_do_this[wcdt_res1_act1] with data.object.users as users
		with data.object.roles as roles
		with data.object.role_bindings as role_bindings
		with data.object.resources as resources
		with data.object.actions as test_actions
		with input as {"subject": "user1", "resource": "resource1", "action": "action1"}
		with data.library.parameters as {"outcome": "allow or deny", "connective": "include or exclude"}

	print("wcdt_res1_act1", wcdt_res1_act1)

	expect_res1_act1 := {{
		"snippet": "global/systemtypes/entitlements:1.0/library/policy/rbac/v1/snippet_who_can_do_this",
		"who_can_do_this": {
			{"connective": "include", "outcome": "allow", "subject": "user1", "action": "action1"},
			{"connective": "include", "outcome": "allow", "subject": "user3", "action": "action1"},
		},
	}}

	# the object.get here is used to avoid the type checker
	wcdt_res1_act1 == object.get({"x": expect_res1_act1}, "x", {})

	actions.snippet_who_can_do_this[wcdt_res1_actX] with data.object.users as users
		with data.object.roles as roles
		with data.object.role_bindings as role_bindings
		with data.object.resources as resources
		with data.object.actions as test_actions
		with input as {"subject": "user1", "resource": "resource1", "action": "X"}
		with data.library.parameters as {"outcome": "allow or deny", "connective": "include or exclude"}

	print("wcdt_res1_actX", wcdt_res1_actX)

	expect_res1_actX := {{
		"snippet": "global/systemtypes/entitlements:1.0/library/policy/rbac/v1/snippet_who_can_do_this",
		"who_can_do_this": set(),
	}}

	# the object.get here is used to avoid the type checker
	wcdt_res1_actX == object.get({"x": expect_res1_actX}, "x", {})

	actions.snippet_who_can_do_this[wcdt_res1] with data.object.users as users
		with data.object.roles as roles
		with data.object.role_bindings as role_bindings
		with data.object.resources as resources
		with data.object.actions as test_actions
		with input as {"resource": "resource1"}
		with data.library.parameters as {"outcome": "allow or deny", "connective": "include or exclude"}

	print("wcdt_res1", wcdt_res1)

	expect_res1 := {{
		"snippet": "global/systemtypes/entitlements:1.0/library/policy/rbac/v1/snippet_who_can_do_this",
		"who_can_do_this": {
			{"action": "action1", "connective": "include", "outcome": "allow", "subject": "user1"},
			{"action": "action1", "connective": "include", "outcome": "allow", "subject": "user3"},
			{"action": "action2", "connective": "include", "outcome": "allow", "subject": "user1"},
			{"action": "action2", "connective": "include", "outcome": "allow", "subject": "user3"},
		},
	}}

	# the object.get here is used to avoid the type checker
	wcdt_res1 == object.get({"x": expect_res1}, "x", {})
}
