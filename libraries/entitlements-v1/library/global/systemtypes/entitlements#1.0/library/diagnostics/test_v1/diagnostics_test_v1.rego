package global.systemtypes["entitlements:1.0"].library.diagnostics.test_v1

import data.global.systemtypes["entitlements:1.0"].library.diagnostics.v1 as diagnostics
import rego.v1

# check that the result from running a diagnostic has the proper schema.
result_check(obj) if {
	print("=== schema check for object:", obj)
	is_string(obj.message)
	print("message is a string")
	is_string(obj.severity)
	print("severity is a string")
	is_string(object.get(obj, "suggestion", ""))
	print("suggestion is a string (or omitted)")
	is_object(object.get(obj, "context", {}))
	print("context is an object (or omitted)")
	obj.type == "diagnostic"
	print("type is diagnostic")
	is_string(obj.diagnostic)
	print("diagnostic is a string")
	is_set(obj.relevance)
	print("relevance is a set")
	is_string(obj.description)
	print("description is a string")
	to_number(is_string(object.get(obj, "suggestion", {}))) + to_number(obj.severity == "OK") > 0
	print("if severity was non-OK, suggestion is present and a string")
}

test_duplicate_subject_check_1 if {
	# test the case where there are duplicate subjects
	diag := diagnostics.diagnostics.duplicate_subject_check with input as {"enable_diagnostics": true}
		with data.object.users as {"foo": {}}
		with data.object.groups as {"foo": {}}
		with data.object.service_accounts as {"foo": {}}

	"foo" in diag.context.duplicate_subject_ids
	count(diag.context.duplicate_subject_ids) == 1
	diag.severity == "PROBLEM"
	result_check(diag)
}

test_duplicate_subject_check_2 if {
	# test the case where there are no duplicate subjects
	diag := diagnostics.diagnostics.duplicate_subject_check with input as {"enable_diagnostics": true}
		with data.object.users as {"foo": {}}
		with data.object.groups as {"bar": {}}
		with data.object.service_accounts as {"baz": {}}

	count(diag.context.duplicate_subject_ids) == 0
	diag.severity == "OK"
	result_check(diag)
}

test_entz_object_check_1 if {
	# case where fields are not defined
	#
	fields := {"actions", "resources", "roles", "role_bindings", "users", "groups", "service_accounts"}

	every field in fields {
		diag := diagnostics.diagnostics[sprintf("entz_object_check_%s", [field])] with input as {"enable_diagnostics": true}

		diag.severity == "WARNING"
		result_check(diag)
	}
}

test_entz_object_check_2 if {
	# case where fields are defined

	fields := {"actions", "resources", "roles", "role_bindings", "users", "groups", "service_accounts"}

	every field in fields {
		diag := diagnostics.diagnostics[sprintf("entz_object_check_%s", [field])] with input as {"enable_diagnostics": true}
			with data.object.actions as {"GET"}
			with data.object.resources as {"resource1": {}}
			with data.object.roles as {"role1": {}}
			with data.object.role_bindings as {"role_binding1": {}}
			with data.object.users as {"user1": {}}
			with data.object.groups as {"group1": {}}
			with data.object.service_accounts as {"svcacct1": {}}

		diag.severity == "OK"
		result_check(diag)
	}
}

test_subject_exists_1 if {
	# case where subject does not exist
	diag := diagnostics.diagnostics.subject_exists with input as {"enable_diagnostics": true, "subject": "bar"}
		with data.object.users as {"foo": {}}

	diag.severity == "WARNING"
	result_check(diag)
}

test_subject_exists_2 if {
	# case where subject does exist
	diag := diagnostics.diagnostics.subject_exists with input as {"enable_diagnostics": true, "subject": "bar"}
		with data.object.users as {"bar": {}}

	diag.severity == "OK"
	result_check(diag)
}

test_subject_has_roles_1 if {
	# case where subject does not have roles
	diag := diagnostics.diagnostics.subject_has_roles with input as {"enable_diagnostics": true, "subject": "user1"}
		with data.object.users as {"user1": {}, "user2": {}}
		with data.object.roels as {"role1": {}}
		with data.object.role_bindings as {"role-binding1": {"subjects": {"ids": ["user2"]}}}

	diag.severity == "PROBLEM"
	result_check(diag)
}

test_subject_has_roles_2 if {
	# case where subject does not have roles
	diag := diagnostics.diagnostics.subject_has_roles with input as {"enable_diagnostics": true, "subject": "user2"}
		with data.object.users as {"user1": {}, "user2": {}}
		with data.object.roels as {"role1": {}}
		with data.object.role_bindings as {"role-binding1": {"subjects": {"ids": ["user2"]}}}

	diag.severity == "OK"
	result_check(diag)
}

test_resource_exists_1 if {
	# case where resource does not exist
	diag := diagnostics.diagnostics.resource_exists with input as {"enable_diagnostics": true, "resource": "resource2"}
		with data.object.resources as {"resource1": {}}

	diag.severity == "WARNING"
	result_check(diag)
}

test_resource_exists_2 if {
	# case where resource does not exist
	diag := diagnostics.diagnostics.resource_exists with input as {"enable_diagnostics": true, "resource": "resource1"}
		with data.object.resources as {"resource1": {}}

	diag.severity == "OK"
	result_check(diag)
}

test_action_exists_1 if {
	# case where action does not exist
	diag := diagnostics.diagnostics.action_exists with input as {"enable_diagnostics": true, "action": "action2"}
		with data.object.actions as {"action1"}

	diag.severity == "WARNING"
	result_check(diag)
}

test_action_exists_2 if {
	# case where action does not exist
	diag := diagnostics.diagnostics.action_exists with input as {"enable_diagnostics": true, "action": "action1"}
		with data.object.actions as {"action1"}

	diag.severity == "OK"
	result_check(diag)
}

test_role_resource_action_1 if {
	# case where a relevant role is found
	diag := diagnostics.diagnostics.role_resource_action with input as {"enable_diagnostics": true, "action": "action1", "resource": "resource2"}
		with data.object.roles as {"role1": {"allow": {"include": [{
			"actions": ["action1", "action3"],
			"resources": ["resource1", "resource2"],
		}]}}}
		with data.object.resources as {"resource1": {}, "resource2": {}, "resource3": {}}
		with data.object.actions as ["action1", "action2", "action3"]

	diag.severity == "OK"
	count(diag.context.allowing_roles) == 1
	"role1" in diag.context.allowing_roles
	result_check(diag)
}

test_role_resource_action_2 if {
	# case where a relevant role is not found
	diag := diagnostics.diagnostics.role_resource_action with input as {"enable_diagnostics": true, "action": "action1", "resource": "resource3"}
		with data.object.roles as {"role1": {"allow": {"include": [{
			"actions": ["action1", "action3"],
			"resources": ["resource1", "resource2"],
		}]}}}
		with data.object.resources as {"resource1": {}, "resource2": {}, "resource3": {}}
		with data.object.actions as ["action1", "action2", "action3"]

	diag.severity == "WARNING"
	not "context" in diag
	result_check(diag)
}

test_role_resource_action_3 if {
	# Check to make sure we can find actions that show up in role/deny.
	# Notice that action1 is not in data.object.actions, so that if
	# our logic to collect up all the actions is wrong, the test will fail.
	diag := diagnostics.diagnostics.role_resource_action with input as {"enable_diagnostics": true, "action": "action1", "resource": "resource1"}
		with data.object.roles as {"role1": {"deny": {"include": [{
			"actions": ["action1", "action3"],
			"resources": ["resource1", "resource2"],
		}]}}}
		with data.object.resources as {"resource1": {}, "resource2": {}, "resource3": {}}
		with data.object.actions as ["action2", "action3"]

	diag.severity == "OK"
	not "context" in diag
	result_check(diag)
}

test_role_resource_action_4 if {
	# Check to make sure that we are searching for actions under both
	# roles/{allow,deny}/include and .../exclude
	diag := diagnostics.diagnostics.role_resource_action with input as {"enable_diagnostics": true, "action": "action1", "resource": "resource1"}
		with data.object.roles as {"role1": {"deny": {"exclude": [{
			"actions": ["action1", "action3"],
			"resources": ["resource1", "resource2"],
		}]}}}
		with data.object.resources as {"resource1": {}, "resource2": {}, "resource3": {}}
		with data.object.actions as ["action2", "action3"]

	print("diag", diag)
	diag.severity == "OK"
	not "context" in diag
	result_check(diag)
}

test_role_resource_action_5 if {
	# Check to make sure that we are searching for resources under both
	# roles/{allow,deny}/include and .../exclude
	diag := diagnostics.diagnostics.role_resource_action with input as {"enable_diagnostics": true, "action": "action1", "resource": "resource1"}
		with data.object.roles as {"role1": {"deny": {"exclude": [{
			"actions": ["action1", "action3"],
			"resources": ["resource1", "resource2"],
		}]}}}
		with data.object.resources as {"resource2": {}, "resource3": {}}
		with data.object.actions as ["action2", "action3"]

	diag.severity == "OK"
	not "context" in diag
	result_check(diag)
}

test_subject_has_attributes_1 if {
	# case where subject does not have attributes
	diag := diagnostics.diagnostics.subject_has_attributes with input as {"enable_diagnostics": true, "subject": "subject1"}
		with data.object.users as {"subject1": {}}

	diag.severity == "WARNING"
	result_check(diag)
}

test_subject_has_attributes_2 if {
	# case where subject does have attributes
	diag := diagnostics.diagnostics.subject_has_attributes with input as {"enable_diagnostics": true, "subject": "subject1"}
		with data.object.users as {"subject1": {"attr1": "val1"}}

	print(diag)
	diag.severity == "OK"
	result_check(diag)
}

test_resource_has_attributes_1 if {
	# case where resource does not have attributes
	diag := diagnostics.diagnostics.resource_has_attributes with input as {"enable_diagnostics": true, "resource": "resource1"}
		with data.object.resources as {"resource1": {}}

	diag.severity == "WARNING"
	result_check(diag)
}

test_resource_has_attributes_2 if {
	# case where resource does have attributes
	diag := diagnostics.diagnostics.resource_has_attributes with input as {"enable_diagnostics": true, "resource": "resource1"}
		with data.object.resources as {"resource1": {"attr1": "val1"}}

	diag.severity == "OK"
	result_check(diag)
}

test_resource_action_for_role_1 if {
	# case where all roles are valid
	diag := diagnostics.diagnostics.resource_action_for_role with input as {"enable_diagnostics": true}
		with data.object.roles as {"role1": {"allow": {"include": [{
			"actions": ["action1", "action3"],
			"resources": ["resource1", "resource2"],
		}]}}}
		with data.object.resources as {"resource1": {}, "resource2": {}, "resource3": {}}
		with data.object.actions as ["action1", "action3"]

	diag.severity == "OK"
	result_check(diag)
}

test_resource_action_for_role_2 if {
	# case where a role references missing actions
	diag := diagnostics.diagnostics.resource_action_for_role with input as {"enable_diagnostics": true}
		with data.object.roles as {"role1": {"allow": {"include": [{
			"actions": ["action1", "action2", "action3"],
			"resources": ["resource1", "resource2"],
		}]}}}
		with data.object.resources as {"resource1": {}, "resource2": {}, "resource3": {}}
		with data.object.actions as ["action1", "action3"]

	diag.context == {"role1": {"dangling_actions": {"action2"}}}
	diag.severity == "WARNING"
	result_check(diag)
}

test_resource_action_for_role_3 if {
	# case where a role references missing resources
	diag := diagnostics.diagnostics.resource_action_for_role with input as {"enable_diagnostics": true}
		with data.object.roles as {"role1": {"allow": {"include": [{
			"actions": ["action1", "action3"],
			"resources": ["resource1", "resource2", "resource4"],
		}]}}}
		with data.object.resources as {"resource1": {}, "resource2": {}, "resource3": {}}
		with data.object.actions as ["action1", "action3"]

	diag.context == {"role1": {"dangling_resources": {"resource4"}}}
	diag.severity == "WARNING"
}

test_subjects_for_role_binding_1 if {
	# case where all is well

	diag := diagnostics.diagnostics.subjects_for_role_binding with input as {"enable_diagnostics": true}
		with data.object.roles as {"role1": {"allow": {"include": [{
			"actions": ["action1", "action2"],
			"resources": ["resource1", "resource2", "resource3"],
		}]}}}
		with data.object.resources as {"resource1": {}, "resource2": {}, "resource3": {}}
		with data.object.actions as ["action1", "action2"]
		with data.object.role_bindings as {"role-binding1": {"subjects": {"ids": ["subject1"]}}}
		with data.object.users as {"subject1": {}}

	diag.severity == "OK"
	result_check(diag)
}

test_subjects_for_role_binding_2 if {
	# if a role binding has no subjects, it should cause a warning

	diag := diagnostics.diagnostics.subjects_for_role_binding with input as {"enable_diagnostics": true}
		with data.object.roles as {"role1": {"allow": {"include": [{
			"actions": ["action1", "action2"],
			"resources": ["resource1", "resource2", "resource3"],
		}]}}}
		with data.object.resources as {"resource1": {}, "resource2": {}, "resource3": {}}
		with data.object.actions as ["action1", "action2"]
		with data.object.role_bindings as {"role-binding1": {"subjects": {"ids": []}}}
		with data.object.users as {"subject1": {}}

	diag.context.no_subjects == {"role-binding1"}
	diag.severity == "WARNING"
	result_check(diag)
}

test_subjects_for_role_binding_3 if {
	# all subjects mentioned in the role binding should be extant

	diag := diagnostics.diagnostics.subjects_for_role_binding with input as {"enable_diagnostics": true}
		with data.object.roles as {"role1": {"allow": {"include": [{
			"actions": ["action1", "action2"],
			"resources": ["resource1", "resource2", "resource3"],
		}]}}}
		with data.object.resources as {"resource1": {}, "resource2": {}, "resource3": {}}
		with data.object.actions as ["action1", "action2"]
		with data.object.role_bindings as {"role-binding1": {"subjects": {"ids": ["subject1", "subject2"]}}}
		with data.object.users as {"subject1": {}}

	diag.context.dangling_subjects == {"role-binding1": {"subject2"}}
	diag.severity == "WARNING"
	result_check(diag)
}

test_object_model_schema_1 if {
	# Case where everything is fine

	diag := diagnostics.diagnostics.object_model_schema with input as {"enable_diagnostics": true}
		with data.object.roles as {"role1": {"allow": {"include": [{
			"actions": ["action1", "action2"],
			"resources": ["resource1", "resource2", "resource3"],
		}]}}}
		with data.object.resources as {"resource1": {}, "resource2": {}, "resource3": {}}
		with data.object.actions as ["action1", "action2"]
		with data.object.role_bindings as {"role-binding1": {"subjects": {"ids": ["subject1", "subject2"]}}}
		with data.object.users as {"subject1": {}}
		with data.object.service_accounts as {"svcacct": {}}
		with data.object.groups as {"group1": {}}

	count(diag.context) == 7
	count({c | c := diag.context[_]; not c}) == 0 # none of the checks can be false
	diag.severity == "OK"
	result_check(diag)
}

test_object_model_schema_2 if {
	# Invalid role

	diag := diagnostics.diagnostics.object_model_schema with input as {"enable_diagnostics": true}
		with data.object.roles as {"role1": {"allow": {"include": [{
			"actions": ["action1", "action2"],
			"resources": ["resource1", "resource2", "resource3"],
			"bogus": ["not", "allowed!"],
		}]}}}
		with data.object.resources as {"resource1": {}, "resource2": {}, "resource3": {}}
		with data.object.actions as ["action1", "action2"]
		with data.object.role_bindings as {"role-binding1": {"subjects": {"ids": ["subject1", "subject2"]}}}
		with data.object.users as {"subject1": {}}
		with data.object.service_accounts as {"svcacct": {}}
		with data.object.groups as {"group1": {}}

	count(diag.context) == 7
	count({c | c := diag.context[_]; not c}) == 1
	diag.severity == "PROBLEM"
	result_check(diag)
}

test_object_model_schema_3 if {
	# Bad resource

	diag := diagnostics.diagnostics.object_model_schema with input as {"enable_diagnostics": true}
		with data.object.roles as {"role1": {"allow": {"include": [{
			"actions": ["action1", "action2"],
			"resources": ["resource1", "resource2", "resource3"],
		}]}}}
		with data.object.resources as [{"bogus": "not allowed"}]
		with data.object.actions as ["action1", "action2"]
		with data.object.role_bindings as {"role-binding1": {"subjects": {"ids": ["subject1", "subject2"]}}}
		with data.object.users as {"subject1": {}}
		with data.object.service_accounts as {"svcacct": {}}
		with data.object.groups as {"group1": {}}

	count(diag.context) == 7
	count({c | c := diag.context[_]; not c}) == 1
	diag.severity == "PROBLEM"
	result_check(diag)
}

test_object_model_schema_4 if {
	# bad action

	diag := diagnostics.diagnostics.object_model_schema with input as {"enable_diagnostics": true}
		with data.object.roles as {"role1": {"allow": {"include": [{
			"actions": ["action1", "action2"],
			"resources": ["resource1", "resource2", "resource3"],
		}]}}}
		with data.object.resources as {"resource1": {}, "resource2": {}, "resource3": {}}
		with data.object.actions as [{"bogus": "not allowed"}]
		with data.object.role_bindings as {"role-binding1": {"subjects": {"ids": ["subject1", "subject2"]}}}
		with data.object.users as {"subject1": {}}
		with data.object.service_accounts as {"svcacct": {}}
		with data.object.groups as {"group1": {}}

	count(diag.context) == 7
	count({c | c := diag.context[_]; not c}) == 1
	diag.severity == "PROBLEM"
	result_check(diag)
}

test_object_model_schema_5 if {
	# bad role binding

	diag := diagnostics.diagnostics.object_model_schema with input as {"enable_diagnostics": true}
		with data.object.roles as {"role1": {"allow": {"include": [{
			"actions": ["action1", "action2"],
			"resources": ["resource1", "resource2", "resource3"],
		}]}}}
		with data.object.resources as {"resource1": {}, "resource2": {}, "resource3": {}}
		with data.object.actions as ["action1", "action2"]
		with data.object.role_bindings as [{"bogus": "not allowed"}]
		with data.object.users as {"subject1": {}}
		with data.object.service_accounts as {"svcacct": {}}
		with data.object.groups as {"group1": {}}

	count(diag.context) == 7
	count({c | c := diag.context[_]; not c}) == 1
	diag.severity == "PROBLEM"
	result_check(diag)
}

# TODO: tests 6-8 are disabled for the time being because of a bug in OPA
# relating to calling object.union_n() on potentially undefined data.
#
# see: https://styra.slack.com/archives/C8QJVT4AJ/p1654803985384799
# test_object_model_schema_6 {
#        # bad user
#
#        diag := diagnostics.diagnostics["object_model_schema"]
#                with input as {"enable_diagnostics": true}
#                with data.object.roles as {"role1": { "allow": {"include": [{
#                                "actions": ["action1", "action2"],
#                                "resources": ["resource1", "resource2", "resource3"],
#                }]}}}
#                with data.object.resources as {"resource1": {}, "resource2": {}, "resource3": {}}
#                with data.object.actions as ["action1", "action2"]
#                with data.object.role_bindings as  {"role-binding1": {"subjects": {"ids": ["subject1", "subject2"]}}}
#                with data.object.users as [{"bogus": "not allowed"}]
#                with data.object.service_accounts as {"svcacct": {}}
#                with data.object.groups as {"group1": {}}
#
#        count(diag.context) == 7
#        count({c | c := diag.context[_]; not c}) == 1
#        diag.severity == "PROBLEM"
# }
# test_object_model_schema_7 {
#        # bad service account
#
#        diag := diagnostics.diagnostics["object_model_schema"]
#                with input as {"enable_diagnostics": true}
#                with data.object.roles as {"role1": { "allow": {"include": [{
#                                "actions": ["action1", "action2"],
#                                "resources": ["resource1", "resource2", "resource3"],
#                }]}}}
#                with data.object.resources as {"resource1": {}, "resource2": {}, "resource3": {}}
#                with data.object.actions as ["action1", "action2"]
#                with data.object.role_bindings as  {"role-binding1": {"subjects": {"ids": ["subject1", "subject2"]}}}
#                with data.object.users as {"subject1": {}}
#                with data.object.service_accounts as [{"bogus": "not allowed"}]
#                with data.object.groups as {"group1": {}}
#
#        count(diag.context) == 7
#        count({c | c := diag.context[_]; not c}) == 1
#        diag.severity == "PROBLEM"
# }
# test_object_model_schema_8 {
#        # bad group
#
#        diag := diagnostics.diagnostics["object_model_schema"]
#                with input as {"enable_diagnostics": true}
#                with data.object.roles as {"role1": { "allow": {"include": [{
#                                "actions": ["action1", "action2"],
#                                "resources": ["resource1", "resource2", "resource3"],
#                }]}}}
#                with data.object.resources as {"resource1": {}, "resource2": {}, "resource3": {}}
#                with data.object.actions as ["action1", "action2"]
#                with data.object.role_bindings as  {"role-binding1": {"subjects": {"ids": ["subject1", "subject2"]}}}
#                with data.object.users as {"subject1": {}}
#                with data.object.service_accounts as {"svcacct": {}}
#                with data.object.groups as [{"bogus": "not allowed"}]
#
#        count(diag.context) == 7
#        count({c | c := diag.context[_]; not c}) == 1
#        diag.severity == "PROBLEM"
# }

test_ucdw_for_request_1 if {
	# bad role binding

	diag := diagnostics.diagnostics.ucdw_for_request with input as {
		"enable_diagnostics": true,
		"subject": "subject1",
		"resource": "resource2/foo",
		"action": "action1",
	}
		with data.object.roles as {"role1": {"allow": {"include": [{
			"actions": ["action1", "action2"],
			"resources": ["resource1", "resource2/*"],
		}]}}}
		with data.object.resources as {"resource1": {}, "resource2/*": {}}
		with data.object.actions as ["action1", "action2"]
		with data.object.role_bindings as {"role1": {"subjects": {"ids": ["subject1"]}}}
		with data.object.users as {"subject1": {}, "subject2": {}}
		with data.object.service_accounts as {"svcacct": {}}
		with data.object.groups as {"group1": {}}

	expect := {
		"context": {
			"ucdw_for_subject": {
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
					"resource": "resource2/*",
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
					"resource": "resource2/*",
				},
			},
			"ucdw_for_subject_and_action": {
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
					"resource": "resource2/*",
				},
			},
			"ucdw_for_subject_and_resource": {
				{
					"action": "action1",
					"connective": "include",
					"outcome": "allow",
					"resource": "resource2/*",
				},
				{
					"action": "action2",
					"connective": "include",
					"outcome": "allow",
					"resource": "resource2/*",
				},
			},
			"ucdw_for_subject_resource_and_action": {{
				"action": "action1",
				"connective": "include",
				"outcome": "allow",
				"resource": "resource2/*",
			}},
		},
		"description": "Check that the given subject, resource, and action all appear together in the 'user can do what' for the Entitlements object model.",
		"diagnostic": "ucdw_for_request",
		"message": "Found 1 combinations of subject 'subject1', resource 'resource2/foo', and action 'action1'.",
		"relevance": {"RBAC"},
		"severity": "OK",
		"title": "User Can Do What For Request",
		"type": "diagnostic",
	}

	print(diag)
	print("---")
	print(expect)

	diag == expect
	result_check(diag)
}

test_wcdt_for_request_1 if {
	# bad role binding

	diag := diagnostics.diagnostics.wcdt_for_request with input as {
		"enable_diagnostics": true,
		"subject": "subject1",
		"resource": "resource2/foo",
		"action": "action1",
	}
		with data.object.roles as {"role1": {"allow": {"include": [{
			"actions": ["action1", "action2"],
			"resources": ["resource1", "resource2/*"],
		}]}}}
		with data.object.resources as {"resource1": {}, "resource2/*": {}}
		with data.object.actions as ["action1", "action2"]
		with data.object.role_bindings as {"role1": {"subjects": {"ids": ["subject1"]}}}
		with data.object.users as {"subject1": {}, "subject2": {}}
		with data.object.service_accounts as {"svcacct": {}}
		with data.object.groups as {"group1": {}}

	expect := {
		"context": {"who_can_do_this": {{"connective": "include", "outcome": "allow", "subject": "subject1", "action": "action1"}}},
		"description": "Check that the subject, resource, and action for the request appear together in the 'who can do this' for the Entitlements object model.",
		"diagnostic": "wcdt_for_request",
		"message": "Found 1 users explicitly allowed or denied action 'action1' on resource 'resource2/foo'.",
		"relevance": {"RBAC"},
		"severity": "OK",
		"title": "Who Can Do This for Request",
		"type": "diagnostic",
	}

	print(diag)
	print("---")
	print(expect)

	diag == expect
	result_check(diag)
}

test_wcdt_for_request_2 if {
	# bad role binding

	diag := diagnostics.diagnostics.wcdt_for_request with input as {
		"enable_diagnostics": true,
		"subject": "subject1",
		"resource": "resource2/foo",
	}
		with data.object.roles as {"role1": {"allow": {"include": [{
			"actions": ["action1", "action2"],
			"resources": ["resource1", "resource2/*"],
		}]}}}
		with data.object.resources as {"resource1": {}, "resource2/*": {}}
		with data.object.actions as ["action1", "action2"]
		with data.object.role_bindings as {"role1": {"subjects": {"ids": ["subject1"]}}}
		with data.object.users as {"subject1": {}, "subject2": {}}
		with data.object.service_accounts as {"svcacct": {}}
		with data.object.groups as {"group1": {}}

	expect := {
		"context": {"who_can_do_this": {
			{"connective": "include", "outcome": "allow", "subject": "subject1", "action": "action1"},
			{"connective": "include", "outcome": "allow", "subject": "subject1", "action": "action2"},
		}},
		"description": "Check that the subject, resource, and action for the request appear together in the 'who can do this' for the Entitlements object model.",
		"diagnostic": "wcdt_for_request",
		"message": "Found 2 users explicitly allowed or denied action '<any action>' on resource 'resource2/foo'.",
		"relevance": {"RBAC"},
		"severity": "OK",
		"title": "Who Can Do This for Request",
		"type": "diagnostic",
	}

	print(diag)
	print("---")
	print(expect)

	diag == expect
	result_check(diag)
}
