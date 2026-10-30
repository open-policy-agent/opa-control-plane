package global.systemtypes["entitlements:1.0"].library.policy.abac.test_v1

import rego.v1
import data.global.systemtypes["entitlements:1.0"].library.policy.abac.v1 as abac

test_resource_has_attributes if {
	attrs := {
		"attr-1": "value-1",
		"attr-2": 2,
	}

	actions := {"create", "delete"}

	match := abac.resource_has_attributes with input as {"resource": "foo", "action": "delete"}
		with data.library.parameters as {"attributes": attrs, "actions": actions}
		with data.object.resources as {"foo": attrs}

	count(match) == 1

	no_match_resource := abac.resource_has_attributes with input as {"resource": "foo", "action": "delete"}
		with data.library.parameters as {"attributes": attrs, "actions": actions}
		with data.object.resources as {"foo": {"attr-1": "value-1"}}

	count(no_match_resource) == 0
}

test_resource_has_attributes_exact if {
	attrs := {
		"attr-1": "value-1",
		"attr-2": 2,
	}

	match := abac.resource_has_attributes_glob with input as {"resource": "foo/bar"}
		with data.library.parameters as {"attributes": attrs}
		with data.object.resources as {"foo/*": attrs}

	count(match) == 1

	no_match_resource := abac.resource_has_attributes with input as {"resource": "foo/bar"}
		with data.library.parameters as {"attributes": attrs}
		with data.object.resources as {"foo/*": attrs}

	count(no_match_resource) == 0
}

test_user_has_attributes if {
	attrs := {
		"attr-1": "value-1",
		"attr-2": 2,
	}

	match := abac.user_has_attributes with input as {"subject": "biggie"}
		with data.library.parameters as {"attributes": attrs}
		with data.object.users as {"biggie": attrs}

	count(match) == 1

	no_match := abac.user_has_attributes with input as {"subject": "biggie"}
		with data.library.parameters as {"attributes": attrs}
		with data.object.resources as {"biggie": {"attr-1": "value-1"}}

	count(no_match) == 0
}

test_user_and_resource_has_attributes if {
	attr1 := {"key1": "val1", "key2": "val2"}
	attr2 := {"key3": "val3", "key4": "val4"}
	attr3 := {"key5": "val5", "key6": "val6"}

	obj := {
		"users": {"user1": attr1},
		"resources": {"foo/*": attr2, "baz": attr3},
	}

	match := abac.user_and_resource_has_attributes_glob with input as {"resource": "foo/bar", "subject": "user1"}
		with data.library.parameters as {"user_attributes": attr1, "resource_attributes": attr2}
		with data.object as obj

	count(match) == 1

	not_match_1 := abac.user_and_resource_has_attributes with input as {"resource": "foo/bar", "subject": "user1"}
		with data.library.parameters as {"user_attributes": attr1, "resource_attributes": attr2}
		with data.object as obj

	count(not_match_1) == 0

	not_match_2 := abac.user_and_resource_has_attributes_glob with input as {"resource": "foo/bar", "subject": "user1"}
		with data.library.parameters as {"user_attributes": attr1, "resource_attributes": attr1}
		with data.object as obj

	count(not_match_2) == 0

	match_exact := abac.user_and_resource_has_attributes with input as {"resource": "baz", "subject": "user1"}
		with data.library.parameters as {"user_attributes": attr1, "resource_attributes": attr3}
		with data.object as obj

	count(match_exact) == 1
}
