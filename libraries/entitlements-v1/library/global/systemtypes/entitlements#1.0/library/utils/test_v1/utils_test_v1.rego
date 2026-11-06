package global.systemtypes["entitlements:1.0"].library.utils.test_v1

import rego.v1
import data.global.systemtypes["entitlements:1.0"].library.utils.v1 as utils

use_input_includes_requirements = x if {
	x := utils.input_includes_requirements(data.filters)
}

test_input_includes_requirements_known_ui_filters if {
	true == use_input_includes_requirements with input as {"action": "read"}
		with data.filters as {"actions": {"read"}}

	false == use_input_includes_requirements with input as {"action": "read"}
		with data.filters as {"actions": {"NOT A MATCH"}}

	full_input := {"action": "read", "subject": "alice", "resource": "api/path"}

	# filter one field
	true == use_input_includes_requirements with input as full_input
		with data.filters as {"actions": {"read"}}

	# filter all the fields
	true == use_input_includes_requirements with input as full_input
		with data.filters as {"actions": {"read"}, "subjects": {"alice"}, "resources": {"not/a/match", "api/path"}}

	# one filter field doesn't match (subject)
	false == use_input_includes_requirements with input as full_input
		with data.filters as {"actions": {"read"}, "subjects": {"no", "match"}, "resources": {"api/path"}}

	# globs in the filters
	true == use_input_includes_requirements with input as full_input
		with data.filters as {"actions": {"*"}, "subjects": {"a", "b", "alic*"}, "resources": {"not/a/match", "api/*"}}

	# globs again, subjects doesn't match
	false == use_input_includes_requirements with input as full_input
		with data.filters as {"actions": {"*"}, "subjects": {"a", "b"}, "resources": {"not/a/match", "api/*"}}
}

test_input_includes_requirements_arbitrary_filters if {
	# mixed case, has actions that and an arbitrary filter foo
	true == use_input_includes_requirements with input as {"action": "read", "foo": "bar"}
		with data.filters as {"actions": {"read"}, "foo": {"bar"}}

	# other test cases use all arbitrary filters
	true == use_input_includes_requirements with input as {"action": "read", "foo": "bar"}
		with data.filters as {"action": {"read"}, "foo": {"bar"}}

	false == use_input_includes_requirements with input as {"action": "read", "foo": "bar"}
		with data.filters as {"action": {"read"}, "foo": {"no match"}}

	true == use_input_includes_requirements with input as {"action": "read", "foo": "bar"}
		with data.filters as {"action": {"read"}, "foo": {"na", "*"}}
}

test_object_get_empty if {
	utils.object_get_empty({"foo": "bar", "baz": 123}, "foo", "xyz") == "bar"
	utils.object_get_empty({"foo": "bar", "baz": 123}, "baz", "xyz") == 123
	utils.object_get_empty({"foo": "bar", "baz": 123}, "spam", "xyz") == "xyz"
	utils.object_get_empty({"foo": "", "baz": 123}, "foo", "xyz") == "xyz"
}

test_super_sub if {
	utils.object_super_sub_compare({"foo": 1, "bar": 2, "baz": 3}, {"foo": 1, "baz": 3})
	utils.object_super_sub_compare({"foo": 1, "bar": 2, "baz": 3}, {"foo": 1, "bar": 2, "baz": 3})
	not utils.object_super_sub_compare({"foo": 1, "bar": 2, "baz": 3}, {"foo": 2, "baz": 3})
	not utils.object_super_sub_compare({"foo": 1, "bar": 2, "baz": 3}, {"foo": 2, "bar": 2, "baz": 3})
}
