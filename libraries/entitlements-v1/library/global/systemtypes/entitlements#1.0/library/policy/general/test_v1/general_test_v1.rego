package global.systemtypes["entitlements:1.0"].library.policy.general.test_v1

import rego.v1
import data.global.systemtypes["entitlements:1.0"].library.policy.general.v1 as general

test_match_glob_action_subject_resource if {
	req := {"subject": "alice", "action": "read", "resource": "foo"}

	# no params, everything is matched
	result := general.match_glob_action_subject_resource
	count(result) == 1

	result_subject := general.match_glob_action_subject_resource with input as req
		with data.library.parameters as {"subjects": ["bob", "alice"]}

	count(result_subject) == 1

	result_action := general.match_glob_action_subject_resource with input as req
		with data.library.parameters as {"subjects": ["bob", "alice"], "actions": ["yuck", "*"]}

	count(result_action) == 1

	result_resource := general.match_glob_action_subject_resource with input as req
		with data.library.parameters as {"resources": ["a", "b", "foo"]}

	count(result_resource) == 1

	result_all := general.match_glob_action_subject_resource with input as req
		with data.library.parameters as {"resources": ["a", "b", "foo"], "subjects": ["bob", "alice"], "actions": ["yuck", "*"]}

	count(result_all) == 1

	# Parameters can be omitted wholesale, or can be simply the empty set as
	# we get with swimlanes.
	result_emptyset_match := general.match_glob_action_subject_resource with input as req
		with data.library.parameters as {"action": set(), "subjects": ["bob", "alice"], "resource": set()}

	count(result_emptyset_match) == 1

	# Even if a parameter is an empty set, we still need to actually match the
	# data.
	result_emptyset_nomatch := general.match_glob_action_subject_resource with input as req
		with data.library.parameters as {"action": set(), "subjects": ["bob", "janet"], "resource": set()}

	count(result_emptyset_nomatch) == 0
}

test_action_not_excluded_1 if {
	# Requests with no action should be allowed even if the unmatch list is
	# empty.

	result := general.action_not_excluded with input as {}
		with data.library.parameters as {"exclude": []}

	count(result) == 1
	result[msg]
	msg == "Action is not specified in the request"
}

test_action_not_excluded_2 if {
	# Requests with no action should be allowed.

	result := general.action_not_excluded with input as {}
		with data.library.parameters as {"exclude": ["foo", "bar", "baz"]}

	count(result) == 1
	result[msg]
	msg == "Action is not specified in the request"
}

test_action_not_excluded_3 if {
	# Requests with an action should always be matched if the unmatch list
	# is empty.

	result := general.action_not_excluded with input as {"action": "foo"}
		with data.library.parameters as {"exclude": []}

	count(result) == 1
	result[msg]
	msg == "Action foo is not excluded"
}

test_action_not_excluded_4 if {
	# Requests with an action can't have that action be in the unmatch
	# list.

	result := general.action_not_excluded with input as {"action": "foo"}
		with data.library.parameters as {"exclude": ["foo"]}

	count(result) == 0
}

test_action_not_excluded_5 if {
	# Requests with an action can't have that action be in the unmatch
	# list even if there are multiple entries in the unmatch list..

	result := general.action_not_excluded with input as {"action": "foo"}
		with data.library.parameters as {"exclude": ["foo", "bar", "baz"]}

	count(result) == 0
}

test_match_requests if {
	count(general.match_requests) == 1 with input as {"foo": "bar"}

	count(general.match_requests) == 1 with input as {"subject": "alice", "action": "read", "resource": "foo"}
}

test_action_is_not_valid if {
	count(general.action_is_not_valid) == 0 with input as {"action": "bar"}
		with data.object.actions as ["foo", "bar", "baz"]

	count(general.action_is_not_valid) == 1 with input as {"foo": "bar"}
		with data.object.actions as ["foo", "bar", "baz"]

	count(general.action_is_not_valid) == 1 with input as {"action": "qux"}
		with data.object.actions as ["foo", "bar", "baz"]
}

test_user_is_not_valid if {
	count(general.user_is_not_valid) == 0 with input as {"subject": "alice"}
		with data.object.users as {"alice": true, "bob": true}

	count(general.user_is_not_valid) == 1 with input as {"subject": "charlie"}
		with data.object.users as {"alice": true, "bob": true}

	count(general.user_is_not_valid) == 1 with input as {"foo": "bar"}
		with data.object.users as {"alice": true, "bob": true}
}
