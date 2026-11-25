package conflicts.test

import rego.v1
import data.global.systemtypes["entitlements:1.0"].conflicts.entry

test_system_no_stacks if {
	allowed_answer := entry.main with data.policy as {"enforce": {{"allowed": true, "message": "abc"}}}
		with data.stacks as {}

	allowed_answer.allowed == true
	allowed_answer.outcome.allow == true
	allowed_answer.outcome.decision_type == "ALLOWED"
	allowed_answer.outcome.policy_type == "rules"
	allowed_answer.outcome.stacks == {}
	allowed_answer.outcome.enforced == {{"allowed": true, "message": "abc"}}
	allowed_answer.outcome.monitored == set()

	denied_answer := entry.main with data.policy as {"enforce": {{"denied": true, "message": "abc"}}}
		with data.stacks as {}

	denied_answer.allowed == false
	denied_answer.outcome.allow == false
	denied_answer.outcome.decision_type == "DENIED"
	denied_answer.outcome.policy_type == "rules"

	undefined_answer := entry.main with data.policy as {}
		with data.stacks as {}

	undefined_answer.allowed == false
	undefined_answer.outcome.allow == false
	undefined_answer.outcome.decision_type == "DENIED"
	undefined_answer.outcome.policy_type == "rules"

	entz_answer := entry.main with data.policy as {"enforce": {{"entz": {"a", "b", "c"}}}}
		with data.stacks as {}

	entz_answer.allowed == false
	entz_answer.entz == {"a", "b", "c"}
	entz_answer.outcome.allow == false
	entz_answer.outcome.decision_type == "DENIED"
	entz_answer.outcome.policy_type == "rules"

	entz_allow_answer := entry.main with data.policy as {"enforce": {{"allowed": true, "message": "abc", "entz": {"a", "b", "c"}}}}
		with data.stacks as {}

	entz_allow_answer.allowed == true
	entz_allow_answer.entz == {"a", "b", "c"}
	entz_allow_answer.outcome.allow == true
	entz_allow_answer.outcome.decision_type == "ALLOWED"
	entz_allow_answer.outcome.policy_type == "rules"
	entz_allow_answer.outcome.enforced == {{"allowed": true, "message": "abc", "entz": {"a", "b", "c"}}}
}

# test_system_with_nested_packages validates that enforce and monitor rules can be
# in packages policy and policy.*
test_system_with_nested_packages if {
	got := entry.main with data.policy as system_nested_packages.policy
		with data.stacks as {}

	count(got.outcome.enforced) == 3
	count(got.outcome.monitored) == 2
}

# mock stack policies for three stacks
stacks := {
	"stack_undefined": {"policy": {}},
	"stack_allow": {"policy": {"enforce": {{"allowed": true, "message": "stack allowed"}}}},
	"stack_deny": {"policy": {"enforce": {{"denied": true, "message": "stack denied"}}}},
	"stack_entz1": {"policy": {"enforce": {{"entz": {"foo", "stack1"}}}}},
	"stack_entz2": {"policy": {"enforce": {{"entz": {"foo", "bar", "stack2"}}}}},
	"stack_entz3": {"policy": {"enforce": {{"entz": {"stack3", "zar"}}}}},
}

# mock system policies for three systems
systems := {
	"system_allow": {"policy": {"enforce": {{"allowed": true, "message": "system allowed"}}}},
	"system_deny": {"policy": {"enforce": {{"denied": true, "message": "system denied"}}}},
	"system_undefined": {"policy": {}},
}

system_nested_packages := {"policy": {
	"enforce": {{"allowed": true, "message": "policy allowed"}}, # package policy
	"monitor": {{"allowed": true, "message": "policy monitored"}},
	# package policy.rbac
	"rbac": {
		"enforce": {{"allowed": true, "message": "rbac allowed"}},
		"monitor": {{"allowed": true, "message": "rbac monitored"}},
	},
	# package policy.abac
	"abac": {"enforce": {{"allowed": true, "message": "abac allowed"}}},
}}

test_deny_stack if {
	# system allows, stack overrides with a deny

	answer_stack_deny := entry.main with data.policy as systems.system_allow.policy
		with data.stacks as stacks
		with entry.applicable_stacks as {"stack_deny"}

	answer_stack_deny.allowed == false
	answer_stack_deny.outcome.enforced == union({systems.system_allow.policy.enforce, stacks.stack_deny.policy.enforce})
}

test_allow_stack if {
	# system denies, stack allows but system deny overrides

	answer := entry.main with data.policy as systems.system_deny.policy
		with data.stacks as stacks
		with entry.applicable_stacks as {"stack_allow"}

	answer.allowed == false
	answer.outcome.enforced == union({systems.system_deny.policy.enforce, stacks.stack_allow.policy.enforce})
}

test_undefined_stack if {
	# system allows, stack is undefined

	answer := entry.main with data.policy as systems.system_allow.policy
		with data.stacks as stacks
		with entry.applicable_stacks as {"stack_undefined"}

	answer.allowed == true
	answer.outcome.stacks.stack_undefined
}

test_undefined_system_and_stack if {
	# system is undefined, stack is undefined

	answer := entry.main with data.policy as systems.system_undefined.policy
		with data.stacks as stacks
		with entry.applicable_stacks as {"stack_undefined"}

	answer.allowed == false
	answer.outcome.stacks.stack_undefined
}

test_mixed_stacks if {
	# system allows, one stack allows, one stack denies, one stack undefined

	answer := entry.main with data.policy as systems.system_allow.policy
		with data.stacks as stacks
		with entry.applicable_stacks as {"stack_undefined", "stack_allow", "stack_deny"}

	answer.allowed == false
	answer.outcome.stacks == {
		"stack_allow": {
			"enforced": {{
				"allowed": true,
				"message": "stack allowed",
			}},
			"monitored": set(),
		},
		"stack_deny": {
			"enforced": {{
				"denied": true,
				"message": "stack denied",
			}},
			"monitored": set(),
		},
		"stack_undefined": {
			"enforced": set(),
			"monitored": set(),
		},
	}
}

test_entz_object_no_stacks if {
	entz := {{"foo": "bar", "a": 1}}

	allowed_answer := entry.main with data.policy as {"enforce": {{"allowed": true, "entz": entz}}}
	allowed_answer.entz == entz
}

test_entz_object_one_stack if {
	entz := {"foo", "system", {"a": 1}}

	answer := entry.main with data.policy as {"enforce": {{"allowed": true, "entz": entz}}}
		with data.stacks as stacks
		with entry.applicable_stacks as {"stack_entz1"}

	# verify final entz object
	answer.entz == union({entz, stacks.stack_entz1.policy.enforce[_].entz})
}

test_entz_object_multiple_stacks if {
	system_entz := {"system_field", "abc", {"nested": "object"}}

	answer := entry.main with data.policy as {"enforce": {{"allowed": true, "entz": system_entz}}}
		with data.stacks as stacks
		with entry.applicable_stacks as {"stack_entz1", "stack_entz2", "stack_entz3"}

	answer.entz == union({
		system_entz,
		stacks.stack_entz1.policy.enforce[_].entz,
		stacks.stack_entz2.policy.enforce[_].entz,
		stacks.stack_entz3.policy.enforce[_].entz,
	})
}

test_applicable_stacks if {
	ans := entry.applicable_stacks with data.styra.stacks.stack1.config.type as "entitlements"
		with data.styra.stacks.stack2.config.type as "entitlements"
		with data.styra.stacks.stack3.config.type as "envoy"
		with data.styra.stacks.stack4.config.type as "entitlements"
		with data.stacks.stack1.selectors.systems as {"myid", "myid2"}
		with data.stacks.stack2.selectors.systems as {"myid", "myid3"}
		with data.stacks.stack3.selectors.systems as {"myid"}
		with data.stacks.stack4.selectors.systems as {"myid2"}
		with data.self.metadata as {"system_type": "entitlements", "system_id": "myid"}

	# ans == {"stack1", "stack2"}
	# NOTE(tsandall): bundle build only includes applicable stacks
	ans == {"stack1", "stack2", "stack3", "stack4"}
}

# notifications

test_system_notifications if {
	# three notifications: one from the system's metadata policy, one from a system's monitor rule, and the
	# third from the system's enforce rule
	n := entry.main.outcome.notifications with data.metadata.mock_system_id.notifications as {"notify": {{"channel": "system", "type": "slack"}}}
		with data.context as {
			"system_id": "mock_system_id",
			"system_type": "mock_system_type",
			"policy_type": "mock_policy_type",
		}
		with data.policy as {
			"enforce": {{"notify": {{"channel": "system-enforce", "type": "slack"}}}},
			"monitor": {{"notify": {{"channel": "system-monitor", "type": "slack"}}}},
		}

	n == {
		{"channel": "system", "type": "slack"},
		{"channel": "system-enforce", "type": "slack"},
		{"channel": "system-monitor", "type": "slack"},
	}
}

system_and_stack_rule_notifications = x if {
	x := entry.main.outcome.notifications with data.context as {
		"system_id": "mock_system_id",
		"system_type": "mock_system_type",
		"policy_type": "mock_policy_type",
	}
		with data.policy.enforce as {{"notify": {{"type": "slack", "channel": "system deny rule"}}}}
		with data.policy.monitor as {{"notify": {{"type": "slack", "channel": "system monitor rule"}}}}
		with data.stacks.stack123.policy.enforce as {{"notify": {{"type": "slack", "channel": "stack deny rule"}}}}
		with data.stacks.stack123.policy.monitor as {{"notify": {{"type": "slack", "channel": "stack monitor rule"}}}}
		with data.stacks.stack123.notifications as {"notify": {{"type": "slack", "channel": "stack notifications policy"}}}
		with entry.applicable_stacks as {"stack123"}
}

test_system_and_stack_notifications if {
	system_and_stack_rule_notifications == {
		{"channel": "system deny rule", "type": "slack"},
		{"channel": "system monitor rule", "type": "slack"},
		{"channel": "stack deny rule", "type": "slack"},
		{"channel": "stack monitor rule", "type": "slack"},
		{"channel": "stack notifications policy", "type": "slack"},
	}
}
