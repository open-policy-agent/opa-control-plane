package global.systemtypes["entitlements:1.0"].conflicts.entry

import rego.v1

# All rules must exist at data.policy

#############################################
# Output construction

# Final allowed bool based on system + stack allow/denied outcomes
main["allowed"] = allow

# Final entz set -- union of system and stack entz sets
main["entz"] = entz

main["outcome"] = outcome

outcome["allow"] = allow

outcome["enforced"] = combined.enforce

outcome["monitored"] = combined.monitor

# outcome.stacks is included so end-users know what stacks contributed to
# the decision at the time it was made
outcome["stacks"] = stacks_outcomes

# GUI uses this to know which policy file to open during replay and which decision to open on Preview.
#   This needs to match up with the 'type' of each of the policies as described in 'manifest.yaml'
#   Default is 'rules'
outcome["policy_type"] = "rules"

# system_type is used by decisions and timeseries
outcome["system_type"] = data.self.metadata.system_type

outcome["decision_type"] = decision_type

outcome["notifications"] = notifications

#############################################
# Combine stacks and systems

default allow = false

allow = x if {
	# if any enforced snippet denied, that overrides allows
	combined.enforce[_].denied
	x := false
} else if {
	# otherwise, allow if any snippet sets allowed to true
	combined.enforce[_].allowed
}

entz := union(system_entz | stacks_entz)

decision_type = "ALLOWED" if {
	allow
}

decision_type = "DENIED" if {
	not allow
}

#############################################
# Combine stacks and systems

# System and Stacks rules return a set of
# {"message": string}

combined["enforce"] = system_enforce | all_stack_enforce

combined["monitor"] = system_monitor | all_stack_monitor

all_stack_enforce contains decision if {
	some stack_id
	stacks_outcomes[stack_id].enforced[decision]
}

all_stack_monitor contains decision if {
	some stack_id
	stacks_outcomes[stack_id].monitored[decision]
}

#############################################
# System processing

system_enforce contains decision if {
	data.policy.enforce[decision]
}

system_enforce contains decision if {
	data.policy[_].enforce[decision]
}

system_monitor contains decision if {
	data.policy.monitor[decision]
}

system_monitor contains decision if {
	data.policy[_].monitor[decision]
}

system_entz := {entz |
	system_enforce[decision]
	entz := get_entz(decision)
}

get_entz(decision) = x if {
	x := decision.entz
} else = set()

#############################################
# Stack processing

stacks_outcomes[stack_id] = x if {
	applicable_stacks[stack_id]

	enforced := {decision |
		data.stacks[stack_id].policy.enforce[decision]
	}

	monitored := {decision |
		data.stacks[stack_id].policy.monitor[decision]
	}

	x := {
		"enforced": enforced,
		"monitored": monitored,
	}
}

stacks_entz contains entz if {
	stacks_outcomes[_].enforced[decision]
	entz := get_entz(decision)
}

applicable_stacks contains stack_id if {
	some stack_id
	data.stacks[stack_id] = _
}

### Notifications handling

# system and stack rules that ask for a notification
notifications contains n if {
	combined.enforce[_].notify[n]
}

notifications contains n if {
	combined.monitor[_].notify[n]
}

# notification_outcome encapsulates the fields that are needed for any notification snippet
notification_outcome := {"allowed": allow}

# system metadata notifications policy
notifications contains n if {
	data.metadata[system_id].notifications.notify[n] with data.context.outcome as notification_outcome
}

# stacks notifications policy
notifications contains n if {
	applicable_stacks[stack_id]
	data.stacks[stack_id].notifications.notify[n] with data.context.outcome as notification_outcome
}
