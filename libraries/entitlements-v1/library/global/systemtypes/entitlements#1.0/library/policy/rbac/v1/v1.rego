package global.systemtypes["entitlements:1.0"].library.policy.rbac.v1

import rego.v1
import data.global.systemtypes["entitlements:1.0"].library.utils.v1 as utils
import data.library.parameters

# optional data
object_groups = data.object.groups if {
	true
} else = set()

object_users = data.object.users if {
	true
} else = set()

# METADATA: library-snippet
# version: v1
# title: "RBAC: Role explicitly allows subject access to resource"
# diagnostics:
#   - entz_object_check_users
#   - entz_object_check_groups
#   - entz_object_check_service_accounts
#   - subject_exists
#   - subject_has_roles
#   - subjects_for_role_binding
#   - resource_exists
#   - role_resource_action
#   - resource_action_for_role
# description: >-
#   Matches requests where a role bound to the subject allows access to the
#   requested resource.
# schema:
#   decision:
#     - type: toggle
#       label: Permission
#       toggles:
#       - key: allowed
#         value: true
#         label: Allow
#     - type: rego
#       key: entz
#       value: "set()"
#     - type: rego
#       key: message
#       value: "message"
any_role_allows_access contains msg if {
	allowing_roles := {role_id |
		roles_bound_to_subject(input.subject)[role_id]
		role_allows_access(data.object.roles[role_id], input)
	}

	count(allowing_roles) > 0
	role_str := concat(", ", allowing_roles)
	msg := sprintf("Access is allowed by roles %s", [role_str])
}

# METADATA: library-snippet
# version: v1
# title: "RBAC: Role explicitly denies subject access to resource"
# diagnostics:
#   - entz_object_check_users
#   - entz_object_check_groups
#   - entz_object_check_service_accounts
#   - subject_exists
#   - subject_has_roles
#   - subjects_for_role_binding
#   - resource_exists
#   - role_resource_action
#   - resource_action_for_role
# description: >-
#   Matches requests where a role bound to the subject denies access to the
#   requested resource.
# schema:
#   decision:
#     - type: toggle
#       label: Permission
#       toggles:
#       - key: denied
#         value: true
#         label: Deny
#     - type: rego
#       key: entz
#       value: "set()"
#     - type: rego
#       key: message
#       value: "message"
any_role_denies_access contains msg if {
	denying_roles := {role_id |
		role_denies_access(data.object.roles[roles_bound_to_subject(input.subject)[role_id]], input)
	}

	count(denying_roles) > 0
	role_str := concat(", ", denying_roles)
	msg := sprintf("Access is denied by roles %s", [role_str])
}

# METADATA: library-snippet
# version: v1
# title: "RBAC: Return the Roles bound to the subject"
# diagnostics:
#   - entz_object_check_users
#   - entz_object_check_groups
#   - entz_object_check_service_accounts
#   - subject_exists
#   - subject_has_roles
#   - subjects_for_role_binding
# return_type: set
# description: >-
#   Returns a set of string ids of the roles bound to the input subject
# policy:
#   rule:
#     type: rego
#     value: "entz := {{this}}"
# schema:
#   decision:
#     - type: rego
#       key: entz
#       value: "entz"
#     - type: string
#       key: message
#       value: ""
roles_bound_to_request_subject = roles if {
	roles := {{
		"snippet": "global/systemtypes/entitlements:1.0/library/policy/rbac/v1/roles_bound_to_request_subject",
		"roles": roles_bound_to_subject(input.subject),
	}}
}

# METADATA: library-snippet
# version: v1
# title: "RBAC: Return the Groups bound to the subject"
# diagnostics:
#   - entz_object_check_users
#   - entz_object_check_groups
#   - entz_object_check_service_accounts
# return_type: set
# description: >-
#   Returns the set of group ids (as strings) for the groups bound to the input subject
# policy:
#   rule:
#     type: rego
#     value: "entz := {{this}}"
# schema:
#   decision:
#     - type: rego
#       key: entz
#       value: "entz"
#     - type: string
#       key: message
#       value: ""
groups_for_input_user = groups if {
	groups := {{
		"snippet": "global/systemtypes/entitlements:1.0/library/policy/rbac/v1/groups_for_input_user",
		"groups": groups_for_subject(input.subject),
	}}
}

role_allows_access(roledef, request) if {
	included := resource_is_matched(roledef, "allow", "include", request.action, request.resource)
	excluded := resource_is_matched(roledef, "allow", "exclude", request.action, request.resource)
	included == true
	excluded == false
}

role_denies_access(roledef, request) if {
	included := resource_is_matched(roledef, "deny", "include", request.action, request.resource)
	excluded := resource_is_matched(roledef, "deny", "exclude", request.action, request.resource)
	included == true
	excluded == false
}

resource_is_matched(roledef, roledef_allow_or_deny, roledef_include_or_exclude, action, resource) if {
	glob.match(roledef[roledef_allow_or_deny][roledef_include_or_exclude][idx].actions[_], ["."], action)
	glob.match(roledef[roledef_allow_or_deny][roledef_include_or_exclude][idx].resources[_], ["."], resource)
} else = false

transitive_roles[subject] = roles if {
	# In the case where a user or service account is bound to a group, they
	# transitively get roles from that group. This returns the roles bound
	# to the groups the subject is in, if the subject is a user, and else
	# the empty set.

	plausible_subjects[subject]
	groups := groups_for_subject(subject)
	roles := {role_id | groups[group]; nontransitive_roles_bound_to_subject(group)[role_id]}
}

# Subjects which either affirmatively exist, or which have roles bound to them
# irrespective of existence.
plausible_subjects := ((({sid | sid := data.object.role_bindings[_].subjects.ids[_]} | {sid | some sid; data.object.users[sid]}) | {sid | some sid; data.object.service_accounts[sid]}) | {sid | some sid; data.object.groups[sid]}) | {sid | sid := data.object.groups[_].users[_]}

# Notice that we explicitly do not allow roles with empty or undefined
# membership attributes to have dynamic membership.
direct_roles_by_subject[subject] = roles if {
	plausible_subjects[subject]
	roles := {role_id | data.object.role_bindings[role_id].subjects.ids[_] == subject}
}

dynamic_roles_by_subject[subject] = roles if {
	plausible_subjects[subject]
	subject_type(subject) == "user"
	roles := {role_id |
		{} != object.get(data.object.role_bindings[role_id].subjects, "membership-attributes", {})
		utils.object_super_sub_compare(data.object.users[subject], data.object.role_bindings[role_id].subjects["membership-attributes"])
	}
}

dynamic_roles_by_subject[subject] = roles if {
	plausible_subjects[subject]
	subject_type(subject) == "service_account"
	roles := {role_id |
		{} != object.get(data.object.role_bindings[role_id].subjects, "membership-attributes", {})
		utils.object_super_sub_compare(data.object.service_accounts[subject], data.object.role_bindings[role_id].subjects["membership-attributes"])
	}
}

dynamic_roles_by_subject[subject] = roles if {
	plausible_subjects[subject]
	subject_type(subject) != "user"
	subject_type(subject) != "service_account"
	roles = set()
}

nontransitive_roles_bound_to_subject(subject) = roles if {
	# Roles directly bound to subjects by their ID.
	roles := {r | some r; direct_roles_by_subject[subject][r]} | {r | some r; dynamic_roles_by_subject[subject][r]}
}

roles_bound_to_subject(subject) = roles if {
	roles := nontransitive_roles_bound_to_subject(subject) | {r | some r; transitive_roles[subject][r]}
}

# Notice that we explicitly do not allow dynamic membership in groups
# which have empty or undefined membership-attributes fields.
dynamic_groups_by_subject[subject] = groups if {
	plausible_subjects[subject]
	subject_type(subject) == "user"
	groups := {group_id |
		{} != object.get(data.object.groups[group_id], "membership-attributes", {})
		utils.object_super_sub_compare(data.object.users[subject], object.get(data.object.groups[group_id], "membership-attributes", {}))
	}
}

dynamic_groups_by_subject[subject] = groups if {
	plausible_subjects[subject]
	subject_type(subject) == "service_account"
	groups := {group_id |
		{} != object.get(data.object.groups[group_id], "membership-attributes", {})
		utils.object_super_sub_compare(data.object.service_accounts[subject], object.get(data.object.groups[group_id], "membership-attributes", {}))
	}
}

groups_for_subject(subject) = groups if {
	# Determine the effective groups for the subject. If the subject is
	# a group, it is considered to be the only group in the set.

	subject_type(subject) != "group"

	# Set of all groups for the user where the subject ID is in the users
	# field for the group.
	direct_groups := {group_id |
		data.object.groups[group_id].users[_] == subject
	}

	# Set of all groups for the user where the user's attributes are a
	# subset of the group's membership attributes. For example, consider
	# the group:
	#
	# "sales": {
	#         "users": ["eric", "cheng"],
	#         "membership-attributes": {"is_employee": true},
	# }
	#
	# And the user:
	#
	# "alice": {
	#         "is_employee": true,
	#         "is_manager": true,
	# },
	#
	# Here, alice's attributes are a superset of those required for
	# membership in the "sales" group.

	# NOTE: This can lead to a situation where a user and a service account
	# can alias. In future, we should consider re-working to avoid this.
	#
	# The suggested workaround for users is to explicitly prefix their
	# users/groups/service accounts with known strings to guarantee there
	# are not collisions.

	groups := direct_groups | {g | some g; dynamic_groups_by_subject[subject][g]}
}

groups_for_subject(subject) = groups if {
	subject_type(subject) == "group"
	groups := {subject}
}

groups_for_subject(subject) = groups if {
	not subject_type(subject)
	groups := set()
}

subject_type(subject) = subject_type if {
	# Given a subject ID, return one of three possible types, as a string:
	#
	# * "user" - the subject ID corresponds to an extant user
	# * "group" - the subject ID correspond to an extant group
	# * "service_account" - the subject ID corresponds to an extant service
	#   account
	# * "none" - the subject ID does not correspond to an extant user,
	#   group, or service account
	#
	# This function is guaranteed to never be undefined.

	utils.object_contains_key(data.object.users, subject)
	subject_type := "user"
} else = subject_type if {
	utils.object_contains_key(data.object.groups, subject)
	subject_type := "group"
} else = subject_type if {
	utils.object_contains_key(data.object.service_accounts, subject)
	subject_type := "service_account"
} else = subject_type if {
	subject_type := "none"
}

# Map of role ID -> { {"resource": X, "action": Y, "outcome": "allow / deny", "connective": "include / exclude"} }
role_can_do_what[roleID] = result if {
	role := data.object.roles[roleID]
	result := {{"resource": resourceID, "action": action, "outcome": outcome, "connective": connective} |
		role[outcome][connective][i]
		resourceID := role[outcome][connective][i].resources[_]
		action := role[outcome][connective][i].actions[_]
	}
}

user_can_do_what[subjectID] = result if {
	plausible_subjects[subjectID]
	roles := roles_bound_to_subject(subjectID)
	result := union({role_can_do_what[r] | r := roles[_]})
}

# METADATA: library-snippet
# version: v1
# title: "RBAC: User Can Do What"
# diagnostics:
#   - entz_object_check_users
#   - entz_object_check_groups
#   - entz_object_check_service_accounts
# return_type: set
# description: >-
#   Returns a set 4-tuples denoting what resources and actions that could cause a request to be allowed or denied for the subject.
# policy:
#   rule:
#     type: rego
#     value: "entz := {{this}}"
# schema:
#   decision:
#     - type: rego
#       key: entz
#       value: "entz"
#     - type: string
#       key: message
#       value: ""
snippet_ucdw = result if {
	result := {{
		"snippet": "global/systemtypes/entitlements:1.0/library/policy/rbac/v1/snippet_ucdw",
		"ucdw": user_can_do_what[input.subject],
	}}
}

subjects_for_role[roleID] = subjects if {
	role := data.object.roles[roleID]
	subjects := {subjectID |
		plausible_subjects[subjectID]
		roles_bound_to_subject(subjectID)[_] == roleID
	}
}

# map of resource ID -> {role, action, connective, outcome}
roles_actions_for_resource[resourceID] = result if {
	data.object.resources[resourceID]
	result := {{"role": roleID, "outcome": outcome, "connective": connective, "action": action} |
		role := data.object.roles[roleID]
		role[outcome][connective][i].resources[_] == resourceID
		action := role[outcome][connective][i].actions[_]
	}
}

# map of resource ID -> action -> {subject, connective, outcome}
who_can_do_this[resourceID] = result if {
	data.object.resources[resourceID]
	actions := {t.action | t := roles_actions_for_resource[resourceID][_]}
	result := {action: {{"subject": subject, "connective": t.connective, "outcome": t.outcome, "action": action} |
		t := roles_actions_for_resource[resourceID][_]
		t.action == action
		subjects := subjects_for_role[t.role]
		subject := subjects[_]
	} |
		action := actions[_]
	}
}

who_can_do_this_glob(resourceID, action) = result if {
	is_string(action)
	matched_resources := {r | data.object.resources[r]; utils.resource_glob(r, resourceID)}
	result := {tup | r := matched_resources[_]; wcdt := who_can_do_this[r][action]; tup := wcdt[_]}
} else = set()

who_can_do_this_glob_all_actions(resourceID) = result if {
	matched_resources := {r | data.object.resources[r]; utils.resource_glob(r, resourceID)}
	result := {tup | r := matched_resources[_]; wcdt := who_can_do_this[r][_]; tup := wcdt[_]}
}

matched_who_can_do_this = result if {
	result := who_can_do_this_glob(input.resource, input.action)
} else = result if {
	result := who_can_do_this_glob_all_actions(input.resource)
} else = set()

# METADATA: library-snippet
# version: v1
# title: "RBAC: Who Can Do This"
# filePath:
#   - systems/.*/policy/.*
# diagnostics:
#   - resource_exists
#   - action_exists
# description: >-
#   Returns a set of 3-tuples representing the subjects, connectives, and outcomes that are related to the request's resource and action based on the Entitlements RBAC data.
# policy:
#   rule:
#     type: rego
#     value: "{{this}}[obj]"
# schema:
#   parameters:
#     - name: outcome
#       type: string
#       description: limit results to only those with this outcome
#       items: ["allow", "deny", "allow or deny"]
#       default: "allow or deny"
#     - name: connective
#       type: string
#       description: limit results to only those with this connective
#       items: ["include", "exclude", "include or exclude"]
#       default: "include or exclude"
#   decision:
#     - type: rego
#       key: entz
#       value: "obj"
snippet_who_can_do_this contains obj if {
	outcome_filter := {
		"allow": {"allow"},
		"deny": {"deny"},
		"allow or deny": {"allow", "deny"},
	}[data.library.parameters.outcome]

	connective_filter := {
		"include": {"include"},
		"exclude": {"exclude"},
		"include or exclude": {"include", "exclude"},
	}[data.library.parameters.connective]

	filtered := {tup | tup := matched_who_can_do_this[_]; tup.outcome == outcome_filter[_]; tup.connective == connective_filter[_]}

	obj := {{
		"snippet": "global/systemtypes/entitlements:1.0/library/policy/rbac/v1/snippet_who_can_do_this",
		"who_can_do_this": filtered,
	}}
}
