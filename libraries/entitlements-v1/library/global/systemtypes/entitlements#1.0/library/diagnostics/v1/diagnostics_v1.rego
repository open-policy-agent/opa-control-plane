package global.systemtypes["entitlements:1.0"].library.diagnostics.v1

import rego.v1
import data.global.systemtypes["entitlements:1.0"].library.policy.rbac.v1 as rbac
import data.global.systemtypes["entitlements:1.0"].library.utils.v1 as utils

# Possible statuses:
#
# * constants.severity.skip - the diagnostic could not run, for example because it was disabled
#   or because it is missing a prerequisite
# * constants.severity.ok - no attention needed
# * constants.severity.warning - attention may be needed, but maybe not, depending on use case
# * constants.severity.problem - there is a problem that needs to be addressed, or something
#    won't work
#
# Result structure:
#
# {
#	"type": "diagnostics",
#	"diagnostic": "name of diagnostic",
#	"relevance": { list of relevant use cases },
#	"severity": constants.severity.ok | constants.severity.warning | constants.severity.problem,
#	"description": "description of what this diagnostic does",
#	"message": "contextual message explaining the result",
#	"suggestion": "(OPTIONAL) suggestion for how to fix the problem"
#	"context": { OPTIONAL: additional contextual data in a diagnostic-specific format }
# }

# This does some type laundering to protect the data being considered. See:
# * STY-11919
# * function docs on the identity() function in utils_v1.rego
data_object := utils.identity(data.object)

data_object_actions := utils.identity(object.get(data_object, "actions", []))

data_object_resources := utils.identity(object.get(data_object, "resources", {}))

data_object_roles := utils.identity(object.get(data_object, "roles", {}))

data_object_role_bindings := utils.identity(object.get(data_object, "role_bindings", {}))

data_object_users := utils.identity(object.get(data_object, "users", {}))

data_object_groups := utils.identity(object.get(data_object, "groups", {}))

data_object_service_accounts := utils.identity(object.get(data_object, "service_accounts", {}))

# TODO: once this gets wired up to the UI, this will probably change to
# `data.styra...` or something like that.
disabled_diagnostics = d if {
	d = data_object.disabled_diagnostics
} else = d if {
	d := set()
}

# Evaluates to true if the diagnostic is enabled, and false otherwise.
diagnostic_enabled(diagnostic_id) if {
	not disabled_diagnostics[diagnostic_id]
}

# Evaluates to undefined if and only if the input is effectively non-empty.
#
# An input is considered to be effectively empty if it is either empty, or
# if it contains only the key enable_diagnostics.
input_effectively_empty if {
	count(input) == 0
} else if {
	count(input) == 1
	input.enable_diagnostics
}

# Implements the common case logic for detecting if a diagnostic should be
# SKIPed, that is if the input is empty (and the diagnostic depends on the
# input), or the diagnostic is enabled.
#
# require_input should be true if the input should be checked against empty.
skip_for_diagnostic(diagnostic_id, require_input) = result if {
	not diagnostic_enabled(diagnostic_id)
	result := {
		"message": get_text("-", "disabled_message", []),
		"severity": constants.severity.skip,
	}
}

skip_for_diagnostic(diagnostic_id, require_input) = result if {
	diagnostic_enabled(diagnostic_id)
	input_effectively_empty
	require_input
	result := {
		"message": get_text("-", "empty_input_message", []),
		"severity": constants.severity.skip,
	}
}

#### constants ################################################################

constants["severity"] = {
	"problem": "PROBLEM",
	"warning": "WARNING",
	"ok": "OK",
	"skip": "SKIP",
	# used only for unhandled errors
	"error": "INTERNAL ERROR",
}

constants["relevance"] = {
	"entz": "ENTZ",
	"rbac": "RBAC",
	"abac": "ABAC",
}

# diagnostic IDs
constants["diagnostics"] = {
	"duplicate_subject_check": "duplicate_subject_check",
	# Note that entz_object_check is special, because the true diagnostic
	# IDs are generated using sprintf based on field names. However the
	# base form of the name is used for lookups into the text table.
	"entz_object_check": "entz_object_check",
	"subject_exists": "subject_exists",
	"subject_has_roles": "subject_has_roles",
	"resource_exists": "resource_exists",
	"action_exists": "action_exists",
	"role_resource_action": "role_resource_action",
	"subject_has_attributes": "subject_has_attributes",
	"resource_has_attributes": "resource_has_attributes",
	"resource_action_for_role": "resource_action_for_role",
	"subjects_for_role_binding": "subjects_for_role_binding",
	"object_model_schema": "object_model_schema",
	"ucdw_for_request": "ucdw_for_request",
	"wcdt_for_request": "wcdt_for_request",
}

#### duplicate subject check ##################################################

entitlements_diagnostics_dupes = dupes if {
	# Return a list of all subject IDs which are present in two or more
	# subject types.
	users := {user | data_object_users[user]}
	groups := {group | data_object_groups[group]}
	svcaccts := {svcacct | data_object_service_accounts[svcacct]}
	dupes := (((users & groups) | (users & svcaccts)) | (groups & svcaccts)) | ((users & groups) & svcaccts)
}

entitlements_diagnostics_duplicate_subject_check_inner = result if {
	count(entitlements_diagnostics_dupes) == 0
	result := {"message": get_text(constants.diagnostics.duplicate_subject_check, "ok_message", []), "severity": constants.severity.ok}
} else = result if {
	count(entitlements_diagnostics_dupes) > 0
	result := {
		"message": get_text(constants.diagnostics.duplicate_subject_check, "dupes_found_message", []),
		"severity": constants.severity.problem,
		"suggestion": get_text(constants.diagnostics.duplicate_subject_check, "dupes_found_suggestion", []),
	}
} else = result if {
	result := {
		"message": get_text("-", "unhandled_error", [constants.diagnostics.duplicate_subject_check]),
		"severity": constants.severity.error,
	}
}

duplicate_subject_check_defaults := {
	"type": "diagnostic",
	"diagnostic": constants.diagnostics.duplicate_subject_check,
	"title": "Duplicate Subject Check",
	"relevance": {constants.relevance.entz},
	"description": get_text(constants.diagnostics.duplicate_subject_check, "description", []),
}

diagnostics[constants.diagnostics.duplicate_subject_check] = result if {
	diagnostic_enabled(constants.diagnostics.duplicate_subject_check)
	input.enable_diagnostics
	result := object.union_n([
		entitlements_diagnostics_duplicate_subject_check_inner,
		{"context": {"duplicate_subject_ids": entitlements_diagnostics_dupes}},
		duplicate_subject_check_defaults,
	])
}

diagnostics[constants.diagnostics.duplicate_subject_check] = result if {
	not diagnostic_enabled(constants.diagnostics.duplicate_subject_check)
	input.enable_diagnostics
	result := object.union_n([
		entitlements_diagnostics_duplicate_subject_check_inner,
		{
			"severity": constants.severity.skip,
			"message": get_text("-", "disabled_message", []),
		},
		duplicate_subject_check_defaults,
	])
}

#### entz object check ########################################################

entitlements_diagnostics_object_check_inner(field) = result if {
	count(data_object[field]) > 0
	result := {
		"message": get_text(constants.diagnostics.entz_object_check, "ok_message", [field]),
		"severity": constants.severity.ok,
	}
} else = result if {
	count(data_object[field]) == 0
	result := {
		"message": get_text(constants.diagnostics.entz_object_check, "exists_empty_message", [field]),
		"severity": constants.severity.warning,
		"suggestion": get_text(constants.diagnostics.entz_object_check, "exists_empty_suggestion", [field]),
	}
} else = result if {
	not data_object[field]
	result := {
		"message": get_text(constants.diagnostics.entz_object_check, "undefined_message", [field]),
		"severity": constants.severity.warning,
		"suggestion": get_text(constants.diagnostics.entz_object_check, "undefined_suggestion", [field]),
	}
} else = result if {
	result := {
		"message": get_text("-", "unhandled_error", [sprintf("entz_object_check_%s", [field])]),
		"severity": constants.severity.error,
	}
}

diagnostics[check] = result if {
	input.enable_diagnostics
	some field
	{"actions", "resources", "roles", "role_bindings", "users", "groups", "service_accounts"}[field]
	check := sprintf("entz_object_check_%s", [field])
	diagnostic_enabled(check)
	result := object.union(entitlements_diagnostics_object_check_inner(field), {
		"type": "diagnostic",
		"title": sprintf("Check data.object.%s", [field]),
		"diagnostic": check,
		"relevance": {constants.relevance.entz},
		"description": get_text(constants.diagnostics.entz_object_check, "description", [field]),
	})
}

diagnostics[check] = result if {
	input.enable_diagnostics
	some field
	{"actions", "resources", "roles", "role_bindings", "users", "groups", "service_accounts"}[field]
	check := sprintf("entz_object_check_%s", [field])
	not diagnostic_enabled(check)
	result := {
		"type": "diagnostic",
		"title": sprintf("Check data.object.%s", [field]),
		"diagnostic": check,
		"relevance": {constants.relevance.entz},
		"description": get_text(constants.diagnostics.entz_object_check, "description", [field]),
		"severity": constants.severity.skip,
		"message": get_text("-", "disabled_message", []),
	}
}

#### subject exists check #####################################################

rbac_diagnostics_subject_exists = result if {
	result := skip_for_diagnostic(constants.diagnostics.subject_exists, true)
} else = result if {
	not input.subject == input.subject
	result := {
		"message": get_text(constants.diagnostics.subject_exists, "input_subject_undefined_message", []),
		"severity": constants.severity.problem,
		"suggestion": get_text(constants.diagnostics.subject_exists, "input_subject_undefined_suggestion", []),
	}
} else = result if {
	rbac.subject_type(input.subject) == "none"
	result := {
		"message": get_text(constants.diagnostics.subject_exists, "invalid_subject_message", [input.subject]),
		"severity": constants.severity.warning,
		"suggestion": get_text(constants.diagnostics.subject_exists, "invalid_subject_suggestion", []),
	}
} else = result if {
	rbac.subject_type(input.subject) != "none"
	result := {
		"message": get_text(constants.diagnostics.subject_exists, "ok_message", [input.subject, rbac.subject_type(input.subject)]),
		"severity": constants.severity.ok,
		"context": {"subject_type": rbac.subject_type(input.subject)},
	}
} else = result if {
	result := {
		"message": get_text("-", "unhandled_error", [constants.diagnostics.subject_exists]),
		"severity": constants.severity.error,
	}
}

diagnostics[constants.diagnostics.subject_exists] = result if {
	input.enable_diagnostics
	result := object.union(rbac_diagnostics_subject_exists, {
		"type": "diagnostic",
		"title": "Check Subject Exists",
		"diagnostic": constants.diagnostics.subject_exists,
		"relevance": {constants.relevance.rbac, constants.relevance.abac},
		"description": get_text(constants.diagnostics.subject_exists, "description", []),
	})
}

#### subject has roles ########################################################

diagnostics_subject_has_roles = result if {
	result := skip_for_diagnostic(constants.diagnostics.subject_has_roles, true)
} else = result if {
	nroles := count(rbac.roles_bound_to_subject(input.subject))
	nroles > 0
	result := {
		"message": get_text(constants.diagnostics.subject_has_roles, "ok_message", [input.subject, nroles]),
		"severity": constants.severity.ok,
		"context": {"roles": rbac.roles_bound_to_subject(input.subject)},
	}
} else = result if {
	nroles := count(rbac.roles_bound_to_subject(input.subject))
	nroles == 0
	result := {
		"message": get_text(constants.diagnostics.subject_has_roles, "no_bindings_message", [input.subject]),
		"severity": constants.severity.problem,
		"suggestion": get_text(constants.diagnostics.subject_has_roles, "no_bindings_suggestion", []),
	}
} else = result if {
	not rbac.roles_bound_to_subject(input.subjec)
	result := {
		"message": get_text(constants.diagnostics.subject_has_roles, "roles_undefined_message", [input.subject]),
		"severity": constants.severity.problem,
		"suggestion": get_text(constants.diagnostics.subject_has_roles, "roles_undefined_suggestion", []),
	}
} else = result if {
	not input.subject == input.subject
	result := {
		"message": get_text(constants.diagnostics.subject_has_roles, "input_subject_undefined_message", []),
		"severity": constants.severity.problem,
		"suggestions": get_text(constants.diagnostics.subject_has_roles, "input_subject_undefined_suggestion", []),
	}
} else = result if {
	result := {
		"message": get_text("-", "unhandled_error", [constants.diagnostics.subject_has_roles]),
		"severity": constants.severity.error,
	}
}

diagnostics[constants.diagnostics.subject_has_roles] = result if {
	input.enable_diagnostics
	result := object.union(diagnostics_subject_has_roles, {
		"type": "diagnostic",
		"title": "Check Subject Roles",
		"diagnostic": constants.diagnostics.subject_has_roles,
		"relevance": {constants.relevance.rbac},
		"description": get_text(constants.diagnostics.subject_has_roles, "description", []),
	})
}

#### resource exists ##########################################################

diagnostics_matching_resources := {resource | data_object_resources[resource]; utils.resource_glob(resource, input.resource)}

diagnostics_resource_exists = result if {
	result := skip_for_diagnostic(constants.diagnostics.resource_exists, true)
} else = result if {
	count(diagnostics_matching_resources) >= 1
	result := {
		"message": get_text(constants.diagnostics.resource_exists, "ok_message", [input.resource]),
		"severity": constants.severity.ok,
	}
} else = result if {
	count(diagnostics_matching_resources) == 0
	result := {
		"message": get_text(constants.diagnostics.resource_exists, "nonexist_message", [input.resource]),
		"severity": constants.severity.warning,
		"suggestion": get_text(constants.diagnostics.resource_exists, "nonexist_suggestion", []),
	}
} else = result if {
	not input.resource == input.resource
	result := {
		"message": get_text(constants.diagnostics.resource_exists, "input_resource_undefined_message", []),
		"severity": constants.severity.problem,
		"suggestion": get_text(constants.diagnostics.resource_exists, "input_resource_undefined_suggestion", []),
	}
} else = result if {
	result := {
		"message": get_text("-", "unhandled_error", [constants.diagnostics.resource_exists]),
		"severity": constants.severity.error,
	}
}

diagnostics[constants.diagnostics.resource_exists] = result if {
	input.enable_diagnostics
	result := object.union(diagnostics_resource_exists, {
		"type": "diagnostic",
		"title": "Ensure Resource Exists",
		"diagnostic": constants.diagnostics.resource_exists,
		"relevance": {constants.relevance.rbac, constants.relevance.abac},
		"description": get_text(constants.diagnostics.resource_exists, "description", []),
		"context": {"matching_resources": diagnostics_matching_resources},
	})
}

#### action exists ############################################################

diagnostics_action_exists = result if {
	result := skip_for_diagnostic(constants.diagnostics.action_exists, true)
} else = result if {
	data_object_actions[_] == input.action
	result := {
		"message": get_text(constants.diagnostics.action_exists, "ok_message", [input.action]),
		"severity": constants.severity.ok,
	}
} else = result if {
	count({i | data_object_actions[i] == input.action}) == 0
	result := {
		"message": get_text(constants.diagnostics.action_exists, "nonexist_message", [input.action]),
		"severity": constants.severity.warning,
		"suggestion": get_text(constants.diagnostics.action_exists, "nonexist_suggestion", []),
	}
} else = result if {
	not input.action == input.action
	result := {
		"message": get_text(constants.diagnostics.action_exists, "input_action_undefined_message", []),
		"severity": constants.severity.problem,
		"suggestion": get_text(constants.diagnostics.action_exists, "input_action_undefined_suggestion", []),
	}
} else = result if {
	result := {
		"message": get_text("-", "unhandled_error", [constants.diagnostics.action_exists]),
		"severity": constants.severity.error,
	}
}

diagnostics[constants.diagnostics.action_exists] = result if {
	input.enable_diagnostics
	result := object.union(diagnostics_action_exists, {
		"type": "diagnostic",
		"title": "Ensure Action Exists",
		"diagnostic": constants.diagnostics.action_exists,
		"relevance": {constants.relevance.rbac},
		"description": get_text(constants.diagnostics.action_exists, "description", []),
	})
}

#### role/resource/action check ###############################################

all_actions := ((({a | a := data_object_roles[_].allow.include[_].actions[_]} | {a | a := data_object_roles[_].deny.include[_].actions[_]}) | {a | a := data_object_roles[_].allow.exclude[_].actions[_]}) | {a | a := data_object_roles[_].deny.exclude[_].actions[_]}) | {a | a := data_object_actions[_]}

allow_roles_by_action[action] = roles if {
	all_actions[action]
	roles := {role | data_object_roles[role].allow.include[_].actions[_] == action} | {role | data_object_roles[role].allow.exclude[_].actions[_] == action}
}

deny_roles_by_action[action] = roles if {
	all_actions[action]
	roles := {role | data_object_roles[role].deny.include[_].actions[_] == action} | {role | data_object_roles[role].deny.exclude[_].actions[_] == action}
}

all_resources := ((({r | r := data_object_roles[role].allow.include[_].resources[_]} | {r | r := data_object_roles[role].deny.include[_].resources[_]}) | {r | r := data_object_roles[role].allow.exclude[_].resources[_]}) | {r | r := data_object_roles[role].deny.exclude[_].resources[_]}) | {r | data_object_resources[r]}

allow_roles_by_resource[resource] = roles if {
	all_resources[resource]
	roles := {role | utils.resource_glob(data_object_roles[role].allow.include[_].resources[_], resource)} | {role | utils.resource_glob(data_object_roles[role].allow.exclude[_].resources[_], resource)}
}

deny_roles_by_resource[resource] = roles if {
	all_resources[resource]
	roles := {role | utils.resource_glob(data_object_roles[role].deny.include[_].resources[_], resource)} | {role | utils.resource_glob(data_object_roles[role].deny.exclude[_].resources[_], resource)}
}

relevant_roles_resource_action = result if {
	# The purpose of this rule is to return all roles that could either
	# allow or deny the request based on input.action and input.resource,
	# irrespective of the roles actually assigned to the subject.

	# TODO: is there any possibility other than 'include' below the
	# allow/deny?

	allow_roles := {role |
		allow_roles_by_action[input.action][role]
		allow_roles_by_resource[input.resource][role]
	}

	deny_roles := {role |
		deny_roles_by_action[input.action][role]
		deny_roles_by_resource[input.resource][role]
	}

	result := {"allow": allow_roles, "deny": deny_roles}
} else = roles if {
	roles := {
		"allow": {},
		"deny": {},
	}
}

diagnostics_role_resource_action = result if {
	result := skip_for_diagnostic(constants.diagnostics.role_resource_action, true)
} else = result if {
	relevant_roles := relevant_roles_resource_action
	nroles := count(relevant_roles.allow) + count(relevant_roles.deny)
	nroles > 0
	result := {
		"message": get_text(constants.diagnostics.role_resource_action, "ok_message", [nroles]),
		"severity": constants.severity.ok,
		"context": {
			"allowing_roles": relevant_roles.allow,
			"denying_roles": relevant_roles.deny,
		},
	}
} else = result if {
	not input.action == input.action
	result := {
		"message": get_text(constants.diagnostics.role_resource_action, "input_action_undefined_message", []),
		"severity": constants.severity.problem,
		"suggestion": get_text(constants.diagnostics.role_resource_action, "input_action_undefined_suggestion", []),
	}
} else = result if {
	not input.resource == input.resource
	result := {
		"message": get_text(constants.diagnostics.role_resource_action, "input_resource_undefined_message", []),
		"severity": constants.severity.problem,
		"suggestion": get_text(constants.diagnostics.role_resource_action, "input_resource_undefined_suggestion", []),
	}
} else = result if {
	relevant_roles := relevant_roles_resource_action
	nroles := count(relevant_roles.allow) + count(relevant_roles.deny)
	nroles == 0
	result := {
		"message": get_text(constants.diagnostics.role_resource_action, "no_relevant_roles_message", []),
		"severity": constants.severity.warning,
		"suggestion": get_text(constants.diagnostics.role_resource_action, "no_relevant_roles_suggestion", []),
	}
} else = result if {
	data_object_roles != data_object_roles
	result := {
		"message": get_text(constants.diagnostics.role_resource_action, "object_roles_undefined_message", []),
		"severity": constants.severity.problem,
		"suggestion": get_text(constants.diagnostics.role_resource_action, "object_roles_undefined_suggestion", []),
	}
} else = result if {
	count(data_object_roles) == 0
	result := {
		"message": get_text(constants.diagnostics.role_resource_action, "object_roles_empty_message", []),
		"severity": constants.severity.warning,
		"suggestion": get_text(constants.diagnostics.role_resource_action, "object_roles_empty_suggestion", []),
	}
} else = result if {
	result := {
		"message": get_text("-", "unhandled_error", [constants.diagnostics.role_resource_action]),
		"severity": constants.severity.error,
	}
}

diagnostics[constants.diagnostics.role_resource_action] = result if {
	input.enable_diagnostics
	result := object.union(diagnostics_role_resource_action, {
		"type": "diagnostic",
		"diagnostic": constants.diagnostics.role_resource_action,
		"relevance": {constants.relevance.rbac},
		"title": "Roles for Resource and Action",
		"description": get_text(constants.diagnostics.role_resource_action, "description", []),
	})
}

#### subject has attributes ###################################################

diagnostics_subject_attrs = attr if {
	rbac.subject_type(input.subject) == "user"
	attr := data_object_users[input.subject]
} else = attr if {
	rbac.subject_type(input.subject) == "group"
	attr := data_object_groups[input.subject]
} else = attr if {
	rbac.subject_type(input.subject) == "service_account"
	attr := data_object_service_accounts[input.subject]
} else = {}

diagnostics_subject_has_attributes = result if {
	result := skip_for_diagnostic(constants.diagnostics.subject_has_attributes, true)
} else = result if {
	not input.subject == input.subject
	result := {
		"message": get_text(constants.diagnostics.subject_has_attributes, "input_subject_undefined_message", []),
		"severity": constants.severity.warning,
		"suggestion": get_text(constants.diagnostics.subject_has_attributes, "input_subject_undefined_suggestion", []),
	}
} else = result if {
	rbac.subject_type(input.subject) == "none"
	result := {
		"message": get_text(constants.diagnostics.subject_has_attributes, "invalid_subject_message", [input.subject]),
		"severity": constants.severity.warning,
		"suggestion": get_text(constants.diagnostics.subject_has_attributes, "invalid_subject_suggestion", []),
	}
} else = result if {
	count(diagnostics_subject_attrs) > 0
	result := {
		"message": get_text(constants.diagnostics.subject_has_attributes, "ok_message", [input.subject, count(diagnostics_subject_attrs)]),
		"severity": constants.severity.ok,
		"context": {"attributes": diagnostics_subject_attrs},
	}
} else = result if {
	count(diagnostics_subject_attrs) == 0
	result := {
		"message": get_text(constants.diagnostics.subject_has_attributes, "no_attributes_message", [input.subject]),
		"severity": constants.severity.warning,
		"suggestion": get_text(constants.diagnostics.subject_has_attributes, "no_attributes_suggestion", []),
	}
} else = result if {
	result := {
		"message": get_text("-", "unhandled_error", [constants.diagnostics.subject_has_attributes]),
		"severity": constants.severity.error,
	}
}

diagnostics[constants.diagnostics.subject_has_attributes] = result if {
	input.enable_diagnostics
	result := object.union(diagnostics_subject_has_attributes, {
		"type": "diagnostic",
		"diagnostic": constants.diagnostics.subject_has_attributes,
		"relevance": {constants.relevance.abac},
		"title": "Ensure Subject has Attributes",
		"description": get_text(constants.diagnostics.subject_has_attributes, "description", []),
	})
}

#### resource has attributes ##################################################

diagnostics_resource_attrs = attr if {
	attr := data_object_resources[input.resource]
} else = {}

diagnostics_resource_has_attributes = result if {
	result := skip_for_diagnostic(constants.diagnostics.resource_has_attributes, true)
} else = result if {
	not input.resource == input.resource
	result := {
		"message": get_text(constants.diagnostics.resource_has_attributes, "input_resource_undefined_message", []),
		"severity": constants.severity.warning,
		"suggestion": get_text(constants.diagnostics.resource_has_attributes, "input_resource_undefined_suggestion", []),
	}
} else = result if {
	count(diagnostics_resource_attrs) > 0
	result := {
		"message": get_text(constants.diagnostics.resource_has_attributes, "ok_message", [input.resource, count(diagnostics_resource_attrs)]),
		"severity": constants.severity.ok,
		"context": {"attributes": diagnostics_resource_attrs},
	}
} else = result if {
	count(diagnostics_resource_attrs) == 0
	result := {
		"message": get_text(constants.diagnostics.resource_has_attributes, "no_attributes_message", [input.resource]),
		"severity": constants.severity.warning,
		"suggestion": get_text(constants.diagnostics.resource_has_attributes, "no_attributes_suggestion", []),
	}
} else = result if {
	result := {
		"message": get_text("-", "unhandled_error", [constants.diagnostics.resource_has_attributes]),
		"severity": constants.severity.error,
	}
}

diagnostics[constants.diagnostics.resource_has_attributes] = result if {
	input.enable_diagnostics
	result := object.union(diagnostics_resource_has_attributes, {
		"type": "diagnostic",
		"diagnostic": constants.diagnostics.resource_has_attributes,
		"title": "Ensure Resource has Attributes",
		"relevance": {constants.relevance.abac},
		"description": get_text(constants.diagnostics.resource_has_attributes, "description", []),
	})
}

#### check that roles reference resource/actions ##############################

resources_for_role[role] = result if {
	data_object_roles[role]

	#                                           *--------- allow/deny
	#                                           |  *------ include/exclude
	#                                           |  |  *--- list index
	#                                           |  |  |
	#                                           v  v  v
	result := {r | r := data_object_roles[role][_][_][_].resources[_]}
}

actions_for_role[role] = result if {
	data_object_roles[role]

	#                                           *--------- allow/deny
	#                                           |  *------ include/exclude
	#                                           |  |  *--- list index
	#                                           |  |  |
	#                                           v  v  v
	result := {r | r := data_object_roles[role][_][_][_].actions[_]}
}

actions_set := {a | a := data_object_actions[_]}

dangling_resources_for_role[role] = result if {
	data_object_roles[role]
	result := {resource | resource := resources_for_role[role][_]; not data_object_resources[resource]}
}

dangling_actions_for_role[role] = result if {
	data_object_roles[role]
	result := {action | action := actions_for_role[role][_]; not actions_set[action]}
}

extant_resources_for_role[role] = result if {
	data_object_roles[role]
	result := {resource | resource := resources_for_role[role][_]; data_object_resources[resource]}
}

extant_actions_for_role[role] = result if {
	data_object_roles[role]
	result := {action | action := actions_for_role[role][_]; actions_set[action]}
}

diagnostics_resource_action_for_role_context[role] = result if {
	data_object_roles[role]

	# Possible cases:
	#
	#	0 * 1 + 0 * 10 = 0		no dangling resources or actions
	#	1 * 1 + 0 * 10 = 1		dangling resources, but not dangling actions
	#	0 * 1 + 1 * 10 = 10		dangling actions, but not dangling resources
	#	1 * 1 + 1 * 10 = 11		both dangling resources and actions
	case := (1 * {true: 1, false: 0}[count(dangling_resources_for_role[role]) > 0]) + (10 * {true: 1, false: 0}[count(dangling_actions_for_role[role]) > 0])

	result := {
		0: {},
		1: {"dangling_resources": dangling_resources_for_role[role]},
		10: {"dangling_actions": dangling_actions_for_role[role]},
		11: {
			"dangling_resources": dangling_resources_for_role[role],
			"dangling_actions": dangling_actions_for_role[role],
		},
	}[case]
}

diagnostics_resource_action_for_role = result if {
	roles := {role | data_object_roles[role]}
	context := {role: ctx | role := roles[_]; ctx := diagnostics_resource_action_for_role_context[role]; ctx != {}}

	n_extant_resources := count({resource | role := roles[_]; resource := extant_resources_for_role[role][_]})
	n_dangling_resources := count({resource | role := roles[_]; resource := dangling_resources_for_role[role][_]})
	n_extant_actions := count({action | role := roles[_]; action := extant_actions_for_role[role][_]})
	n_dangling_actions := count({action | role := roles[_]; action := dangling_actions_for_role[role][_]})

	suggestions := {
		true: {"suggestion": get_text(constants.diagnostics.resource_action_for_role, "dangling_suggestion", [])},
		false: {},
	}

	suggestion := suggestions[(n_dangling_resources + n_dangling_actions) > 0]

	severities := {
		true: constants.severity.warning,
		false: constants.severity.ok,
	}

	severity := severities[(n_dangling_resources + n_dangling_actions) > 0]

	# We use union_n for the suggestion, since the field is optional.
	result := object.union_n([
		{
			"message": get_text(constants.diagnostics.resource_action_for_role, "message", [
				n_extant_resources,
				n_dangling_resources,
				n_extant_actions,
				n_dangling_actions,
			]),
			"context": context,
			"severity": severity,
		},
		suggestion,
	])
}

resource_action_for_role_defaults := {
	"type": "diagnostic",
	"diagnostic": constants.diagnostics.resource_action_for_role,
	"title": "Check Resource and Action for Roles",
	"relevance": {constants.relevance.rbac},
	"description": get_text(constants.diagnostics.resource_action_for_role, "description", []),
}

diagnostics[constants.diagnostics.resource_action_for_role] = result if {
	diagnostic_enabled(constants.diagnostics.resource_action_for_role)
	input.enable_diagnostics
	result := object.union_n([
		diagnostics_resource_action_for_role,
		resource_action_for_role_defaults,
	])
}

diagnostics[constants.diagnostics.resource_action_for_role] = result if {
	not diagnostic_enabled(constants.diagnostics.resource_action_for_role)
	input.enable_diagnostics
	result := object.union_n([
		skip_for_diagnostic(constants.diagnostics.resource_action_for_role, false),
		resource_action_for_role_defaults,
	])
}

#### check that role bindings reference extant subjects #######################

role_binding_dangling_subjects[role] = result if {
	data_object_role_bindings[role]
	result := {subject |
		subject := data_object_role_bindings[role].subjects.ids[_]
		rbac.subject_type(subject) == "none"
	}
}

subjects_for_role_binding[role] = result if {
	data_object_role_bindings[role]

	direct_subjects := {subject | subject := data_object_role_bindings[role].subjects.ids[_]}

	all_subjects := ({subject | data_object_users[subject]} | {subject | data_object_groups[subject]}) | {subject | data_object_service_accounts[subject]}

	# This is probably not very performant, may need to rewrite this in a
	# more direct way later. Maybe not though, since actually checking for
	# membership by attributes does imply a check for every single subject.
	indirect_subjects := {subject |
		subject := all_subjects[_]
		rbac.roles_bound_to_subject(subject)[role]
	}

	result := direct_subjects | indirect_subjects
}

diagnostics_subjects_for_role_binding = result if {
	context := {
		"no_subjects": {role |
			some role
			data_object_role_bindings[role]
			count(subjects_for_role_binding[role]) == 0
		},
		"dangling_subjects": {role: dangling |
			some role
			data_object_role_bindings[role]
			dangling := role_binding_dangling_subjects[role]
			count(dangling) > 0
		},
	}

	n_no_subject := count(context.no_subjects)
	n_dangling_subjects := count(context.dangling_subjects)

	# 1 * 0 + 10 * 0 = 0		OK
	# 1 * 1 + 10 * 0 = 1		some role bindings have no subjects
	# 1 * 0 + 10 * 1 = 10		some role bindings have dangling subjects
	# 1 * 1 + 10 * 1 = 11		some role bindings have no subjects, and some have dangling subjects
	case := (1 * to_number(n_no_subject > 0)) + (10 * to_number(n_dangling_subjects > 0))

	severity := {
		0: constants.severity.ok,
		1: constants.severity.warning,
		10: constants.severity.warning,
		11: constants.severity.warning,
	}[case]

	suggestion := {
		0: {},
		1: {"suggestion": get_text(constants.diagnostics.subjects_for_role_binding, "no_subjects_suggestion", [])},
		10: {"suggestion": get_text(constants.diagnostics.subjects_for_role_binding, "dangling_subjects_suggestion", [])},
		11: {"suggestion": get_text(constants.diagnostics.subjects_for_role_binding, "both_suggestion", [])},
	}[case]

	result := object.union(
		{
			"message": get_text(constants.diagnostics.subjects_for_role_binding, "message", [n_no_subject, n_dangling_subjects]),
			"context": context,
			"severity": severity,
		},
		suggestion,
	)
}

subjects_for_role_binding_defaults := {
	"type": "diagnostic",
	"diagnostic": constants.diagnostics.subjects_for_role_binding,
	"title": "Check the Subjects for Role Bindings",
	"relevance": {constants.relevance.rbac},
	"description": get_text(constants.diagnostics.subjects_for_role_binding, "description", []),
}

diagnostics[constants.diagnostics.subjects_for_role_binding] = result if {
	diagnostic_enabled(constants.diagnostics.subjects_for_role_binding)
	input.enable_diagnostics
	result := object.union(diagnostics_subjects_for_role_binding, subjects_for_role_binding_defaults)
}

diagnostics[constants.diagnostics.subjects_for_role_binding] = result if {
	not diagnostic_enabled(constants.diagnostics.subjects_for_role_binding)
	input.enable_diagnostics
	result := object.union(skip_for_diagnostic(constants.diagnostics.subjects_for_role_binding, false), subjects_for_role_binding_defaults)
}

#### object model schema ######################################################

schema_actions = result if {
	is_array(data_object_actions)
	count(data_object_actions) == count({a | a := data_object_actions[_]; is_string(a)})
	result := {"data.object.actions is an array of strings": true}
} else = result if {
	result := {"data.object.actions is an array of strings": false}
}

schema_resources = result if {
	is_object(data_object_resources)
	count(data_object_resources) == count({k | some k; r := data_object_resources[k]; is_object(r)})
	result := {"data.object.resources is an object of attributes": true}
} else = result if {
	result := {"data.object.resources is an object of attributes": false}
}

# Set of all roles which contain keys other than just allow/deny
role_violation_allow_deny[role] if {
	obj := data_object_roles[role]
	count({k | _ := obj[k]; k != "allow"; k != "deny"}) != 0
}

# Set of all roles which contain keys other than just include/exclude nested
# below allow/deny. Also check that include and exclude are arrays if they are
# present.
role_violation_include_exclude[role] if {
	obj := data_object_roles[role]
	badvals := (({k | _ := obj.allow[k]; k != "include"; k != "exclude"} | {k | _ := obj.deny[k]; k != "include"; k != "exclude"}) | {k | v := obj.allow[k]; not is_array(v)}) | {k | v := obj.deny[k]; not is_array(v)}

	count(badvals) != 0
}

# Just the bare values under include/exclude across allow and deny, by role.
include_exclude_by_role[role] = result if {
	obj := data_object_roles[role]
	result := (({d | d := obj.allow.include} | {d | d := obj.allow.exclude}) | {d | d := obj.deny.include}) | {d | d := obj.deny.exclude}
}

# Set of all roles which contain keys other than just actions/resources nested
# below include/exclude.
role_violation_actions_resources[role] if {
	obj := data_object_roles[role]
	incexc := include_exclude_by_role[role]
	badvals := {k | _ := incexc[_][_][k]; k != "actions"; k != "resources"}
	count(badvals) != 0
}

# Just the resource/action values across allow/deny and exclude/exclude, by
# role.
resources_actions_by_role[role] = result if {
	obj := data_object_roles[role]
	incexc := include_exclude_by_role[role]
	result := {r | r := incexc[_][_].resources} | {a | a := incexc[_][_].actions}
}

# The actual array values of the resource and actions, merged into a single set.
unwrapped_resources_actions_by_role[role] = result if {
	obj := data_object_roles[role]
	ra := resources_actions_by_role[role]
	result := {v | v := ra[_][_]}
}

# Set of all roles which have values under actions/resources which aren't
# arrays.
role_violation_arrays[role] if {
	obj := data_object_roles[role]
	ra := resources_actions_by_role[role]
	badvals := {v | v := ra[_]; not is_array(v)}
	count(badvals) != 0
}

# Set of all roles which have non-string values in their actions/resources
# arrays.
role_violation_strings[role] if {
	obj := data_object_roles[role]
	unwrapped := unwrapped_resources_actions_by_role[role]
	badvals := {v | v := unwrapped[_]; not is_string(v)}
	count(badvals) != 0
}

schema_roles = result if {
	is_object(data_object_roles)

	count(role_violation_allow_deny) == 0
	count(role_violation_include_exclude) == 0
	count(role_violation_actions_resources) == 0
	count(role_violation_arrays) == 0
	count(role_violation_strings) == 0

	result := {"data.object.roles is an object of role data": true}
} else = result if {
	result := {"data.object.roles is an object of role data": false}
}

schema_role_bindings = result if {
	valid_role_bindings := {role_id: {"subjects": {
		"membership-attributes": attr,
		"ids": ids,
	}} |
		binding := data_object_role_bindings[role_id]
		attr := {an: av | av := binding.subjects["membership-attributes"][an]}
		ids := {i | i := binding.subjects.ids[_]}
	}

	# Note that because `ids` may be a list, we have to care about
	# the order of the elements, hence the use of count().
	matching_bindings := {roleid |
		data_object_role_bindings[roleid]
		valid_role_bindings[roleid]
		valid_role_bindings[roleid].subjects["membership-attributes"] == object.get(data_object_role_bindings[roleid].subjects, "membership-attributes", {})
		count(valid_role_bindings[roleid].subjects.ids) == count(object.get(data_object_role_bindings[roleid].subjects, "ids", []))
	}

	count(matching_bindings) == count(data_object_role_bindings)

	result := {"data.object.role_bindings is an object of role binding data": true}
} else = result if {
	result := {"data.object.role_bindings is an object of role binding data": false}
}

schema_users = result if {
	is_object(data_object_users)
	count({u | u := data_object_users[_]; is_object(u)}) == count(data_object_users)
	result := {"data.object.users is an object of user data": true}
} else if {
	result := {"data.object.users is an object of user data": false}
}

schema_groups = result if {
	is_object(data_object_groups)

	valid_groups := {group_id: {
		"membership-attributes": attr,
		"users": users,
	} |
		group := data_object_groups[group_id]
		attr := {an: av | av := group["membership-attributes"][an]}
		users := {u | u := group.users[_]}
	}

	matching_groups := {group_id |
		data_object_groups[group_id]
		valid_groups[group_id]
		valid_groups[group_id]["membership-attributes"] == object.get(data_object_groups[group_id], "membership-attributes", {})
		count(valid_groups[group_id].users) == count(object.get(data_object_groups[group_id], "users", []))
	}

	count(matching_groups) == count(data_object_groups)

	result := {"data.object.groups is an object of group data": true}
} else if {
	result := {"data.object.groups is an object of group data": false}
}

schema_service_accounts = result if {
	is_object(data_object_service_accounts)
	count({u | u := data_object_service_accounts[_]; is_object(u)}) == count(data_object_service_accounts)
	result := {"data.object.service_accounts is an object of service account data": true}
} else if {
	result := {"data.object.service_accounts is an object of service account data": false}
}

diagnostics_object_model_schema = result if {
	context := object.union_n([
		schema_actions,
		schema_resources,
		schema_roles,
		schema_role_bindings,
		schema_users,
		schema_groups,
		schema_service_accounts,
	])

	n_violations := count(context) - count({k | some k; context[k]})

	severity := {
		false: constants.severity.ok,
		true: constants.severity.problem,
	}[n_violations > 0]

	suggestion := {
		false: {},
		true: {"suggestion": get_text(constants.diagnostics.object_model_schema, "suggestion", [])},
	}[n_violations > 0]

	result := object.union(
		{
			"context": context,
			"message": get_text(constants.diagnostics.object_model_schema, "message", [n_violations]),
			"severity": severity,
		},
		suggestion,
	)
}

object_model_schema_defaults := {
	"type": "diagnostic",
	"diagnostic": constants.diagnostics.object_model_schema,
	"title": "Validate the Entitlements Object Model",
	"relevance": {constants.relevance.entz},
	"description": get_text(constants.diagnostics.object_model_schema, "description", []),
}

# NOTE: using the constant as they key for the partial object definition causes
# OPA to panic, see: https://styra.slack.com/archives/C8QJVT4AJ/p1658956766498929
diagnostics["object_model_schema"] = result if {
	diagnostic_enabled(constants.diagnostics.object_model_schema)
	input.enable_diagnostics
	result := object.union(diagnostics_object_model_schema, object_model_schema_defaults)
}

diagnostics["object_model_schema"] = result if {
	not diagnostic_enabled(constants.diagnostics.object_model_schema)
	input.enable_diagnostics
	result := object.union(skip_for_diagnostic(constants.diagnostics.object_model_schema, false), object_model_schema_defaults)
}

#### ucdw for request #########################################################

diagnostics_ucdw_for_request_defaults := {
	"type": "diagnostic",
	"diagnostic": constants.diagnostics.ucdw_for_request,
	"title": "User Can Do What For Request",
	"relevance": {constants.relevance.rbac},
	"description": get_text(constants.diagnostics.ucdw_for_request, "description", []),
}

diagnostics_ucdw_for_request = result if {
	result := skip_for_diagnostic(constants.diagnostics.ucdw_for_request, true)
} else = result if {
	not input.subject == input.subject
	result := {
		"message": get_text(constants.diagnostics.ucdw_for_request, "input_subject_undefined_message", []),
		"severity": constants.severity.warning,
		"suggestion": get_text(constants.diagnostics.ucdw_for_request, "input_subject_undefined_suggestion", []),
	}
} else = result if {
	not input.resource == input.resource
	result := {
		"message": get_text(constants.diagnostics.ucdw_for_request, "input_resource_undefined_message", []),
		"severity": constants.severity.warning,
		"suggestion": get_text(constants.diagnostics.ucdw_for_request, "input_resource_undefined_suggestion", []),
	}
} else = result if {
	not input.action == input.action
	result := {
		"message": get_text(constants.diagnostics.ucdw_for_request, "input_action_undefined_message", []),
		"severity": constants.severity.warning,
		"suggestion": get_text(constants.diagnostics.ucdw_for_request, "input_action_undefined_suggestion", []),
	}
} else = result if {
	ucdw := object.get(rbac.user_can_do_what, input.subject, set())
	with_resource := {tup | tup := ucdw[_]; utils.resource_glob(tup.resource, input.resource)}
	with_action := {tup | tup := ucdw[_]; tup.action == input.action}

	# We use with_resource as the basis here to avoid needing to run
	# resource_glob() multiple times.
	with_both := {tup | tup := with_resource[_]; tup.action == input.action}
	has_tups := count(with_both) > 0

	severity := {true: constants.severity.ok, false: constants.severity.warning}[has_tups]
	message := {
		true: get_text(constants.diagnostics.ucdw_for_request, "has_tups_message", [count(with_both), input.subject, input.resource, input.action]),
		false: get_text(constants.diagnostics.ucdw_for_request, "no_tups_message", [input.subject, input.resource, input.action]),
	}[has_tups]

	suggestion_obj := {
		true: {},
		false: {"suggestion": get_text(constants.diagnostics.ucdw_for_request, "no_tups_suggestion", [])},
	}[has_tups]

	context := {
		"ucdw_for_subject": ucdw,
		"ucdw_for_subject_and_resource": with_resource,
		"ucdw_for_subject_and_action": with_action,
		"ucdw_for_subject_resource_and_action": with_both,
	}

	result := object.union(suggestion_obj, {
		"severity": severity,
		"message": message,
		"context": context,
	})
} else = result if {
	result := {
		"message": get_text("-", "unhandled_error", [constants.diagnostics.ucdw_for_request]),
		"severity": constants.severity.error,
	}
}

diagnostics[constants.diagnostics.ucdw_for_request] = result if {
	diagnostic_enabled(constants.diagnostics.ucdw_for_request)
	input.enable_diagnostics
	result := object.union(diagnostics_ucdw_for_request, diagnostics_ucdw_for_request_defaults)
}

#### wcdt for request #########################################################

diagnostics_wcdt_for_request_defaults := {
	"type": "diagnostic",
	"diagnostic": constants.diagnostics.wcdt_for_request,
	"title": "Who Can Do This for Request",
	"relevance": {constants.relevance.rbac},
	"description": get_text(constants.diagnostics.wcdt_for_request, "description", []),
}

wcdt_for_input = result if {
	result := rbac.who_can_do_this_glob(input.resource, input.action)
} else = result if {
	result := rbac.who_can_do_this_glob_all_actions(input.resource)
}

diagnostics_wcdt_for_request = result if {
	result := skip_for_diagnostic(constants.diagnostics.wcdt_for_request, true)
} else = result if {
	not input.resource == input.resource
	result := {
		"message": get_text(constants.diagnostics.wcdt_for_request, "input_resource_undefined_message", []),
		"severity": constants.severity.warning,
		"suggestion": get_text(constants.diagnostics.wcdt_for_request, "input_resource_undefined_suggestion", []),
	}
} else = result if {
	wcdt := wcdt_for_input
	has_tups := count(wcdt) > 0

	msg_action := object.get(input, "action", "<any action>")

	severity := {true: constants.severity.ok, false: constants.severity.warning}[has_tups]
	message := {
		true: get_text(constants.diagnostics.wcdt_for_request, "has_tups_message", [count(wcdt), msg_action, input.resource]),
		false: get_text(constants.diagnostics.wcdt_for_request, "no_tups_message", [input.resource, msg_action]),
	}[has_tups]

	suggestion_obj := {
		true: {},
		false: {"suggestion": get_text(constants.diagnostics.wcdt_for_request, "no_tups_suggestion", [])},
	}[has_tups]

	context := {"who_can_do_this": wcdt}

	result := object.union(suggestion_obj, {
		"severity": severity,
		"message": message,
		"context": context,
	})
} else = result if {
	result := {
		"message": get_text("-", "unhandled_error", [constants.diagnostics.wcdt_for_request]),
		"severity": constants.severity.error,
	}
}

diagnostics[constants.diagnostics.wcdt_for_request] = result if {
	diagnostic_enabled(constants.diagnostics.wcdt_for_request)
	input.enable_diagnostics
	result := object.union(diagnostics_wcdt_for_request, diagnostics_wcdt_for_request_defaults)
}
