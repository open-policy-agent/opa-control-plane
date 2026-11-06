package global.systemtypes["entitlements:1.0"].library.diagnostics.v1

import rego.v1

# This file contains user-visible text/messages/prose for diagnostics, to allow
# those messages to be viewed and modified independently from the rest of the
# diagnostics code.
#
# At time of writing, OPA does not support string interpolation/templating,
# see: https://github.com/open-policy-agent/opa/issues/4733
#
# Therefore, strings that need to have additional information formatted into
# them should simply indicate in a comment what values pertain to any format
# codes.

# This is a 2-level index. The outer index is the diagnostic ID. The inner
# index is the text ID. Text which could be used for multiple different
# diagnostics should use the diagnostic ID "-".
#
# Callers should not use this structure directly, but instead the get_text()
# helper function.
#
# Diagnostic has multiple types of text fragments, including messages,
# suggestions, and descriptions. This structure does not make any assumptions
# about the text type. The suggested convention is to suffix the text ID with
# one of "_message", "_description", or "_suggestion".
text := {
	# Generic messages that can be used for multiple diagnostics.
	"-": {
		# Fallback message used by get_text() if we fail to lookup
		# the given diagnosticID/textID pair.
		"lookup_error": "Failed to look up text fragment with ID '%s' for diagnostic ID '%s'.",
		# Message used for uncaught errors.
		"unhandled_error": "Diagnostics encountered an unexpected error (diagnostic ID '%s').",
		"disabled_message": "This diagnostic was skipped because it was explicitly disabled.",
		"empty_input_message": "This diagnostic was skipped because the input was empty.",
	},
	constants.diagnostics.duplicate_subject_check: {
		# The duplicate subject check handles the possibility that the
		# same subject ID could exist in multiple subject types, for
		# example a group and a user with the same subject ID. The
		# behavior of Entz in this situation is undefined, so it's
		# important to check for it.
		"description": "Check to ensure that there are no subject ID collisions between users, groups, and service accounts.",
		"ok_message": "No duplicate subject IDs found.",
		# If there are duplicates, the suggested way to work around it
		# is to prefix all the subject IDs for one or all of the
		# subject types with a unique string, so instead of having
		# "jsmith", you might have "user:jsmith" instead.
		#
		# Note that it is impossible to have duplicate subject IDs in
		# the same subject type, since entries in the relevant object
		# in data.object are keyed by their subject ID, so any
		# duplicates within the same type would be overwritten, and
		# there is no way to detect if this has happened.
		"dupes_found_message": "One or more subject IDs are defined for multiple subject types.",
		"dupes_found_suggestion": "Verify data sources are combined properly in object.rego. If the data sources contain ID collisions, modify object.rego to prefix subject IDs with a unique prefix per-datasource or per-subject type.",
	},
	constants.diagnostics.entz_object_check: {
		# Note that a separate entz_object_check is generated for each
		# field in object.rego, so the actual diagnostic IDs will be
		# something like entz_object_check_FIELDNAME.
		#
		# Most of these texts expect the format array to be the field
		# in question, e.g. 'actions', 'resources', etc.
		"description": "Check to ensure that data.object.%s is defined and non-empty.",
		"ok_message": "'data.object.%s' exists and is non-empty.",
		# One failure mode is for a field to be defined, but be empty.
		# This might be OK in certain cases - we expect lots of people
		# will end up seeing this warning for service accounts for
		# example. However, if the end user is utilizing Entz fully,
		# most or all of their fields should be populated with data,
		# and an empty one could imply a bad transform or datasource
		# configuration.
		"exists_empty_message": "'data.object.%s' exists, but is empty",
		"exists_empty_suggestion": "Modify object.rego to ensure data.object.%s contains the expected data.",
		# It's also possible for a field to be undefined. This could be
		# deliberate if the end user doesn't intend to use that type of
		# entz object, but can also easily be a symptom of an incorrect
		# setup.
		"undefined_message": "data.object.%s is undefined",
		"undefined_suggestion": "Modify object.rego to ensure data.object.%s is defined.",
	},
	constants.diagnostics.subject_exists: {
		"input_subject_undefined_message": "Subject not specified in input (input.subject undefined).",
		"input_subject_undefined_suggestion": "Check the source of the request, and ensure it is properly defining the 'subject' field.",
		"invalid_subject_message": "Subject '%s' is not valid.",
		"invalid_subject_suggestion": "Check the source of the request, and ensure it is properly defining the 'subject' field.",
		"ok_message": "Subject '%s' exists and is a %s.",
		"description": "Ensure that the request contains a valid subject.",
	},
	constants.diagnostics.subject_has_roles: {
		"ok_message": "Subject '%s' has %d roles.",
		"no_bindings_message": "Subject '%s' has no roles.",
		"no_bindings_suggestion": "Check object.rego to ensure that there are role bindings that apply to the subject.",
		"roles_undefined_message": "Subject '%s' roles are undefined.",
		"role_undefined_suggestion": "Check the role bindings in object.rego for malformed data.",
		"input_subject_undefined_message": "Subject not specified in input (input.subject undefined).",
		"input_subject_undefined_suggestion": "Check the source of the request, and ensure it is properly defining the 'subject' field.",
		"description": "Ensure that there are roles bound to the request subject.",
	},
	constants.diagnostics.resource_exists: {
		"ok_message": "Resource '%s' exists.",
		"nonexist_message": "Resource '%s' does not exist.",
		"nonexist_suggestion": "Check data.object.resources in object.rego.",
		"input_resource_undefined_message": "No resource specified in input (input.resource undefined).",
		"input_resource_undefined_suggestion": "Check the source of the request and ensure it is properly defining the 'resource' field.",
		"description": "Ensure that input.resource is defined within the object model.",
	},
	constants.diagnostics.action_exists: {
		"ok_message": "Action '%s' exists.",
		"nonexist_message": "Action '%s' does not exist",
		"nonexist_suggestion": "If you believe the action is valid, ensure it is defined in data.object.actions.",
		"input_action_undefined_message": "no action specified in input (input.action undefined)",
		"input_action_undefined_suggestion": "Check the source of the request and ensure it is properly defining the 'action' field.",
		"description": "Ensure that input.action is defined within the object model.",
	},
	constants.diagnostics.role_resource_action: {
		"ok_message": "%d relevant roles found.",
		"input_action_undefined_message": "No action specified in input (input.action undefined).",
		"input_action_undefined_suggestion": "Check the source of the request and ensure it is properly defining the 'action' field.",
		"input_resource_undefined_message": "No resource specified in input (input.resource undefined).",
		"input_resource_undefined_suggestion": "Check the source of the request and ensure it is properly defining the 'resource' field.",
		"no_relevant_roles_message": "No relevant roles found.",
		"no_relevant_roles_suggestion": "The (action, resource) combination specified in the input don't match up with any roles. Check data.object.roles in object.rego.",
		"object_roles_undefined_message": "object.roles not defined",
		"object_roles_undefined_suggestion": "Check data.object.roles in object.rego and ensure it is defined.",
		"object_roles_empty_message": "object.roles is empty",
		"object_roles_empty_suggestion": "Check data.object.roles in object.rego and ensure it contains the desired roles.",
		"description": "Check to make sure there are roles associated with the (action, resource) combination (ignoring the subject specified, if any) specified in the input. If there are not, it won't be possible to create RBAC policies that explicitly allow or deny access to that (action, resource) pair.",
	},
	constants.diagnostics.subject_has_attributes: {
		"input_subject_undefined_message": "Subject not specified in input (input.subject undefined).",
		"input_subject_undefined_suggestion": "Check the source of the request, and ensure it is properly defining the 'subject' field.",
		"invalid_subject_message": "Subject '%s' is invalid (not a user, group, or service account).",
		"invalid_subject_suggestion": "If you believe the subject should be valid, check object.rego to ensure the user, group, and service_account field have the proper contents.",
		"ok_message": "Subject '%s' has %d attributes.",
		"no_attributes_message": "Subject '%s' has no attributes.",
		"no_attributes_suggestion": "Check object.rego to ensure that the subject has been assigned attributes.",
		"description": "Check to make sure that there are attributes associated with the subject. If not, it won't be possible to explicitly allow or deny access to the subject based on its attributes.",
	},
	constants.diagnostics.resource_has_attributes: {
		"input_resource_undefined_message": "No resource specified in input (input.resource undefined).",
		"input_resource_undefined_suggestion": "Check the source of the request and ensure it is properly defining the 'resource' field.",
		"ok_message": "Resource '%s' has %d attributes.",
		"no_attributes_message": "Resource '%s' has no attributes.",
		"no_attributes_suggestion": "Check data.object.resources in object.rego to ensure that the resource has been assigned attributes.",
		"description": "Check to make sure that there are attributes associated with the resource. If not, it won't be possible to explicitly allow or deny access to the resource based on its attributes.",
	},
	constants.diagnostics.resource_action_for_role: {
		"dangling_suggestion": "Check object.rego and data sources to ensure that the resources and actions referenced in data.object.roles align with the roles and actions defined by data.object.actions and data.object.roles.",
		"message": "Found %d extant and %d dangling resources across all roles. Found %d extant and %d dangling actions across all roles.",
		"description": "Checks that every role references only resources and actions defined in data.object.resources and data.object.roles, respectively.",
	},
	constants.diagnostics.subjects_for_role_binding: {
		"no_subjects_suggestion": "Check data.object.role_bindings, it is likely you are using attribute-based role assignment, and no subjects have the attributes to be assigned to some of your role bindings.",
		"dangling_subjects_suggestion": "Check data.object.role_bindings. Some of your roles directly bind to subject by their IDs, but those subject IDs don't correspond to extant users, groups, or service accounts.",
		"both_suggestion": "Check data.object.role_bindings. Some of your roles directly bind to subject by their IDs, but those subject IDs don't correspond to extant users, groups, or service accounts. Check data.object.role_bindings, it is likely you are using attribute-based role assignment, and no subjects have the attributes to be assigned to some of your role bindings.",
		"message": "Found %d role bindings with no subject, and %d with dangling subjects.",
		"description": "Checks that any subjects mentioned in a role binding by ID are extant, and checks that each role binding has at least one subject.",
	},
	constants.diagnostics.object_model_schema: {
		"suggestion": "Check object.rego and ensure the data follows the entitlements schema.",
		"message": "Found %d schema violations.",
		"description": "Checks that the Entitlements object model follows the correct schema.",
	},
	constants.diagnostics.ucdw_for_request: {
		"description": "Check that the given subject, resource, and action all appear together in the 'user can do what' for the Entitlements object model.",
		"input_subject_undefined_message": "Subject not specified in input (input.subject undefined).",
		"input_subject_undefined_suggestion": "Check the source of the request, and ensure it is properly defining the 'subject' field.",
		"input_resource_undefined_message": "No resource specified in input (input.resource undefined).",
		"input_resource_undefined_suggestion": "Check the source of the request and ensure it is properly defining the 'resource' field.",
		"input_action_undefined_message": "no action specified in input (input.action undefined)",
		"input_action_undefined_suggestion": "Check the source of the request and ensure it is properly defining the 'action' field.",
		"no_tups_message": "No connection found between subject '%s', resource '%s', and action '%s'. This request is likely be default-denied depending on the configured policy.",
		"no_tups_suggestion": "Check that the expected roles are bound to the subject, and check that those roles either allow or deny access to the resource using the action.",
		"has_tups_message": "Found %d combinations of subject '%s', resource '%s', and action '%s'.",
	},
	constants.diagnostics.wcdt_for_request: {
		"description": "Check that the subject, resource, and action for the request appear together in the 'who can do this' for the Entitlements object model.",
		"input_resource_undefined_message": "No resource specified in input (input.resource undefined).",
		"input_resource_undefined_suggestion": "Check the source of the request and ensure it is properly defining the 'resource' field.",
		"no_tups_message": "No connection found between resource '%s' and action '%s'. This request is likely be default-denied depending on the configured policy.",
		"no_tups_suggestion": "Check that the expected roles are bound to the subject, and check that those roles either allow or deny access to the resource using the action.",
		"has_tups_message": "Found %d users explicitly allowed or denied action '%s' on resource '%s'.",
	},
}

###############################################################################

# get_text is the canonical method of accessing diagnostic text content.
#
# diagnosticID - the key for the diagnostic within the diagnostics object, or
#                "-" for generic messages (see above).
#
# textID - the ID for the text fragment.
#
# fmt - array passed to sprintf for formatting diagnostic text.
get_text(diagnosticID, textID, fmt) = fragment if {
	# If only the diagnosticID is bad, then the not clause will always be
	# true since outer will be an empty object. If only the textID is bad,
	# then it still won't be found in outer.
	outer := object.get(text, diagnosticID, {})
	not outer[textID]
	fragment := sprintf(text["-"].lookup_error, [textID, diagnosticID])
	# print(sprintf("get_text(%s, %s, %v) -> %s", [diagnosticID, textID, fmt, fragment]))
}

get_text(diagnosticID, textID, fmt) = fragment if {
	outer := object.get(text, diagnosticID, {})
	unformatted := outer[textID]
	fragment := sprintf(unformatted, fmt)
	# print(sprintf("get_text(%s, %s, %v) -> %s", [diagnosticID, textID, fmt, fragment]))
}
