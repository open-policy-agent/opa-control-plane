package global.systemtypes["entitlements:1.0"].library.policy.general.v1

import rego.v1
import data.library.parameters

# METADATA: library-snippet
# version: v1
# title: "General: Glob match action, subject, and/or resource"
# description: >-
#   Matches any combination of action, subject, resource through glob-matching with delimiters "." and "/".
# details: >-
#   For each input field (action, subject, resource), you may specify a collection of glob patterns; if any of those glob-patterns match the corresponding
#   input field's value, you match that field. For this rule to match as a whole, you must match all input fields for which you supply glob patterns.  Any
#   field without a glob pattern is matched automatically.
# schema:
#   type: object
#   properties:
#     actions:
#       type: array
#       title: "Match Actions"
#       items:
#         type: string
#       uniqueItems: true
#       "hint:items":
#         package: "object"
#         query: "actions"
#     resources:
#       type: array
#       title: "Resource selector"
#       items:
#         type: string
#       uniqueItems: true
#       "hint:items":
#         package: "completions"
#         query: "resources"
#     subjects:
#       type: array
#       title: "Match subjects"
#       items:
#         type: string
#       uniqueItems: true
#       "hint:items":
#         package: "completions"
#         query: "subjects"

match_glob_action_subject_resource contains msg if {
	optional_array_parameter("action", "actions")
	optional_array_parameter("subject", "subjects")
	optional_array_parameter("resource", "resources")
	msg := "Snippet: glob match action, subject or resource"
}

# METADATA: library-snippet
# version: v1
# title: "General: Match all requests"
# description: >-
#   Match all requests.  Generally used along with filters to do exact matching.

match_requests contains msg if {
	msg := "Match all requests snippet"
}

input_field_matches_some_array_value_or_is_undefined(fieldname, array) if {
	# input.fieldname is undefined, return true
	not input[fieldname] == input[fieldname]
} else if {
	input[fieldname] == array[_]
}

optional_array_parameter(input_field, param) if {
	# If the parameter is undefined, then return true.
	not data.library.parameters[param] == data.library.parameters[param]
}

optional_array_parameter(input_field, param) if {
	# If the parameter is the empty set, then return true.
	is_set(data.library.parameters[param])
	count(data.library.parameters[param]) == 0
}

optional_array_parameter(input_field, param) if {
	# If the parameter is defined and non-empty, then return true.
	glob.match(data.library.parameters[param][_], [".", "/"], input[input_field])
}

# METADATA: library-snippet
# version: v1
# title: "General: Match requests with all but specific actions"
# diagnostics:
#   - entz_object_check_actions
# description: >-
#   All requests with an action listed as an excluded action will not be
#   matched. For example, if actions "GET" and "PUT" are excluded, then a
#   request with action "GET" or "PUT" will not be matched, but a request with
#   action "POST" will be matched. Requests with no action are always matched.
# schema:
#   type: object
#   properties:
#     exclude:
#       type: array
#       title: "List of actions that are excluded from"
#       items:
#         type: string
#       uniqueItems: true
#   required:
#     - unmatch_actions
action_not_excluded contains msg if {
	# This is still confusing, even after trying to make it less so. To
	# formalize what's going on a bit, this rule is equivalent to:
	#
	#	(input.action ∉ unmatch_actions) ∨ (input.action ≡ ∅)

	matching_actions := {action | action := parameters.exclude[_]; input.action == action}
	count(matching_actions) == 0
	msg := sprintf("Action %s is not excluded", [input.action])
}

action_not_excluded contains msg if {
	# input.action is undefined
	not input.action == input.action
	msg := "Action is not specified in the request"
}

# METADATA: library-snippet
# version: v1
# title: "General: Invalid action"
# diagnostics:
#   - entz_object_check_actions
#   - action_exists
# description: >-
#   Matches requests where the input action is missing or is NOT contained
#   within the object model's user list.
action_is_not_valid contains msg if {
	# equivalent to 'not input.action in data.object.actions',
	#   but written this way to avoid requiring new OPAs
	count({1 | input.action == data.object.actions[_]}) == 0
	msg := sprintf("Action %s is not valid", [input.action])
}

action_is_not_valid contains msg if {
	# input.action is undefined
	not input.action == input.action
	msg := "Action is not specified in the request"
}

# METADATA: library-snippet
# version: v1
# title: "General: Invalid user"
# diagnostics:
#   - entz_object_check_users
#   - subject_exists
# description: >-
#   Matches requests where the input subject is missing or is NOT contained
#   within the object model's user list.
user_is_not_valid contains msg if {
	not data.object.users[input.subject]
	msg := sprintf("User %s is not valid", [input.subject])
}

user_is_not_valid contains msg if {
	not input.subject == input.subject
	msg := "No subject found in the input request"
}
