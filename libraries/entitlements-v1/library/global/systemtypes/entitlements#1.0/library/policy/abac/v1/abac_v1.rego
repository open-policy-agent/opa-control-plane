package global.systemtypes["entitlements:1.0"].library.policy.abac.v1

import rego.v1
import data.global.systemtypes["entitlements:1.0"].library.utils.v1 as utils
import data.library.parameters

object_users = data.object.users if {
	true
} else = {}

object_resources = data.object.resources if {
	true
} else = {}

# METADATA: library-snippet
# version: v1
# title: "ABAC: Resource has attributes"
# diagnostics:
#   - entz_object_check_resources
#   - resource_exists
#   - resource_has_attributes
# description: >-
#   Matches requests where the request resource glob matches at least one
#   resource from data.object.resources with all of the selected attributes.
# schema:
#   type: object
#   properties:
#     attributes:
#       type: object
#       title: Attributes
#       patternNames:
#         title: "Key"
#       additionalProperties:
#         type: string
#         title: "Value"
#   required:
#     - attributes
resource_has_attributes_glob contains msg if {
	some resourceID
	resource := object_resources[resourceID]
	utils.resource_glob(resourceID, input.resource)
	object_has_all_attributes(resource, parameters.attributes)
	msg := sprintf("Resource %s has attributes %v", [input.resource, parameters.attributes])
}

# METADATA: library-snippet
# version: v1
# title: "ABAC: Resource has attributes (exact resource matching)"
# diagnostics:
#   - entz_object_check_resources
#   - resource_exists
#   - resource_has_attributes
# description: >-
#   Matches requests where the request resource is exactly equal to a resource
#   from data.object.resources which has all of the selected attributes.
# schema:
#   type: object
#   properties:
#     attributes:
#       type: object
#       title: Attributes
#       patternNames:
#         title: "Key"
#       additionalProperties:
#         type: string
#         title: "Value"
#   required:
#     - attributes
#     - actions
resource_has_attributes contains msg if {
	# Backwards-compatibility - before filters were implemented, we used to
	# allow a list of actions to be provided. This feature is deprecated,
	# but existing code that uses this snippet should continue to work.
	not utils.object_contains_key(parameters, "actions")
	object_has_all_attributes(object_resources[input.resource], parameters.attributes)
	msg := sprintf("Resource %s has attributes %v", [input.resource, parameters.attributes])
}

# DEPRECATED
#
# Maintained for backwards-compatibility only.
resource_has_attributes contains msg if {
	utils.object_contains_key(parameters, "actions")
	object_has_all_attributes(object_resources[input.resource], parameters.attributes)
	input.action == parameters.actions[_]
	msg := sprintf("Resource %s has attributes %v", [input.resource, parameters.attributes])
}

# METADATA: library-snippet
# version: v1
# title: "ABAC: User has attributes"
# diagnostics:
#   - entz_object_check_users
#   - subject_exists
#   - subject_has_attributes
# description: >-
#   Matches requests where the user making a request has all of the selected attributes.
# schema:
#   type: object
#   properties:
#     attributes:
#       type: object
#       title: Attributes
#       patternNames:
#         title: "Key"
#       additionalProperties:
#         type: string
#         title: "Value"
#   additionalProperties: false
#   required:
#     - attributes

user_has_attributes contains msg if {
	object_has_all_attributes(object_users[input.subject], parameters.attributes)
	msg := sprintf("User %s has attributes %v", [input.subject, parameters.attributes])
}

# METADATA: library-snippet
# version: v1
# title: "ABAC: User and resource have attributes (exact resource matching)"
# diagnostics:
#   - entz_object_check_users
#   - subject_exists
#   - subject_has_attributes
#   - entz_object_check_resources
#   - resource_exists
#   - resource_has_attributes
# description: >-
#   Matches requests where user matches a set of attributes and the request
#   resource exactly matches a resource from data.object.resources which has
#   another set of attributes.
# schema:
#   type: object
#   properties:
#     user_attributes:
#       type: object
#       title: User Attributes
#       patternNames:
#         title: "Key"
#       additionalProperties:
#         type: string
#         title: "Value"
#     resource_attributes:
#       type: object
#       title: Resource Attributes
#       patternNames:
#         title: "Key"
#       additionalProperties:
#         type: string
#         title: "Value"
#   required:
#     - user_attributes
#     - resource_attributes

user_and_resource_has_attributes contains msg if {
	object_has_all_attributes(object_users[input.subject], parameters.user_attributes)
	object_has_all_attributes(object_resources[input.resource], parameters.resource_attributes)
	msg := sprintf("User %s has attributes %q and resource %s has attributes %q", [input.subject, parameters.user_attributes, input.resource, parameters.resource_attributes])
}

# METADATA: library-snippet
# version: v1
# title: "ABAC: User and resource have attributes"
# diagnostics:
#   - entz_object_check_users
#   - subject_exists
#   - subject_has_attributes
#   - entz_object_check_resources
#   - resource_exists
#   - resource_has_attributes
# description: >-
#   Matches requests where the user glob matches a set of attributes and the
#   request resource matches at least one resource from data.object.resources
#   with another set of attributes.
# schema:
#   type: object
#   properties:
#     user_attributes:
#       type: object
#       title: User Attributes
#       patternNames:
#         title: "Key"
#       additionalProperties:
#         type: string
#         title: "Value"
#     resource_attributes:
#       type: object
#       title: Resource Attributes
#       patternNames:
#         title: "Key"
#       additionalProperties:
#         type: string
#         title: "Value"
#   required:
#     - user_attributes
#     - resource_attributes
user_and_resource_has_attributes_glob contains msg if {
	object_has_all_attributes(object_users[input.subject], parameters.user_attributes)
	some resourceID
	resource := object_resources[resourceID]
	utils.resource_glob(resourceID, input.resource)
	object_has_all_attributes(resource, parameters.resource_attributes)
	msg := sprintf("User %s has attributes %q and resource %s has attributes %q", [input.subject, parameters.user_attributes, input.resource, parameters.resource_attributes])
}

object_has_all_attributes(object, attributes) if {
	matches := [match |
		attr_value := attributes[attr_key]
		object[attr_key] == attr_value
		match := true
	]

	count(matches) == count(attributes)
}
