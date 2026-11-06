package global.systemtypes["entitlements:1.0"].library.transform.openapi.v1

import rego.v1

# METADATA: transform-snippet
# version: v1
# title: "OpenAPI spec to resources"
# description: >-
#   Transforms an OpenAPI v2 or v3 spec to DAS-compatible resource definitions.
# datasource:
#   categories:
#    - http
#    - aws/s3
#    - git/content
#    - rest
#    - git/content

openapi_resources[id] = attributes if {
	# openapi v2
	input.swagger == "2.0"
	base_attributes := input.paths[path]
	parsed := replace_path_templates_with_globs(path)
	id := parsed.path
	attributes := add_variables_attribute(base_attributes, parsed)
}

openapi_resources[id] = attributes if {
	# openapi v3
	input.openapi == ["3.0", "3.0.1", "3.0.2", "3.0.3"][_]
	base_attributes := input.paths[path]
	parsed := replace_path_templates_with_globs(path)
	id := parsed.path
	attributes := add_variables_attribute(base_attributes, parsed)
}

add_variables_attribute(base_attributes, parsed_path) = attributes if {
	parsed_path.variables != {}
	attributes := object.union(base_attributes, {"_variables": parsed_path.variables})
} else = base_attributes

# replace_path_templates_with_globs rewrites openapi path templates to globs
# e.g., /shelves/{shelf}/books/{book} to /shelves/*/books/*
# and returns a map with position indices mapping to variable names
# e.g., {1: shelf, 3: book} for above
replace_path_templates_with_globs(path) = {"path": rewritten_path, "variables": vars} if {
	segments := split(path, "/")
	rewritten_segments := [rewritten |
		original := segments[_]
		rewritten := replace_segment_with_globs(original).segment
	]

	vars := {position: var_name |
		original := segments[position]
		var_name := replace_segment_with_globs(original).variable
	}

	rewritten_path := concat("/", rewritten_segments)
}

replace_segment_with_globs(segment) = {"segment": rewritten_segment, "variable": variable} if {
	startswith(segment, "{")
	endswith(segment, "}")
	rewritten_segment := "*"
	variable := trim_prefix(trim_suffix(segment, "}"), "{")
} else = {"segment": segment}
