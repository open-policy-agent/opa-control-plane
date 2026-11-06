package global.systemtypes["entitlements:1.0"].library.policy.locations.v1

import rego.v1
import data.library.parameters

# METADATA: library-snippet
# version: v1
# title: "Location: Match exact"
# description: >-
#   Matches all requests where the value of input.context.location is
#   contained within the list of locations, using exact matching
# schema:
#   type: object
#   properties:
#     regions:
#       type: array
#       title: "List of locations to be matched"
#       items:
#         type: string
#       uniqueItems: true
#   required:
#     - locations
match_exact contains msg if {
	input.context.location == parameters.regions[_]
	msg := sprintf("User is from matching location %s", [input.context.location])
}
