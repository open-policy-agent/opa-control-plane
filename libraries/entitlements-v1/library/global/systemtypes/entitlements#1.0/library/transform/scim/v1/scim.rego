package global.systemtypes["entitlements:1.0"].library.transform.scim.v1

import rego.v1

# METADATA: transform-snippet
# version: v1
# title: "SCIM records to users"
# description: >-
#   Transforms an array of SCIM records to DAS-compatible user definitions.
# datasource:
#   categories:
#    - ldap
#    - http
#    - aws/s3
#    - git/content

users[id] = attributes if {
	record := input[_]
	record.schemas[_] == "urn:ietf:params:scim:schemas:core:2.0:User"

	id := record.id
	attributes := object.remove(record, ["meta", "id"])
}

# METADATA: transform-snippet
# version: v1
# title: "SCIM records to groups"
# description: >-
#   Transforms an array of SCIM records to DAS-compatible user definitions.
# datasource:
#   categories:
#    - ldap
#    - http
#    - aws/s3
#    - git/content

groups[id] = attributes if {
	record := input[_]
	record.schemas[_] == "urn:ietf:params:scim:schemas:core:2.0:Group"

	id := record.id
	attributes := object.remove(record, ["meta", "id"])
}
