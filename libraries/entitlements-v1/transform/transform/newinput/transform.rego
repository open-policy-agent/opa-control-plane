package transform.newinput

# This package is used to transform the input request from
# an existing schema to the Styra-supported entz schema.
# This is done by creating a rule here named "newinput" that
# translates the input to the Styra schema
#
# import rego.v1
#
# decoded_jwt := io.jwt.decode(input.jwt)
#
# jwt_context := {
#     "jwt": {
#         "header": decoded_jwt[0],
#         "payload": decoded_jwt[1],
#         "signature": decoded_jwt[2],
#         "raw": input.jwt
#     }
# }
#
# newinput = obj if {
#     obj = object.union(input, {"context": jwt_context})
# } else = input
