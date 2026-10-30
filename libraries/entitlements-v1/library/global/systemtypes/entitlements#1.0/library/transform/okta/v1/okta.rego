package global.systemtypes["entitlements:1.0"].library.transform.okta.v1

import rego.v1

# METADATA: transform-snippet
# version: v1
# title: "Import Okta Data (Okta IDs)"
# description: >-
#    Transform Okta data into a format compatible with the Entitlements object
#    model. Object IDs from the Okta API will be used as IDs in the transformed
#    data. The resulting IDs will be less readable, but are guaranteed not to
#    have collisions.
# datasource:
#   categories:
#    - http
#    - aws/s3
#    - okta
okta_raw = obj if {
	obj := {
		"users": okta_raw_users,
		"groups": okta_raw_groups,
		"resources": okta_raw_resources,
		"roles": okta_raw_roles,
	}
}

okta_raw_users[id] = attributes if {
	okta_user := input[""].users[_]
	id := okta_user.id
	attributes := okta_user
}

okta_raw_groups[id] = users if {
	members := input[""]["group-members"][id]
	users := {"users": {member.id | member := members[_]}}
}

okta_raw_resources[id] = attributes if {
	app := input[""].apps[_]
	id := app.id
	attributes := app
}

okta_raw_roles[id] = {} if {
	role := input[""].roles[_]
	id := role.id
}

# METADATA: transform-snippet
# version: v1
# title: "Import Okta Data (human readable IDs)"
# description: >-
#    Transform Okta data into a format compatible with the Entitlements object
#    model. Where possible, human-readable identifiers will be used in the
#    transformed data. Depending on how you use Okta, this may cause ID
#    conflicts - if so consider using the "Okta IDs" transform.
# datasource:
#   categories:
#    - http
#    - aws/s3
#    - okta
okta_readable = obj if {
	obj := {
		"users": okta_readable_users,
		"groups": okta_readable_groups,
		"resources": okta_readable_resources,
		"roles": okta_readable_roles,
	}
}

okta_readable_users[id] = attributes if {
	okta_user := input[""].users[_]
	raw_id := okta_user.id
	profile := object.get(okta_user, "profile", {})
	id := object.get(profile, "login", raw_id)
	attributes := okta_user
}

okta_readable_groups[id] = users if {
	input[""]["group-members"][raw_id]
	group := input[""].groups[_]
	group.id == raw_id
	profile := object.get(group, "profile", {})
	id := object.get(profile, "name", raw_id)
	members := input[""]["group-members"][raw_id]
	users := {"users": {object.get(object.get(member, "profile", {}), "login", member.id) | member := members[_]}}
}

okta_readable_resources[id] = attributes if {
	app := input[""].apps[_]
	raw_id := app.id
	id := object.get(app, "name", raw_id)
	attributes := app
}

okta_readable_roles[id] = {} if {
	role := input[""].roles[_]
	id := role.id
}
