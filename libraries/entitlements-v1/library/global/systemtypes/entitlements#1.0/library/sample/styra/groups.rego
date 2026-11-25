package global.systemtypes["entitlements:1.0"].library.sample.styra

import rego.v1

groups := {
	"admin-team": {
		"users": ["bob", "diya"],
		"membership-attributes": {"global_admin": true},
	},
	"platform-team": {"users": ["cheng", "eric"]},
}
