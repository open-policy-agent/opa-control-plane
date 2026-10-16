package global.systemtypes["entitlements:1.0"].library.sample.styra

import rego.v1

users := {
	"alice": {
		"name": "Alice",
		"organization": "Styra",
		"location": "Mars",
	},
	"bob": {
		"name": "Bob",
		"organization": "Styra",
	},
	"cheng": {"name": "cheng"},
	"diya": {"name": "Diya"},
	"eric": {
		"name": "Eric",
		"contractor": "true",
	},
}
