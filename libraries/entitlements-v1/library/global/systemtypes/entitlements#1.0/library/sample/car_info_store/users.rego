package global.systemtypes["entitlements:1.0"].library.sample.car_info_store

import rego.v1

users := {
	"alice": {
		"name": "Alice",
		"organization": "Styra",
		"location": "Mars",
		"title": "general manager",
		"is_employee": true,
		"team": "sales",
	},
	"bob": {
		"name": "Bob",
		"organization": "Styra",
		"title": "CEO",
		"is_employee": true,
		"team": "SLT",
	},
	"cheng": {
		"name": "Cheng",
		"title": "sales associate",
		"is_employee": true,
		"team": "sales",
	},
	"diya": {
		"name": "Diya",
		"title": "CFO",
		"is_employee": true,
		"team": "SLT",
	},
	"eric": {
		"name": "Eric",
		"title": "sales associate",
		"is_employee": true,
		"team": "sales",
	},
	"janet": {
		"name": "Janet",
		"title": "accountant",
		"is_employee": true,
	},
	"william": {
		"name": "William",
		"is_contractor": true,
		"is_employee": false,
	},
	"sarah": {"is_employee": true},
}
