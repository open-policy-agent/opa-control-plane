package global.systemtypes["entitlements:1.0"].library.sample.car_info_store

import rego.v1

resources := {
	"/cars": {"public": "true"},
	"/cars/*": {},
	"/cars/*/status": {"restricted": "true"},
	"/entz-playground/buttons/*": {"playground": "true"},
	"/entz-playground/buttons/edit": {"playground": "true"},
	"/entz-playground/buttons/copy": {"playground": "true"},
	"/entz-playground/buttons/remove": {"playground": "true"},
}
