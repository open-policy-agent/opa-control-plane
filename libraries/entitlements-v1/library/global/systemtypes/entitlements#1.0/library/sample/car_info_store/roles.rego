package global.systemtypes["entitlements:1.0"].library.sample.car_info_store

import rego.v1

roles := {
	"car-creators": {"allow": {"include": [{
		"actions": ["POST"],
		"resources": ["/cars", "/cars/*"],
	}]}},
	"car-updaters": {"allow": {"include": [{
		"actions": ["POST", "PUT"],
		"resources": ["/cars", "/cars/*"],
	}]}},
	"car-readers": {"allow": {"include": [{
		"actions": ["GET"],
		"resources": ["/cars", "/cars/*"],
	}]}},
	"status-updaters": {"allow": {"include": [{
		"actions": ["PUT"],
		"resources": ["/cars/*/status"],
	}]}},
	"status-readers": {"allow": {"include": [{
		"actions": ["GET"],
		"resources": ["/cars/*/status"],
	}]}},
}
