package global.systemtypes["entitlements:1.0"].library.sample.car_info_store

import rego.v1

groups := {
	"senior-leadership-team": {"membership-attributes": {"team": "SLT"}},
	"store-managers": {"users": ["alice"]},
	"sales": {"membership-attributes": {"team": "sales"}},
	"back-office": {"users": ["janet", "william"]},
}
