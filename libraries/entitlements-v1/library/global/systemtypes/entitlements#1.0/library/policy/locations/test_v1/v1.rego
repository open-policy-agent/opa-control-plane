package global.systemtypes["entitlements:1.0"].library.policy.locations.test_v1

import rego.v1
import data.global.systemtypes["entitlements:1.0"].library.policy.locations.v1 as location

test_location_exact if {
	count(location.match_exact) == 1 with input as {"context": {"location": "spain"}}
		with data.library.parameters as {"regions": ["us", "spain"]}

	count(location.match_exact) == 0 with input as {"context": {"location": "germany"}}
		with data.library.parameters as {"regions": ["us", "spain"]}
}
