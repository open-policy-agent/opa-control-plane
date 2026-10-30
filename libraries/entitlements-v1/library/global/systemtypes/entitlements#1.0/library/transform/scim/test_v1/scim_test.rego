package global.systemtypes["entitlements:1.0"].library.transform.scim.test_v1

import rego.v1
import data.global.systemtypes["entitlements:1.0"].library.transform.scim.v1 as scim

test_scim_users if {
	id := "8F12B67E-456D-4941-B99B-9975932B69EF"
	user := {
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"id": id,
		"userName": "test@styra.local",
		"name": {
			"givenName": "Test",
			"middleName": "",
			"familyName": "User",
		},
		"active": true,
		"emails": [{
			"primary": true,
			"value": "test.user@styra.local",
			"type": "work",
			"display": "test.user@styra.local",
		}],
		"groups": [],
		"meta": {"resourceType": "User"},
	}

	users := scim.users with input as [user]
	u := users[id]
	u.userName == "test@styra.local"
}

test_scim_groups if {
	group := {
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
		"id": "abf4dd94-a4c0-4f67-89c9-76b03340cb9b",
		"displayName": "Test SCIMv2",
		"members": [{
			"value": "b1c794f24f4c49f4b5d503a4cb2686ea",
			"display": "SCIM 2 Group A",
		}],
		"meta": {"resourceType": "Group"},
	}

	expected := {"abf4dd94-a4c0-4f67-89c9-76b03340cb9b": {
		"displayName": "Test SCIMv2",
		"members": [{
			"display": "SCIM 2 Group A",
			"value": "b1c794f24f4c49f4b5d503a4cb2686ea",
		}],
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
	}}

	groups := scim.groups with input as [group]

	groups == expected
}
