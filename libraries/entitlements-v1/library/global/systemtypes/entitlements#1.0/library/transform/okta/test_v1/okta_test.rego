package global.systemtypes["entitlements:1.0"].library.transform.okta.test_v1

import rego.v1
import data.global.systemtypes["entitlements:1.0"].library.transform.okta.v1 as okta

sample_okta_data := {
	"apps": [
		{
			"_embedded": null,
			"_links": {
				"appLinks": [{
					"href": "https://dev-36468868.okta.com/home/saasure/0oa3jvzgfqVELvozl5d7/2",
					"name": "admin",
					"type": "text/html",
				}],
				"deactivate": {"href": "https://dev-36468868.okta.com/api/v1/apps/0oa3jvzgfqVELvozl5d7/lifecycle/deactivate"},
				"groups": {"href": "https://dev-36468868.okta.com/api/v1/apps/0oa3jvzgfqVELvozl5d7/groups"},
				"logo": [{
					"href": "https://ok12static.oktacdn.com/assets/img/logos/okta_admin_app.da3325676d57eaf566cb786dd0c7a819.png",
					"name": "medium",
					"type": "image/png",
				}],
				"uploadLogo": {
					"hints": {"allow": ["POST"]},
					"href": "https://dev-36468868.okta.com/api/v1/apps/0oa3jvzgfqVELvozl5d7/logo",
				},
				"users": {"href": "https://dev-36468868.okta.com/api/v1/apps/0oa3jvzgfqVELvozl5d7/users"},
			},
			"accessibility": {
				"errorRedirectUrl": null,
				"loginRedirectUrl": null,
				"selfService": false,
			},
			"created": "2022-01-10T19:45:00.000Z",
			"credentials": {
				"signing": {"kid": "Aeyg4LnK2K6uE5rr_gtETViAiOWPqXHmQgQo_IUluBI"},
				"userNameTemplate": {
					"template": "${source.login}",
					"type": "BUILT_IN",
				},
			},
			"features": [],
			"id": "0oa3jvzgfqVELvozl5d7",
			"label": "Okta Admin Console",
			"lastUpdated": "2022-01-10T19:45:01.000Z",
			"name": "saasure",
			"profile": null,
			"request_object_signing_alg": "",
			"settings": {
				"app": {},
				"notifications": {"vpn": {
					"helpUrl": null,
					"message": null,
					"network": {"connection": "DISABLED"},
				}},
			},
			"signOnMode": "OPENID_CONNECT",
			"status": "ACTIVE",
			"visibility": {
				"appLinks": {"admin": true},
				"autoSubmitToolbar": false,
				"hide": {
					"iOS": false,
					"web": false,
				},
			},
		},
		{
			"_embedded": null,
			"_links": {
				"appLinks": [],
				"deactivate": {"href": "https://dev-36468868.okta.com/api/v1/apps/0oa3jvzgkbNA6SYEC5d7/lifecycle/deactivate"},
				"groups": {"href": "https://dev-36468868.okta.com/api/v1/apps/0oa3jvzgkbNA6SYEC5d7/groups"},
				"logo": [{
					"href": "https://ok12static.oktacdn.com/assets/img/logos/okta-logo-end-user-dashboard.fc6d8fdbcb8cb4c933d009e71456cec6.svg",
					"name": "medium",
					"type": "image/png",
				}],
				"uploadLogo": {
					"hints": {"allow": ["POST"]},
					"href": "https://dev-36468868.okta.com/api/v1/apps/0oa3jvzgkbNA6SYEC5d7/logo",
				},
				"users": {"href": "https://dev-36468868.okta.com/api/v1/apps/0oa3jvzgkbNA6SYEC5d7/users"},
			},
			"accessibility": {
				"errorRedirectUrl": null,
				"loginRedirectUrl": null,
				"selfService": false,
			},
			"created": "2022-01-10T19:45:03.000Z",
			"credentials": {
				"signing": {"kid": "Aeyg4LnK2K6uE5rr_gtETViAiOWPqXHmQgQo_IUluBI"},
				"userNameTemplate": {
					"template": "${source.login}",
					"type": "BUILT_IN",
				},
			},
			"features": [],
			"id": "0oa3jvzgkbNA6SYEC5d7",
			"label": "Okta Dashboard",
			"lastUpdated": "2022-01-10T19:45:03.000Z",
			"name": "okta_enduser",
			"profile": null,
			"request_object_signing_alg": "",
			"settings": {
				"app": {},
				"notifications": {"vpn": {
					"helpUrl": null,
					"message": null,
					"network": {"connection": "DISABLED"},
				}},
			},
			"signOnMode": "OPENID_CONNECT",
			"status": "ACTIVE",
			"visibility": {
				"appLinks": {},
				"autoSubmitToolbar": false,
				"hide": {
					"iOS": false,
					"web": false,
				},
			},
		},
	],
	"group-members": {"00g5h3ops7yvVzesh5d7": [
		{
			"id": "00u5gzjgk6uHO7Mhr5d7",
			"status": "STAGED",
			"created": "2022-06-22T16:50:02.000Z",
			"activated": "",
			"statusChanged": null,
			"lastLogin": null,
			"lastUpdated": "2022-06-22T16:50:02.000Z",
			"passwordChanged": null,
			"type": {"id": "oty3jvzggclbK159z5d7"},
			"transitioningToStatus": null,
			"profile": {
				"city": "Lake Philiphaven",
				"email": "robertwells@example.net",
				"firstName": "Oscar",
				"lastName": "Alvarado",
				"login": "robertwells@example.net",
				"mobilePhone": null,
				"primaryPhone": "+1-403-441-2897x138",
				"secondEmail": null,
				"state": "New York",
				"streetAddress": "416 Brown Village Suite 655",
				"timezone": "Indian/Mahe",
				"title": "FAKE TEST USER",
				"zipCode": "10730",
			},
			"credentials": {
				"emails": [{
					"status": "VERIFIED",
					"type": "PRIMARY",
					"value": "robertwells@example.net",
				}],
				"provider": {
					"name": "OKTA",
					"type": "OKTA",
				},
			},
			"_links": {"self": {"href": "https://dev-36468868.okta.com/api/v1/users/00u5gzjgk6uHO7Mhr5d7"}},
			"_embedded": null,
		},
		{
			"id": "00u5gzkdmzIgvqo705d7",
			"status": "STAGED",
			"created": "2022-06-22T16:51:19.000Z",
			"activated": "",
			"statusChanged": null,
			"lastLogin": null,
			"lastUpdated": "2022-06-22T16:51:19.000Z",
			"passwordChanged": null,
			"type": {"id": "oty3jvzggclbK159z5d7"},
			"transitioningToStatus": null,
			"profile": {
				"city": "Reynoldsfurt",
				"email": "kneal@example.com",
				"firstName": "Peggy",
				"lastName": "Abbott",
				"login": "kneal@example.com",
				"mobilePhone": null,
				"primaryPhone": "+1-871-318-6846x8395",
				"secondEmail": null,
				"state": "Virginia",
				"streetAddress": "4019 Jennifer Keys Apt. 562",
				"timezone": "Asia/Phnom_Penh",
				"title": "FAKE TEST USER",
				"zipCode": "22899",
			},
			"credentials": {
				"emails": [{
					"status": "VERIFIED",
					"type": "PRIMARY",
					"value": "kneal@example.com",
				}],
				"provider": {
					"name": "OKTA",
					"type": "OKTA",
				},
			},
			"_links": {"self": {"href": "https://dev-36468868.okta.com/api/v1/users/00u5gzkdmzIgvqo705d7"}},
			"_embedded": null,
		},
	]},
	"users": [
		{
			"id": "00u5gzjgk6uHO7Mhr5d7",
			"status": "STAGED",
			"created": "2022-06-22T16:50:02.000Z",
			"activated": "",
			"statusChanged": null,
			"lastLogin": null,
			"lastUpdated": "2022-06-22T16:50:02.000Z",
			"passwordChanged": null,
			"type": {"id": "oty3jvzggclbK159z5d7"},
			"transitioningToStatus": null,
			"profile": {
				"city": "Lake Philiphaven",
				"email": "robertwells@example.net",
				"firstName": "Oscar",
				"lastName": "Alvarado",
				"login": "robertwells@example.net",
				"mobilePhone": null,
				"primaryPhone": "+1-403-441-2897x138",
				"secondEmail": null,
				"state": "New York",
				"streetAddress": "416 Brown Village Suite 655",
				"timezone": "Indian/Mahe",
				"title": "FAKE TEST USER",
				"zipCode": "10730",
			},
			"credentials": {
				"emails": [{
					"status": "VERIFIED",
					"type": "PRIMARY",
					"value": "robertwells@example.net",
				}],
				"provider": {
					"name": "OKTA",
					"type": "OKTA",
				},
			},
			"_links": {"self": {"href": "https://dev-36468868.okta.com/api/v1/users/00u5gzjgk6uHO7Mhr5d7"}},
			"_embedded": null,
		},
		{
			"id": "00u5gzkdmzIgvqo705d7",
			"status": "STAGED",
			"created": "2022-06-22T16:51:19.000Z",
			"activated": "",
			"statusChanged": null,
			"lastLogin": null,
			"lastUpdated": "2022-06-22T16:51:19.000Z",
			"passwordChanged": null,
			"type": {"id": "oty3jvzggclbK159z5d7"},
			"transitioningToStatus": null,
			"profile": {
				"city": "Reynoldsfurt",
				"email": "kneal@example.com",
				"firstName": "Peggy",
				"lastName": "Abbott",
				"login": "kneal@example.com",
				"mobilePhone": null,
				"primaryPhone": "+1-871-318-6846x8395",
				"secondEmail": null,
				"state": "Virginia",
				"streetAddress": "4019 Jennifer Keys Apt. 562",
				"timezone": "Asia/Phnom_Penh",
				"title": "FAKE TEST USER",
				"zipCode": "22899",
			},
			"credentials": {
				"emails": [{
					"status": "VERIFIED",
					"type": "PRIMARY",
					"value": "kneal@example.com",
				}],
				"provider": {
					"name": "OKTA",
					"type": "OKTA",
				},
			},
			"_links": {"self": {"href": "https://dev-36468868.okta.com/api/v1/users/00u5gzkdmzIgvqo705d7"}},
			"_embedded": null,
		},
	],
	"groups": [{
		"_embedded": null,
		"_links": {
			"apps": {"href": "https://dev-36468868.okta.com/api/v1/groups/00g5h3ops7yvVzesh5d7/apps"},
			"logo": [
				{
					"href": "https://ok12static.oktacdn.com/assets/img/logos/groups/odyssey/okta-medium.1a5ebe44c4244fb796c235d86b47e3bb.png",
					"name": "medium",
					"type": "image/png",
				},
				{
					"href": "https://ok12static.oktacdn.com/assets/img/logos/groups/odyssey/okta-large.d9cfbd8a00a4feac1aa5612ba02e99c0.png",
					"name": "large",
					"type": "image/png",
				},
			],
			"users": {"href": "https://dev-36468868.okta.com/api/v1/groups/00g5h3ops7yvVzesh5d7/users"},
		},
		"created": "2022-06-22T21:10:04.000Z",
		"id": "00g5h3ops7yvVzesh5d7",
		"lastMembershipUpdated": "2022-06-22T21:10:29.000Z",
		"lastUpdated": "2022-06-22T21:10:04.000Z",
		"objectClass": ["okta:user_group"],
		"profile": {
			"description": null,
			"name": "test1",
		},
		"type": "OKTA_GROUP",
	}],
	"roles": [{
		"_embedded": null,
		"_links": {
			"permissions": {"href": "https://dev-36468868-admin.okta.com/api/v1/iam/roles/cr05vv3tpccc6WbKH5d7/permissions"},
			"self": {"href": "https://dev-36468868-admin.okta.com/api/v1/iam/roles/cr05vv3tpccc6WbKH5d7"},
		},
		"created": "2022-07-22T16:04:30.000Z",
		"id": "cr05vv3tpccc6WbKH5d7",
		"label": "testrole1",
		"lastUpdated": "2022-07-22T16:04:30.000Z",
		"status": "",
		"type": "",
		"resource-set": "",
	}],
}

expected_output_raw := {
	"groups": {"00g5h3ops7yvVzesh5d7": {"users": {
		"00u5gzjgk6uHO7Mhr5d7",
		"00u5gzkdmzIgvqo705d7",
	}}},
	"resources": {
		"0oa3jvzgfqVELvozl5d7": {
			"_embedded": null,
			"_links": {
				"appLinks": [{
					"href": "https://dev-36468868.okta.com/home/saasure/0oa3jvzgfqVELvozl5d7/2",
					"name": "admin",
					"type": "text/html",
				}],
				"deactivate": {"href": "https://dev-36468868.okta.com/api/v1/apps/0oa3jvzgfqVELvozl5d7/lifecycle/deactivate"},
				"groups": {"href": "https://dev-36468868.okta.com/api/v1/apps/0oa3jvzgfqVELvozl5d7/groups"},
				"logo": [{
					"href": "https://ok12static.oktacdn.com/assets/img/logos/okta_admin_app.da3325676d57eaf566cb786dd0c7a819.png",
					"name": "medium",
					"type": "image/png",
				}],
				"uploadLogo": {
					"hints": {"allow": ["POST"]},
					"href": "https://dev-36468868.okta.com/api/v1/apps/0oa3jvzgfqVELvozl5d7/logo",
				},
				"users": {"href": "https://dev-36468868.okta.com/api/v1/apps/0oa3jvzgfqVELvozl5d7/users"},
			},
			"accessibility": {
				"errorRedirectUrl": null,
				"loginRedirectUrl": null,
				"selfService": false,
			},
			"created": "2022-01-10T19:45:00.000Z",
			"credentials": {
				"signing": {"kid": "Aeyg4LnK2K6uE5rr_gtETViAiOWPqXHmQgQo_IUluBI"},
				"userNameTemplate": {
					"template": "${source.login}",
					"type": "BUILT_IN",
				},
			},
			"features": [],
			"id": "0oa3jvzgfqVELvozl5d7",
			"label": "Okta Admin Console",
			"lastUpdated": "2022-01-10T19:45:01.000Z",
			"name": "saasure",
			"profile": null,
			"request_object_signing_alg": "",
			"settings": {
				"app": {},
				"notifications": {"vpn": {
					"helpUrl": null,
					"message": null,
					"network": {"connection": "DISABLED"},
				}},
			},
			"signOnMode": "OPENID_CONNECT",
			"status": "ACTIVE",
			"visibility": {
				"appLinks": {"admin": true},
				"autoSubmitToolbar": false,
				"hide": {
					"iOS": false,
					"web": false,
				},
			},
		},
		"0oa3jvzgkbNA6SYEC5d7": {
			"_embedded": null,
			"_links": {
				"appLinks": [],
				"deactivate": {"href": "https://dev-36468868.okta.com/api/v1/apps/0oa3jvzgkbNA6SYEC5d7/lifecycle/deactivate"},
				"groups": {"href": "https://dev-36468868.okta.com/api/v1/apps/0oa3jvzgkbNA6SYEC5d7/groups"},
				"logo": [{
					"href": "https://ok12static.oktacdn.com/assets/img/logos/okta-logo-end-user-dashboard.fc6d8fdbcb8cb4c933d009e71456cec6.svg",
					"name": "medium",
					"type": "image/png",
				}],
				"uploadLogo": {
					"hints": {"allow": ["POST"]},
					"href": "https://dev-36468868.okta.com/api/v1/apps/0oa3jvzgkbNA6SYEC5d7/logo",
				},
				"users": {"href": "https://dev-36468868.okta.com/api/v1/apps/0oa3jvzgkbNA6SYEC5d7/users"},
			},
			"accessibility": {
				"errorRedirectUrl": null,
				"loginRedirectUrl": null,
				"selfService": false,
			},
			"created": "2022-01-10T19:45:03.000Z",
			"credentials": {
				"signing": {"kid": "Aeyg4LnK2K6uE5rr_gtETViAiOWPqXHmQgQo_IUluBI"},
				"userNameTemplate": {
					"template": "${source.login}",
					"type": "BUILT_IN",
				},
			},
			"features": [],
			"id": "0oa3jvzgkbNA6SYEC5d7",
			"label": "Okta Dashboard",
			"lastUpdated": "2022-01-10T19:45:03.000Z",
			"name": "okta_enduser",
			"profile": null,
			"request_object_signing_alg": "",
			"settings": {
				"app": {},
				"notifications": {"vpn": {
					"helpUrl": null,
					"message": null,
					"network": {"connection": "DISABLED"},
				}},
			},
			"signOnMode": "OPENID_CONNECT",
			"status": "ACTIVE",
			"visibility": {
				"appLinks": {},
				"autoSubmitToolbar": false,
				"hide": {
					"iOS": false,
					"web": false,
				},
			},
		},
	},
	"roles": {"cr05vv3tpccc6WbKH5d7": {}},
	"users": {
		"00u5gzjgk6uHO7Mhr5d7": {
			"_embedded": null,
			"_links": {"self": {"href": "https://dev-36468868.okta.com/api/v1/users/00u5gzjgk6uHO7Mhr5d7"}},
			"activated": "",
			"created": "2022-06-22T16:50:02.000Z",
			"credentials": {
				"emails": [{
					"status": "VERIFIED",
					"type": "PRIMARY",
					"value": "robertwells@example.net",
				}],
				"provider": {
					"name": "OKTA",
					"type": "OKTA",
				},
			},
			"id": "00u5gzjgk6uHO7Mhr5d7",
			"lastLogin": null,
			"lastUpdated": "2022-06-22T16:50:02.000Z",
			"passwordChanged": null,
			"profile": {
				"city": "Lake Philiphaven",
				"email": "robertwells@example.net",
				"firstName": "Oscar",
				"lastName": "Alvarado",
				"login": "robertwells@example.net",
				"mobilePhone": null,
				"primaryPhone": "+1-403-441-2897x138",
				"secondEmail": null,
				"state": "New York",
				"streetAddress": "416 Brown Village Suite 655",
				"timezone": "Indian/Mahe",
				"title": "FAKE TEST USER",
				"zipCode": "10730",
			},
			"status": "STAGED",
			"statusChanged": null,
			"transitioningToStatus": null,
			"type": {"id": "oty3jvzggclbK159z5d7"},
		},
		"00u5gzkdmzIgvqo705d7": {
			"_embedded": null,
			"_links": {"self": {"href": "https://dev-36468868.okta.com/api/v1/users/00u5gzkdmzIgvqo705d7"}},
			"activated": "",
			"created": "2022-06-22T16:51:19.000Z",
			"credentials": {
				"emails": [{
					"status": "VERIFIED",
					"type": "PRIMARY",
					"value": "kneal@example.com",
				}],
				"provider": {
					"name": "OKTA",
					"type": "OKTA",
				},
			},
			"id": "00u5gzkdmzIgvqo705d7",
			"lastLogin": null,
			"lastUpdated": "2022-06-22T16:51:19.000Z",
			"passwordChanged": null,
			"profile": {
				"city": "Reynoldsfurt",
				"email": "kneal@example.com",
				"firstName": "Peggy",
				"lastName": "Abbott",
				"login": "kneal@example.com",
				"mobilePhone": null,
				"primaryPhone": "+1-871-318-6846x8395",
				"secondEmail": null,
				"state": "Virginia",
				"streetAddress": "4019 Jennifer Keys Apt. 562",
				"timezone": "Asia/Phnom_Penh",
				"title": "FAKE TEST USER",
				"zipCode": "22899",
			},
			"status": "STAGED",
			"statusChanged": null,
			"transitioningToStatus": null,
			"type": {"id": "oty3jvzggclbK159z5d7"},
		},
	},
}

test_okta_raw if {
	actual := okta.okta_raw with input as {"": sample_okta_data}
	print("---- expected")
	print(expected_output_raw)
	print("---- actual")
	print(actual)

	actual == expected_output_raw
}

expected_output_readable := {
	"groups": {"test1": {"users": {
		"kneal@example.com",
		"robertwells@example.net",
	}}},
	"resources": {
		"okta_enduser": {
			"_embedded": null,
			"_links": {
				"appLinks": [],
				"deactivate": {"href": "https://dev-36468868.okta.com/api/v1/apps/0oa3jvzgkbNA6SYEC5d7/lifecycle/deactivate"},
				"groups": {"href": "https://dev-36468868.okta.com/api/v1/apps/0oa3jvzgkbNA6SYEC5d7/groups"},
				"logo": [{
					"href": "https://ok12static.oktacdn.com/assets/img/logos/okta-logo-end-user-dashboard.fc6d8fdbcb8cb4c933d009e71456cec6.svg",
					"name": "medium",
					"type": "image/png",
				}],
				"uploadLogo": {
					"hints": {"allow": ["POST"]},
					"href": "https://dev-36468868.okta.com/api/v1/apps/0oa3jvzgkbNA6SYEC5d7/logo",
				},
				"users": {"href": "https://dev-36468868.okta.com/api/v1/apps/0oa3jvzgkbNA6SYEC5d7/users"},
			},
			"accessibility": {
				"errorRedirectUrl": null,
				"loginRedirectUrl": null,
				"selfService": false,
			},
			"created": "2022-01-10T19:45:03.000Z",
			"credentials": {
				"signing": {"kid": "Aeyg4LnK2K6uE5rr_gtETViAiOWPqXHmQgQo_IUluBI"},
				"userNameTemplate": {
					"template": "${source.login}",
					"type": "BUILT_IN",
				},
			},
			"features": [],
			"id": "0oa3jvzgkbNA6SYEC5d7",
			"label": "Okta Dashboard",
			"lastUpdated": "2022-01-10T19:45:03.000Z",
			"name": "okta_enduser",
			"profile": null,
			"request_object_signing_alg": "",
			"settings": {
				"app": {},
				"notifications": {"vpn": {
					"helpUrl": null,
					"message": null,
					"network": {"connection": "DISABLED"},
				}},
			},
			"signOnMode": "OPENID_CONNECT",
			"status": "ACTIVE",
			"visibility": {
				"appLinks": {},
				"autoSubmitToolbar": false,
				"hide": {
					"iOS": false,
					"web": false,
				},
			},
		},
		"saasure": {
			"_embedded": null,
			"_links": {
				"appLinks": [{
					"href": "https://dev-36468868.okta.com/home/saasure/0oa3jvzgfqVELvozl5d7/2",
					"name": "admin",
					"type": "text/html",
				}],
				"deactivate": {"href": "https://dev-36468868.okta.com/api/v1/apps/0oa3jvzgfqVELvozl5d7/lifecycle/deactivate"},
				"groups": {"href": "https://dev-36468868.okta.com/api/v1/apps/0oa3jvzgfqVELvozl5d7/groups"},
				"logo": [{
					"href": "https://ok12static.oktacdn.com/assets/img/logos/okta_admin_app.da3325676d57eaf566cb786dd0c7a819.png",
					"name": "medium",
					"type": "image/png",
				}],
				"uploadLogo": {
					"hints": {"allow": ["POST"]},
					"href": "https://dev-36468868.okta.com/api/v1/apps/0oa3jvzgfqVELvozl5d7/logo",
				},
				"users": {"href": "https://dev-36468868.okta.com/api/v1/apps/0oa3jvzgfqVELvozl5d7/users"},
			},
			"accessibility": {
				"errorRedirectUrl": null,
				"loginRedirectUrl": null,
				"selfService": false,
			},
			"created": "2022-01-10T19:45:00.000Z",
			"credentials": {
				"signing": {"kid": "Aeyg4LnK2K6uE5rr_gtETViAiOWPqXHmQgQo_IUluBI"},
				"userNameTemplate": {
					"template": "${source.login}",
					"type": "BUILT_IN",
				},
			},
			"features": [],
			"id": "0oa3jvzgfqVELvozl5d7",
			"label": "Okta Admin Console",
			"lastUpdated": "2022-01-10T19:45:01.000Z",
			"name": "saasure",
			"profile": null,
			"request_object_signing_alg": "",
			"settings": {
				"app": {},
				"notifications": {"vpn": {
					"helpUrl": null,
					"message": null,
					"network": {"connection": "DISABLED"},
				}},
			},
			"signOnMode": "OPENID_CONNECT",
			"status": "ACTIVE",
			"visibility": {
				"appLinks": {"admin": true},
				"autoSubmitToolbar": false,
				"hide": {
					"iOS": false,
					"web": false,
				},
			},
		},
	},
	"roles": {"cr05vv3tpccc6WbKH5d7": {}},
	"users": {
		"kneal@example.com": {
			"_embedded": null,
			"_links": {"self": {"href": "https://dev-36468868.okta.com/api/v1/users/00u5gzkdmzIgvqo705d7"}},
			"activated": "",
			"created": "2022-06-22T16:51:19.000Z",
			"credentials": {
				"emails": [{
					"status": "VERIFIED",
					"type": "PRIMARY",
					"value": "kneal@example.com",
				}],
				"provider": {
					"name": "OKTA",
					"type": "OKTA",
				},
			},
			"id": "00u5gzkdmzIgvqo705d7",
			"lastLogin": null,
			"lastUpdated": "2022-06-22T16:51:19.000Z",
			"passwordChanged": null,
			"profile": {
				"city": "Reynoldsfurt",
				"email": "kneal@example.com",
				"firstName": "Peggy",
				"lastName": "Abbott",
				"login": "kneal@example.com",
				"mobilePhone": null,
				"primaryPhone": "+1-871-318-6846x8395",
				"secondEmail": null,
				"state": "Virginia",
				"streetAddress": "4019 Jennifer Keys Apt. 562",
				"timezone": "Asia/Phnom_Penh",
				"title": "FAKE TEST USER",
				"zipCode": "22899",
			},
			"status": "STAGED",
			"statusChanged": null,
			"transitioningToStatus": null,
			"type": {"id": "oty3jvzggclbK159z5d7"},
		},
		"robertwells@example.net": {
			"_embedded": null,
			"_links": {"self": {"href": "https://dev-36468868.okta.com/api/v1/users/00u5gzjgk6uHO7Mhr5d7"}},
			"activated": "",
			"created": "2022-06-22T16:50:02.000Z",
			"credentials": {
				"emails": [{
					"status": "VERIFIED",
					"type": "PRIMARY",
					"value": "robertwells@example.net",
				}],
				"provider": {
					"name": "OKTA",
					"type": "OKTA",
				},
			},
			"id": "00u5gzjgk6uHO7Mhr5d7",
			"lastLogin": null,
			"lastUpdated": "2022-06-22T16:50:02.000Z",
			"passwordChanged": null,
			"profile": {
				"city": "Lake Philiphaven",
				"email": "robertwells@example.net",
				"firstName": "Oscar",
				"lastName": "Alvarado",
				"login": "robertwells@example.net",
				"mobilePhone": null,
				"primaryPhone": "+1-403-441-2897x138",
				"secondEmail": null,
				"state": "New York",
				"streetAddress": "416 Brown Village Suite 655",
				"timezone": "Indian/Mahe",
				"title": "FAKE TEST USER",
				"zipCode": "10730",
			},
			"status": "STAGED",
			"statusChanged": null,
			"transitioningToStatus": null,
			"type": {"id": "oty3jvzggclbK159z5d7"},
		},
	},
}

test_okta_readable if {
	actual := okta.okta_readable with input as {"": sample_okta_data}
	print("---- expected")
	print(expected_output_readable)
	print("---- actual")
	print(actual)

	actual == expected_output_readable
}
