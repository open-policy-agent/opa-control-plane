package global.systemtypes["entitlements:1.0"].library.transform.openapi.test_v1

import rego.v1
import data.global.systemtypes["entitlements:1.0"].library.transform.openapi.v1 as openapi

test_openapi_resources_v2 if {
	doc := {
		"swagger": "2.0",
		"info": {
			"description": "Test data",
			"title": "Test data",
			"termsOfService": "xxx",
			"contact": {"email": "support@local"},
			"license": {
				"name": "Apache 2.0",
				"url": "https://www.apache.org/licenses/LICENSE-2.0.html",
			},
			"version": "2.0.0",
		},
		"paths": {
			"/foo": {"get": {}},
			"/foo/bar": {
				"get": {},
				"post": {},
			},
			"/foo/bar/{id}": {
				"get": {},
				"post": {},
			},
		},
	}

	expected := {
		"/foo": {"get": {}},
		"/foo/bar": {
			"get": {},
			"post": {},
		},
		"/foo/bar/*": {
			"_variables": {3: "id"},
			"get": {},
			"post": {},
		},
	}

	got := openapi.openapi_resources with input as doc

	got == expected
}

test_openapi_resources_v3 if {
	doc := {
		"openapi": "3.0",
		"paths": {"/foo/bar/{id}": {
			"get": {},
			"post": {},
		}},
	}

	expected := {"/foo/bar/*": {
		"_variables": {3: "id"},
		"get": {},
		"post": {},
	}}

	got := openapi.openapi_resources with input as doc

	got == expected
}

test_replace_path_templates_with_globs if {
	tests := [
		{
			"input": "/foo/bar",
			"path": "/foo/bar",
			"variable": {},
		},
		{
			"input": "/foo/{bar}",
			"path": "/foo/*",
			"variable": {2: "bar"},
		},
		{
			"input": "/foo/{bar}/baz/{maz}",
			"path": "/foo/*/baz/*",
			"variable": {2: "bar", 4: "maz"},
		},
		{
			"input": "/{foo}/{bar}/{baz}",
			"path": "/*/*/*",
			"variable": {1: "foo", 2: "bar", 3: "baz"},
		},
	]

	results := [got |
		got := openapi.replace_path_templates_with_globs(tests[i].input)
		tests[i].path == got.path
		tests[i].variable == got.variables
	]

	count(results) == count(tests)
}
