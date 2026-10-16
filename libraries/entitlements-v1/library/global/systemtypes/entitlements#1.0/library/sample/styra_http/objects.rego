package global.systemtypes["entitlements:1.0"].library.sample.styra_http

import rego.v1

input_request := {
	"action": "create",
	"context": {
		"channel": "API-MOBILE-BROWSER",
		"location": "China",
	},
	"resource": "resource-id",
	"subject": "subject-id",
}

# Permissions

role_bindings := {
	"SystemPolicyEditor": {"subjects": {"ids": ["alice", "bob", "platform-team"]}},
	"WorkspaceAdmin": {"subjects": {"ids": ["admin-team"]}},
	"DenySystemConfigModification": {"subjects": {"ids": ["bob"]}},
}

roles := {
	"WorkspaceAdmin": {"allow": {"include": [{
		"actions": ["*"],
		"resources": ["**"],
	}]}},
	"SystemPolicyEditor": {"allow": {"include": [
		{
			"actions": ["*"],
			"resources": ["System.Policies"],
		},
		{
			"actions": ["read"],
			"resources": ["System.Authz", "System.Configuration", "System.Datasources", "System.Eval", "System.LogReplay", "System.Suggestions", "System.Validate"],
		},
	]}},
	"DenySystemConfigModification": {"deny": {"include": [{
		"actions": ["update", "delete"],
		"resources": ["System.Configuration"],
	}]}},
}

# Subjects

users := {
	"alice": {"name": "Alice"},
	"bob": {"name": "Bob"},
	"cheng": {"name": "cheng"},
	"diya": {"name": "Diya"},
	"eric": {"name": "Eric"},
}

groups := {
	"admin-team": {"users": ["bob", "diya"]},
	"platform-team": {"users": ["cheng", "eric"]},
}

# Resources

actions := [
	"GET",
	"POST",
	"PUT",
	"PATCH",
	"DELETE",
]

resources := {r: {} | openapi.paths[r]}

openapi := {
	"swagger": "2.0",
	"info": {
		"description": "Styra DAS is entirely API-driven.\n\nAccess to the APIs requires authentication that should be provided as an Authorization HTTP header including a Styra DAS-issued token:\n\n`Authorization: Bearer <YOURTOKENHERE>`\n\nTo request a token you need to have an Styra account, and create a token via the API Tokens menu.",
		"title": "Styra API",
		"termsOfService": "https://doc-policies.s3-us-west-2.amazonaws.com/terms.html",
		"contact": {"email": "support@styra.com"},
		"license": {
			"name": "Apache 2.0",
			"url": "http://www.apache.org/licenses/LICENSE-2.0.html",
		},
		"version": "1.0.0",
	},
	"paths": {
		"/v1/activity": {"post": {
			"description": "At most 256 entries returned per request. If only start_time or end_time is provided by the caller then the request defaults to 1 hour range",
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["activity"],
			"summary": "Retrieve activity log",
			"operationId": "HandleActivity",
			"parameters": [{
				"name": "body",
				"in": "body",
				"required": true,
				"schema": {"$ref": "#/definitions/v1.ActivityPostRequest"},
			}],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.ActivityPostResponse"},
				},
				"400": {
					"description": "Invalid Parameter",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/agents/{kind}": {"get": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["agents"],
			"summary": "Get current agent statuses",
			"operationId": "GetAgentStatuses",
			"parameters": [
				{
					"type": "string",
					"description": "agent kind such as \"agents\", \"datasources\", \"slps\"",
					"name": "kind",
					"in": "path",
					"required": true,
				},
				{
					"type": "string",
					"description": "return only statuses for one or more system ID",
					"name": "system",
					"in": "query",
				},
				{
					"type": "string",
					"description": "return only statuses for one or more agent ID",
					"name": "id",
					"in": "query",
				},
			],
			"responses": {"200": {
				"description": "OK",
				"schema": {"$ref": "#/definitions/v1.StatusGetResponse"},
			}},
		}},
		"/v1/agents/{kind}/status": {"post": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["agents"],
			"summary": "Post agent status",
			"operationId": "PostAgentStatus",
			"parameters": [{
				"type": "string",
				"description": "agent kind such as \"agents\", \"datasources\", \"slps\"",
				"name": "kind",
				"in": "path",
				"required": true,
			}],
			"responses": {"200": {
				"description": "OK",
				"schema": {"$ref": "#/definitions/v1.StatusPostResponse"},
			}},
		}},
		"/v1/agents/{kind}/{id}": {"delete": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["agents"],
			"summary": "Delete agent information",
			"operationId": "DeleteAgentInfo",
			"parameters": [
				{
					"type": "string",
					"description": "agent kind such as \"agents\", \"datasources\", \"slps\"",
					"name": "kind",
					"in": "path",
					"required": true,
				},
				{
					"pattern": ".*",
					"type": "string",
					"description": "agent id",
					"name": "id",
					"in": "path",
					"required": true,
				},
			],
			"responses": {"200": {
				"description": "OK",
				"schema": {"$ref": "#/definitions/v1.DeleteAgentResponse"},
			}},
		}},
		"/v1/agents/{kind}/{id}/status": {"put": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["agents"],
			"summary": "Update agent status",
			"operationId": "UpdateAgentStatus",
			"parameters": [
				{
					"type": "string",
					"description": "agent kind such as \"agents\", \"datasources\", \"slps\"",
					"name": "kind",
					"in": "path",
					"required": true,
				},
				{
					"pattern": ".*",
					"type": "string",
					"description": "agent id",
					"name": "id",
					"in": "path",
					"required": true,
				},
			],
			"responses": {"200": {
				"description": "OK",
				"schema": {"$ref": "#/definitions/v1.StatusPostResponse"},
			}},
		}},
		"/v1/authz/evaluation": {"post": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["authz"],
			"summary": "Evaluate a list of permissions",
			"operationId": "CheckPermissions",
			"parameters": [{
				"name": "body",
				"in": "body",
				"required": true,
				"schema": {
					"type": "array",
					"items": {"$ref": "#/definitions/v1.CheckPermissionInput"},
				},
			}],
			"responses": {"200": {
				"description": "OK",
				"schema": {"$ref": "#/definitions/v1.CheckPermissionsPostResponse"},
			}},
		}},
		"/v1/authz/rolebindings": {"get": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["authz"],
			"summary": "List all role bindings for all resources of all resource types",
			"operationId": "ListAllRoleBindings",
			"responses": {"200": {
				"description": "OK",
				"schema": {"$ref": "#/definitions/v1.RoleBindingsListAllResponse"},
			}},
		}},
		"/v1/authz/rolebindings/{resourcetype}/{resource}": {"get": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["authz"],
			"summary": "List role bindings",
			"operationId": "ListRoleBindings.v1",
			"parameters": [
				{
					"pattern": ".*",
					"type": "string",
					"description": "resource type",
					"name": "resourcetype",
					"in": "path",
					"required": true,
				},
				{
					"pattern": ".*",
					"type": "string",
					"description": "resource id",
					"name": "resource",
					"in": "path",
					"required": true,
				},
			],
			"responses": {"200": {
				"description": "OK",
				"schema": {"$ref": "#/definitions/v1.RoleBindingsListResponse"},
			}},
		}},
		"/v1/authz/rolebindings/{resourcetype}/{resource}/{rolebinding}": {
			"get": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["authz"],
				"summary": "Get a role binding",
				"operationId": "GetRoleBinding.v1",
				"parameters": [
					{
						"pattern": ".*",
						"type": "string",
						"description": "resource type",
						"name": "resourcetype",
						"in": "path",
						"required": true,
					},
					{
						"pattern": ".*",
						"type": "string",
						"description": "resource id",
						"name": "resource",
						"in": "path",
						"required": true,
					},
					{
						"pattern": ".*",
						"type": "string",
						"description": "role binding id",
						"name": "rolebinding",
						"in": "path",
						"required": true,
					},
				],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.RoleBindingsGetResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"put": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["authz"],
				"summary": "Update a role binding",
				"operationId": "UpdateRoleBinding",
				"parameters": [
					{
						"pattern": ".*",
						"type": "string",
						"description": "resource type",
						"name": "resourcetype",
						"in": "path",
						"required": true,
					},
					{
						"pattern": ".*",
						"type": "string",
						"description": "resource id",
						"name": "resource",
						"in": "path",
						"required": true,
					},
					{
						"pattern": ".*",
						"type": "string",
						"description": "role binding id",
						"name": "rolebinding",
						"in": "path",
						"required": true,
					},
					{
						"name": "body",
						"in": "body",
						"required": true,
						"schema": {"$ref": "#/definitions/v1.RoleBindingsPutRequest"},
					},
				],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.RoleBindingsPutResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"delete": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["authz"],
				"summary": "Delete a resource role binding",
				"operationId": "DeleteRoleBinding.v1",
				"parameters": [
					{
						"pattern": ".*",
						"type": "string",
						"description": "resource type",
						"name": "resourcetype",
						"in": "path",
						"required": true,
					},
					{
						"pattern": ".*",
						"type": "string",
						"description": "resource id",
						"name": "resource",
						"in": "path",
						"required": true,
					},
					{
						"pattern": ".*",
						"type": "string",
						"description": "role binding id",
						"name": "rolebinding",
						"in": "path",
						"required": true,
					},
					{
						"type": "string",
						"description": "if set to 'false', only deletes the role binding configuration and does not delete associated objects",
						"name": "recursive",
						"in": "query",
					},
				],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.RoleBindingsDeleteResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
		},
		"/v1/authz/roles": {"get": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["authz"],
			"summary": "List Styra-defined roles",
			"operationId": "ListRoles.v1",
			"responses": {"200": {
				"description": "OK",
				"schema": {"$ref": "#/definitions/v1.RolesListResponse"},
			}},
		}},
		"/v1/bundles": {"get": {
			"produces": [
				"application/gzip",
				"application/json",
			],
			"tags": ["bundles"],
			"summary": "Get a policy bundle",
			"operationId": "GetPolicyBundle1",
			"parameters": [
				{
					"type": "string",
					"description": "policy name",
					"name": "policy",
					"in": "query",
				},
				{
					"type": "string",
					"description": "path to partial evaluation",
					"name": "eval_path",
					"in": "query",
				},
				{
					"type": "string",
					"description": "etag",
					"name": "If-None-Match",
					"in": "header",
				},
			],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {
						"type": "array",
						"items": {"type": "integer"},
					},
				},
				"304": {"description": "Not Modified"},
			},
		}},
		"/v1/bundles/{policy}": {"get": {
			"produces": [
				"application/gzip",
				"application/json",
			],
			"tags": ["bundles"],
			"summary": "Get a policy bundle",
			"operationId": "GetPolicyBundle2",
			"parameters": [
				{
					"pattern": ".*",
					"type": "string",
					"description": "policy name",
					"name": "policy",
					"in": "path",
					"required": true,
				},
				{
					"type": "string",
					"description": "path to partial evaluation",
					"name": "eval_path",
					"in": "query",
				},
				{
					"type": "string",
					"description": "etag",
					"name": "If-None-Match",
					"in": "header",
				},
			],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {
						"type": "array",
						"items": {"type": "integer"},
					},
				},
				"304": {"description": "Not Modified"},
				"404": {
					"description": "Not Found",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/data": {
			"get": {
				"description": "Data (whether the result of evaluating policy or the data gathered by datasources) is arranged into a tree.  List the locations within the tree that data exists.",
				"consumes": [
					"application/json",
					"text/plain",
				],
				"produces": ["application/json"],
				"tags": ["data"],
				"summary": "List data",
				"operationId": "ListData",
				"parameters": [
					{
						"type": "string",
						"description": "rego query",
						"name": "rego",
						"in": "query",
					},
					{
						"type": "string",
						"description": "JSON path",
						"name": "jsonpath",
						"in": "query",
					},
				],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.DataResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"post": {
				"consumes": [
					"application/json",
					"text/plain",
				],
				"produces": ["application/json"],
				"tags": ["data"],
				"summary": "Show all data",
				"operationId": "ShowAllData",
				"parameters": [{
					"name": "body",
					"in": "body",
					"required": true,
					"schema": {"$ref": "#/definitions/v1.DataRequest"},
				}],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.DataResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
		},
		"/v1/data/{name}": {
			"get": {
				"description": "Show data at the given `name`.  `name` must be an extension of one of the locations of data as returned by `GET v1/data`",
				"consumes": [
					"application/json",
					"text/plain",
				],
				"produces": ["application/json"],
				"tags": ["data"],
				"summary": "Get data",
				"operationId": "GetData",
				"parameters": [
					{
						"pattern": ".*",
						"type": "string",
						"description": "data name",
						"name": "name",
						"in": "path",
						"required": true,
					},
					{
						"type": "string",
						"description": "rego query",
						"name": "rego",
						"in": "query",
					},
					{
						"type": "string",
						"description": "JSON path",
						"name": "jsonpath",
						"in": "query",
					},
				],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.DataResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"put": {
				"description": "Set the data for the datasource registered at `<name>` to an arbitrary JSON document.  This data can be read by doing `GET v1/data/<path>`",
				"consumes": [
					"application/json",
					"application/octet-stream",
					"application/vnd.styra.push+json",
				],
				"produces": ["application/json"],
				"tags": ["data"],
				"summary": "Publish data",
				"operationId": "PutData",
				"parameters": [
					{
						"pattern": ".*",
						"type": "string",
						"description": "data name",
						"name": "name",
						"in": "path",
						"required": true,
					},
					{
						"type": "string",
						"description": "etag",
						"name": "If-Match",
						"in": "header",
					},
				],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.DataPutResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"post": {
				"description": "Show data at the given `name`.  `name` must be an extension of one of the locations of data as returned by `GET v1/data`.  ",
				"consumes": [
					"application/json",
					"text/plain",
				],
				"produces": ["application/json"],
				"tags": ["data"],
				"summary": "Show data",
				"operationId": "ShowData",
				"parameters": [
					{
						"name": "body",
						"in": "body",
						"required": true,
						"schema": {"$ref": "#/definitions/v1.DataRequest"},
					},
					{
						"pattern": ".*",
						"type": "string",
						"description": "data name",
						"name": "name",
						"in": "path",
						"required": true,
					},
				],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.DataResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"patch": {
				"description": "Modify the data of the push datasource registered at `<path>` by applying a JSON patch to the JSON document. The content type for the patch is `application/json-patch+json`. The operation returns the modified data.",
				"consumes": [
					"application/json-patch+json",
					"application/vnd.styra.patch+json",
				],
				"produces": ["application/json"],
				"tags": ["data"],
				"summary": "Patch data",
				"operationId": "PatchData",
				"parameters": [
					{
						"pattern": ".*",
						"type": "string",
						"description": "data name",
						"name": "name",
						"in": "path",
						"required": true,
					},
					{
						"type": "string",
						"description": "etag",
						"name": "If-Match",
						"in": "header",
					},
				],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.DataPatchResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
		},
		"/v1/datasources": {"get": {
			"produces": ["application/json"],
			"tags": ["datasources"],
			"summary": "List datasources",
			"operationId": "ListDatasources",
			"responses": {"200": {
				"description": "OK",
				"schema": {"$ref": "#/definitions/v1.DatasourcesListResponse"},
			}},
		}},
		"/v1/datasources/{datasource}": {
			"get": {
				"produces": ["application/json"],
				"tags": ["datasources"],
				"summary": "Get a datasource",
				"operationId": "GetDatasource",
				"parameters": [
					{
						"pattern": ".*",
						"type": "string",
						"description": "datasource name",
						"name": "datasource",
						"in": "path",
						"required": true,
					},
					{
						"type": "boolean",
						"description": "execute datasource",
						"name": "execute",
						"in": "query",
					},
				],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.DatasourcesGetResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"put": {
				"produces": ["application/json"],
				"tags": ["datasources"],
				"summary": "Upsert a datasource",
				"operationId": "UpsertDatasource",
				"parameters": [
					{
						"name": "body",
						"in": "body",
						"required": true,
						"schema": {"$ref": "#/definitions/v1.DatasourcesPutRequest"},
					},
					{
						"pattern": ".*",
						"type": "string",
						"description": "datasource name",
						"name": "datasource",
						"in": "path",
						"required": true,
					},
					{
						"type": "string",
						"description": "etag",
						"name": "If-None-Match",
						"in": "header",
					},
				],
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.DatasourcesPutResponse"},
				}},
			},
			"post": {
				"produces": ["application/json"],
				"tags": ["datasources"],
				"summary": "Execute a datasource",
				"operationId": "ExecuteDatasource",
				"parameters": [
					{
						"name": "body",
						"in": "body",
						"required": true,
						"schema": {"$ref": "#/definitions/v1.DatasourcesPutRequest"},
					},
					{
						"pattern": ".*",
						"type": "string",
						"description": "datasource name",
						"name": "datasource",
						"in": "path",
						"required": true,
					},
					{
						"type": "boolean",
						"description": "execute datasource",
						"name": "execute",
						"in": "query",
					},
					{
						"type": "boolean",
						"description": "preview datasource",
						"name": "preview",
						"in": "query",
					},
				],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.DatasourcesPostResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"delete": {
				"produces": ["application/json"],
				"tags": ["datasources"],
				"summary": "Delete a datasource",
				"operationId": "DeleteDatasource",
				"parameters": [{
					"pattern": ".*",
					"type": "string",
					"description": "datasource name",
					"name": "datasource",
					"in": "path",
					"required": true,
				}],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.DatasourcesDeleteResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
		},
		"/v1/decisions": {
			"get": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["decisions"],
				"summary": "Search decision logs",
				"operationId": "SearchDecisionLogsGet",
				"parameters": [
					{
						"type": "string",
						"description": "continue from cursor position of previous query",
						"name": "cursor",
						"in": "query",
					},
					{
						"type": "string",
						"description": "minimum decision time",
						"name": "start_time",
						"in": "query",
					},
					{
						"type": "string",
						"description": "maximum decision time",
						"name": "end_time",
						"in": "query",
					},
					{
						"type": "string",
						"description": "search query",
						"name": "search",
						"in": "query",
					},
					{
						"type": "string",
						"description": "system ID",
						"name": "system",
						"in": "query",
					},
					{
						"type": "string",
						"description": "stack ID",
						"name": "stack",
						"in": "query",
					},
					{
						"type": "integer",
						"description": "maximum number of decisions to return",
						"name": "limit",
						"in": "query",
					},
					{
						"type": "string",
						"description": "comma-separated list of ALL, UNKNOWN, ADVICE, ALLOWED, DENIED, ERROR",
						"name": "result_kind",
						"in": "query",
					},
					{
						"type": "string",
						"description": "ASC, DESC (default)",
						"name": "order",
						"in": "query",
					},
					{
						"type": "string",
						"description": "client time zone offset e.g. -07:00, +3:00, Z. Local time expressions in query are adjusted with this offset",
						"name": "default_timezone",
						"in": "query",
					},
					{
						"type": "boolean",
						"description": "return only essential decision fields",
						"name": "compact",
						"in": "query",
					},
				],
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.DecisionsResponse"},
				}},
			},
			"post": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["decisions"],
				"summary": "Search decision logs",
				"operationId": "SearchDecisionLogsPost",
				"parameters": [{
					"name": "body",
					"in": "body",
					"required": true,
					"schema": {"$ref": "#/definitions/v1.DecisionsGetRequest"},
				}],
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.DecisionsResponse"},
				}},
			},
		},
		"/v1/decisions/{cursor}": {"get": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["decisions"],
			"summary": "Get a single decision",
			"operationId": "GetDecision",
			"parameters": [{
				"type": "string",
				"description": "decision cursor value",
				"name": "cursor",
				"in": "path",
				"required": true,
			}],
			"responses": {"200": {
				"description": "OK",
				"schema": {"$ref": "#/definitions/v1.DecisionResponse"},
			}},
		}},
		"/v1/docs": {"get": {
			"consumes": ["application/json"],
			"produces": ["application/xml"],
			"tags": ["docs"],
			"summary": "Get documentation index",
			"operationId": "GetDocsIndex",
			"responses": {"200": {"description": "OK"}},
		}},
		"/v1/docs/{path}": {"get": {
			"consumes": ["application/json"],
			"produces": ["application/xml"],
			"tags": ["docs"],
			"summary": "Get documentation",
			"operationId": "GetDocs",
			"parameters": [{
				"pattern": ".*",
				"type": "string",
				"description": "path",
				"name": "path",
				"in": "path",
				"required": true,
			}],
			"responses": {
				"200": {"description": "OK"},
				"404": {
					"description": "Not Found",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/identity-providers": {
			"get": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["identity-providers"],
				"summary": "List providers",
				"operationId": "ListProviders",
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.ProvidersListResponse"},
				}},
			},
			"post": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["identity-providers"],
				"summary": "Create provider",
				"operationId": "CreateProvider",
				"parameters": [{
					"name": "body",
					"in": "body",
					"required": true,
					"schema": {"$ref": "#/definitions/v1.ProvidersPostRequest"},
				}],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.ProvidersPostResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
		},
		"/v1/identity-providers/{providerId}": {
			"get": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["identity-providers"],
				"summary": "Get provider",
				"operationId": "GetProvider",
				"parameters": [{
					"pattern": ".+",
					"type": "string",
					"description": "provider ID",
					"name": "providerId",
					"in": "path",
					"required": true,
				}],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.ProvidersGetResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"put": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["identity-providers"],
				"summary": "Create or update provider",
				"operationId": "UpdateProvider",
				"parameters": [
					{
						"name": "body",
						"in": "body",
						"required": true,
						"schema": {"$ref": "#/definitions/v1.ProvidersPutRequest"},
					},
					{
						"pattern": ".+",
						"type": "string",
						"description": "provider ID",
						"name": "providerId",
						"in": "path",
						"required": true,
					},
					{
						"type": "string",
						"description": "if set to '*' then creates a new provider with type-specific related objects",
						"name": "If-None-Match",
						"in": "header",
					},
				],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.ProvidersPutResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"delete": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["identity-providers"],
				"summary": "Delete provider",
				"operationId": "DeleteProvider",
				"parameters": [{
					"pattern": ".+",
					"type": "string",
					"description": "provider ID",
					"name": "providerId",
					"in": "path",
					"required": true,
				}],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.ProvidersDeleteResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
		},
		"/v1/invitations": {
			"get": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["invitations"],
				"summary": "List invitations",
				"operationId": "ListInvitations",
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.InvitationsListResponse"},
				}},
			},
			"post": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["invitations"],
				"summary": "Invite user",
				"operationId": "Create invitation",
				"parameters": [
					{
						"name": "body",
						"in": "body",
						"required": true,
						"schema": {"$ref": "#/definitions/v1.InvitationsPostRequest"},
					},
					{
						"type": "boolean",
						"description": "set to false to avoid sending an email",
						"name": "email",
						"in": "query",
					},
				],
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.InvitationsPostResponse"},
				}},
			},
		},
		"/v1/invitations/{id}": {
			"get": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["invitations"],
				"summary": "Get invitation",
				"operationId": "GetInvitation",
				"parameters": [{
					"pattern": ".+",
					"type": "string",
					"description": "user ID",
					"name": "id",
					"in": "path",
					"required": true,
				}],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.InvitationsGetResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"delete": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["invitations"],
				"summary": "Revoke invitation",
				"operationId": "RevokeInvitation",
				"parameters": [{
					"pattern": ".+",
					"type": "string",
					"description": "user ID",
					"name": "id",
					"in": "path",
					"required": true,
				}],
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.InvitationsDeleteResponse"},
				}},
			},
		},
		"/v1/invitations/{token}": {"put": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["invitations"],
			"summary": "Accept invitation",
			"operationId": "AcceptInvitation",
			"parameters": [
				{
					"name": "body",
					"in": "body",
					"required": true,
					"schema": {"$ref": "#/definitions/v1.InvitationsPutRequest"},
				},
				{
					"pattern": ".+",
					"type": "string",
					"description": "token from the invitation URL",
					"name": "token",
					"in": "path",
					"required": true,
				},
			],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.InvitationsPutResponse"},
				},
				"404": {
					"description": "Not Found",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/logreplay": {"post": {
			"description": "# log-replay\n\n`log-replay` is a service that re-evaluates past decision logs in order to estimate what would change if one of the policies\nwould be different. `log-replay` is used as an analysis tool to analyze the impact of a policy change.\n\n\n## API\n\nThe service has only one API call to run decision logs re-evaluation:\n\n`POST /v1/logreplay`\n\n### Request\n\n```json\n{\n    \"duration\": \"10s\",\n    \"max_samples\": 5,\n    \"skip_batches\": [\n      \"boicesr68fj0\",\n      \"boiceye3aeew\"\n    ],\n    \"policies\": {\n      \"httpapi/authz\": \"package httpapi.authz\\n # rego policy contents\"\n    },\n    \"data_patches\": [\n      [\n        {\"op\":  \"add\", \"path\": \"/mydata/value\", \"value\": \"something\"}\n      ]\n    ],\n    \"scope\": [\n      {\"path\": \"httpapi/authz/allow\"}\n    ]\n}\n``` \n\n`duration` specifies the total time the analyzer spends on evaluations. If the value is omitted or less than zero then\n`DefaultReplayDuration` is used instead. If the value exceeds `MaxReplayDuration`, then it is suppressed.\n\n`max_samples` is the maximum number of representative change samples to return. The value is limited to `MaxSamples` and defaults to `DefaultSamples`.\n\n`skip_batches` is an optional list of batch IDs to skip (obtained from `analyzed_batches` attribute of previous replay run).\n\n`policies` tells `log-replay` which policies to alter in the form of path to payload map. \n`log-replay` will re-evaluate any decision log that can be affected by any change in these policies. \n\n`data_patches` is an optional list of atomic JSON-patches to be applied to the data prior to evaluation. The data changes without any policy modifications (empty `policies` map) are accepted. However, at least one of `policies` or `data_patches` must be present.\n\n`decision_patches` is an optional list of atomic JSON-patches to be applied to the decision JSONs as a whole (sic!) before it is replayed. It can be used to compensate values stripped by the mask policy or just inject sample data into the inputs.\n\n`compare_full_results`: do not compare decisions by system-type-dependent significant fields (default: `false`).\n\n`deterministic_policies`: signals that decisions having the same inputs, data and revision always evaluate to the same \nresult and therefore can be cached (default: `true`).\n\n`scope` allows filtering of analyzed log decisions. It is a list of documents, each can have any of the following attributes:    \n* `path`: \n    * if the decision log path is prefixed by this value, then it will be considered for re-evaluation.\n    * if the decision log path is a prefix of this value (for example, scope.path = `policy/allow` and log.path = `scope`), then it is assumed that the decision log result is narrowed to the specified subpath (`/allow` as shown in `policy/allow`).\n    * if non of above is true then the decision log will be ignored\n* `max_revisions`: only consider last `max_revisions` revisions of the policy (for example, in range `[current - max_revisions .. current]`).\n* `max_age`: only consider decision logs that are not older than this parameter. It can be specified either in relative (for example, \"30s\") or absolute time (RFC3339Nano) formats.\n* `min_age`: only consider decision logs that are not newer than this parameter. It can be specified either in relative (for example, \"30s\") or absolute time (RFC3339Nano) formats.\n\nIf `scope` list is empty then any decision log is considered for re-evaluation. The same effect can be achieved with the `[{}]` list.\n\n\n### Response\n```json\n{\n    \"result\": {\n        \"started\": \"2018-11-26T19:59:28.879307Z\",\n        \"samples\": [{\n            \"labels\": {\n                \"hostname\": \"8508d25dc62c\"\n            },\n            \"type\": \"agent\",\n            \"name\": \"16b93fad-c221-4d67-a44f-a1aa90f7a099\",\n            \"agent_id\": \"16b93fad-c221-4d67-a44f-a1aa90f7a099\",\n            \"timestamp\": \"2018-11-24T21:43:45.166990877Z\",\n            \"revision\": \"W3sibCI6Imh0dHBhcGkvYXV0aHoiLCJzIjowfSx7ImwiOiJzeXMvY2F0YWxvZyIsInMiOjEyMjd9XQ\",\n            \"path\": \"httpapi/authz/allow\",\n            \"input\": {\n                \"method\": \"GET\",\n                \"path\": [\"finance\", \"salary\", \"donna\"],\n                \"user\": \"sam\"\n            },\n            \"result\": false,\n            \"requested_by\": \"172.19.0.3:38470\",\n            \"decision_id\": \"1f6b94cf-f077-4899-8b69-af76e7cdf533\",\n            \"new_result\": true\n        }],\n        \"stats\": {\n            \"batches_observed\": 203,\n            \"batches_analyzed\": 203,\n            \"entries_observed\": 57311,\n            \"entries_evaluated\": 56263,\n            \"entries_scheduled\": 56263,\n            \"entries_failed\": 0,\n            \"analysis_errors\": 0,\n            \"results_changed\": 2825,\n            \"batches_downloaded\": 203,\n            \"batches_download_errors\": 0,\n            \"batches_skipped\": 2,\n            \"batches_from_cache\": 180,\n            \"batches_scheduled\": 4067\n        },\n        \"analyzed_batches\": [\n            \"boic4gb84ik9\",\n            \"boic6657ynoz\",\n            \"boic7ldstvyy\"\n        ],\n        \"duration\": 10000201000\n    }\n}\n```\n\n`samples` is the list of representative change samples (up to `max_samples`). Even though the example above found 2875 changed results of past policy decisions, it returned only one sample because all of them were similar (had the same input and data/modules revisions).\n\nAll the samples are in regular decision log format with the following two additional attributes:\n\n  * `new_result`: new result of the re-evaluation.\n  * `error`: error text when re-evaluation failed (omitted otherwise).\n\n`stats` are various metrics of the analysis, as follows:\n\n  * `batches_scheduled`: number of decision log batches that were scheduled for analysis.\n  * `batches_downloaded`: how many decision log batches were downloaded during the analysis (<= `batches_scheduled`).\n  * `batches_download_errors`: number of decision batches that could not be downloaded.\n  * `batches_skipped`: how many decision log batches were skipped because of the `skip_batches` input or pre-filtration.\n  * `batches_from_cache`: how many of downloaded batches were actually taken from the cache (<= `batches_downloaded`).\n  * `batches_observed`: number of decision log batches picked by the analyzers (<= `batches_downloaded`).\n  * `batches_analyzed`: number of decision log batches fully analyzed (<= `batches_observed`).\n  * `entries_observed`: number of decision logs seen in all analyzed batches.\n  * `entries_scheduled`: number of decisions scheduled for replay (<= entries_observed).\n  * `entries_evaluated`: number of replayed decisions (<= entries_scheduled).\n  * `results_changed`: how many decision logs got different result value after re-evaluation (<= `entries_evaluated`).\n  * `entries_failed`: how many decision log re-evaluations resulted in error (<= `entries_evaluated`).\n  * `analysis_errors`: how many analysis errors happened and potentially caused some decisions to be skipped (<= `entries_observed`).\n\n`duration` is the duration of the analysis in nanoseconds (<= `duration` from the request).\n\n`analyzed_batches`: list of fully analyzed batch IDs (`batches_analyzed` entries).\n",
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["logreplay"],
			"summary": "Run log-replay",
			"operationId": "RunLogReplay",
			"parameters": [{
				"name": "body",
				"in": "body",
				"required": true,
				"schema": {"$ref": "#/definitions/v1.ReplayRequest"},
			}],
			"responses": {"200": {
				"description": "OK",
				"schema": {"$ref": "#/definitions/v1.ReplayResult"},
			}},
		}},
		"/v1/logs": {"post": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["logs"],
			"summary": "Post decision logs",
			"operationId": "PostDecisions",
			"responses": {"200": {
				"description": "OK",
				"schema": {"$ref": "#/definitions/v1.PostDecisionsResponse"},
			}},
		}},
		"/v1/logs/{partition}": {"post": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["logs"],
			"summary": "Post decision logs with partition",
			"operationId": "PostDecisionsWithPartition",
			"parameters": [{
				"pattern": ".*",
				"type": "string",
				"description": "partition name. Currently not used",
				"name": "partition",
				"in": "path",
				"required": true,
			}],
			"responses": {"200": {
				"description": "OK",
				"schema": {"$ref": "#/definitions/v1.PostDecisionsResponse"},
			}},
		}},
		"/v1/notifications-install/callback/{type}": {"get": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["notifications"],
			"summary": "Handle callbacks from notification applications.",
			"operationId": "RegisterNotificationTool",
			"parameters": [
				{
					"pattern": ".*",
					"type": "string",
					"description": "notification type",
					"name": "type",
					"in": "path",
					"required": true,
				},
				{
					"type": "string",
					"description": "authorization code from notification tool",
					"name": "code",
					"in": "query",
				},
				{
					"type": "string",
					"description": "unique identification code",
					"name": "state",
					"in": "query",
				},
			],
			"responses": {"307": {
				"description": "OK",
				"schema": {"$ref": "#/definitions/v1.NotificationIntegrationResponse"},
			}},
		}},
		"/v1/notifications-install/state/{type}": {"get": {
			"tags": ["notifications-install"],
			"summary": "Start installing the notification tool.",
			"operationId": "InitiateNotificationInstall",
			"parameters": [
				{
					"pattern": ".*",
					"type": "string",
					"description": "notification type",
					"name": "type",
					"in": "path",
					"required": true,
				},
				{
					"type": "string",
					"description": "the landing page when OAuth is successfully done.",
					"name": "redirect_url",
					"in": "query",
				},
			],
			"responses": {"200": {
				"description": "OK",
				"schema": {"$ref": "#/definitions/v1.NotificationInstallNewStateResponse"},
			}},
		}},
		"/v1/notifications/{type}": {
			"get": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["notifications"],
				"summary": "Get the status of a notification tool.",
				"operationId": "GetNotificationToolStatus",
				"parameters": [{
					"pattern": ".*",
					"type": "string",
					"description": "notification type",
					"name": "type",
					"in": "path",
					"required": true,
				}],
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.NotificationToolStatusResponse"},
				}},
			},
			"put": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["notifications"],
				"summary": "Insert an access token for the notification tool.",
				"operationId": "InsertNotificationToolToken",
				"parameters": [
					{
						"pattern": ".*",
						"type": "string",
						"description": "notification type",
						"name": "type",
						"in": "path",
						"required": true,
					},
					{
						"name": "body",
						"in": "body",
						"required": true,
						"schema": {"$ref": "#/definitions/v1.NotificationToolTokenRequest"},
					},
				],
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.NotificationToolTokenResponse"},
				}},
			},
			"delete": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["notifications"],
				"summary": "Uninstall a notification tool.",
				"operationId": "UninstallNotificationToolStatus",
				"parameters": [{
					"pattern": ".*",
					"type": "string",
					"description": "notification type",
					"name": "type",
					"in": "path",
					"required": true,
				}],
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.NotificationToolDeleteResponse"},
				}},
			},
		},
		"/v1/policies": {
			"get": {
				"consumes": [
					"application/json",
					"text/plain",
				],
				"produces": ["application/json"],
				"tags": ["policies"],
				"summary": "List policies",
				"operationId": "ListPolicies",
				"parameters": [
					{
						"type": "string",
						"description": "return rego metadata of specified type or all if no type provided",
						"name": "metadata",
						"in": "query",
					},
					{
						"type": "boolean",
						"description": "return rego metadata for draft policies (when metadata flag is used)",
						"name": "drafts",
						"in": "query",
					},
				],
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.PoliciesListResponse"},
				}},
			},
			"post": {
				"consumes": ["application/gzip"],
				"produces": ["application/json"],
				"tags": ["policies"],
				"summary": "Bulk upload policies",
				"operationId": "BulkUploadPolicies",
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.PoliciesBulkUploadResponse"},
				}},
			},
		},
		"/v1/policies/systems/{system}": {
			"get": {
				"consumes": [
					"application/json",
					"text/plain",
				],
				"produces": ["application/json"],
				"tags": ["policies"],
				"summary": "List system policies",
				"operationId": "ListSystemPolicies",
				"parameters": [
					{
						"type": "string",
						"description": "system id",
						"name": "system",
						"in": "path",
						"required": true,
					},
					{
						"type": "string",
						"description": "return rego metadata of specified type or all if no type provided",
						"name": "metadata",
						"in": "query",
					},
					{
						"type": "boolean",
						"description": "return rego metadata for draft policies (when metadata flag is used)",
						"name": "drafts",
						"in": "query",
					},
				],
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.PoliciesListResponse"},
				}},
			},
			"post": {
				"consumes": ["application/gzip"],
				"produces": ["application/json"],
				"tags": ["policies"],
				"summary": "Bulk upload system policies",
				"operationId": "BulkUploadSystemPolicies",
				"parameters": [{
					"type": "string",
					"description": "system id",
					"name": "system",
					"in": "path",
					"required": true,
				}],
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.PoliciesBulkUploadResponse"},
				}},
			},
		},
		"/v1/policies/{policy}": {
			"get": {
				"consumes": [
					"application/json",
					"text/plain",
				],
				"produces": ["application/json"],
				"tags": ["policies"],
				"summary": "Get a policy",
				"operationId": "GetPolicy",
				"parameters": [
					{
						"pattern": ".+",
						"type": "string",
						"description": "policy name",
						"name": "policy",
						"in": "path",
						"required": true,
					},
					{
						"type": "boolean",
						"description": "include dependencies",
						"name": "dependencies",
						"in": "query",
					},
				],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.PolicyGetResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"put": {
				"consumes": [
					"application/json",
					"text/plain",
				],
				"produces": ["application/json"],
				"tags": ["policies"],
				"summary": "Update a policy",
				"operationId": "UpdatePolicy",
				"parameters": [
					{
						"name": "body",
						"in": "body",
						"required": true,
						"schema": {"$ref": "#/definitions/v1.PoliciesPutRequest"},
					},
					{
						"pattern": ".+",
						"type": "string",
						"description": "policy name",
						"name": "policy",
						"in": "path",
						"required": true,
					},
					{
						"type": "string",
						"description": "etag",
						"name": "If-None-Match",
						"in": "header",
					},
				],
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.PolicyPutResponse"},
				}},
			},
			"delete": {
				"consumes": [
					"application/json",
					"text/plain",
				],
				"produces": ["application/json"],
				"tags": ["policies"],
				"summary": "Delete a policy",
				"operationId": "DeletePolicy",
				"parameters": [{
					"pattern": ".+",
					"type": "string",
					"description": "policy name",
					"name": "policy",
					"in": "path",
					"required": true,
				}],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.PolicyDeleteResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
		},
		"/v1/relay/clients": {"get": {
			"tags": ["relay-server"],
			"summary": "Get clients",
			"operationId": "GetClients",
			"responses": {"200": {
				"description": "OK",
				"schema": {"$ref": "#/definitions/protocol.ClientsResponse"},
			}},
		}},
		"/v1/relay/register/{key}": {"get": {
			"tags": ["relay-server"],
			"summary": "Register Client",
			"operationId": "RegisterClient",
			"parameters": [{
				"pattern": "[a-zA-Z0-9-]*",
				"type": "string",
				"description": "key to register the relay client with",
				"name": "key",
				"in": "path",
				"required": true,
			}],
			"responses": {"200": {"description": "OK"}},
		}},
		"/v1/relay/{key}/{path}": {
			"get": {
				"consumes": ["*/*"],
				"produces": ["*/*"],
				"tags": ["relay-server"],
				"summary": "Relays HTTP GET requests",
				"operationId": "RelayGET",
				"parameters": [
					{
						"pattern": "[a-zA-Z0-9-]*",
						"type": "string",
						"description": "identifies the relay client that should execute relayed request",
						"name": "key",
						"in": "path",
						"required": true,
					},
					{
						"pattern": ".*",
						"type": "string",
						"description": "path to be queried on the base-url that relay client is configured with",
						"name": "path",
						"in": "path",
						"required": true,
					},
				],
				"responses": {"200": {"description": "OK"}},
			},
			"put": {
				"consumes": ["*/*"],
				"produces": ["*/*"],
				"tags": ["relay-server"],
				"summary": "Relays HTTP PUT requests",
				"operationId": "RelayPUT",
				"parameters": [
					{
						"pattern": "[a-zA-Z0-9-]*",
						"type": "string",
						"description": "identifies the relay client that should execute relayed request",
						"name": "key",
						"in": "path",
						"required": true,
					},
					{
						"pattern": ".*",
						"type": "string",
						"description": "path to be queried on the base-url that relay client is configured with",
						"name": "path",
						"in": "path",
						"required": true,
					},
				],
				"responses": {"200": {"description": "OK"}},
			},
			"post": {
				"consumes": ["*/*"],
				"produces": ["*/*"],
				"tags": ["relay-server"],
				"summary": "Relays HTTP POST requests",
				"operationId": "RelayPOST",
				"parameters": [
					{
						"pattern": "[a-zA-Z0-9-]*",
						"type": "string",
						"description": "identifies the relay client that should execute relayed request",
						"name": "key",
						"in": "path",
						"required": true,
					},
					{
						"pattern": ".*",
						"type": "string",
						"description": "path to be queried on the base-url that relay client is configured with",
						"name": "path",
						"in": "path",
						"required": true,
					},
				],
				"responses": {"200": {"description": "OK"}},
			},
			"delete": {
				"consumes": ["*/*"],
				"produces": ["*/*"],
				"tags": ["relay-server"],
				"summary": "Relays HTTP DELETE requests",
				"operationId": "RelayDELETE",
				"parameters": [
					{
						"pattern": "[a-zA-Z0-9-]*",
						"type": "string",
						"description": "identifies the relay client that should execute relayed request",
						"name": "key",
						"in": "path",
						"required": true,
					},
					{
						"pattern": ".*",
						"type": "string",
						"description": "path to be queried on the base-url that relay client is configured with",
						"name": "path",
						"in": "path",
						"required": true,
					},
				],
				"responses": {"200": {"description": "OK"}},
			},
			"head": {
				"consumes": ["*/*"],
				"produces": ["*/*"],
				"tags": ["relay-server"],
				"summary": "Relays HTTP HEAD requests",
				"operationId": "RelayHEAD",
				"parameters": [
					{
						"pattern": "[a-zA-Z0-9-]*",
						"type": "string",
						"description": "identifies the relay client that should execute relayed request",
						"name": "key",
						"in": "path",
						"required": true,
					},
					{
						"pattern": ".*",
						"type": "string",
						"description": "path to be queried on the base-url that relay client is configured with",
						"name": "path",
						"in": "path",
						"required": true,
					},
				],
				"responses": {"200": {"description": "OK"}},
			},
			"patch": {
				"consumes": ["*/*"],
				"produces": ["*/*"],
				"tags": ["relay-server"],
				"summary": "Relays HTTP PATCH requests",
				"operationId": "RelayPATCH",
				"parameters": [
					{
						"pattern": "[a-zA-Z0-9-]*",
						"type": "string",
						"description": "identifies the relay client that should execute relayed request",
						"name": "key",
						"in": "path",
						"required": true,
					},
					{
						"pattern": ".*",
						"type": "string",
						"description": "path to be queried on the base-url that relay client is configured with",
						"name": "path",
						"in": "path",
						"required": true,
					},
				],
				"responses": {"200": {"description": "OK"}},
			},
		},
		"/v1/secrets": {"get": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["secrets"],
			"summary": "List secrets",
			"operationId": "ListSecrets",
			"responses": {"200": {
				"description": "OK",
				"schema": {"$ref": "#/definitions/v1.SecretsListResponse"},
			}},
		}},
		"/v1/secrets/{secretId}": {
			"get": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["secrets"],
				"summary": "Get secret",
				"operationId": "GetSecret",
				"parameters": [{
					"pattern": ".*",
					"type": "string",
					"description": "secret ID",
					"name": "secretId",
					"in": "path",
					"required": true,
				}],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.SecretsGetResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"put": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["secrets"],
				"summary": "Create/update secret",
				"operationId": "CreateUpdateSecret",
				"parameters": [
					{
						"pattern": ".*",
						"type": "string",
						"description": "secret ID",
						"name": "secretId",
						"in": "path",
						"required": true,
					},
					{
						"type": "string",
						"description": "if set to '*' then the request fill fail if the secret already exists",
						"name": "If-None-Match",
						"in": "header",
					},
					{
						"name": "body",
						"in": "body",
						"required": true,
						"schema": {"$ref": "#/definitions/v1.SecretsPutRequest"},
					},
				],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.SecretsPutResponse"},
					},
					"409": {
						"description": "Secret already exists",
						"schema": {"$ref": "#/definitions/v1.SecretsPutResponse"},
					},
				},
			},
			"delete": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["secrets"],
				"summary": "Delete secret",
				"operationId": "DeleteSecret",
				"parameters": [{
					"pattern": ".*",
					"type": "string",
					"description": "secret ID",
					"name": "secretId",
					"in": "path",
					"required": true,
				}],
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.SecretsDeleteResponse"},
				}},
			},
		},
		"/v1/stacks": {
			"get": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["stacks"],
				"summary": "List stacks",
				"operationId": "ListStacks",
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.StacksListResponse"},
				}},
			},
			"post": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["stacks"],
				"summary": "Create a stack",
				"operationId": "CreateStack",
				"parameters": [{
					"name": "body",
					"in": "body",
					"required": true,
					"schema": {"$ref": "#/definitions/v1.StacksPostRequest"},
				}],
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.StacksPostResponse"},
				}},
			},
		},
		"/v1/stacks/source-control/verify-config": {"post": {
			"description": "Verifies that the repository can be accessed with the provided credentials",
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["stacks"],
			"summary": "Verify git access",
			"operationId": "func2",
			"parameters": [{
				"name": "body",
				"in": "body",
				"required": true,
				"schema": {"$ref": "#/definitions/v1.VerifyConfigRequest"},
			}],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.VerifyConfigResponse"},
				},
				"400": {
					"description": "Invalid Parameter",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/stacks/{id}/branch": {
			"get": {
				"description": "Gets the list of files for the branch that the Styra DAS creates when modifying rego in the Styra DAS UI and pushing the changes to GitHub in a branch for review.",
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["stacks"],
				"summary": "List files in Styra DAS-created branch.",
				"operationId": "GetSourceControlFilesBranchStack",
				"parameters": [{
					"pattern": ".*",
					"type": "string",
					"description": "stack id",
					"name": "id",
					"in": "path",
					"required": true,
				}],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.GetFilesResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"delete": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["stacks"],
				"summary": "Delete a user-owned branch",
				"operationId": "DeleteUserBranchStack",
				"parameters": [{
					"pattern": ".*",
					"type": "string",
					"description": "stack id",
					"name": "id",
					"in": "path",
					"required": true,
				}],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.DeleteBranchResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
		},
		"/v1/stacks/{id}/commits": {"post": {
			"description": "Commit files to source control associated with a stack",
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["stacks"],
			"summary": "Commit files to stack source control",
			"operationId": "CommitFilesToSourceControlStack",
			"parameters": [{
				"pattern": ".*",
				"type": "string",
				"description": "stack id",
				"name": "id",
				"in": "path",
				"required": true,
			}],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.PostCommitResponse"},
				},
				"404": {
					"description": "Not Found",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/stacks/{id}/master": {"get": {
			"description": "Gets the list of files in the currently chosen branch.",
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["stacks"],
			"summary": "List files in current branch.",
			"operationId": "GetSourceControlFilesMasterStack",
			"parameters": [{
				"pattern": ".*",
				"type": "string",
				"description": "stack id",
				"name": "id",
				"in": "path",
				"required": true,
			}],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.GetFilesResponse"},
				},
				"404": {
					"description": "Not Found",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/stacks/{stack}": {
			"get": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["stacks"],
				"summary": "Get a stack configuration",
				"operationId": "GetStack",
				"parameters": [
					{
						"pattern": ".*",
						"type": "string",
						"description": "stack id",
						"name": "stack",
						"in": "path",
						"required": true,
					},
					{
						"type": "boolean",
						"description": "set to 'false' to omit datasources from the output",
						"name": "datasources",
						"in": "query",
					},
				],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.StacksGetResponse"},
					},
					"404": {"description": "Not found"},
				},
			},
			"put": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["stacks"],
				"summary": "Create or update a stack",
				"operationId": "UpdateStack",
				"parameters": [
					{
						"name": "body",
						"in": "body",
						"required": true,
						"schema": {"$ref": "#/definitions/v1.StacksPutRequest"},
					},
					{
						"pattern": ".*",
						"type": "string",
						"description": "stack id",
						"name": "stack",
						"in": "path",
						"required": true,
					},
				],
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.StacksPutResponse"},
				}},
			},
			"delete": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["stacks"],
				"summary": "Delete a stack",
				"operationId": "DeleteStack",
				"parameters": [{
					"pattern": ".*",
					"type": "string",
					"description": "stack id",
					"name": "stack",
					"in": "path",
					"required": true,
				}],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.StacksDeleteResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
		},
		"/v1/stacks/{stack}/validate/compliance": {"post": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["stacks"],
			"summary": "Validate stack compliance",
			"operationId": "ValidateStackCompliance",
			"parameters": [
				{
					"name": "body",
					"in": "body",
					"required": true,
					"schema": {"$ref": "#/definitions/v1.StacksComplianceRequest"},
				},
				{
					"pattern": ".*",
					"type": "string",
					"description": "stack id",
					"name": "stack",
					"in": "path",
					"required": true,
				},
				{
					"type": "string",
					"description": "set delay of asynchronous response HTTP(202); range [1s - compliance-api-timeout].",
					"name": "asyncdelay",
					"in": "query",
				},
				{
					"type": "string",
					"description": "get asynchronous response; see HTTP(202) Location parameter",
					"name": "asyncresponse",
					"in": "query",
				},
				{
					"type": "string",
					"description": "if set to 'latest', get most recent cached results for specified stack.",
					"name": "interval",
					"in": "query",
				},
			],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.StacksComplianceResponse"},
				},
				"202": {"description": "Accepted"},
				"404": {
					"description": "Not Found",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/stacks/{stack}/validate/tests": {"post": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["stacks"],
			"summary": "Validate stack unit tests",
			"operationId": "ValidateStackTests",
			"parameters": [
				{
					"name": "body",
					"in": "body",
					"required": true,
					"schema": {"$ref": "#/definitions/v1.StacksTestsRequest"},
				},
				{
					"pattern": ".*",
					"type": "string",
					"description": "stack id",
					"name": "stack",
					"in": "path",
					"required": true,
				},
			],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.StacksTestsResponse"},
				},
				"404": {
					"description": "Not Found",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/status": {
			"get": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["status"],
				"summary": "Get current OPA statuses",
				"operationId": "GetStatuses",
				"parameters": [{
					"type": "string",
					"description": "return only statuses for one or more system ID",
					"name": "system",
					"in": "query",
				}],
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.StatusGetResponse"},
				}},
			},
			"post": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["status"],
				"summary": "Update current OPA status",
				"operationId": "UpdateStatus",
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.StatusPostResponse"},
				}},
			},
		},
		"/v1/status/{partition}": {"post": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["status"],
			"summary": "Update current OPA status",
			"operationId": "UpdateStatusWithPartition",
			"parameters": [{
				"pattern": ".*",
				"type": "string",
				"description": "partition name. Currently not used",
				"name": "partition",
				"in": "path",
				"required": true,
			}],
			"responses": {"200": {
				"description": "OK",
				"schema": {"$ref": "#/definitions/v1.StatusPostResponse"},
			}},
		}},
		"/v1/systems": {
			"get": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["systems"],
				"summary": "List systems",
				"operationId": "ListSystems",
				"parameters": [
					{
						"type": "boolean",
						"description": "if set to 'true', returns only minimal configuration information for each system",
						"name": "compact",
						"in": "query",
					},
					{
						"type": "boolean",
						"description": "set to 'false' to omit policies from the output",
						"name": "policies",
						"in": "query",
					},
					{
						"type": "boolean",
						"description": "set to 'false' to omit modules from the output",
						"name": "modules",
						"in": "query",
					},
					{
						"type": "boolean",
						"description": "set to 'false' to omit datasources from the output",
						"name": "datasources",
						"in": "query",
					},
					{
						"type": "boolean",
						"description": "set to 'false' to omit errors/warnings from the output",
						"name": "errors",
						"in": "query",
					},
					{
						"type": "boolean",
						"description": "set to 'false' to omit authz info from the output",
						"name": "authz",
						"in": "query",
					},
					{
						"type": "boolean",
						"description": "set to 'false' to omit metadata from the output",
						"name": "metadata",
						"in": "query",
					},
					{
						"type": "string",
						"description": "if set returns only systems of the specified type",
						"name": "type",
						"in": "query",
					},
					{
						"type": "string",
						"description": "if set returns only systems with a name matching the given regex",
						"name": "name",
						"in": "query",
					},
				],
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.SystemsListResponse"},
				}},
			},
			"post": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["systems"],
				"summary": "Create a system",
				"operationId": "CreateSystem",
				"parameters": [{
					"name": "body",
					"in": "body",
					"required": true,
					"schema": {"$ref": "#/definitions/v1.SystemsPostRequest"},
				}],
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.SystemsPostResponse"},
				}},
			},
		},
		"/v1/systems/external-ids": {"post": {
			"description": "Translate external identifiers to system identifiers",
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["systems"],
			"summary": "Translate identifiers",
			"operationId": "TranslateExternalIds",
			"parameters": [{
				"name": "body",
				"in": "body",
				"required": true,
				"schema": {"$ref": "#/definitions/v1.SystemsTranslateExternalIdsRequest"},
			}],
			"responses": {"200": {
				"description": "OK",
				"schema": {"$ref": "#/definitions/v1.SystemsTranslateExternalIdsResponse"},
			}},
		}},
		"/v1/systems/metrics": {"get": {
			"consumes": ["application/json"],
			"produces": ["text/plain"],
			"tags": ["systems"],
			"summary": "Handle system metrics",
			"operationId": "HandleSystemMetrics",
			"responses": {"200": {"description": "OK"}},
		}},
		"/v1/systems/source-control/verify-config": {"post": {
			"description": "Verifies that the repository can be accessed with the provided credentials",
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["systems"],
			"summary": "Verify git access",
			"operationId": "func1",
			"parameters": [{
				"name": "body",
				"in": "body",
				"required": true,
				"schema": {"$ref": "#/definitions/v1.VerifyConfigRequest"},
			}],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.VerifyConfigResponse"},
				},
				"400": {
					"description": "Invalid Parameter",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/systems/{id}/branch": {
			"get": {
				"description": "Gets the list of files for the branch that the Styra DAS creates when modifying rego in the Styra DAS UI and pushing the changes to GitHub in a branch for review.",
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["systems"],
				"summary": "List files in Styra DAS-created branch.",
				"operationId": "GetSourceControlFilesBranchSystem",
				"parameters": [{
					"pattern": ".*",
					"type": "string",
					"description": "system id",
					"name": "id",
					"in": "path",
					"required": true,
				}],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.GetFilesResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"delete": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["systems"],
				"summary": "Delete a user-owned branch",
				"operationId": "DeleteUserBranchSystem",
				"parameters": [{
					"pattern": ".*",
					"type": "string",
					"description": "system id",
					"name": "id",
					"in": "path",
					"required": true,
				}],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.DeleteBranchResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
		},
		"/v1/systems/{id}/commits": {"post": {
			"description": "Commit files to source control associated with a system",
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["systems"],
			"summary": "Commit files to system source control",
			"operationId": "CommitFilesToSourceControlSystem",
			"parameters": [{
				"pattern": ".*",
				"type": "string",
				"description": "system id",
				"name": "id",
				"in": "path",
				"required": true,
			}],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.PostCommitResponse"},
				},
				"404": {
					"description": "Not Found",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/systems/{id}/master": {"get": {
			"description": "Gets the list of files in the currently chosen branch.",
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["systems"],
			"summary": "List files in current branch.",
			"operationId": "GetSourceControlFilesMasterSystem",
			"parameters": [{
				"pattern": ".*",
				"type": "string",
				"description": "system id",
				"name": "id",
				"in": "path",
				"required": true,
			}],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.GetFilesResponse"},
				},
				"404": {
					"description": "Not Found",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/systems/{system}": {
			"get": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["systems"],
				"summary": "Get a system",
				"operationId": "GetSystem",
				"parameters": [
					{
						"pattern": ".*",
						"type": "string",
						"description": "system ID",
						"name": "system",
						"in": "path",
						"required": true,
					},
					{
						"type": "boolean",
						"description": "set to 'false' to omit errors/warnings from the output",
						"name": "errors",
						"in": "query",
					},
					{
						"type": "boolean",
						"description": "set to 'false' to omit policies from the output",
						"name": "policies",
						"in": "query",
					},
					{
						"type": "boolean",
						"description": "set to 'false' to omit modules from the output",
						"name": "modules",
						"in": "query",
					},
					{
						"type": "boolean",
						"description": "set to 'false' to omit datasources from the output",
						"name": "datasources",
						"in": "query",
					},
				],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.SystemsGetResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"put": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["systems"],
				"summary": "Create or update a system",
				"operationId": "UpdateSystem",
				"parameters": [
					{
						"name": "body",
						"in": "body",
						"required": true,
						"schema": {"$ref": "#/definitions/v1.SystemsPutRequest"},
					},
					{
						"pattern": ".*",
						"type": "string",
						"description": "system ID",
						"name": "system",
						"in": "path",
						"required": true,
					},
					{
						"type": "string",
						"description": "if set to '*' then creates a new system with type-specific related objects",
						"name": "If-None-Match",
						"in": "header",
					},
				],
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.SystemsPutResponse"},
				}},
			},
			"delete": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["systems"],
				"summary": "Delete a system",
				"operationId": "DeleteSystem",
				"parameters": [
					{
						"pattern": ".*",
						"type": "string",
						"description": "system ID",
						"name": "system",
						"in": "path",
						"required": true,
					},
					{
						"type": "string",
						"description": "if set to 'false', only deletes the system configuration and does not delete associated objects",
						"name": "recursive",
						"in": "query",
					},
				],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.SystemsDeleteResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
		},
		"/v1/systems/{system}/agents": {"get": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["systems"],
			"summary": "Get system agents",
			"operationId": "GetSystemAgents",
			"parameters": [{
				"pattern": ".*",
				"type": "string",
				"description": "system ID",
				"name": "system",
				"in": "path",
				"required": true,
			}],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.SystemsGetAgentsResponse"},
				},
				"404": {
					"description": "Not Found",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/systems/{system}/assets/{assettype}": {"get": {
			"consumes": ["application/json"],
			"produces": [
				"application/x-yaml",
				"application/gzip",
				"application/json",
			],
			"tags": ["systems"],
			"summary": "Get system asset",
			"operationId": "GetAsset",
			"parameters": [
				{
					"pattern": ".*",
					"type": "string",
					"description": "system ID",
					"name": "system",
					"in": "path",
					"required": true,
				},
				{
					"pattern": ".*",
					"type": "string",
					"description": "asset type",
					"name": "assettype",
					"in": "path",
					"required": true,
				},
			],
			"responses": {"404": {
				"description": "Not Found",
				"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
			}},
		}},
		"/v1/systems/{system}/bundle-compile": {"put": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["systems"],
			"summary": "Compile a system bundle",
			"operationId": "UpdateSystemBundleCompile",
			"parameters": [
				{
					"name": "body",
					"in": "body",
					"required": true,
					"schema": {"$ref": "#/definitions/v1.SystemsPutBundleCompileRequest"},
				},
				{
					"pattern": ".*",
					"type": "string",
					"description": "system ID",
					"name": "system",
					"in": "path",
					"required": true,
				},
			],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.SystemsPutBundleCompileResponse"},
				},
				"404": {
					"description": "Not Found",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/systems/{system}/bundle-deploy": {
			"get": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["systems"],
				"summary": "Get a system bundle deployment and build status",
				"operationId": "GetSystemBundleDeploy",
				"parameters": [{
					"pattern": ".*",
					"type": "string",
					"description": "system ID",
					"name": "system",
					"in": "path",
					"required": true,
				}],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.SystemsGetBundleDeployResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"put": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["systems"],
				"summary": "Deploy a system bundle",
				"operationId": "UpdateSystemBundleDeploy",
				"parameters": [
					{
						"name": "body",
						"in": "body",
						"required": true,
						"schema": {"$ref": "#/definitions/v1.SystemsPutBundleDeployRequest"},
					},
					{
						"pattern": ".*",
						"type": "string",
						"description": "system ID",
						"name": "system",
						"in": "path",
						"required": true,
					},
				],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.SystemsPutBundleDeployResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
					"409": {
						"description": "Conflict",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
		},
		"/v1/systems/{system}/bundles": {"get": {
			"description": "List system bundles, starting from the newest towards the oldest",
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["systems"],
			"summary": "List system bundles",
			"operationId": "GetSystemBundles",
			"parameters": [
				{
					"type": "boolean",
					"description": "if set to 'true', returns only bundles deployed in the past",
					"name": "past",
					"in": "query",
				},
				{
					"type": "integer",
					"description": "if set, the newest version to return",
					"name": "version",
					"in": "query",
				},
				{
					"pattern": ".*",
					"type": "string",
					"description": "system ID",
					"name": "system",
					"in": "path",
					"required": true,
				},
			],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.SystemsGetBundlesResponse"},
				},
				"404": {
					"description": "Not Found",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/systems/{system}/bundles/{bundle}/{version}/bundle": {"get": {
			"consumes": ["application/json"],
			"produces": [
				"application/gzip",
				"application/json",
			],
			"tags": ["systems"],
			"summary": "Get system bundle",
			"operationId": "GetSystemBundle",
			"parameters": [
				{
					"pattern": ".*",
					"type": "string",
					"description": "system ID",
					"name": "system",
					"in": "path",
					"required": true,
				},
				{
					"pattern": ".*",
					"type": "string",
					"description": "bundle ID",
					"name": "bundle",
					"in": "path",
					"required": true,
				},
				{
					"type": "integer",
					"description": "version #",
					"name": "version",
					"in": "path",
					"required": true,
				},
			],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.SystemsGetBundleDetailsResponse"},
				},
				"404": {
					"description": "Not Found",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/systems/{system}/bundles/{bundle}/{version}/details": {"get": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["systems"],
			"summary": "Get system bundle details",
			"operationId": "GetSystemBundleDetails",
			"parameters": [
				{
					"pattern": ".*",
					"type": "string",
					"description": "system ID",
					"name": "system",
					"in": "path",
					"required": true,
				},
				{
					"pattern": ".*",
					"type": "string",
					"description": "bundle ID",
					"name": "bundle",
					"in": "path",
					"required": true,
				},
				{
					"type": "integer",
					"description": "version #",
					"name": "version",
					"in": "path",
					"required": true,
				},
			],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.SystemsGetBundleDetailsResponse"},
				},
				"404": {
					"description": "Not Found",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/systems/{system}/default-policies": {"get": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["systems"],
			"summary": "Get default system policies",
			"operationId": "GetDefaultPolicies",
			"parameters": [{
				"pattern": ".*",
				"type": "string",
				"description": "system ID",
				"name": "system",
				"in": "path",
				"required": true,
			}],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.SystemsGetDefaultPoliciesResponse"},
				},
				"404": {
					"description": "Not Found",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/systems/{system}/default-policies/{path}": {"get": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["systems"],
			"summary": "Get default system policy",
			"operationId": "GetDefaultPolicy",
			"parameters": [
				{
					"pattern": ".*",
					"type": "string",
					"description": "system ID",
					"name": "system",
					"in": "path",
					"required": true,
				},
				{
					"pattern": ".*",
					"type": "string",
					"description": "policy path",
					"name": "path",
					"in": "path",
					"required": true,
				},
			],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.SystemsGetDefaultPolicyResponse"},
				},
				"404": {
					"description": "Not Found",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/systems/{system}/discovery": {"get": {
			"consumes": ["application/json"],
			"produces": ["application/gzip"],
			"tags": ["systems"],
			"summary": "Get the OPA discovery config for a system",
			"operationId": "GetOPADiscoveryConfig",
			"parameters": [
				{
					"pattern": ".*",
					"type": "string",
					"description": "system ID",
					"name": "system",
					"in": "path",
					"required": true,
				},
				{
					"type": "string",
					"description": "etag",
					"name": "If-None-Match",
					"in": "header",
				},
			],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.SystemsGetResponse"},
				},
				"304": {"description": "Not Modified"},
				"404": {
					"description": "Not Found",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/systems/{system}/instructions": {"get": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["systems"],
			"summary": "Get system install/uninstall instructions",
			"operationId": "GetInstructions",
			"parameters": [{
				"pattern": ".*",
				"type": "string",
				"description": "system ID",
				"name": "system",
				"in": "path",
				"required": true,
			}],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.SystemsGetInstructionsResponse"},
				},
				"404": {
					"description": "Not Found",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/systems/{system}/suggestions": {"get": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["systems"],
			"summary": "Get rule suggestions",
			"operationId": "RuleSuggestions",
			"parameters": [
				{
					"pattern": ".*",
					"type": "string",
					"description": "system ID",
					"name": "system",
					"in": "path",
					"required": true,
				},
				{
					"type": "boolean",
					"description": "true to get only the stateful suggestions, false for stateless, omit for both",
					"name": "stateful",
					"in": "query",
				},
			],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.SystemsSuggestedRulesResponse"},
				},
				"404": {
					"description": "Not Found",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
				"503": {
					"description": "Not available, please retry later",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/systems/{system}/validate/compliance": {"post": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["systems"],
			"summary": "Validate system compliance",
			"operationId": "ValidateSystemCompliance",
			"parameters": [
				{
					"name": "body",
					"in": "body",
					"required": true,
					"schema": {"$ref": "#/definitions/v1.SystemsComplianceRequest"},
				},
				{
					"pattern": ".*",
					"type": "string",
					"description": "system ID",
					"name": "system",
					"in": "path",
					"required": true,
				},
				{
					"type": "string",
					"description": "set delay of asynchronous response HTTP(202); range [1s - compliance-api-timeout].",
					"name": "asyncdelay",
					"in": "query",
				},
				{
					"type": "string",
					"description": "get asynchronous response; see HTTP(202) Location parameter.",
					"name": "asyncresponse",
					"in": "query",
				},
				{
					"type": "string",
					"description": "if set to 'latest', get most recent cached results for specified system.",
					"name": "interval",
					"in": "query",
				},
			],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.SystemsComplianceResponse"},
				},
				"202": {"description": "Accepted"},
				"404": {
					"description": "Not Found",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/systems/{system}/validate/tests": {"post": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["systems"],
			"summary": "Validate system unit tests",
			"operationId": "ValidateSystemTests",
			"parameters": [
				{
					"name": "body",
					"in": "body",
					"required": true,
					"schema": {"$ref": "#/definitions/v1.SystemsTestsRequest"},
				},
				{
					"pattern": ".*",
					"type": "string",
					"description": "system ID",
					"name": "system",
					"in": "path",
					"required": true,
				},
			],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.SystemsTestsResponse"},
				},
				"404": {
					"description": "Not Found",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/timeseries/advice": {"post": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["timeseries"],
			"summary": "Handle advice",
			"operationId": "HandleAdvice",
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.TimeSeriesPostResponse"},
				},
				"400": {
					"description": "Invalid Parameter",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/timeseries/decision": {"post": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["timeseries"],
			"summary": "Handle decision",
			"operationId": "HandleDecision",
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.TimeSeriesPostResponse"},
				},
				"400": {
					"description": "Invalid Parameter",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/timeseries/deny": {"post": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["timeseries"],
			"summary": "Handle deny",
			"operationId": "HandleDeny",
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.TimeSeriesPostResponse"},
				},
				"400": {
					"description": "Invalid Parameter",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/timeseries/error": {"post": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["timeseries"],
			"summary": "Handle error",
			"operationId": "HandleError",
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.TimeSeriesPostResponse"},
				},
				"400": {
					"description": "Invalid Parameter",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/timeseries/latency": {"post": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["timeseries"],
			"summary": "Handle latency",
			"operationId": "HandleLatency",
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.TimeSeriesPostResponse"},
				},
				"400": {
					"description": "Invalid Parameter",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/timeseries/metrics": {"get": {
			"consumes": ["application/json"],
			"produces": ["text/plain"],
			"tags": ["timeseries"],
			"summary": "Handle timeseries metrics",
			"operationId": "HandleTimeseriesMetrics",
			"responses": {"200": {"description": "OK"}},
		}},
		"/v1/timeseries/unknown": {"post": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["timeseries"],
			"summary": "Handle unknown",
			"operationId": "HandleUnknown",
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.TimeSeriesPostResponse"},
				},
				"400": {
					"description": "Invalid Parameter",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/timeseries/usage": {"post": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["timeseries"],
			"summary": "Handle usage",
			"operationId": "HandleUsage",
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.TimeSeriesUsagePostResponse"},
				},
				"400": {
					"description": "Invalid Parameter",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/timeseries/violation": {"post": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["timeseries"],
			"summary": "Handle violation",
			"operationId": "HandleViolation",
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.TimeSeriesPostResponse"},
				},
				"400": {
					"description": "Invalid Parameter",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/tokens": {"get": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["tokens"],
			"summary": "List tokens",
			"operationId": "ListTokens",
			"responses": {"200": {
				"description": "OK",
				"schema": {"$ref": "#/definitions/v1.TokensListResponse"},
			}},
		}},
		"/v1/tokens/{tokenId}": {
			"get": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["tokens"],
				"summary": "Get token",
				"operationId": "GetToken",
				"parameters": [{
					"pattern": ".+",
					"type": "string",
					"description": "token ID",
					"name": "tokenId",
					"in": "path",
					"required": true,
				}],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.TokensGetResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"put": {
				"description": "If If-None-Match header is set to *, tries to create a token, otherwise will try to either update or create depending on whether an unexpired token with that ID already exists. Token creation errors with a 409 code if an unexpired one already exists, on success returns the token secret (valid for the TTL whose default value is ~10 years). Token updates return nothing unless `regenerate` is true, in which case it returns the new secret. WARNING: If allow_path_patterns is unset or an empty list, all paths are allowed.",
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["tokens"],
				"summary": "Create or update a token",
				"operationId": "CreateToken",
				"parameters": [
					{
						"name": "body",
						"in": "body",
						"required": true,
						"schema": {"$ref": "#/definitions/v1.TokensPutRequest"},
					},
					{
						"pattern": ".+",
						"type": "string",
						"description": "token ID",
						"name": "tokenId",
						"in": "path",
						"required": true,
					},
				],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.TokensPutResponse"},
					},
					"409": {
						"description": "Token already exists",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"delete": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["tokens"],
				"summary": "Revoke token",
				"operationId": "RevokeToken",
				"parameters": [{
					"pattern": ".+",
					"type": "string",
					"description": "token ID",
					"name": "tokenId",
					"in": "path",
					"required": true,
				}],
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.TokensDeleteResponse"},
				}},
			},
		},
		"/v1/users": {"get": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["users"],
			"summary": "List users",
			"operationId": "ListUsers",
			"responses": {"200": {
				"description": "OK",
				"schema": {"$ref": "#/definitions/v1.UsersListResponse"},
			}},
		}},
		"/v1/users/{userId}": {
			"get": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["users"],
				"summary": "Get user",
				"operationId": "GetUser",
				"parameters": [{
					"pattern": ".+",
					"type": "string",
					"description": "user ID",
					"name": "userId",
					"in": "path",
					"required": true,
				}],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.UsersGetResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"put": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["users"],
				"summary": "Create/update user",
				"operationId": "CreateUpdateUser",
				"parameters": [
					{
						"name": "body",
						"in": "body",
						"required": true,
						"schema": {"$ref": "#/definitions/v1.UsersPutRequest"},
					},
					{
						"pattern": ".+",
						"type": "string",
						"description": "user ID",
						"name": "userId",
						"in": "path",
						"required": true,
					},
					{
						"type": "string",
						"description": "if set to '*' then the request fill fail if the user already exists",
						"name": "If-None-Match",
						"in": "header",
					},
				],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.UsersPutResponse"},
					},
					"409": {
						"description": "User already exists",
						"schema": {"$ref": "#/definitions/v1.UsersPutResponse"},
					},
				},
			},
			"delete": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["users"],
				"summary": "Delete user",
				"operationId": "DeleteUser",
				"parameters": [{
					"pattern": ".+",
					"type": "string",
					"description": "user ID",
					"name": "userId",
					"in": "path",
					"required": true,
				}],
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.UsersDeleteResponse"},
				}},
			},
		},
		"/v1/workspace": {
			"get": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["workspace"],
				"summary": "Get workspace",
				"operationId": "GetWorkspace",
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.WorkspaceGetResponse"},
					},
					"404": {
						"description": "Not found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"put": {
				"description": "Updates workspace configuration",
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["workspace"],
				"summary": "Update workspace",
				"operationId": "UpdateWorkspace",
				"parameters": [{
					"name": "body",
					"in": "body",
					"required": true,
					"schema": {"$ref": "#/definitions/v1.WorkspacePutRequest"},
				}],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.WorkspacePutResponse"},
					},
					"400": {
						"description": "Invalid Parameter",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
		},
		"/v1/workspace/regions/{storagesvc}": {"get": {
			"description": "Get list of valid regions for S3 integration type",
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["workspace"],
			"summary": "Get S3 regions list",
			"operationId": "GetRegions",
			"parameters": [{
				"pattern": ".*",
				"type": "string",
				"description": "storagesvc id",
				"name": "storagesvc",
				"in": "path",
				"required": true,
			}],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.GetRegionResponse"},
				},
				"404": {
					"description": "Not found",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/workspace/s3-config": {
			"get": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["workspace"],
				"summary": "Get S3 decision configuration",
				"operationId": "GetS3Config",
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.S3ConfigGetResponse"},
					},
					"404": {
						"description": "Not found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"put": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["workspace"],
				"summary": "Update S3 decision configuration",
				"operationId": "UpdateS3Config",
				"parameters": [{
					"name": "body",
					"in": "body",
					"required": true,
					"schema": {"$ref": "#/definitions/v1.S3ConfigPutRequest"},
				}],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.WorkspacePutResponse"},
					},
					"400": {
						"description": "Invalid Parameter",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
		},
		"/v1/workspace/s3/verify-config": {"post": {
			"description": "Verifies that the S3 bucket can be accessed with the provided credentials. Creates styra_test.json file",
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["workspace"],
			"summary": "S3 connectivity test",
			"operationId": "S3VerifyConfig",
			"parameters": [{
				"name": "body",
				"in": "body",
				"required": true,
				"schema": {"$ref": "#/definitions/v1.S3Config"},
			}],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.S3VerifyResponse"},
				},
				"400": {
					"description": "Invalid Parameter",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/workspace/source-control/verify-config": {"post": {
			"description": "Verifies that the repository can be accessed with the provided credentials",
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["workspace"],
			"summary": "Verify git access",
			"operationId": "func3",
			"parameters": [{
				"name": "body",
				"in": "body",
				"required": true,
				"schema": {"$ref": "#/definitions/v1.VerifyConfigRequest"},
			}],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.VerifyConfigResponse"},
				},
				"400": {
					"description": "Invalid Parameter",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/workspace/{id}/branch": {
			"get": {
				"description": "Gets the list of files for the branch that the Styra DAS creates when modifying rego in the Styra DAS UI and pushing the changes to GitHub in a branch for review.",
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["workspace"],
				"summary": "List files in Styra DAS-created branch.",
				"operationId": "GetSourceControlFilesBranchWorkspace",
				"parameters": [{
					"pattern": ".*",
					"type": "string",
					"description": "workspace id",
					"name": "id",
					"in": "path",
					"required": true,
				}],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.GetFilesResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"delete": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["workspace"],
				"summary": "Delete a user-owned branch",
				"operationId": "DeleteUserBranchWorkspace",
				"parameters": [{
					"pattern": ".*",
					"type": "string",
					"description": "workspace id",
					"name": "id",
					"in": "path",
					"required": true,
				}],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v1.DeleteBranchResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
		},
		"/v1/workspace/{id}/commits": {"post": {
			"description": "Commit files to source control associated with a workspace",
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["workspace"],
			"summary": "Commit files to workspace source control",
			"operationId": "CommitFilesToSourceControlWorkspace",
			"parameters": [{
				"pattern": ".*",
				"type": "string",
				"description": "workspace id",
				"name": "id",
				"in": "path",
				"required": true,
			}],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.PostCommitResponse"},
				},
				"404": {
					"description": "Not Found",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v1/workspace/{id}/master": {"get": {
			"description": "Gets the list of files in the currently chosen branch.",
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["workspace"],
			"summary": "List files in current branch.",
			"operationId": "GetSourceControlFilesMasterWorkspace",
			"parameters": [{
				"pattern": ".*",
				"type": "string",
				"description": "workspace id",
				"name": "id",
				"in": "path",
				"required": true,
			}],
			"responses": {
				"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v1.GetFilesResponse"},
				},
				"404": {
					"description": "Not Found",
					"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
				},
			},
		}},
		"/v2/authz/migration/status": {"put": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["authz"],
			"summary": "Update migration status",
			"operationId": "UpdateMigrationStatus",
			"parameters": [{
				"name": "body",
				"in": "body",
				"required": true,
				"schema": {"$ref": "#/definitions/v2.RoleBindingsPutStatusRequest"},
			}],
			"responses": {"200": {
				"description": "OK",
				"schema": {"$ref": "#/definitions/v2.RoleBindingsPutStatusResponse"},
			}},
		}},
		"/v2/authz/reset/rolebindings": {"put": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["authz"],
			"summary": "Reset rolebindings",
			"operationId": "ResetRoleBindings",
			"parameters": [{
				"name": "body",
				"in": "body",
				"required": true,
				"schema": {"$ref": "#/definitions/v2.RoleBindingsPutResetRequest"},
			}],
			"responses": {"200": {
				"description": "OK",
				"schema": {"$ref": "#/definitions/v2.RoleBindingsPutResetResponse"},
			}},
		}},
		"/v2/authz/rolebindings": {
			"get": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["authz"],
				"summary": "List role bindings",
				"operationId": "ListRoleBindings.v2",
				"parameters": [
					{
						"type": "string",
						"description": "if set returns only rolebindings involving the specified resource kind (if supplied multiple times will return rolebindings that match any of the specified resource kinds)",
						"name": "resource_kind",
						"in": "query",
					},
					{
						"type": "string",
						"description": "if set returns only rolebindings involving the specified resource id (if supplied multiple times will return rolebindings that match any of the specified resource ids)",
						"name": "resource_id",
						"in": "query",
					},
					{
						"type": "string",
						"description": "if set returns only rolebindings involving the specified role id (if supplied multiple times will return rolebindings that match any of the specified role ids)",
						"name": "role_id",
						"in": "query",
					},
					{
						"type": "string",
						"description": "if set returns only rolebindings involving the specified subject kind (if supplied multiple times will return rolebindings that match any of the specified subject kinds)",
						"name": "subject_kind",
						"in": "query",
					},
					{
						"type": "string",
						"description": "if set returns only rolebindings involving the specified subject id (if supplied multiple times will return rolebindings that match any of the specified subject ids)",
						"name": "subject_id",
						"in": "query",
					},
					{
						"type": "boolean",
						"description": "if set to 'true', returns only internal rolebindings",
						"name": "internal",
						"in": "query",
					},
				],
				"responses": {"200": {
					"description": "OK",
					"schema": {"$ref": "#/definitions/v2.RoleBindingsListResponse"},
				}},
			},
			"post": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["authz"],
				"summary": "Create or update rolebinding",
				"operationId": "CreateRoleBinding",
				"parameters": [
					{
						"name": "body",
						"in": "body",
						"required": true,
						"schema": {"$ref": "#/definitions/v2.RoleBindingsPostRequest"},
					},
					{
						"type": "string",
						"description": "if set to '*', will not update existing rolebinding",
						"name": "If-None-Match",
						"in": "header",
					},
				],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v2.RoleBindingsPostResponse"},
					},
					"400": {
						"description": "Invalid Parameter",
						"schema": {"$ref": "#/definitions/v2.RoleBindingsPostResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
					"409": {
						"description": "Conflict",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
		},
		"/v2/authz/rolebindings/{id}": {
			"get": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["authz"],
				"summary": "Get rolebinding",
				"operationId": "GetRoleBinding.v2",
				"parameters": [{
					"pattern": ".*",
					"type": "string",
					"description": "rolebinding ID",
					"name": "id",
					"in": "path",
					"required": true,
				}],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v2.RoleBindingsGetResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"delete": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["authz"],
				"summary": "Delete rolebinding",
				"operationId": "DeleteRoleBinding.v2",
				"parameters": [
					{
						"type": "string",
						"description": "if set to '*', will return success if not found",
						"name": "If-Match",
						"in": "header",
					},
					{
						"pattern": ".*",
						"type": "string",
						"description": "rolebinding ID",
						"name": "id",
						"in": "path",
						"required": true,
					},
				],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v2.RoleBindingsDeleteResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
		},
		"/v2/authz/rolebindings/{id}/subjects": {
			"put": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["authz"],
				"summary": "Merge rolebinding subjects",
				"operationId": "MergeRoleBindingSubjects",
				"parameters": [
					{
						"name": "body",
						"in": "body",
						"required": true,
						"schema": {"$ref": "#/definitions/v2.RoleBindingsPutSubjectsRequest"},
					},
					{
						"pattern": ".*",
						"type": "string",
						"description": "rolebinding ID",
						"name": "id",
						"in": "path",
						"required": true,
					},
				],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v2.RoleBindingsPutSubjectsResponse"},
					},
					"400": {
						"description": "Invalid Parameter",
						"schema": {"$ref": "#/definitions/v2.RoleBindingsPostResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"post": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["authz"],
				"summary": "Update rolebinding subjects",
				"operationId": "UpdateRoleBindingSubjects",
				"parameters": [
					{
						"name": "body",
						"in": "body",
						"required": true,
						"schema": {"$ref": "#/definitions/v2.RoleBindingsPostSubjectsRequest"},
					},
					{
						"pattern": ".*",
						"type": "string",
						"description": "rolebinding ID",
						"name": "id",
						"in": "path",
						"required": true,
					},
				],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v2.RoleBindingsPostSubjectsResponse"},
					},
					"400": {
						"description": "Invalid Parameter",
						"schema": {"$ref": "#/definitions/v2.RoleBindingsPostResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
			"delete": {
				"consumes": ["application/json"],
				"produces": ["application/json"],
				"tags": ["authz"],
				"summary": "Delete rolebinding subjects",
				"operationId": "DeleteRoleBindingSubjects",
				"parameters": [
					{
						"name": "body",
						"in": "body",
						"required": true,
						"schema": {"$ref": "#/definitions/v2.RoleBindingsDeleteSubjectsRequest"},
					},
					{
						"pattern": ".*",
						"type": "string",
						"description": "rolebinding ID",
						"name": "id",
						"in": "path",
						"required": true,
					},
				],
				"responses": {
					"200": {
						"description": "OK",
						"schema": {"$ref": "#/definitions/v2.RoleBindingsDeleteSubjectsResponse"},
					},
					"400": {
						"description": "Invalid Parameter",
						"schema": {"$ref": "#/definitions/v2.RoleBindingsPostResponse"},
					},
					"404": {
						"description": "Not Found",
						"schema": {"$ref": "#/definitions/v1.ErrorResponse"},
					},
				},
			},
		},
		"/v2/authz/roles": {"get": {
			"consumes": ["application/json"],
			"produces": ["application/json"],
			"tags": ["authz"],
			"summary": "List roles",
			"operationId": "ListRoles",
			"parameters": [{
				"type": "string",
				"description": "if set returns only roles applicable to specific resource kind",
				"name": "resource_kind",
				"in": "query",
			}],
			"responses": {"200": {
				"description": "OK",
				"schema": {"$ref": "#/definitions/v2.RolesListResponse"},
			}},
		}},
	},
	"definitions": {
		".status": {
			"required": ["reason"],
			"properties": {"reason": {"type": "string"}},
		},
		"ast.Expr": {
			"required": [
				"terms",
				"index",
			],
			"properties": {
				"generated": {"type": "boolean"},
				"index": {
					"type": "integer",
					"format": "int32",
				},
				"negated": {"type": "boolean"},
				"terms": {"$ref": "#/definitions/ast.Expr.terms"},
				"with": {
					"type": "array",
					"items": {"$ref": "#/definitions/ast.With"},
				},
			},
		},
		"ast.Expr.terms": {},
		"ast.With": {
			"required": [
				"target",
				"value",
			],
			"properties": {
				"target": {"type": "string"},
				"value": {"type": "string"},
			},
		},
		"crypto.FilterTree": {"properties": {
			"digest": {"type": "string"},
			"nodes": {
				"type": "object",
				"additionalProperties": {"$ref": "#/definitions/crypto.FilterTree"},
			},
		}},
		"crypto.Signature": {"properties": {
			"excluded": {"$ref": "#/definitions/crypto.FilterTree"},
			"signatures": {
				"type": "array",
				"items": {"$ref": "#/definitions/crypto.Signature.signatures"},
			},
		}},
		"crypto.Signature.signatures": {},
		"decision.Decision": {
			"required": [
				"input",
				"output",
			],
			"properties": {
				"input": {"$ref": "#/definitions/decision.Input"},
				"output": {"$ref": "#/definitions/decision.Output"},
			},
		},
		"decision.Input": {
			"required": [
				"method",
				"path",
				"user",
			],
			"properties": {
				"body": {"type": "object"},
				"method": {"type": "string"},
				"path": {"type": "string"},
				"user": {"type": "string"},
				"user_claims": {"type": "object"},
			},
		},
		"decision.Output": {
			"required": [
				"allow",
				"status",
			],
			"properties": {
				"allow": {"type": "boolean"},
				"status": {"$ref": "#/definitions/.status"},
			},
		},
		"json.JsonPatchSpec": {},
		"location.Location": {
			"required": [
				"file",
				"row",
				"col",
			],
			"properties": {
				"col": {
					"type": "integer",
					"format": "int32",
				},
				"file": {"type": "string"},
				"row": {
					"type": "integer",
					"format": "int32",
				},
			},
		},
		"logs.BundleInfoV1": {"properties": {"revision": {"type": "string"}}},
		"protocol.Client": {"properties": {
			"client_key": {"type": "string"},
			"remote_address": {"type": "string"},
			"version": {"type": "string"},
		}},
		"protocol.ClientsResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {
					"type": "array",
					"items": {"$ref": "#/definitions/protocol.Client"},
				},
			},
		},
		"security.RoleName": {},
		"v1.ActivityData": {
			"required": [
				"request",
				"response",
				"duration",
			],
			"properties": {
				"decision": {"$ref": "#/definitions/decision.Decision"},
				"duration": {
					"type": "integer",
					"format": "integer",
				},
				"request": {"$ref": "#/definitions/v1.RequestData"},
				"response": {"$ref": "#/definitions/v1.ResponseData"},
			},
		},
		"v1.ActivityExporterConfig": {"properties": {
			"interval": {
				"description": "S3 exporter interval: range [30s,1h]",
				"type": "string",
				"default": "5m",
			},
			"s3_activity": {"$ref": "#/definitions/v1.S3Config"},
		}},
		"v1.ActivityPostRequest": {"properties": {
			"count": {
				"description": "max count of records to return: default(256), max(4096)",
				"type": "integer",
				"format": "int32",
			},
			"end_time": {
				"description": "filter time range end_time",
				"type": "string",
				"format": "date-time",
			},
			"forward": {
				"description": "search from start or end of table: default end(false)",
				"type": "boolean",
			},
			"request_id": {
				"description": "filter on matching request_id",
				"type": "string",
			},
			"start_time": {
				"description": "filter time range start_time",
				"type": "string",
				"format": "date-time",
			},
		}},
		"v1.ActivityPostResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.ActivityResult"},
			},
		},
		"v1.ActivityResult": {
			"required": ["data"],
			"properties": {"data": {
				"type": "array",
				"items": {"$ref": "#/definitions/v1.ActivityData"},
			}},
		},
		"v1.AgentConfig": {
			"required": ["id"],
			"properties": {
				"id": {
					"description": "agent ID",
					"type": "string",
				},
				"status": {
					"description": "agent status",
					"type": "object",
					"readOnly": true,
				},
			},
		},
		"v1.AgentErrors": {
			"required": [
				"waiting",
				"errors",
			],
			"properties": {
				"errors": {
					"description": "list of system errors",
					"type": "array",
					"items": {"$ref": "#/definitions/v1.Status"},
				},
				"waiting": {
					"description": "true if the the system is waiting for error to be resolved",
					"type": "boolean",
				},
			},
		},
		"v1.AgentStatus": {},
		"v1.AllowedMapping": {
			"required": ["path"],
			"properties": {
				"expected": {
					"description": "expected value of the decision property",
					"$ref": "#/definitions/v1.AllowedMapping.expected",
				},
				"negated": {
					"description": "when set to true, decision is Allowed when the mapped property IS NOT equal to the expected value",
					"type": "boolean",
					"default": false,
				},
				"path": {
					"description": "dot-separated decision property path",
					"type": "string",
				},
			},
		},
		"v1.AllowedMapping.expected": {},
		"v1.AllowedValue": {"properties": {
			"error": {"type": "string"},
			"value": {"type": "boolean"},
		}},
		"v1.AuthzConfig": {"properties": {"role_bindings": {
			"description": "a list of role binding configs",
			"type": "array",
			"items": {"$ref": "#/definitions/v1.RoleBindingConfig"},
			"readOnly": true,
		}}},
		"v1.BuiltinMocks": {"properties": {
			"http.send": {
				"description": "Mocks http.send results",
				"$ref": "#/definitions/v1.MocksHttpSend",
			},
			"opa.runtime": {
				"description": "Mocks opa.runtime result",
				"$ref": "#/definitions/v1.MocksOPARuntime",
			},
		}},
		"v1.Bundle": {
			"required": [
				"id",
				"version",
				"size",
				"active",
				"created_at",
				"revision",
			],
			"properties": {
				"active": {
					"description": "activation percentage",
					"type": "integer",
					"format": "int64",
				},
				"created_at": {
					"description": "when created",
					"type": "string",
					"format": "date-time",
				},
				"id": {
					"description": "bundle ID",
					"type": "string",
				},
				"last_deployed_at": {
					"description": "when deployed last, if ever",
					"type": "string",
					"format": "date-time",
				},
				"minimum_opa_version": {
					"description": "minimum OPA version required by the bundle if known",
					"type": "string",
				},
				"revision": {
					"description": "bundle revision identifier",
					"type": "string",
				},
				"size": {
					"description": "size in bytes",
					"type": "integer",
					"format": "int64",
				},
				"version": {
					"description": "bundle version",
					"type": "integer",
					"format": "int64",
				},
			},
		},
		"v1.BundleActivation": {
			"required": [
				"id",
				"version",
				"revision",
			],
			"properties": {
				"id": {"type": "string"},
				"revision": {"type": "string"},
				"version": {
					"type": "integer",
					"format": "int64",
				},
			},
		},
		"v1.BundleDeployStatus": {
			"required": ["build_errors"],
			"properties": {
				"build_errors": {
					"description": "build errors (per bundle id) when building the latest bundle, if any",
					"type": "object",
					"additionalProperties": {"type": "string"},
				},
				"primary": {
					"description": "primary bundle to activate",
					"$ref": "#/definitions/v1.BundleActivation",
				},
			},
		},
		"v1.BundleDetails": {
			"required": [
				"id",
				"version",
				"size",
				"active",
				"created_at",
				"revision",
			],
			"properties": {
				"active": {
					"description": "activation percentage",
					"type": "integer",
					"format": "int64",
				},
				"created_at": {
					"description": "when created",
					"type": "string",
					"format": "date-time",
				},
				"id": {
					"description": "bundle ID",
					"type": "string",
				},
				"last_deployed_at": {
					"description": "when deployed last, if ever",
					"type": "string",
					"format": "date-time",
				},
				"minimum_opa_version": {
					"description": "minimum OPA version required by the bundle if known",
					"type": "string",
				},
				"revision": {
					"description": "bundle revision identifier",
					"type": "string",
				},
				"size": {
					"description": "size in bytes",
					"type": "integer",
					"format": "int64",
				},
				"version": {
					"description": "bundle version",
					"type": "integer",
					"format": "int64",
				},
			},
		},
		"v1.BundleDistributionS3Config": {
			"required": [
				"region",
				"bucket",
				"discovery_path",
				"policy_path",
			],
			"properties": {
				"access_keys": {
					"description": "access key id and secret access key are looked under the key <name>/<access_keys>",
					"type": "string",
				},
				"bucket": {
					"description": "bucket name",
					"type": "string",
				},
				"discovery_path": {
					"description": "discovery bundle path",
					"type": "string",
				},
				"endpoint": {
					"description": "AWS endpoint",
					"type": "string",
				},
				"opa_credentials": {
					"description": "if provided, OPA uses this 'services[_].credentials.s3_signing' config to connect directly to S3 for bundle downloads",
					"$ref": "#/definitions/v1.BundleDistributionS3Config.opa_credentials",
				},
				"policy_path": {
					"description": "bundle path",
					"type": "string",
				},
				"region": {
					"description": "AWS region",
					"type": "string",
				},
			},
		},
		"v1.BundleDistributionS3Config.opa_credentials": {"properties": {
			"environment_credentials": {"$ref": "#/definitions/v1.BundleDistributionS3Config.opa_credentials.environment_credentials"},
			"metadata_credentials": {"$ref": "#/definitions/v1.BundleDistributionS3Config.opa_credentials.metadata_credentials"},
			"web_identity_credentials": {"$ref": "#/definitions/v1.BundleDistributionS3Config.opa_credentials.web_identity_credentials"},
		}},
		"v1.BundleDistributionS3Config.opa_credentials.environment_credentials": {},
		"v1.BundleDistributionS3Config.opa_credentials.metadata_credentials": {
			"required": [
				"aws_region",
				"iam_role",
			],
			"properties": {
				"aws_region": {"type": "string"},
				"iam_role": {"type": "string"},
			},
		},
		"v1.BundleDistributionS3Config.opa_credentials.web_identity_credentials": {
			"required": [
				"aws_region",
				"session_name",
			],
			"properties": {
				"aws_region": {"type": "string"},
				"session_name": {"type": "string"},
			},
		},
		"v1.BundleRegistryConfig": {"properties": {
			"distribution_s3": {
				"description": "configuration for external S3 bucket to use for bundle distribution",
				"$ref": "#/definitions/v1.BundleDistributionS3Config",
			},
			"manual_deployment": {
				"description": "manual deployment mode to prevent automatic deployment of new bundles",
				"type": "boolean",
			},
			"max_bundles": {
				"description": "maximum number of all bundles to store (default 100)",
				"type": "integer",
				"format": "int64",
			},
			"max_deployed_bundles": {
				"description": "maximum number of previously deployed bundles to store (default 10)",
				"type": "integer",
				"format": "int64",
			},
		}},
		"v1.CheckPermissionInput": {
			"required": [
				"check_option",
				"operation",
				"action",
				"path",
				"body",
			],
			"properties": {
				"action": {"type": "string"},
				"body": {"type": "object"},
				"check_option": {"type": "string"},
				"operation": {"type": "string"},
				"path": {"type": "string"},
			},
		},
		"v1.CheckPermissionOutput": {
			"required": [
				"check_option",
				"operation",
				"path",
				"allowed",
				"eval_error",
			],
			"properties": {
				"allowed": {"type": "boolean"},
				"body": {"type": "object"},
				"check_option": {"type": "string"},
				"eval_error": {"type": "boolean"},
				"operation": {"type": "string"},
				"path": {"type": "string"},
			},
		},
		"v1.CheckPermissionsPostResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {
					"type": "array",
					"items": {"$ref": "#/definitions/v1.CheckPermissionOutput"},
				},
			},
		},
		"v1.ColumnMapping": {
			"required": [
				"key",
				"path",
			],
			"properties": {
				"key": {
					"description": "column key (also the search key)",
					"type": "string",
				},
				"path": {
					"description": "dot-separated decision property path",
					"type": "string",
				},
				"type": {
					"description": "column type: one of \"string\", \"boolean\", \"date\", \"integer\", \"float\"",
					"type": "string",
					"default": "string",
				},
			},
		},
		"v1.ColumnValue": {
			"required": ["key"],
			"properties": {
				"error": {"type": "string"},
				"key": {"type": "string"},
				"type": {"type": "string"},
				"value": {"$ref": "#/definitions/v1.ColumnValue.value"},
			},
		},
		"v1.ColumnValue.value": {},
		"v1.Commit": {
			"required": [
				"files_to_delete",
				"author",
				"email",
				"message",
				"files",
				"branch",
			],
			"properties": {
				"author": {"type": "string"},
				"branch": {"type": "string"},
				"email": {"type": "string"},
				"files": {
					"description": "Map of filenames to file contents",
					"type": "object",
					"additionalProperties": {"type": "string"},
				},
				"files_to_delete": {
					"description": "List of filenames to delete from the repo",
					"type": "array",
					"items": {"type": "string"},
				},
				"message": {"type": "string"},
			},
		},
		"v1.ComplianceValidation": {"properties": {
			"all": {
				"type": "array",
				"items": {"$ref": "#/definitions/v1.ComplianceValidation.all"},
			},
			"all_count": {
				"type": "integer",
				"format": "int32",
			},
			"new": {
				"type": "array",
				"items": {"$ref": "#/definitions/v1.ComplianceValidation.new"},
			},
			"new_count": {
				"type": "integer",
				"format": "int32",
			},
			"resolved": {
				"type": "array",
				"items": {"$ref": "#/definitions/v1.ComplianceValidation.resolved"},
			},
			"resolved_count": {
				"type": "integer",
				"format": "int32",
			},
			"unchanged": {
				"type": "array",
				"items": {"$ref": "#/definitions/v1.ComplianceValidation.unchanged"},
			},
			"unchanged_count": {
				"type": "integer",
				"format": "int32",
			},
		}},
		"v1.ComplianceValidation.all": {},
		"v1.ComplianceValidation.new": {},
		"v1.ComplianceValidation.resolved": {},
		"v1.ComplianceValidation.unchanged": {},
		"v1.Config": {},
		"v1.DataPatchResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.DataPatchResponse.result"},
			},
		},
		"v1.DataPatchResponse.result": {},
		"v1.DataPutResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.DataRequest": {"properties": {
			"input": {"type": "object"},
			"jsonpath": {"type": "string"},
			"mocks": {
				"description": "mock http.send and opa.runtime builtins",
				"$ref": "#/definitions/v1.BuiltinMocks",
			},
			"query_package": {"type": "string"},
			"rego": {"type": "string"},
			"rego_modules": {
				"type": "object",
				"additionalProperties": {"type": "string"},
			},
		}},
		"v1.DataResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.DataResponse.result"},
			},
		},
		"v1.DataResponse.result": {},
		"v1.DatasourceConfig": {
			"required": [
				"id",
				"category",
				"type",
			],
			"properties": {
				"category": {
					"description": "datasource category",
					"type": "string",
				},
				"id": {
					"description": "datasource ID",
					"type": "string",
				},
				"optional": {
					"description": "optional datasources can be deleted without being recreated automatically",
					"type": "boolean",
				},
				"status": {
					"description": "datasource status",
					"$ref": "#/definitions/v1.Status",
				},
				"type": {
					"description": "pull or push",
					"type": "string",
				},
			},
		},
		"v1.DatasourcesDeleteResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.DatasourcesGetResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"type": "object"},
			},
		},
		"v1.DatasourcesListResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {
					"type": "array",
					"items": {"$ref": "#/definitions/v1.Config"},
				},
			},
		},
		"v1.DatasourcesPostResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.DatasourcesPostResponse.result"},
			},
		},
		"v1.DatasourcesPostResponse.result": {},
		"v1.DatasourcesPutRequest": {},
		"v1.DatasourcesPutResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.Decision": {
			"required": [
				"columns",
				"decision_type",
			],
			"properties": {
				"agent_id": {"type": "string"},
				"allowed": {"$ref": "#/definitions/v1.AllowedValue"},
				"bundles": {
					"description": "configured bundles",
					"type": "object",
					"additionalProperties": {"$ref": "#/definitions/logs.BundleInfoV1"},
				},
				"columns": {
					"type": "array",
					"items": {"$ref": "#/definitions/v1.ColumnValue"},
				},
				"cursor": {"type": "string"},
				"decision_id": {
					"description": "unique decision ID",
					"type": "string",
				},
				"decision_type": {"type": "string"},
				"erased": {
					"description": "erased fields",
					"type": "array",
					"items": {"type": "string"},
				},
				"error": {
					"description": "error information for failed decisions",
					"$ref": "#/definitions/v1.LogEntry.error",
				},
				"input": {
					"description": "rego inputs",
					"$ref": "#/definitions/v1.LogEntry.input",
				},
				"labels": {
					"description": "OPA labels",
					"type": "object",
					"additionalProperties": {"type": "string"},
				},
				"metrics": {
					"description": "decision metrics",
					"type": "object",
				},
				"path": {
					"description": "evaluated path",
					"type": "string",
				},
				"policy_type": {"type": "string"},
				"query": {
					"description": "ad-hoc query",
					"type": "string",
				},
				"reason": {"$ref": "#/definitions/v1.ReasonValue"},
				"received": {
					"type": "string",
					"format": "date-time",
				},
				"requested_by": {
					"description": "requested by IP:port",
					"type": "string",
				},
				"result": {
					"description": "evaluation result",
					"$ref": "#/definitions/v1.LogEntry.result",
				},
				"revision": {
					"description": "bundle revision",
					"type": "string",
				},
				"stacks": {
					"type": "array",
					"items": {"type": "string"},
				},
				"system_id": {"type": "string"},
				"system_type": {"type": "string"},
				"timestamp": {
					"description": "OPA-side decision timestamp",
					"type": "string",
					"format": "date-time",
				},
			},
		},
		"v1.DecisionExporterConfig": {"properties": {
			"interval": {
				"description": "S3 exporter interval: range [30s,1h]",
				"type": "string",
				"default": "30s",
			},
			"s3_decisions": {"$ref": "#/definitions/v1.S3Config"},
		}},
		"v1.DecisionResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"type": "string"},
			},
		},
		"v1.DecisionSearchResult": {
			"required": ["items"],
			"properties": {
				"cursor": {"type": "string"},
				"items": {
					"type": "array",
					"items": {"$ref": "#/definitions/v1.Decision"},
				},
			},
		},
		"v1.DecisionsGetRequest": {
			"required": [
				"cursor",
				"start_time",
				"end_time",
				"search",
				"system",
				"stack",
				"limit",
				"result_kind",
				"order",
				"default_timezone",
				"compact",
			],
			"properties": {
				"compact": {
					"description": "return only essential decision fields",
					"type": "boolean",
				},
				"cursor": {
					"description": "continue from cursor position of previous query",
					"type": "string",
				},
				"default_timezone": {
					"description": "client time zone offset. Local time expressions in query are adjusted with this offset",
					"type": "string",
				},
				"end_time": {
					"description": "maximum decision time",
					"type": "string",
					"format": "date-time",
				},
				"limit": {
					"description": "maximum number of decisions to return",
					"type": "integer",
					"format": "int64",
				},
				"order": {
					"description": "ASC, DESC",
					"type": "string",
					"default": "DESC",
				},
				"result_kind": {
					"description": "comma-separated list of ALL, UNKNOWN, ADVICE, ALLOWED, DENIED, ERROR",
					"type": "string",
				},
				"search": {
					"description": "search query",
					"type": "string",
				},
				"stack": {
					"description": "stack ID",
					"type": "string",
				},
				"start_time": {
					"description": "minimum decision time",
					"type": "string",
					"format": "date-time",
				},
				"system": {
					"description": "system ID",
					"type": "string",
				},
			},
		},
		"v1.DecisionsResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.DecisionSearchResult"},
			},
		},
		"v1.DeleteAgentResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.DeleteBranchResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.DeploymentCommand": {
			"required": [
				"title",
				"action",
			],
			"properties": {
				"action": {
					"description": "command text",
					"type": "string",
				},
				"title": {
					"description": "command title",
					"type": "string",
				},
			},
		},
		"v1.DeploymentInstruction": {
			"required": [
				"category",
				"commands",
			],
			"properties": {
				"category": {
					"description": "category/tool name",
					"type": "string",
				},
				"commands": {
					"description": "commands",
					"type": "array",
					"items": {"$ref": "#/definitions/v1.DeploymentCommand"},
				},
			},
		},
		"v1.DeploymentInstructions": {"properties": {
			"install": {
				"description": "installation instructions for various tools",
				"type": "array",
				"items": {"$ref": "#/definitions/v1.DeploymentInstruction"},
				"readOnly": true,
			},
			"uninstall": {
				"description": "uninstallation instructions for various tools",
				"type": "array",
				"items": {"$ref": "#/definitions/v1.DeploymentInstruction"},
				"readOnly": true,
			},
		}},
		"v1.EnforcementConfig": {
			"required": [
				"enforced",
				"type",
			],
			"properties": {
				"enforced": {
					"description": "true if the policy is enforced",
					"type": "boolean",
				},
				"type": {
					"description": "enforcement type e.g. opa, test, mask",
					"type": "string",
				},
			},
		},
		"v1.EntryReplayResult": {"properties": {
			"bundles": {
				"description": "configured bundles",
				"type": "object",
				"additionalProperties": {"$ref": "#/definitions/logs.BundleInfoV1"},
			},
			"decision_id": {
				"description": "unique decision ID",
				"type": "string",
			},
			"erased": {
				"description": "erased fields",
				"type": "array",
				"items": {"type": "string"},
			},
			"error": {
				"description": "evaluation error",
				"type": "string",
			},
			"input": {
				"description": "rego inputs",
				"$ref": "#/definitions/v1.LogEntry.input",
			},
			"labels": {
				"description": "OPA labels",
				"type": "object",
				"additionalProperties": {"type": "string"},
			},
			"metrics": {
				"description": "decision metrics",
				"type": "object",
			},
			"new_result": {
				"description": "new decision result",
				"$ref": "#/definitions/v1.EntryReplayResult.new_result",
			},
			"path": {
				"description": "evaluated path",
				"type": "string",
			},
			"query": {
				"description": "ad-hoc query",
				"type": "string",
			},
			"requested_by": {
				"description": "requested by IP:port",
				"type": "string",
			},
			"result": {
				"description": "evaluation result",
				"$ref": "#/definitions/v1.LogEntry.result",
			},
			"revision": {
				"description": "bundle revision",
				"type": "string",
			},
			"timestamp": {
				"description": "OPA-side decision timestamp",
				"type": "string",
				"format": "date-time",
			},
		}},
		"v1.EntryReplayResult.new_result": {},
		"v1.ErrorResponse": {
			"required": [
				"code",
				"message",
				"errors",
			],
			"properties": {
				"code": {"type": "string"},
				"errors": {
					"type": "array",
					"items": {"type": "string"},
				},
				"message": {"type": "string"},
				"request_id": {"type": "string"},
			},
		},
		"v1.GetFilesResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.RepoFiles"},
			},
		},
		"v1.GetRegionResponse": {
			"required": ["result"],
			"properties": {"result": {
				"type": "array",
				"items": {"$ref": "#/definitions/v1.RegionFF"},
			}},
		},
		"v1.GitRepoConfig": {
			"required": [
				"url",
				"reference",
				"credentials",
				"path",
			],
			"properties": {
				"credentials": {
					"description": "Credentials are looked under the key <name>/<creds>",
					"type": "string",
				},
				"path": {
					"description": "Path to limit the import to",
					"type": "string",
				},
				"reference": {
					"description": "Remote reference, defaults to refs/heads/master",
					"type": "string",
				},
				"ssh_credentials": {
					"description": "SSHCredentials including ssh private key and passphrase for ssh-based auth",
					"$ref": "#/definitions/v1.SSHCredentials",
				},
				"url": {
					"description": "Repository URL",
					"type": "string",
				},
			},
		},
		"v1.GithubConfiguration": {
			"required": ["organizations"],
			"properties": {"organizations": {
				"type": "array",
				"items": {"type": "string"},
			}},
		},
		"v1.Invitation": {
			"required": [
				"id",
				"expiration",
			],
			"properties": {
				"expiration": {
					"description": "invitation expiration date/time",
					"type": "string",
					"format": "date-time",
				},
				"id": {
					"description": "invitation ID (user ID)",
					"type": "string",
				},
			},
		},
		"v1.InvitationResponse": {
			"required": ["url"],
			"properties": {"url": {
				"description": "invitation URL",
				"type": "string",
			}},
		},
		"v1.InvitationsDeleteResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.InvitationsGetResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.Invitation"},
			},
		},
		"v1.InvitationsListResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {
					"type": "array",
					"items": {"$ref": "#/definitions/v1.Invitation"},
				},
			},
		},
		"v1.InvitationsPostRequest": {
			"required": [
				"user_id",
				"roles",
			],
			"properties": {
				"roles": {
					"description": "list of roles for the invited user",
					"type": "array",
					"items": {"$ref": "#/definitions/security.RoleName"},
				},
				"user_id": {
					"description": "user ID to create invitation for",
					"type": "string",
				},
			},
		},
		"v1.InvitationsPostResponse": {"properties": {
			"request_id": {"type": "string"},
			"result": {
				"description": "result with URL is only returned when invitation was not send with e-mail",
				"$ref": "#/definitions/v1.InvitationResponse",
			},
		}},
		"v1.InvitationsPutRequest": {
			"required": [
				"user_id",
				"password",
				"tos_checked",
			],
			"properties": {
				"password": {
					"description": "new user password",
					"type": "string",
				},
				"tos_checked": {
					"description": "terms of service were accepted",
					"type": "boolean",
				},
				"user_id": {
					"description": "new user ID",
					"type": "string",
				},
			},
		},
		"v1.InvitationsPutResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.LogEntry.error": {},
		"v1.LogEntry.input": {},
		"v1.LogEntry.result": {},
		"v1.MetricsExporterConfig": {
			"required": ["targets"],
			"properties": {"targets": {
				"type": "array",
				"items": {"$ref": "#/definitions/v1.MetricsExporterTarget"},
			}},
		},
		"v1.MetricsExporterTarget": {
			"required": [
				"plugin",
				"token_id",
			],
			"properties": {
				"interval": {
					"description": "Metrics polling interval range [30,3600] (seconds)",
					"type": "integer",
					"format": "int32",
					"default": 60,
				},
				"plugin": {
					"description": "Metrics output plugin name [datadog|signalfx]",
					"type": "string",
				},
				"realm": {
					"description": "Plugin realm",
					"type": "string",
				},
				"token_id": {
					"description": "Plugin bearer token reference id to secret stored in v1/secrets",
					"type": "string",
				},
				"url": {
					"description": "Plugin URL",
					"type": "string",
				},
			},
		},
		"v1.MocksHttpData": {
			"required": [
				"url",
				"method",
				"result",
			],
			"properties": {
				"method": {
					"description": "request method",
					"type": "string",
				},
				"result": {
					"description": "mock json result",
					"type": "object",
				},
				"url": {
					"description": "request URL",
					"type": "string",
				},
			},
		},
		"v1.MocksHttpSend": {
			"required": ["data"],
			"properties": {"data": {
				"description": "mock http.send data",
				"type": "array",
				"items": {"$ref": "#/definitions/v1.MocksHttpData"},
			}},
		},
		"v1.MocksOPARuntime": {
			"required": ["result"],
			"properties": {"result": {
				"description": "mock json result",
				"type": "object",
			}},
		},
		"v1.Module": {
			"required": [
				"name",
				"read_only",
			],
			"properties": {
				"name": {
					"description": "module name",
					"type": "string",
				},
				"placeholder": {
					"description": "module is a placeholder",
					"type": "boolean",
					"default": false,
					"readOnly": true,
				},
				"read_only": {
					"description": "true if module is read-only",
					"type": "boolean",
				},
				"rules": {
					"description": "module rule count",
					"$ref": "#/definitions/v1.RuleCounts",
					"readOnly": true,
				},
			},
		},
		"v1.NotificationInstallNewStateResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.NotificationIntegrationResponse": {"properties": {
			"request_id": {"type": "string"},
			"response_url": {"type": "string"},
		}},
		"v1.NotificationToolDeleteResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.NotificationToolResult": {"properties": {
			"installed": {"type": "boolean"},
			"type": {"type": "string"},
		}},
		"v1.NotificationToolStatusResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.NotificationToolResult"},
			},
		},
		"v1.NotificationToolTokenRequest": {
			"required": ["token"],
			"properties": {"token": {"type": "string"}},
		},
		"v1.NotificationToolTokenResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.ObjectMeta": {"properties": {
			"created_at": {
				"type": "string",
				"format": "date-time",
			},
			"created_by": {"type": "string"},
			"created_through": {"type": "string"},
			"last_modified_at": {
				"type": "string",
				"format": "date-time",
			},
			"last_modified_by": {"type": "string"},
			"last_modified_through": {"type": "string"},
		}},
		"v1.PoliciesBulkUploadResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.PoliciesListResponse": {
			"required": ["result"],
			"properties": {
				"metadata": {
					"type": "array",
					"items": {"$ref": "#/definitions/v1.ObjectMeta"},
				},
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.PoliciesListResponse.result"},
			},
		},
		"v1.PoliciesListResponse.result": {},
		"v1.PoliciesPutRequest": {
			"required": [
				"modules",
				"signature",
			],
			"properties": {
				"modules": {
					"type": "object",
					"additionalProperties": {"type": "string"},
				},
				"signature": {"$ref": "#/definitions/crypto.Signature"},
			},
		},
		"v1.PolicyConfig": {
			"required": [
				"id",
				"type",
				"enforcement",
			],
			"properties": {
				"created": {
					"description": "policy on when to (re)generate the policy",
					"type": "string",
				},
				"enforcement": {
					"description": "enforcement status of the policy",
					"$ref": "#/definitions/v1.EnforcementConfig",
				},
				"id": {
					"description": "policy ID (path)",
					"type": "string",
				},
				"modules": {
					"description": "rego modules policy consists of",
					"type": "array",
					"items": {"$ref": "#/definitions/v1.Module"},
				},
				"rules": {
					"description": "rule count",
					"$ref": "#/definitions/v1.RuleCounts",
				},
				"type": {
					"description": "policy type e.g. validating/rules",
					"type": "string",
				},
			},
		},
		"v1.PolicyDeleteResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.PolicyGetResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.PolicyGetResponse.result"},
			},
		},
		"v1.PolicyGetResponse.result": {},
		"v1.PolicyPutResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.PostCommitResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.Commit"},
			},
		},
		"v1.PostDecisionsResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.ProviderConfig": {
			"required": [
				"id",
				"enabled",
				"type",
				"jit",
				"allowed_domains",
				"issuer_url",
				"auth_url",
				"token_url",
				"user_info_url",
				"proxy_url",
				"client_id",
				"client_secret",
				"scopes",
				"metadata",
				"key_certificate",
				"email_attribute",
				"allow_idp_initiated",
			],
			"properties": {
				"allow_idp_initiated": {"type": "boolean"},
				"allowed_domains": {
					"type": "array",
					"items": {"type": "string"},
				},
				"auth_url": {"type": "string"},
				"client_id": {"type": "string"},
				"client_secret": {"type": "string"},
				"email_attribute": {"type": "string"},
				"enabled": {"type": "boolean"},
				"id": {"type": "string"},
				"issuer_url": {"type": "string"},
				"jit": {"type": "boolean"},
				"key_certificate": {"type": "string"},
				"metadata": {"type": "string"},
				"proxy_url": {"type": "string"},
				"scopes": {
					"type": "array",
					"items": {"type": "string"},
				},
				"token_url": {"type": "string"},
				"type": {"type": "string"},
				"user_info_url": {"type": "string"},
			},
		},
		"v1.ProvidersDeleteResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.ProvidersGetResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.ProviderConfig"},
			},
		},
		"v1.ProvidersListResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {
					"type": "array",
					"items": {"$ref": "#/definitions/v1.ProviderConfig"},
				},
			},
		},
		"v1.ProvidersPostRequest": {
			"required": [
				"id",
				"enabled",
				"type",
				"jit",
				"allowed_domains",
				"issuer_url",
				"auth_url",
				"token_url",
				"user_info_url",
				"proxy_url",
				"client_id",
				"client_secret",
				"scopes",
				"metadata",
				"key_certificate",
				"email_attribute",
				"allow_idp_initiated",
			],
			"properties": {
				"allow_idp_initiated": {"type": "boolean"},
				"allowed_domains": {
					"type": "array",
					"items": {"type": "string"},
				},
				"auth_url": {"type": "string"},
				"client_id": {"type": "string"},
				"client_secret": {"type": "string"},
				"email_attribute": {"type": "string"},
				"enabled": {"type": "boolean"},
				"id": {"type": "string"},
				"issuer_url": {"type": "string"},
				"jit": {"type": "boolean"},
				"key_certificate": {"type": "string"},
				"metadata": {"type": "string"},
				"proxy_url": {"type": "string"},
				"scopes": {
					"type": "array",
					"items": {"type": "string"},
				},
				"token_url": {"type": "string"},
				"type": {"type": "string"},
				"user_info_url": {"type": "string"},
			},
		},
		"v1.ProvidersPostResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.ProvidersPutRequest": {
			"required": [
				"id",
				"enabled",
				"type",
				"jit",
				"allowed_domains",
				"issuer_url",
				"auth_url",
				"token_url",
				"user_info_url",
				"proxy_url",
				"client_id",
				"client_secret",
				"scopes",
				"metadata",
				"key_certificate",
				"email_attribute",
				"allow_idp_initiated",
			],
			"properties": {
				"allow_idp_initiated": {"type": "boolean"},
				"allowed_domains": {
					"type": "array",
					"items": {"type": "string"},
				},
				"auth_url": {"type": "string"},
				"client_id": {"type": "string"},
				"client_secret": {"type": "string"},
				"email_attribute": {"type": "string"},
				"enabled": {"type": "boolean"},
				"id": {"type": "string"},
				"issuer_url": {"type": "string"},
				"jit": {"type": "boolean"},
				"key_certificate": {"type": "string"},
				"metadata": {"type": "string"},
				"proxy_url": {"type": "string"},
				"scopes": {
					"type": "array",
					"items": {"type": "string"},
				},
				"token_url": {"type": "string"},
				"type": {"type": "string"},
				"user_info_url": {"type": "string"},
			},
		},
		"v1.ProvidersPutResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.ReasonMapping": {
			"required": ["path"],
			"properties": {"path": {
				"description": "dot-separated decision property path",
				"type": "string",
			}},
		},
		"v1.ReasonValue": {"properties": {
			"error": {"type": "string"},
			"value": {"type": "string"},
		}},
		"v1.RegionFF": {
			"required": [
				"description",
				"title",
				"value",
			],
			"properties": {
				"description": {"type": "string"},
				"title": {"type": "string"},
				"value": {"type": "string"},
			},
		},
		"v1.ReplayRequest": {"properties": {
			"compare_full_results": {
				"description": "do not compare decisions by system-type-dependent significant fields",
				"type": "boolean",
				"default": false,
			},
			"data_patches": {
				"description": "list of JSON Patches to apply to the data namespace",
				"type": "array",
				"items": {"$ref": "#/definitions/json.JsonPatchSpec"},
			},
			"decision_patches": {
				"description": "list of JSON Patches to apply to the decisions before they evaluated",
				"type": "array",
				"items": {"$ref": "#/definitions/json.JsonPatchSpec"},
			},
			"deterministic_policies": {
				"description": "signals that decisions having the same inputs, data and revision always evaluate to the same result and therefore can be cached",
				"type": "boolean",
				"default": true,
			},
			"duration": {
				"description": "maximum replay duration (e.g. \"20s\")",
				"type": "string",
			},
			"max_samples": {
				"description": "maximum number of samples to return",
				"type": "integer",
				"format": "int32",
			},
			"mocks": {
				"description": "mock http.send and opa.runtime builtins",
				"$ref": "#/definitions/v1.BuiltinMocks",
			},
			"policies": {
				"description": "modified rego policies (path => rego content)",
				"type": "object",
				"additionalProperties": {"type": "string"},
			},
			"scope": {
				"description": "list of scopes to narrow the decision search",
				"type": "array",
				"items": {"$ref": "#/definitions/v1.ReplayScope"},
			},
			"skip_batches": {
				"description": "list of batch IDs to skip",
				"type": "array",
				"items": {"type": "string"},
			},
		}},
		"v1.ReplayResult": {
			"required": [
				"started",
				"samples",
				"stats",
				"duration",
				"analyzed_batches",
			],
			"properties": {
				"analyzed_batches": {
					"description": "analyzed decision batches IDs to be used for skip_batches in subsequent requests",
					"type": "array",
					"items": {"type": "string"},
				},
				"duration": {
					"description": "replay duration",
					"type": "integer",
					"format": "integer",
				},
				"samples": {
					"description": "representative change samples",
					"type": "array",
					"items": {"$ref": "#/definitions/v1.EntryReplayResult"},
				},
				"started": {
					"description": "replay start time",
					"type": "string",
					"format": "date-time",
				},
				"stats": {
					"description": "replay statistics",
					"$ref": "#/definitions/v1.ReplayStats",
				},
			},
		},
		"v1.ReplayScope": {"properties": {
			"max_age": {
				"description": "maximum decision age (either in relative duration or in absolute time string)",
				"type": "string",
			},
			"max_revisions": {
				"description": "maximum number of revisions to analyze back from the latest revision",
				"type": "integer",
				"format": "int64",
				"default": 1,
			},
			"min_age": {
				"description": "minimum decision age (either in relative duration or in absolute time string)",
				"type": "string",
			},
			"path": {
				"description": "decision path must overlap with this one (can be subpath of the decision path to compare portion of the result)",
				"type": "string",
			},
		}},
		"v1.ReplayStats": {
			"required": [
				"batches_observed",
				"batches_analyzed",
				"entries_observed",
				"entries_evaluated",
				"entries_scheduled",
				"entries_failed",
				"analysis_errors",
				"results_changed",
				"batches_downloaded",
				"batches_download_errors",
				"batches_from_cache",
				"batches_scheduled",
				"batches_skipped",
			],
			"properties": {
				"analysis_errors": {
					"description": "number of invalid decisions that could not be replayed (<= entries_evaluated)",
					"type": "integer",
					"format": "int64",
				},
				"batches_analyzed": {
					"description": "number of fully analyzed decision batches (<= batches_observed)",
					"type": "integer",
					"format": "int64",
				},
				"batches_download_errors": {
					"description": "number of decision batches that could not be downloaded",
					"type": "integer",
					"format": "int64",
				},
				"batches_downloaded": {
					"description": "number of downloaded decision batches (<= batches_scheduled)",
					"type": "integer",
					"format": "int64",
				},
				"batches_from_cache": {
					"description": "number of downloaded decision batches taken from the cache (<= batches_downloaded)",
					"type": "integer",
					"format": "int64",
				},
				"batches_observed": {
					"description": "number of decision batches picked by the analyzers (<= batches_downloaded)",
					"type": "integer",
					"format": "int64",
				},
				"batches_scheduled": {
					"description": "number of decision batches scheduled for download",
					"type": "integer",
					"format": "int64",
				},
				"batches_skipped": {
					"description": "number of decision batches skipped due to the skip_batches input or pre-filtration (timestamp range, system/stack IDs)",
					"type": "integer",
					"format": "int64",
				},
				"entries_evaluated": {
					"description": "number of replayed decisions (<= entries_scheduled)",
					"type": "integer",
					"format": "int64",
				},
				"entries_failed": {
					"description": "number of decisions evaluated to error (<= entries_evaluated)",
					"type": "integer",
					"format": "int64",
				},
				"entries_observed": {
					"description": "number of decisions in batches_observed batches",
					"type": "integer",
					"format": "int64",
				},
				"entries_scheduled": {
					"description": "number of decisions scheduled for replay (<= entries_observed)",
					"type": "integer",
					"format": "int64",
				},
				"results_changed": {
					"description": "number of observed decision changes (<= entries_evaluated)",
					"type": "integer",
					"format": "int64",
				},
			},
		},
		"v1.RepoFiles": {
			"required": ["files"],
			"properties": {
				"deleted_files": {
					"type": "array",
					"items": {"type": "string"},
				},
				"files": {
					"type": "object",
					"additionalProperties": {"type": "string"},
				},
			},
		},
		"v1.RequestData": {
			"required": [
				"tenant",
				"id",
				"host",
				"method",
				"path",
				"timestamp",
			],
			"properties": {
				"body": {"type": "string"},
				"errors": {"$ref": "#/definitions/v1.RequestErrors"},
				"host": {"type": "string"},
				"id": {"type": "string"},
				"method": {"type": "string"},
				"path": {"type": "string"},
				"request_body": {"type": "string"},
				"requested_by": {"type": "string"},
				"requested_through": {"type": "string"},
				"tenant": {"type": "string"},
				"timestamp": {
					"type": "string",
					"format": "date-time",
				},
			},
		},
		"v1.RequestErrors": {"properties": {"evaluation": {"type": "string"}}},
		"v1.ResourceRole": {
			"required": [
				"resource_type",
				"resource_id",
				"role_name",
			],
			"properties": {
				"resource_id": {"type": "string"},
				"resource_type": {"type": "string"},
				"role_name": {"type": "string"},
			},
		},
		"v1.ResponseData": {
			"required": [
				"timestamp",
				"status_code",
			],
			"properties": {
				"body": {"type": "string"},
				"errors": {"$ref": "#/definitions/v1.ResponseErrors"},
				"status_code": {
					"type": "integer",
					"format": "int32",
				},
				"timestamp": {
					"type": "string",
					"format": "date-time",
				},
			},
		},
		"v1.ResponseErrors": {"properties": {"processing": {"type": "string"}}},
		"v1.RoleBindingConfig": {
			"required": [
				"id",
				"role_name",
			],
			"properties": {
				"id": {
					"description": "role binding ID",
					"type": "string",
				},
				"role_name": {
					"description": "role name",
					"type": "string",
				},
			},
		},
		"v1.RoleBindingsDeleteResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.RoleBindingsGetResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.RoleBindingConfig"},
			},
		},
		"v1.RoleBindingsListAllResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {
					"type": "object",
					"additionalProperties": {"$ref": "#/definitions/v1.RoleBindingsListAllResponse.result"},
				},
			},
		},
		"v1.RoleBindingsListAllResponse.result": {},
		"v1.RoleBindingsListResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {
					"type": "array",
					"items": {"$ref": "#/definitions/v1.RoleBindingConfig"},
				},
			},
		},
		"v1.RoleBindingsPutRequest": {
			"required": [
				"id",
				"description",
				"subjects",
				"role_name",
			],
			"properties": {
				"description": {"type": "string"},
				"id": {"type": "string"},
				"role_name": {"type": "string"},
				"subjects": {
					"type": "array",
					"items": {"type": "string"},
				},
			},
		},
		"v1.RoleBindingsPutResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.RoleConfig": {
			"required": ["name"],
			"properties": {"name": {"type": "string"}},
		},
		"v1.RolesListResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {
					"type": "array",
					"items": {"$ref": "#/definitions/v1.RoleConfig"},
				},
			},
		},
		"v1.RuleCounts": {
			"required": [
				"total",
				"allow",
				"deny",
				"enforce",
				"monitor",
				"ignore",
				"notify",
				"test",
				"other",
			],
			"properties": {
				"allow": {
					"description": "number of allow rules",
					"type": "integer",
					"format": "int32",
				},
				"deny": {
					"description": "number of deny rules",
					"type": "integer",
					"format": "int32",
				},
				"enforce": {
					"description": "number of enforce rules",
					"type": "integer",
					"format": "int32",
				},
				"ignore": {
					"description": "number of ignore rules",
					"type": "integer",
					"format": "int32",
				},
				"monitor": {
					"description": "number of monitor rules",
					"type": "integer",
					"format": "int32",
				},
				"notify": {
					"description": "number of notify rules",
					"type": "integer",
					"format": "int32",
				},
				"other": {
					"description": "number of unclassified rules",
					"type": "integer",
					"format": "int32",
				},
				"test": {
					"description": "number of test rules",
					"type": "integer",
					"format": "int32",
				},
				"total": {
					"description": "total number of rules",
					"type": "integer",
					"format": "int32",
				},
			},
		},
		"v1.RuleDecisionMappings": {"properties": {
			"allowed": {
				"description": "rules to determine decision type (allowed, denied)",
				"$ref": "#/definitions/v1.AllowedMapping",
			},
			"columns": {
				"description": "decision mappings for additional columns",
				"type": "array",
				"items": {"$ref": "#/definitions/v1.ColumnMapping"},
			},
			"reason": {
				"description": "decision mapping for the reason field",
				"$ref": "#/definitions/v1.ReasonMapping",
			},
		}},
		"v1.S3Config": {
			"required": [
				"url",
				"region",
				"access_keys",
			],
			"properties": {
				"access_keys": {
					"description": "Access key ID and secret access key are stored at /v1/secrets/${access_keys}",
					"type": "string",
				},
				"endpoint": {
					"description": "Custom endpoint or S3 compatible system endpoint (ie: https://storage.googleapis.com)",
					"type": "string",
				},
				"region": {
					"description": "S3 Region (ie: us-east-1 or auto)",
					"type": "string",
				},
				"url": {
					"description": "S3 Bucket URL (ie: s3://styra-storage or gs://styra-storage/folder)",
					"type": "string",
				},
			},
		},
		"v1.S3ConfigGetResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.DecisionExporterConfig"},
			},
		},
		"v1.S3ConfigPutRequest": {"properties": {
			"interval": {
				"description": "S3 exporter interval: range [30s,1h]",
				"type": "string",
				"default": "30s",
			},
			"s3_decisions": {"$ref": "#/definitions/v1.S3Config"},
		}},
		"v1.S3VerifyResponse": {
			"required": [
				"s3_code",
				"s3_message",
			],
			"properties": {
				"request_id": {"type": "string"},
				"s3_code": {"type": "string"},
				"s3_message": {"type": "string"},
			},
		},
		"v1.SSHCredentials": {
			"required": [
				"private_key",
				"passphrase",
			],
			"properties": {
				"passphrase": {
					"description": "Passphrase is looked under the key passphrase/<pass>",
					"type": "string",
				},
				"private_key": {
					"description": "PrivateKey is looked under the key private-key/<key>",
					"type": "string",
				},
			},
		},
		"v1.Secret": {
			"required": [
				"name",
				"description",
				"id",
				"metadata",
			],
			"properties": {
				"description": {"type": "string"},
				"id": {"type": "string"},
				"metadata": {"$ref": "#/definitions/v1.ObjectMeta"},
				"name": {"type": "string"},
			},
		},
		"v1.SecretsDeleteResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.SecretsGetResponse": {"properties": {
			"request_id": {"type": "string"},
			"result": {"$ref": "#/definitions/v1.Secret"},
		}},
		"v1.SecretsListResponse": {"properties": {
			"request_id": {"type": "string"},
			"result": {
				"type": "array",
				"items": {"$ref": "#/definitions/v1.Secret"},
			},
		}},
		"v1.SecretsPutRequest": {
			"required": [
				"name",
				"description",
				"secret",
			],
			"properties": {
				"description": {"type": "string"},
				"name": {"type": "string"},
				"secret": {"type": "string"},
			},
		},
		"v1.SecretsPutResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.SortField": {
			"required": ["field"],
			"properties": {
				"descending": {
					"description": "true to sort in descending order",
					"type": "boolean",
				},
				"field": {
					"description": "dot.path field expression",
					"type": "string",
				},
			},
		},
		"v1.SourceControlConfig": {
			"required": ["origin"],
			"properties": {"origin": {"$ref": "#/definitions/v1.GitRepoConfig"}},
		},
		"v1.StackConfig": {
			"required": [
				"description",
				"read_only",
				"name",
				"type",
				"id",
				"policies",
				"metadata",
				"status",
			],
			"properties": {
				"authz": {
					"description": "authorization config",
					"$ref": "#/definitions/v1.AuthzConfig",
					"readOnly": true,
				},
				"datasources": {
					"description": "datasources created for the stack",
					"type": "array",
					"items": {"$ref": "#/definitions/v1.DatasourceConfig"},
					"readOnly": true,
				},
				"description": {"type": "string"},
				"id": {"type": "string"},
				"matching_systems": {
					"description": "IDs of systems matching the stack",
					"type": "array",
					"items": {"type": "string"},
				},
				"metadata": {"$ref": "#/definitions/v1.ObjectMeta"},
				"minimum_opa_version": {
					"description": "minimum running OPA version for any of the matching systems",
					"type": "string",
				},
				"name": {"type": "string"},
				"policies": {
					"type": "array",
					"items": {"$ref": "#/definitions/v1.PolicyConfig"},
				},
				"read_only": {"type": "boolean"},
				"source_control": {"$ref": "#/definitions/v1.SourceControlConfig"},
				"status": {"type": "string"},
				"type": {"type": "string"},
				"type_parameters": {
					"description": "stack type parameter values (for template.* types)",
					"type": "object",
				},
			},
		},
		"v1.StacksComplianceRequest": {"properties": {
			"drafts": {
				"description": "draft policies to be used for 'new' violations computation (path => rego)",
				"type": "object",
				"additionalProperties": {"type": "string"},
			},
			"extended": {
				"description": "run extended compliance validation that is specific for the system/stack type",
				"type": "boolean",
			},
			"filter": {
				"description": "filter violations with this selector (dot.path => value)",
				"type": "object",
			},
			"group_by": {
				"description": "group results by dot.path values (list of group levels with list of fields at each level)",
				"type": "array",
				"items": {"$ref": "#/definitions/v1.StacksComplianceRequest.group_by"},
			},
			"mocks": {
				"description": "mock http.send and opa.runtime builtins",
				"$ref": "#/definitions/v1.BuiltinMocks",
			},
			"mode": {
				"description": "validation mode. One of (delta, all, delta-count, all-count)",
				"type": "string",
				"default": "delta",
			},
			"policy_type": {
				"description": "policy type to narrow the monitor policy search (e.g. validating, mutating). Default (empty string or missing) is to run all monitoring policies",
				"type": "string",
			},
			"sort": {
				"description": "list of fields to sort by",
				"type": "array",
				"items": {"$ref": "#/definitions/v1.SortField"},
			},
		}},
		"v1.StacksComplianceRequest.group_by": {},
		"v1.StacksComplianceResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {
					"type": "object",
					"additionalProperties": {"$ref": "#/definitions/v1.ComplianceValidation"},
				},
			},
		},
		"v1.StacksDeleteResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.StacksGetResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.StackConfig"},
			},
		},
		"v1.StacksListResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {
					"type": "array",
					"items": {"$ref": "#/definitions/v1.StackConfig"},
				},
			},
		},
		"v1.StacksPostRequest": {
			"required": [
				"name",
				"type",
				"description",
				"read_only",
			],
			"properties": {
				"description": {"type": "string"},
				"name": {"type": "string"},
				"read_only": {"type": "boolean"},
				"source_control": {"$ref": "#/definitions/v1.SourceControlConfig"},
				"type": {"type": "string"},
				"type_parameters": {
					"description": "stack type parameter values (for template.* types)",
					"type": "object",
				},
			},
		},
		"v1.StacksPostResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.StackConfig"},
			},
		},
		"v1.StacksPutRequest": {
			"required": [
				"name",
				"type",
				"description",
				"read_only",
			],
			"properties": {
				"description": {"type": "string"},
				"name": {"type": "string"},
				"read_only": {"type": "boolean"},
				"source_control": {"$ref": "#/definitions/v1.SourceControlConfig"},
				"type": {"type": "string"},
				"type_parameters": {
					"description": "stack type parameter values (for template.* types)",
					"type": "object",
				},
			},
		},
		"v1.StacksPutResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.StacksTestsRequest": {"properties": {
			"drafts": {
				"description": "draft policies to be used for 'new' violations computation (path => rego)",
				"type": "object",
				"additionalProperties": {"type": "string"},
			},
			"mode": {
				"description": "validation mode. One of (delta, all, delta-count, all-count)",
				"type": "string",
				"default": "delta",
			},
			"policy_type": {
				"description": "policy type to narrow the monitor policy search (e.g. validating, mutating). Default (empty string or missing) is to run all monitoring policies",
				"type": "string",
			},
		}},
		"v1.StacksTestsResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {
					"type": "object",
					"additionalProperties": {"$ref": "#/definitions/v1.UnitTestsValidation"},
				},
			},
		},
		"v1.Status": {
			"required": ["authz_migration"],
			"properties": {"authz_migration": {"type": "string"}},
		},
		"v1.StatusGetResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {
					"type": "object",
					"additionalProperties": {"$ref": "#/definitions/v1.AgentStatus"},
				},
			},
		},
		"v1.StatusPostResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.SystemConfig": {
			"required": [
				"name",
				"type",
				"id",
				"policies",
				"authz",
				"metadata",
				"status",
			],
			"properties": {
				"authz": {
					"description": "authorization config",
					"$ref": "#/definitions/v1.AuthzConfig",
				},
				"bundle_registry": {
					"description": "bundle registry configuration",
					"$ref": "#/definitions/v1.BundleRegistryConfig",
				},
				"datasources": {
					"description": "datasources created for the system",
					"type": "array",
					"items": {"$ref": "#/definitions/v1.DatasourceConfig"},
					"readOnly": true,
				},
				"decision_mappings": {
					"description": "location of key attributes and additional columns in the decisions grouped by policy entry point path",
					"type": "object",
					"additionalProperties": {"$ref": "#/definitions/v1.RuleDecisionMappings"},
				},
				"deployment_parameters": {
					"description": "configuration settings to be used by the system agents",
					"$ref": "#/definitions/v1.SystemDeploymentParameters",
				},
				"description": {
					"description": "description for the system",
					"type": "string",
				},
				"error_setting": {
					"description": "error/warning configuration: one of \"all\", \"errors\", \"none\"",
					"type": "string",
				},
				"errors": {
					"description": "current deployment errors",
					"type": "object",
					"additionalProperties": {"$ref": "#/definitions/v1.AgentErrors"},
					"readOnly": true,
				},
				"external_id": {
					"description": "external system ID",
					"type": "string",
				},
				"id": {
					"description": "system ID",
					"type": "string",
				},
				"install": {
					"description": "installation instructions by installation method and asset type (deprecated)",
					"type": "object",
					"additionalProperties": {"$ref": "#/definitions/v1.SystemConfig.install"},
					"readOnly": true,
				},
				"matching_stacks": {
					"description": "IDs of stacks matching the system",
					"type": "array",
					"items": {"type": "string"},
				},
				"metadata": {
					"description": "system object metadata",
					"$ref": "#/definitions/v1.ObjectMeta",
				},
				"minimum_opa_version": {
					"description": "minimum running OPA version for the systems",
					"type": "string",
				},
				"name": {
					"description": "system name",
					"type": "string",
				},
				"policies": {
					"description": "policies created for the system",
					"type": "array",
					"items": {"$ref": "#/definitions/v1.PolicyConfig"},
				},
				"read_only": {
					"description": "prevents users from modifying policies using Styra UIs",
					"type": "boolean",
					"default": false,
				},
				"source_control": {
					"description": "source control system configuration",
					"$ref": "#/definitions/v1.SourceControlConfig",
				},
				"status": {
					"description": "system status",
					"type": "string",
				},
				"tokens": {
					"description": "tokens created for the system",
					"type": "array",
					"items": {"$ref": "#/definitions/v1.Token"},
					"readOnly": true,
				},
				"type": {
					"description": "system type e.g. kubernetes",
					"type": "string",
				},
				"type_parameters": {
					"description": "system type parameter values (for template.* types)",
					"type": "object",
				},
				"uninstall": {
					"description": "uninstallation instructions by installation method (deprecated)",
					"type": "object",
					"additionalProperties": {"type": "string"},
					"readOnly": true,
				},
				"warnings": {
					"description": "current deployment warnings",
					"type": "object",
					"additionalProperties": {"$ref": "#/definitions/v1.SystemConfig.warnings"},
					"readOnly": true,
				},
			},
		},
		"v1.SystemConfig.install": {},
		"v1.SystemConfig.warnings": {
			"required": [
				"code",
				"message",
				"timestamp",
			],
			"properties": {
				"code": {"type": "string"},
				"message": {"type": "string"},
				"timestamp": {
					"type": "string",
					"format": "date-time",
				},
			},
		},
		"v1.SystemDeploymentParameters": {"properties": {
			"deny_on_opa_fail": {
				"description": "true to fail close",
				"type": "boolean",
				"default": false,
			},
			"extra": {
				"description": "extra deployment settings",
				"type": "object",
			},
			"http_proxy": {
				"description": "HTTP proxy URL",
				"type": "string",
			},
			"https_proxy": {
				"description": "HTTPS proxy URL",
				"type": "string",
			},
			"kubernetes_version": {
				"description": "minimum Kubernetes version expected (where applicable)",
				"type": "string",
			},
			"namespace": {
				"description": "Kubernetes namespace the system is deployed to",
				"type": "string",
			},
			"no_proxy": {
				"description": "URLs that should be excluded from proxying",
				"type": "string",
			},
			"timeout_seconds": {
				"description": "Kubernetes webhook timeout (where applicable)",
				"type": "integer",
				"format": "int32",
			},
			"trusted_ca_certs": {
				"description": "trusted CA certificates",
				"type": "array",
				"items": {"type": "string"},
			},
			"trusted_container_registry": {
				"description": "trusted container registry",
				"type": "string",
			},
		}},
		"v1.SystemsComplianceRequest": {"properties": {
			"drafts": {
				"description": "draft policies to be used for 'new' violations computation (path => rego)",
				"type": "object",
				"additionalProperties": {"type": "string"},
			},
			"extended": {
				"description": "run extended compliance validation that is specific for the system/stack type",
				"type": "boolean",
			},
			"filter": {
				"description": "filter violations with this selector (dot.path => value)",
				"type": "object",
			},
			"group_by": {
				"description": "group results by dot.path values (list of group levels with list of fields at each level)",
				"type": "array",
				"items": {"$ref": "#/definitions/v1.SystemsComplianceRequest.group_by"},
			},
			"mocks": {
				"description": "mock http.send and opa.runtime builtins",
				"$ref": "#/definitions/v1.BuiltinMocks",
			},
			"mode": {
				"description": "validation mode. One of (delta, all, delta-count, all-count)",
				"type": "string",
				"default": "delta",
			},
			"policy_type": {
				"description": "policy type to narrow the monitor policy search (e.g. validating, mutating). Default (empty string or missing) is to run all monitoring policies",
				"type": "string",
			},
			"sort": {
				"description": "list of fields to sort by",
				"type": "array",
				"items": {"$ref": "#/definitions/v1.SortField"},
			},
		}},
		"v1.SystemsComplianceRequest.group_by": {},
		"v1.SystemsComplianceResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {
					"type": "object",
					"additionalProperties": {"$ref": "#/definitions/v1.ComplianceValidation"},
				},
			},
		},
		"v1.SystemsDeleteResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.SystemsGetAgentsResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {
					"type": "array",
					"items": {"$ref": "#/definitions/v1.AgentConfig"},
				},
			},
		},
		"v1.SystemsGetBundleDeployResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.BundleDeployStatus"},
			},
		},
		"v1.SystemsGetBundleDetailsResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.BundleDetails"},
			},
		},
		"v1.SystemsGetBundlesResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {
					"type": "array",
					"items": {"$ref": "#/definitions/v1.Bundle"},
				},
			},
		},
		"v1.SystemsGetDefaultPoliciesResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {
					"type": "object",
					"additionalProperties": {"type": "string"},
				},
			},
		},
		"v1.SystemsGetDefaultPolicyResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"type": "string"},
			},
		},
		"v1.SystemsGetInstructionsResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.DeploymentInstructions"},
			},
		},
		"v1.SystemsGetResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.SystemConfig"},
			},
		},
		"v1.SystemsListResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {
					"type": "array",
					"items": {"$ref": "#/definitions/v1.SystemConfig"},
				},
			},
		},
		"v1.SystemsPostRequest": {
			"required": [
				"name",
				"type",
			],
			"properties": {
				"bundle_registry": {
					"description": "bundle registry configuration",
					"$ref": "#/definitions/v1.BundleRegistryConfig",
				},
				"decision_mappings": {
					"description": "location of key attributes and additional columns in the decisions grouped by policy entry point path",
					"type": "object",
					"additionalProperties": {"$ref": "#/definitions/v1.RuleDecisionMappings"},
				},
				"deployment_parameters": {
					"description": "configuration settings to be used by the system agents",
					"$ref": "#/definitions/v1.SystemDeploymentParameters",
				},
				"description": {
					"description": "description for the system",
					"type": "string",
				},
				"error_setting": {
					"description": "error/warning configuration: one of \"all\", \"errors\", \"none\"",
					"type": "string",
				},
				"external_id": {
					"description": "external system ID",
					"type": "string",
				},
				"name": {
					"description": "system name",
					"type": "string",
				},
				"read_only": {
					"description": "prevents users from modifying policies using Styra UIs",
					"type": "boolean",
					"default": false,
				},
				"source_control": {
					"description": "source control system configuration",
					"$ref": "#/definitions/v1.SourceControlConfig",
				},
				"type": {
					"description": "system type e.g. kubernetes",
					"type": "string",
				},
				"type_parameters": {
					"description": "system type parameter values (for template.* types)",
					"type": "object",
				},
			},
		},
		"v1.SystemsPostResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.SystemConfig"},
			},
		},
		"v1.SystemsPutBundleCompileRequest": {},
		"v1.SystemsPutBundleCompileResponse": {
			"required": ["result"],
			"properties": {"result": {"$ref": "#/definitions/v1.BundleDetails"}},
		},
		"v1.SystemsPutBundleDeployRequest": {
			"required": [
				"primary",
				"force",
			],
			"properties": {
				"force": {
					"description": "activate even if bundle is not compatible with running agents",
					"type": "boolean",
				},
				"primary": {
					"description": "primary bundle to activate",
					"$ref": "#/definitions/v1.BundleActivation",
				},
			},
		},
		"v1.SystemsPutBundleDeployResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.SystemsPutRequest": {
			"required": [
				"name",
				"type",
			],
			"properties": {
				"bundle_registry": {
					"description": "bundle registry configuration",
					"$ref": "#/definitions/v1.BundleRegistryConfig",
				},
				"decision_mappings": {
					"description": "location of key attributes and additional columns in the decisions grouped by policy entry point path",
					"type": "object",
					"additionalProperties": {"$ref": "#/definitions/v1.RuleDecisionMappings"},
				},
				"deployment_parameters": {
					"description": "configuration settings to be used by the system agents",
					"$ref": "#/definitions/v1.SystemDeploymentParameters",
				},
				"description": {
					"description": "description for the system",
					"type": "string",
				},
				"error_setting": {
					"description": "error/warning configuration: one of \"all\", \"errors\", \"none\"",
					"type": "string",
				},
				"external_id": {
					"description": "external system ID",
					"type": "string",
				},
				"name": {
					"description": "system name",
					"type": "string",
				},
				"read_only": {
					"description": "prevents users from modifying policies using Styra UIs",
					"type": "boolean",
					"default": false,
				},
				"source_control": {
					"description": "source control system configuration",
					"$ref": "#/definitions/v1.SourceControlConfig",
				},
				"type": {
					"description": "system type e.g. kubernetes",
					"type": "string",
				},
				"type_parameters": {
					"description": "system type parameter values (for template.* types)",
					"type": "object",
				},
			},
		},
		"v1.SystemsPutResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.SystemConfig"},
			},
		},
		"v1.SystemsSuggestedRulesResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"type": "string"},
			},
		},
		"v1.SystemsTestsRequest": {"properties": {
			"drafts": {
				"description": "draft policies to be used for 'new' violations computation (path => rego)",
				"type": "object",
				"additionalProperties": {"type": "string"},
			},
			"mode": {
				"description": "validation mode. One of (delta, all, delta-count, all-count)",
				"type": "string",
				"default": "delta",
			},
			"policy_type": {
				"description": "policy type to narrow the monitor policy search (e.g. validating, mutating). Default (empty string or missing) is to run all monitoring policies",
				"type": "string",
			},
		}},
		"v1.SystemsTestsResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {
					"type": "object",
					"additionalProperties": {"$ref": "#/definitions/v1.UnitTestsValidation"},
				},
			},
		},
		"v1.SystemsTranslateExternalIdsRequest": {
			"required": ["external_ids"],
			"properties": {"external_ids": {
				"type": "array",
				"items": {"type": "string"},
			}},
		},
		"v1.SystemsTranslateExternalIdsResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {
					"type": "object",
					"additionalProperties": {"$ref": "#/definitions/v1.SystemsTranslateExternalIdsResponse.result"},
				},
			},
		},
		"v1.SystemsTranslateExternalIdsResponse.result": {},
		"v1.TesterResult": {
			"required": [
				"location",
				"package",
				"name",
				"fail",
				"duration",
			],
			"properties": {
				"duration": {
					"type": "integer",
					"format": "integer",
				},
				"error": {"type": "string"},
				"fail": {"type": "boolean"},
				"failed_at": {"$ref": "#/definitions/ast.Expr"},
				"location": {"$ref": "#/definitions/location.Location"},
				"name": {"type": "string"},
				"package": {"type": "string"},
				"presence_changed": {"type": "boolean"},
			},
		},
		"v1.TimeSeriesData": {
			"required": [
				"date",
				"value",
			],
			"properties": {
				"date": {"type": "string"},
				"value": {
					"type": "integer",
					"format": "int64",
				},
			},
		},
		"v1.TimeSeriesPostResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.TimeSeriesResult"},
			},
		},
		"v1.TimeSeriesResult": {
			"required": ["data"],
			"properties": {"data": {
				"type": "array",
				"items": {"$ref": "#/definitions/v1.TimeSeriesData"},
			}},
		},
		"v1.TimeSeriesUsageData": {
			"required": [
				"date",
				"node_count",
				"decision_rate",
			],
			"properties": {
				"date": {"type": "string"},
				"decision_rate": {
					"type": "integer",
					"format": "int64",
				},
				"node_count": {
					"type": "integer",
					"format": "int64",
				},
			},
		},
		"v1.TimeSeriesUsagePostResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.TimeSeriesUsageResult"},
			},
		},
		"v1.TimeSeriesUsageResult": {
			"required": ["data"],
			"properties": {"data": {
				"type": "array",
				"items": {"$ref": "#/definitions/v1.TimeSeriesUsageData"},
			}},
		},
		"v1.Token": {
			"required": [
				"id",
				"description",
				"uses",
				"ttl",
				"expires",
				"allow_path_patterns",
				"metadata",
			],
			"properties": {
				"allow_path_patterns": {
					"type": "array",
					"items": {"type": "string"},
				},
				"description": {"type": "string"},
				"expires": {
					"type": "string",
					"format": "date-time",
				},
				"id": {"type": "string"},
				"metadata": {"$ref": "#/definitions/v1.ObjectMeta"},
				"token": {"type": "string"},
				"ttl": {"type": "string"},
				"uses": {
					"type": "integer",
					"format": "int64",
				},
			},
		},
		"v1.TokensDeleteResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.TokensGetResponse": {"properties": {
			"request_id": {"type": "string"},
			"result": {"$ref": "#/definitions/v1.Token"},
		}},
		"v1.TokensListResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {
					"type": "array",
					"items": {"$ref": "#/definitions/v1.Token"},
				},
			},
		},
		"v1.TokensPutRequest": {
			"required": [
				"description",
				"allow_path_patterns",
				"regenerate",
			],
			"properties": {
				"allow_path_patterns": {
					"type": "array",
					"items": {"type": "string"},
				},
				"description": {"type": "string"},
				"regenerate": {"type": "boolean"},
				"ttl": {"type": "string"},
			},
		},
		"v1.TokensPutResponse": {"properties": {
			"request_id": {"type": "string"},
			"result": {"type": "string"},
		}},
		"v1.UnitTestsValidation": {"properties": {
			"all": {
				"type": "array",
				"items": {"$ref": "#/definitions/v1.TesterResult"},
			},
			"all_count": {
				"type": "integer",
				"format": "int32",
			},
			"all_errors_count": {
				"type": "integer",
				"format": "int32",
			},
			"all_failed_count": {
				"type": "integer",
				"format": "int32",
			},
			"new": {
				"type": "array",
				"items": {"$ref": "#/definitions/v1.TesterResult"},
			},
			"new_count": {
				"type": "integer",
				"format": "int32",
			},
			"new_errors_count": {
				"type": "integer",
				"format": "int32",
			},
			"new_failed_count": {
				"type": "integer",
				"format": "int32",
			},
			"resolved": {
				"type": "array",
				"items": {"$ref": "#/definitions/v1.TesterResult"},
			},
			"resolved_count": {
				"type": "integer",
				"format": "int32",
			},
			"resolved_errors_count": {
				"type": "integer",
				"format": "int32",
			},
			"resolved_failed_count": {
				"type": "integer",
				"format": "int32",
			},
			"unchanged": {
				"type": "array",
				"items": {"$ref": "#/definitions/v1.TesterResult"},
			},
			"unchanged_count": {
				"type": "integer",
				"format": "int32",
			},
			"unchanged_errors_count": {
				"type": "integer",
				"format": "int32",
			},
			"unchanged_failed_count": {
				"type": "integer",
				"format": "int32",
			},
		}},
		"v1.User": {
			"required": [
				"enabled",
				"id",
			],
			"properties": {
				"enabled": {"type": "boolean"},
				"id": {"type": "string"},
				"resource_roles": {
					"type": "array",
					"items": {"$ref": "#/definitions/v1.ResourceRole"},
				},
				"roles": {
					"type": "array",
					"items": {"$ref": "#/definitions/security.RoleName"},
				},
			},
		},
		"v1.UsersDeleteResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.UsersGetResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.User"},
			},
		},
		"v1.UsersListResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {
					"type": "array",
					"items": {"$ref": "#/definitions/v1.User"},
				},
			},
		},
		"v1.UsersPutRequest": {
			"required": ["enabled"],
			"properties": {
				"enabled": {"type": "boolean"},
				"old_password": {"type": "string"},
				"password": {"type": "string"},
				"roles": {
					"type": "array",
					"items": {"$ref": "#/definitions/security.RoleName"},
				},
			},
		},
		"v1.UsersPutResponse": {"properties": {"request_id": {"type": "string"}}},
		"v1.VerifiedRepoConfig": {
			"required": [
				"url",
				"reference",
				"credentials",
				"path",
				"sha",
			],
			"properties": {
				"credentials": {
					"description": "Credentials are looked under the key <name>/<creds>",
					"type": "string",
				},
				"path": {
					"description": "Path to limit the import to",
					"type": "string",
				},
				"reference": {
					"description": "Remote reference, defaults to refs/heads/master",
					"type": "string",
				},
				"sha": {"type": "string"},
				"ssh_credentials": {
					"description": "SSHCredentials including ssh private key and passphrase for ssh-based auth",
					"$ref": "#/definitions/v1.SSHCredentials",
				},
				"url": {
					"description": "Repository URL",
					"type": "string",
				},
			},
		},
		"v1.VerifyConfigRequest": {
			"required": [
				"id",
				"path",
				"url",
				"reference",
				"credentials",
			],
			"properties": {
				"credentials": {
					"description": "Credentials are looked under the key <name>/<creds>",
					"type": "string",
				},
				"id": {
					"description": "id of the entity so that the config can be checked for duplicates",
					"type": "string",
				},
				"path": {
					"description": "Path to limit the import to",
					"type": "string",
				},
				"reference": {
					"description": "Remote reference, defaults to refs/heads/master",
					"type": "string",
				},
				"ssh_credentials": {
					"description": "SSHCredentials including ssh private key and passphrase for ssh-based auth",
					"$ref": "#/definitions/v1.SSHCredentials",
				},
				"url": {
					"description": "Repository URL",
					"type": "string",
				},
			},
		},
		"v1.VerifyConfigResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.VerifiedRepoConfig"},
			},
		},
		"v1.WorkspaceConfig": {"properties": {
			"activity_exporter": {"$ref": "#/definitions/v1.ActivityExporterConfig"},
			"decisions_exporter": {"$ref": "#/definitions/v1.DecisionExporterConfig"},
			"github": {"$ref": "#/definitions/v1.GithubConfiguration"},
			"metadata": {"$ref": "#/definitions/v1.ObjectMeta"},
			"metrics_exporter": {"$ref": "#/definitions/v1.MetricsExporterConfig"},
			"source_control": {"$ref": "#/definitions/v1.SourceControlConfig"},
			"status": {"$ref": "#/definitions/v1.Status"},
		}},
		"v1.WorkspaceGetResponse": {
			"required": ["result"],
			"properties": {
				"request_id": {"type": "string"},
				"result": {"$ref": "#/definitions/v1.WorkspaceConfig"},
			},
		},
		"v1.WorkspacePutRequest": {"properties": {
			"activity_exporter": {"$ref": "#/definitions/v1.ActivityExporterConfig"},
			"decisions_exporter": {"$ref": "#/definitions/v1.DecisionExporterConfig"},
			"github": {"$ref": "#/definitions/v1.GithubConfiguration"},
			"metrics_exporter": {"$ref": "#/definitions/v1.MetricsExporterConfig"},
			"source_control": {"$ref": "#/definitions/v1.SourceControlConfig"},
		}},
		"v1.WorkspacePutResponse": {"properties": {"request_id": {"type": "string"}}},
		"v2.ClaimConfig": {
			"required": [
				"identity_provider",
				"key",
				"value",
			],
			"properties": {
				"identity_provider": {"type": "string"},
				"key": {"type": "string"},
				"value": {"type": "string"},
			},
		},
		"v2.ResourceFilter": {
			"required": [
				"kind",
				"id",
			],
			"properties": {
				"id": {"type": "string"},
				"kind": {"type": "string"},
			},
		},
		"v2.RoleBindingConfig": {
			"required": [
				"resource_filter",
				"role_id",
				"subjects",
				"id",
				"metadata",
			],
			"properties": {
				"id": {"type": "string"},
				"metadata": {"$ref": "#/definitions/v1.ObjectMeta"},
				"resource_filter": {"$ref": "#/definitions/v2.ResourceFilter"},
				"role_id": {"type": "string"},
				"subjects": {
					"type": "array",
					"items": {"$ref": "#/definitions/v2.Subject"},
				},
			},
		},
		"v2.RoleBindingsDeleteResponse": {"properties": {"request_id": {"type": "string"}}},
		"v2.RoleBindingsDeleteSubjectsRequest": {
			"required": ["subjects"],
			"properties": {"subjects": {
				"type": "array",
				"items": {"$ref": "#/definitions/v2.Subject"},
			}},
		},
		"v2.RoleBindingsDeleteSubjectsResponse": {
			"required": ["rolebinding"],
			"properties": {
				"request_id": {"type": "string"},
				"rolebinding": {"$ref": "#/definitions/v2.RoleBindingConfig"},
			},
		},
		"v2.RoleBindingsGetResponse": {
			"required": ["rolebinding"],
			"properties": {
				"request_id": {"type": "string"},
				"rolebinding": {"$ref": "#/definitions/v2.RoleBindingConfig"},
			},
		},
		"v2.RoleBindingsListResponse": {
			"required": ["rolebindings"],
			"properties": {
				"request_id": {"type": "string"},
				"rolebindings": {
					"type": "array",
					"items": {"$ref": "#/definitions/v2.RoleBindingConfig"},
				},
			},
		},
		"v2.RoleBindingsPostRequest": {
			"required": [
				"resource_filter",
				"role_id",
				"subjects",
				"id",
			],
			"properties": {
				"id": {"type": "string"},
				"resource_filter": {"$ref": "#/definitions/v2.ResourceFilter"},
				"role_id": {"type": "string"},
				"subjects": {
					"type": "array",
					"items": {"$ref": "#/definitions/v2.Subject"},
				},
			},
		},
		"v2.RoleBindingsPostResponse": {
			"required": ["rolebinding"],
			"properties": {
				"request_id": {"type": "string"},
				"rolebinding": {"$ref": "#/definitions/v2.RoleBindingConfig"},
			},
		},
		"v2.RoleBindingsPostSubjectsRequest": {
			"required": ["subjects"],
			"properties": {"subjects": {
				"type": "array",
				"items": {"$ref": "#/definitions/v2.Subject"},
			}},
		},
		"v2.RoleBindingsPostSubjectsResponse": {
			"required": ["rolebinding"],
			"properties": {
				"request_id": {"type": "string"},
				"rolebinding": {"$ref": "#/definitions/v2.RoleBindingConfig"},
			},
		},
		"v2.RoleBindingsPutResetRequest": {},
		"v2.RoleBindingsPutResetResponse": {"properties": {"request_id": {"type": "string"}}},
		"v2.RoleBindingsPutStatusRequest": {
			"required": ["migrated"],
			"properties": {"migrated": {"type": "boolean"}},
		},
		"v2.RoleBindingsPutStatusResponse": {"properties": {"request_id": {"type": "string"}}},
		"v2.RoleBindingsPutSubjectsRequest": {
			"required": ["subjects"],
			"properties": {"subjects": {
				"type": "array",
				"items": {"$ref": "#/definitions/v2.Subject"},
			}},
		},
		"v2.RoleBindingsPutSubjectsResponse": {
			"required": ["rolebinding"],
			"properties": {
				"request_id": {"type": "string"},
				"rolebinding": {"$ref": "#/definitions/v2.RoleBindingConfig"},
			},
		},
		"v2.RoleConfig": {
			"required": [
				"id",
				"resource_kind",
				"metadata",
			],
			"properties": {
				"id": {"type": "string"},
				"metadata": {"$ref": "#/definitions/v1.ObjectMeta"},
				"resource_kind": {"type": "string"},
			},
		},
		"v2.RolesListResponse": {
			"required": ["roles"],
			"properties": {
				"request_id": {"type": "string"},
				"roles": {
					"type": "array",
					"items": {"$ref": "#/definitions/v2.RoleConfig"},
				},
			},
		},
		"v2.Subject": {
			"required": [
				"kind",
				"id",
			],
			"properties": {
				"claim_config": {"$ref": "#/definitions/v2.ClaimConfig"},
				"id": {"type": "string"},
				"kind": {"type": "string"},
			},
		},
	},
	"tags": [
		{
			"description": "Activity log",
			"name": "activity",
		},
		{
			"description": "Data read/write",
			"name": "data",
		},
		{
			"description": "Policy management",
			"name": "policies",
		},
		{
			"description": "User management",
			"name": "users",
		},
		{
			"description": "API tokens management",
			"name": "tokens",
		},
		{
			"description": "Identity Providers management",
			"name": "identity-providers",
		},
		{
			"description": "User invitations",
			"name": "invitations",
		},
		{
			"description": "Timeseries",
			"name": "timeseries",
		},
		{
			"description": "Systems management",
			"name": "systems",
		},
		{
			"description": "Stacks management",
			"name": "stacks",
		},
		{
			"description": "Workspace management",
			"name": "workspace",
		},
		{
			"description": "manages relay-clients",
			"name": "relay-server",
		},
		{
			"description": "Authz management",
			"name": "authz",
		},
		{
			"description": "analysis",
			"name": "decisions",
		},
		{
			"description": "OPA statuses API",
			"name": "status",
		},
		{
			"description": "Agent statuses API",
			"name": "agents",
		},
		{
			"description": "OPA decision logs API",
			"name": "logs",
		},
	],
	"externalDocs": {
		"description": "Styra DAS Documentation",
		"url": "https://docs.styra.com",
	},
}
