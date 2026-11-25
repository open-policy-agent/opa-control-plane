package global.systemtypes["entitlements:1.0"].library.sample.styra

import rego.v1

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
