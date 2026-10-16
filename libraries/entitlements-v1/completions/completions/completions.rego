package completions

import rego.v1

subjects contains s if {
	_ := data.object.users[s]
}

subjects contains s if {
	_ := data.object.groups[s]
}

subjects contains s if {
	_ := data.object.serviceaccounts[s]
}

resources := [r | _ := data.object.resources[r]]
