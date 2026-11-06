package main

import rego.v1

# Note: we should only need to pass in system_id and then lookup system_type from styra.systems[system_id]
#    except styra.systems is an array and we'd need to walk it.  That would be okay if it only included
#    this system's data, but if it includes all systems on the cluster, that'll be costly.

newinput = data.transform.newinput.newinput if {
	true
} else = input if {
	true
}

# handle case for tests where input is undefined

else = {}

main = x if {
	x := data.global.systemtypes["entitlements:1.0"].conflicts.entry.main with input as newinput
}
