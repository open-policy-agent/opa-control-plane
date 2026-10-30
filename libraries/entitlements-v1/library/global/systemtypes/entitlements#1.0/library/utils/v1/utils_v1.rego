package global.systemtypes["entitlements:1.0"].library.utils.v1

import rego.v1

input_includes_requirements(filters) if {
	new_filters := rewrite_known_filters(filters)
	matches := [m | m := glob.match(new_filters[field][_], [".", "/"], input[field]); m == true]
	count(matches) == count(new_filters)
} else = false

# rewrite_known_filters maps the known fields actions, resources, subjects to their singular values
rewrite_known_filters(filters) = filters_updated if {
	known_filters := {new_key: value |
		value := filters[key]
		key_matches_well_known_filter(key)
		new_key := trim_suffix(key, "s")
	}

	unknown_filters := {key: value |
		value := filters[key]
		not key_matches_well_known_filter(key)
	}

	filters_updated := object.union(known_filters, unknown_filters)
}

key_matches_well_known_filter(key) if {
	key == ["actions", "subjects", "resources"][_]
} else = false

object_get_empty(obj, key, defaultVal) = result if {
	# This helper function behaves like object.get(), but treats the value
	# being the empty string the same as it being omitted entirely.

	obj[key] == ""
	result := defaultVal
}

object_get_empty(obj, key, defaultVal) = result if {
	obj[key] != ""
	result := obj[key]
}

object_contains_key(obj, key) if {
	_ := obj[key]
}

object_get_empty(obj, key, defaultVal) = result if {
	not object_contains_key(obj, key)
	result := defaultVal
}

object_super_sub_compare(super, sub) if {
	# For this function to return true, the object super must contain
	# all of the keys in object sub (though sub need not contain every
	# key in super), and in all cases where both objects contain the same
	# keys, those values need to match.

	object.union(super, sub) == super
}

resource_glob(pattern, match) = result if {
	# Globs against resources should use this, because it means we can
	# manage the delimiters all in one place.
	#
	# Note that in general, an input resource cannot contain a glob, but
	# a resource, in object.resources or object.roles can contain a glob.
	result := glob.match(pattern, [".", "/", ":"], match)
}

# This function should be used when "type laundering" is required. This can be
# used to wrap static statements which would otherwise be type checked. For
# additional context, see: https://styrainc.atlassian.net/browse/STY-11919
#
# This addresses situations like the following; suppose you have something
# like:
#
#     my_cool_func(obj) = result {
#         intermediate := obj.foo.bar
#         # do some cool stuff...
#         result := whatever
#     } else {
#         result := "default!"
#     }
#
# If this function is called on a statically declared object constant, and that
# object is missing, say, the `foo` key, this will cause a Rego compile error.
# This can lead to inconsistant behavior, since a dynamic object created at
# runtime would simply cause `obj.foo.bar` to become undefined. Meaning that if
# `obj` is malformed, `my_cool_func(obj)` might either evaluate to
# `"default!"`, OR cause a compile error depending on what it is called on.
#
# You can work around this issue via "type laundering", which this function
# accomplishes. Thus you might rewrite your call to `my_cool_func(obj)` as
# `my_cool_func(utils.identity(obj))`. This ensures that from the perspective
# of the type checker, `obj` is dynamic by the time `obj.foo.bar` gets
# evaluated. You could also put the call to `identity()` inside of your
# `my_cool_func()` declaration; which approach is appropriate is situational.
identity(x) = result if {
	result := x
}
