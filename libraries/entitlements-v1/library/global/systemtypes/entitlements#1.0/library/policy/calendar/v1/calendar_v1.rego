package global.systemtypes["entitlements:1.0"].library.policy.calendar.v1

import rego.v1
import data.library.parameters
import data.global.systemtypes["entitlements:1.0"].library.utils.v1 as utils

now := time.now_ns()

# METADATA: library-snippet
# version: v1
# title: "Calendar: Match a Day of the week"
# description: >-
#   Matches requests that occured on specific days of the week.
# details: >-
#   If no timezone is supplied, UTC is assumed. Timezones are in the IANA
#   format, a list of which can be found at:
#   https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
# schema:
#   type: object
#   properties:
#     days:
#       type: array
#       title: "Days of the week to match (example: Saturday)"
#       items:
#         type: string
#       uniqueItems: true
#     timezone:
#       type: string
#       title: "IANA Timezone name (example: America/Los_Angeles)"
#   required:
#     - days
#     - timezone

match_day_of_week contains msg if {
	tz := object.get(parameters, "timezone", "UTC")
	day_of_week := time.weekday([now, parameters.timezone])
	lower_day_of_week := lower(day_of_week)
	lower_day_of_week == lower(parameters.days[_])
	msg := sprintf("Weekday is %s", [day_of_week])
}

# METADATA: library-snippet
# version: v1
# title: "Calendar: Match a Date/time range"
# description: >-
#   Match all requests where the date/time is before the end-time (if provided) and after the start-time (if provided).
# details: >-
#   Matches all requests that occur within a specified time range. If the start
#   date/time is omitted, then any request before the given end date/time will
#   be matched. Similarly, if the end date/time is omitted, then any request
#   after the start date/time will be matched. If both are omitted, then this
#   snippet will match all requests.
#
#   Note that the "date/time" used for matching requests will be the system
#   time on the OPA server evaluating this snippet, which is not necessarily the same
#   time (or timezone) as the client.
# schema:
#   type: object
#   properties:
#     start_time:
#       type: string
#       title: "Start date and time (inclusive) in RFC3339 format"
#     end_time:
#       type: string
#       title: "End date and time (inclusive) in RFC3339 format"

match_time_range contains msg if {
	# Note that we want to do this only once to make sure now_ns() does not
	# change between checks.
	now_time := time.now_ns()

	# The significance of 2000000000 is that this is 2 seconds,
	# guaranteeing that the actual formatted RFC3339 timestamp will have a
	# seconds field at least one higher than that of the RFC3339 timestamp
	# corresponding to the current time.
	start_time := time.parse_rfc3339_ns(utils.object_get_empty(parameters, "start_time", ns_to_rfc3339(now_time - 20000000000)))
	end_time := time.parse_rfc3339_ns(utils.object_get_empty(parameters, "end_time", ns_to_rfc3339(now_time + 20000000000)))

	now_time >= start_time
	now_time <= end_time

	msg := match_requests_by_time_range_msg
}

# METADATA: library-snippet
# version: v1
# title: "Calendar: Match a Month"
# description: >-
#   Matches all requests that occur within the specified month(s). You can
#   enter a month name like "April", a 3-letter abbreviation like "APR", or
#   a month number like "4". Month names/abbreviations are case-insensitive.
#   If no timezone is supplied, UTC is assumed.
# schema:
#   type: object
#   properties:
#     months:
#       type: array
#       title: "Months"
#       uniqueItems: true
#       items:
#         type: string
#     timezone:
#       type: string
#       title: "IANA Timezone name (example: America/Los_Angeles)"
#   required:
#     - months

match_month contains msg if {
	#   The months must be provided as a list of strings with full month names,
	#   1-indexed month number, or 3 letter abbreviations. The months are
	#   case-insensitive.
	#
	#   Month name     Abbreviation     Number
	#   January        Jan              1
	#   February       Feb              2
	#   March          Mar              3
	#   April          Apr              4
	#   May            May              5
	#   June           Jun              6
	#   July           Jul              7
	#   August         Aug              8
	#   September      Sep              9
	#   October        Oct              10
	#   November       Nov              11
	#   December       Dec              12

	tz := object.get(parameters, "timezone", "UTC")
	date := time.date([time.now_ns(), tz])
	month := date[1]
	some i
	string_to_month_number(parameters.months[i]) == month
	msg := sprintf("Request occurred in %s", [month_number_to_string(month)])
}

# Helper rule to get the correct message to display for the
# match_requests_by_time rule.
match_requests_by_time_range_msg = msg if {
	utils.object_contains_key(parameters, "start_time")
	utils.object_contains_key(parameters, "end_time")
	parameters.start_time != ""
	parameters.end_time != ""
	msg := sprintf("Request occurred between %s and %s", [parameters.start_time, parameters.end_time])
} else = msg if {
	utils.object_contains_key(parameters, "start_time")
	parameters.start_time != ""
	msg := sprintf("Request occurred after %s", [parameters.start_time])
} else = msg if {
	utils.object_contains_key(parameters, "end_time")
	parameters.end_time != ""
	msg := sprintf("Request occurred before %s", [parameters.end_time])
} else = msg if {
	msg := "Request allowed because neither start_time nor end_time specified"
}

# Helper function to convert a string month, month number, or 3 letter
# abbreviation (see match_requests_by_month) to a 1-indexed month number.
string_to_month_number(s) := month_number(lower(numbers_to_strings(s)))

numbers_to_strings(s) := s if {
	is_string(s)
}

else := sprintf("%d", [floor(s)])

month_number("january") := 1

month_number("jan") := 1

month_number("february") := 2

month_number("feb") := 2

month_number("march") := 3

month_number("mar") := 3

month_number("april") := 4

month_number("apr") := 4

month_number("may") := 5

month_number("june") := 6

month_number("jun") := 6

month_number("july") := 7

month_number("jul") := 7

month_number("august") := 8

month_number("aug") := 8

month_number("september") := 9

month_number("sep") := 9

month_number("october") := 10

month_number("oct") := 10

month_number("november") := 11

month_number("nov") := 11

month_number("december") := 12

month_number("dec") := 12

month_number(s) := x if { # "1", "2", ...
	x := to_number(s)
	x <= 12
	x >= 1
}

month_number_to_string(1) = "January"

month_number_to_string(2) = "February"

month_number_to_string(3) = "March"

month_number_to_string(4) = "April"

month_number_to_string(5) = "May"

month_number_to_string(6) = "June"

month_number_to_string(7) = "July"

month_number_to_string(8) = "August"

month_number_to_string(9) = "September"

month_number_to_string(10) = "October"

month_number_to_string(11) = "November"

month_number_to_string(12) = "December"

# Helper function to convert a timestamp in ns to an RFC3339 string.
ns_to_rfc3339(ns) = result if {
	date := time.date(ns)
	year := date[0]
	month := date[1]
	day := date[2]

	clock := time.clock(ns)
	hour := clock[0]
	minute := clock[1]
	seconds := clock[2]

	result := sprintf("%04d-%02d-%02dT%02d:%02d:%02d+00:00", [year, month, day, hour, minute, seconds])
}
