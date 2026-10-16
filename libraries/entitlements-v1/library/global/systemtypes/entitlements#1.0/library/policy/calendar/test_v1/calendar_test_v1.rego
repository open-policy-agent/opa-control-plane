package global.systemtypes["entitlements:1.0"].library.policy.calendar.test_v1

import rego.v1
import data.global.systemtypes["entitlements:1.0"].library.policy.calendar.v1 as calendar

# This timestamp corresponds to 2021-12-21T23:04:49+00:00. This is simply an
# arbitrary known time uesd for testing purposes.
sample_timestamp_1_ns := 1640127889000000000

ns_per_day := 86400000000000

test_match_day_of_week if {
	got := calendar.match_day_of_week with data.library.parameters as {"days": ["tUesDay", "wedNESday"], "timezone": "America/Los_Angeles"}
		with calendar.now as 1640128124769342000

	count(got) == 1
	got[msg]
	msg == "Weekday is Tuesday"
}

test_ns_to_rfc3339_1 if {
	# Check that a known RFC3339 timestamp is obtained from a known ns
	# count
	result := calendar.ns_to_rfc3339(sample_timestamp_1_ns)
	result == "2021-12-21T23:04:49+00:00"
}

test_ns_to_rfc3339_2 if {
	# Test that we can roundtrip from ns -> RFC3339 -> ns.
	#
	# Note that information is lost -- any time smaller than 1 second is
	# discarded.
	t := sample_timestamp_1_ns
	t_str := calendar.ns_to_rfc3339(t)
	t_parsed := time.parse_rfc3339_ns(t_str)
	t == t_parsed
}

test_match_request_by_time_range_1 if {
	# This test asserts that if the present time is within the allowed
	# range, then the rule matches

	now := time.now_ns()
	start_time := now - ns_per_day
	end_time := now + ns_per_day

	result := calendar.match_time_range with input as {}
		with data.library.parameters as {
			"start_time": calendar.ns_to_rfc3339(start_time),
			"end_time": calendar.ns_to_rfc3339(end_time),
		}

	count(result) == 1
	result[msg]
	msg == sprintf("Request occurred between %s and %s", [calendar.ns_to_rfc3339(start_time), calendar.ns_to_rfc3339(end_time)])
}

test_match_request_by_time_range_2 if {
	# This test assets that if the present time is not within the allowed
	# range, then the rule does not matches

	now := time.now_ns()
	start_time := now - (2 * ns_per_day)
	end_time := now - ns_per_day

	result := calendar.match_time_range with input as {}
		with data.library.parameters as {
			"start_time": calendar.ns_to_rfc3339(start_time),
			"end_time": calendar.ns_to_rfc3339(end_time),
		}

	count(result) == 0
}

test_match_request_by_time_range_3 if {
	# Check that if the end time is not specified, then any request after
	# the given start time should be allowed.

	now := time.now_ns()
	start_time := now - ns_per_day

	result := calendar.match_time_range with input as {}
		with data.library.parameters as {"start_time": calendar.ns_to_rfc3339(start_time)}

	count(result) == 1
	result[msg]
	msg == sprintf("Request occurred after %s", [calendar.ns_to_rfc3339(start_time)])
}

test_match_request_by_time_range_4 if {
	# Check that if the end time is not specified, then any request before
	# the given start time should not be allowed.

	now := time.now_ns()
	start_time := now + ns_per_day

	result := calendar.match_time_range with input as {}
		with data.library.parameters as {"start_time": calendar.ns_to_rfc3339(start_time)}

	count(result) == 0
}

test_match_request_by_time_range_5 if {
	# Check that if the start time is not specified, then any request
	# before the given end time should be allowed.

	now := time.now_ns()
	end_time := now + ns_per_day

	result := calendar.match_time_range with input as {}
		with data.library.parameters as {"end_time": calendar.ns_to_rfc3339(end_time)}

	count(result) == 1
	result[msg]
	msg == sprintf("Request occurred before %s", [calendar.ns_to_rfc3339(end_time)])
}

test_match_request_by_time_range_6 if {
	# Check that if the start time is not specified, then any request
	# after the given end time should not be allowed.

	now := time.now_ns()
	end_time := now - ns_per_day

	result := calendar.match_time_range with input as {}
		with data.library.parameters as {"end_time": calendar.ns_to_rfc3339(end_time)}

	count(result) == 0
}

test_match_request_by_time_range_7 if {
	# If neither the start nor end time is specified, then any request
	# should be allowed.

	now := time.now_ns()
	end_time := now - ns_per_day

	result := calendar.match_time_range with input as {}
		with data.library.parameters as {}

	count(result) == 1
	result[msg]
	msg == "Request allowed because neither start_time nor end_time specified"
}

test_match_request_by_time_range_8 if {
	# Check that if the end time is not specified, then any request after
	# the given start time should be allowed.
	#
	# (variant where omitted parameter is empty)

	now := time.now_ns()
	start_time := now - ns_per_day

	result := calendar.match_time_range with input as {}
		with data.library.parameters as {
			"start_time": calendar.ns_to_rfc3339(start_time),
			"end_time": "",
		}

	count(result) == 1
	result[msg]
	msg == sprintf("Request occurred after %s", [calendar.ns_to_rfc3339(start_time)])
}

test_match_request_by_time_range_9 if {
	# Check that if the end time is not specified, then any request before
	# the given start time should not be allowed.
	#
	# (variant where omitted parameter is empty)

	now := time.now_ns()
	start_time := now + ns_per_day

	result := calendar.match_time_range with input as {}
		with data.library.parameters as {
			"start_time": calendar.ns_to_rfc3339(start_time),
			"end_time": "",
		}

	count(result) == 0
}

test_match_request_by_time_range_10 if {
	# Check that if the start time is not specified, then any request
	# before the given end time should be allowed.
	#
	# (variant where omitted parameter is empty)

	now := time.now_ns()
	end_time := now + ns_per_day

	result := calendar.match_time_range with input as {}
		with data.library.parameters as {
			"start_time": "",
			"end_time": calendar.ns_to_rfc3339(end_time),
		}

	count(result) == 1
	result[msg]
	msg == sprintf("Request occurred before %s", [calendar.ns_to_rfc3339(end_time)])
}

test_match_request_by_time_range_11 if {
	# Check that if the start time is not specified, then any request
	# after the given end time should not be allowed.
	#
	# (variant where omitted parameter is empty)

	now := time.now_ns()
	end_time := now - ns_per_day

	result := calendar.match_time_range with input as {}
		with data.library.parameters as {
			"start_time": "",
			"end_time": calendar.ns_to_rfc3339(end_time),
		}

	count(result) == 0
}

test_string_to_month_number if {
	1 == calendar.string_to_month_number("january")
	1 == calendar.string_to_month_number("jan")
	1 == calendar.string_to_month_number("January")
	1 == calendar.string_to_month_number("JAN")
	1 == calendar.string_to_month_number("1")
	1 == calendar.string_to_month_number(1.0)

	2 == calendar.string_to_month_number("february")
	2 == calendar.string_to_month_number("feb")
	2 == calendar.string_to_month_number("February")
	2 == calendar.string_to_month_number("FEB")
	2 == calendar.string_to_month_number("2")
	2 == calendar.string_to_month_number(2)
	2 == calendar.string_to_month_number(2.0)

	3 == calendar.string_to_month_number("march")
	3 == calendar.string_to_month_number("mar")
	3 == calendar.string_to_month_number("March")
	3 == calendar.string_to_month_number("MAR")
	3 == calendar.string_to_month_number("3")
	3 == calendar.string_to_month_number(3)
	3 == calendar.string_to_month_number(3.0)

	4 == calendar.string_to_month_number("april")
	4 == calendar.string_to_month_number("apr")
	4 == calendar.string_to_month_number("April")
	4 == calendar.string_to_month_number("APR")
	4 == calendar.string_to_month_number("4")
	4 == calendar.string_to_month_number(4)
	4 == calendar.string_to_month_number(4.0)

	5 == calendar.string_to_month_number("may")
	5 == calendar.string_to_month_number("may")
	5 == calendar.string_to_month_number("May")
	5 == calendar.string_to_month_number("MAY")
	5 == calendar.string_to_month_number("5")
	5 == calendar.string_to_month_number(5)
	5 == calendar.string_to_month_number(5.0)

	6 == calendar.string_to_month_number("june")
	6 == calendar.string_to_month_number("jun")
	6 == calendar.string_to_month_number("June")
	6 == calendar.string_to_month_number("JUN")
	6 == calendar.string_to_month_number("6")
	6 == calendar.string_to_month_number(6)
	6 == calendar.string_to_month_number(6.0)

	7 == calendar.string_to_month_number("july")
	7 == calendar.string_to_month_number("jul")
	7 == calendar.string_to_month_number("July")
	7 == calendar.string_to_month_number("JUL")
	7 == calendar.string_to_month_number("7")
	7 == calendar.string_to_month_number(7)
	7 == calendar.string_to_month_number(7.0)

	8 == calendar.string_to_month_number("august")
	8 == calendar.string_to_month_number("aug")
	8 == calendar.string_to_month_number("August")
	8 == calendar.string_to_month_number("AUG")
	8 == calendar.string_to_month_number("8")
	8 == calendar.string_to_month_number(8)
	8 == calendar.string_to_month_number(8.0)

	9 == calendar.string_to_month_number("september")
	9 == calendar.string_to_month_number("sep")
	9 == calendar.string_to_month_number("September")
	9 == calendar.string_to_month_number("SEP")
	9 == calendar.string_to_month_number("9")
	9 == calendar.string_to_month_number(9)
	9 == calendar.string_to_month_number(9.0)

	10 == calendar.string_to_month_number("october")
	10 == calendar.string_to_month_number("oct")
	10 == calendar.string_to_month_number("October")
	10 == calendar.string_to_month_number("OCT")
	10 == calendar.string_to_month_number("10")
	10 == calendar.string_to_month_number(10)
	10 == calendar.string_to_month_number(10.0)

	11 == calendar.string_to_month_number("november")
	11 == calendar.string_to_month_number("nov")
	11 == calendar.string_to_month_number("November")
	11 == calendar.string_to_month_number("NOV")
	11 == calendar.string_to_month_number("11")
	11 == calendar.string_to_month_number(11)
	11 == calendar.string_to_month_number(11.0)

	12 == calendar.string_to_month_number("december")
	12 == calendar.string_to_month_number("dec")
	12 == calendar.string_to_month_number("December")
	12 == calendar.string_to_month_number("DEC")
	12 == calendar.string_to_month_number("12")
	12 == calendar.string_to_month_number(12)
	12 == calendar.string_to_month_number(12.0)

	not calendar.string_to_month_number(0)
	not calendar.string_to_month_number(13)
	not calendar.string_to_month_number(-1)
}

test_match_month_1 if {
	# simple test with one month to be matched

	date := time.date(time.now_ns())
	month := date[1]

	result := calendar.match_month with input as {}
		with data.library.parameters as {"months": [month]}

	count(result) == 1
	result[msg]
	msg == sprintf("Request occurred in %s", [calendar.month_number_to_string(month)])
}

test_match_month_2 if {
	# test with multiple months to be matched

	date := time.date(time.now_ns())
	month := date[1]

	result := calendar.match_month with input as {}
		with data.library.parameters as {"months": [month, 3, 5, 7, 8]}

	count(result) == 1
	result[msg]
	msg == sprintf("Request occurred in %s", [calendar.month_number_to_string(month)])
}

test_match_month_3 if {
	# test with multiple months to be matched, and where the one that matches
	# isn't the first one

	date := time.date(time.now_ns())
	month := date[1]

	result := calendar.match_month with input as {}
		with data.library.parameters as {"months": [3, 5, month, 7, 8]}

	count(result) == 1
	result[msg]
	msg == sprintf("Request occurred in %s", [calendar.month_number_to_string(month)])
}

test_match_month_4 if {
	# Now we want to not match, so we want to explicitly NOT choose
	# the current month in our input.

	date := time.date(time.now_ns())
	month := date[1]

	# guaranteed to be in 1...12 but =/= to the current month
	different_month := ((date[1] + 1) % 11) + 1

	result := calendar.match_month with input as {}
		with data.library.parameters as {"months": [different_month]}

	count(result) == 0
}

test_month_number_to_string if {
	calendar.month_number_to_string(1) == "January"
	calendar.month_number_to_string(2) == "February"
	calendar.month_number_to_string(3) == "March"
	calendar.month_number_to_string(4) == "April"
	calendar.month_number_to_string(5) == "May"
	calendar.month_number_to_string(6) == "June"
	calendar.month_number_to_string(7) == "July"
	calendar.month_number_to_string(8) == "August"
	calendar.month_number_to_string(9) == "September"
	calendar.month_number_to_string(10) == "October"
	calendar.month_number_to_string(11) == "November"
	calendar.month_number_to_string(12) == "December"
}
