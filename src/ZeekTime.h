#pragma once

#include <sys/time.h>
#include <cstdint>

namespace zeek::time
	{

enum Units : int64_t
	{
	Nanoseconds = 1,
	Microseconds = static_cast<int64_t>(1e3),
	Milliseconds = static_cast<int64_t>(1e6),
	Seconds = static_cast<int64_t>(1e9),
	Minutes = 60 * Seconds,
	Hours = 60 * Minutes,
	Days = 24 * Hours
	};

/**
 * Returns the current time. In pseudo-realtime mode, this is faked to be
 * the start time of the trace plus the time interval Zeek has been running.
 *
 * @param real Overrides the pseudo-realtime checks to always return the
 * current wallclock time.
 */
extern double current_time(bool real = false);

/**
 * Convert a time represented as a double to a timeval struct.
 */
extern struct timeval double_to_timeval(double t);

/**
 * Compares two timeval structs.
 *
 * @return > 0 if tv_a > tv_b, 0 if equal, < 0 if tv_a < tv_b.
 */
extern int time_compare(struct timeval* tv_a, struct timeval* tv_b);

	}
