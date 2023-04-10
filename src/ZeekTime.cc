#include "ZeekTime.h"

#include <unistd.h>

#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/iosource/Manager.h"

namespace zeek::time
	{

double current_time(bool real)
	{
	struct timeval tv;
#ifdef _MSC_VER
	auto now = std::chrono::system_clock::now();
	auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
	tv.tv_sec = ms.count() / 1000;
	tv.tv_usec = (ms.count() % 1000) * 1000;
#else
	if ( gettimeofday(&tv, 0) < 0 )
		reporter->InternalError("gettimeofday failed in current_time()");
#endif
	double t = double(tv.tv_sec) + double(tv.tv_usec) / 1e6;

	if ( ! run_state::pseudo_realtime || real || ! iosource_mgr || ! iosource_mgr->GetPktSrc() )
		return t;

	// This obviously only works for a single source ...
	iosource::PktSrc* src = iosource_mgr->GetPktSrc();

	if ( run_state::is_processing_suspended() )
		return run_state::current_packet_timestamp();

	// We don't scale with pseudo_realtime here as that would give us a
	// jumping real-time.
	return run_state::current_packet_timestamp() + (t - run_state::current_packet_wallclock());
	}

struct timeval double_to_timeval(double t)
	{
	struct timeval tv;

	double t1 = floor(t);
	tv.tv_sec = int(t1);
	tv.tv_usec = int((t - t1) * 1e6 + 0.5);

	return tv;
	}

int time_compare(struct timeval* tv_a, struct timeval* tv_b)
	{
	if ( tv_a->tv_sec == tv_b->tv_sec )
		return tv_a->tv_usec - tv_b->tv_usec;
	else
		return tv_a->tv_sec - tv_b->tv_sec;
	}

	}
