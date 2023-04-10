// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/NetVar.h"
#include "zeek/analyzer/Analyzer.h"

namespace zeek::analyzer::conn_size
	{

class ConnSize_Analyzer : public analyzer::Analyzer
	{
public:
	explicit ConnSize_Analyzer(Connection* c);
	~ConnSize_Analyzer() override;

	void Init() override;
	void Done() override;

	// from Analyzer.h
	void UpdateConnVal(RecordVal* conn_val) override;
	void FlipRoles() override;

	void SetByteAndPacketThreshold(uint64_t threshold, bool bytes, bool orig);
	uint64_t GetByteAndPacketThreshold(bool bytes, bool orig);

	[[deprecated("Remove in v6.1. Use the version that takes a int64_t instead.")]] void
	SetDurationThreshold(double duration);
	[[deprecated("Remove in v6.1. Use the version that returns a int64_t instead.")]] double
	GetDurationThreshold() const
		{
		return duration_thresh;
		}

	/**
	 * Set the duration threshold.
	 * @param duration the new threshold in seconds.
	 */
	void SetDurationThreshold(int64_t duration);

	/**
	 * Get the duration threshold, in seconds.
	 */
	int64_t DurationThreshold() const { return duration_thresh; }

	static analyzer::Analyzer* Instantiate(Connection* conn) { return new ConnSize_Analyzer(conn); }

protected:
	void DeliverPacket(int len, const u_char* data, bool is_orig, uint64_t seq, const IP_Hdr* ip,
	                   int caplen) override;
	void CheckThresholds(bool is_orig);

	void ThresholdEvent(EventHandlerPtr f, uint64_t threshold, bool is_orig);

	uint64_t orig_bytes;
	uint64_t resp_bytes;
	uint64_t orig_pkts;
	uint64_t resp_pkts;

	uint64_t orig_bytes_thresh;
	uint64_t resp_bytes_thresh;
	uint64_t orig_pkts_thresh;
	uint64_t resp_pkts_thresh;

	int64_t start_time;
	int64_t duration_thresh;
	};

	} // namespace zeek::analyzer::conn_size
