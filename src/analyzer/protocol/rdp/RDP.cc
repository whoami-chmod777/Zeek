#include "RDP.h"
#include "analyzer/protocol/tcp/TCP_Reassembler.h"
#include "Reporter.h"
#include "events.bif.h"

using namespace analyzer::rdp;

RDP_Analyzer::RDP_Analyzer(Connection* c)

: tcp::TCP_ApplicationAnalyzer("RDP", c)
	{
	interp = new binpac::RDP::RDP_Conn(this);
	
	had_gap = false;
	
	}

RDP_Analyzer::~RDP_Analyzer()
	{
	delete interp;
	}

void RDP_Analyzer::Done()
	{
	
	tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	
	}

void RDP_Analyzer::EndpointEOF(bool is_orig)
	{
	tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void RDP_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());
	if ( TCP()->IsPartial() )
		return;

	if ( had_gap )
		// If only one side had a content gap, we could still try to
		// deliver data to the other side if the script layer can handle this.
		return;

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void RDP_Analyzer::Undelivered(uint64 seq, int len, bool orig)
	{
	tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	had_gap = true;
	interp->NewGap(orig, len);
	}
