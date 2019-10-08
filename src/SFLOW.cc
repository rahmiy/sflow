#include "SFLOW.h"

#include "Reporter.h"

#include "events.bif.h"

using namespace analyzer::SFLOW;

SFLOW_Analyzer::SFLOW_Analyzer(Connection* c)

: analyzer::Analyzer("SFLOW", c)

	{
	interp = new binpac::SFLOW::SFLOW_Conn(this);
	
	}

SFLOW_Analyzer::~SFLOW_Analyzer()
	{
	delete interp;
	}

void SFLOW_Analyzer::Done()
	{
	
	Analyzer::Done();
	
	}

void SFLOW_Analyzer::DeliverPacket(int len, const u_char* data,
	 			  bool orig, uint64 seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}
