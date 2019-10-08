#ifndef ANALYZER_PROTOCOL_SFLOW_SFLOW_H
#define ANALYZER_PROTOCOL_SFLOW_SFLOW_H

#include "events.bif.h"


#include "analyzer/protocol/udp/UDP.h"

#include "sflow_pac.h"

namespace analyzer { namespace SFLOW {

class SFLOW_Analyzer

: public analyzer::Analyzer {

public:
	SFLOW_Analyzer(Connection* conn);
	virtual ~SFLOW_Analyzer();

	// Overriden from Analyzer.
	virtual void Done();
	
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					uint64 seq, const IP_Hdr* ip, int caplen);
	

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new SFLOW_Analyzer(conn); }

protected:
	binpac::SFLOW::SFLOW_Conn* interp;
	
};

} } // namespace analyzer::* 

#endif
