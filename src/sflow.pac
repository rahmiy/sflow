# sFlow PAC specification

# Analyzer for sFlow Protocol 
#  - sflow-protocol.pac: describes the SFLOW protocol messages
#  - sflow-analyzer.pac: describes the SFLOW analyzer code

%include binpac.pac
%include bro.pac

%extern{
	#include "events.bif.h"
%}

analyzer SFLOW withcontext {
	connection: SFLOW_Conn;
	flow:       SFLOW_Flow;
};

# Our connection consists of two flows, one in each direction.
connection SFLOW_Conn(bro_analyzer: BroAnalyzer) {
	upflow   = SFLOW_Flow(true);
	downflow = SFLOW_Flow(false);
};

%include sflow-protocol.pac

# Now we define the flow:
flow SFLOW_Flow(is_orig: bool) {
	datagram = SFLOW_PDU(is_orig) withcontext(connection, this);
};

%include sflow-analyzer.pac
