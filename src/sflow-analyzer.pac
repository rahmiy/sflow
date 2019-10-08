# sFlow PAC analyzer specification

refine flow SFLOW_Flow += {
	function proc_sflow_message(msg: SFLOW_PDU): bool
		%{
		// Report first the general sflow event
		BifEvent::generate_sflow_event(connection()->bro_analyzer(), 
		                               connection()->bro_analyzer()->Conn(),
		                               msg->header()->version(),
		                               msg->header()->ip_version(),
		                               msg->header()->agent_addr(),
		                               msg->header()->subagent_id(),
		                               msg->header()->seq_num(),
		                               msg->header()->sys_uptime(),
		                               msg->header()->num_samples());
		// Report all packet samples
		SFLOW_SAMPLE *sfsample;
		FLOW_SAMPLE *fsample;
		FLOW_RECORD *frec;
		EXT_SWITCH_DATA_REC *esrec;
		RAW_PKT_HEADER_REC *rprec;
		ETHER_PKT *eth_pkt;
		IPV4_PKT *ip_pkt;
		uint32 addr_src;
		uint32 addr_dst;
		uint16 port_src;
		uint16 port_dst;
		for (int i = 0; i < msg->samples()->size(); i++) {
			sfsample = (*(msg->samples()->val()))[i];
			if (sfsample->sample_body_case_index() != 1) 
				continue; // Process only flow samples
			// It's a flow sample, report it
			fsample = sfsample->flow_sample();
			for (int j = 0; j < fsample->flow_recs()->size(); j++) {
				frec = (*(fsample->flow_recs()->val()))[j];
				if (frec->rec_body_case_index() != 1)
					continue; // Process only packet headers
				rprec = frec->raw_pkt_header();
				if (rprec->hdr_proto() != 1)
					continue; // Process only ethernet packets
				eth_pkt = rprec->eth_pkt();
				if (eth_pkt->eth_hdr()->type() != 8)
					continue; // Process only IP packets
				ip_pkt = eth_pkt->ipv4_pkt();
				addr_src = ip_pkt->ip_hdr()->addr_src();
				addr_dst = ip_pkt->ip_hdr()->addr_dst();
				port_src = ip_pkt->l4_pshdr()->port_src();
				port_dst = ip_pkt->l4_pshdr()->port_dst();
				if (ip_pkt->ip_hdr()->proto() != 6 &&
				    ip_pkt->ip_hdr()->proto() != 17)
					continue; // Process only TCP and UDP packets 
				BifEvent::generate_sflow_pkt_sample(
				                    connection()->bro_analyzer(), 
		                                    connection()->bro_analyzer()->Conn(),
		                                    addr_src,
		                                    addr_dst,
		                                    port_src,
		                                    port_dst,
		                                    ip_pkt->ip_hdr()->proto(),
				                    fsample->srate(),
		                                    1);
			}
		}
		return true;
		%}
};

refine typeattr SFLOW_PDU += &let {
	proc: bool = $context.flow.proc_sflow_message(this);
};
