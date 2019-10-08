# sFlow PAC protocol specification
# See:
#  - http://sflow.org/sflow_version_5.txt

type SFLOW_HEADER = record {
	version: uint32;
	ip_version: uint32;
	agent_addr: uint32;
	subagent_id: uint32;
	seq_num: uint32;
	sys_uptime: uint32;
	num_samples: uint32; 
} &let {
	nsamples: int = num_samples > 1024 ? 1024 : num_samples;
} &length=28;

type EXT_SWITCH_DATA_REC = record {
	in_802_1q_vlan: uint32;
	in_802_1p_prio: uint32;
	out_802_1q_vlan: uint32;
	out_802_1p_prio: uint32;
};

type ETHER_HDR = record {
	mac_dest: uint8[6];
	mac_src: uint8[6];
	type: uint16 &byteorder=littleendian;
};

type IPV4_HDR = record {
	ver_len: uint8;
	ds: uint8;
	tot_len: uint16;
	id: uint16;
	flags_offset: uint16;
	ttl: uint8;
	proto: uint8;
	cksum: uint16;
	addr_src: uint32;
	addr_dst: uint32;
	options: uint8[(ver_len & 0xf) * 4 - 20];
};

type L4_PSEUDO_HDR = record {
	# Applicable to both TCP and UDP packets
	port_src: uint16;
	port_dst: uint16;
};

type IPV4_PKT(len: uint32) = record {
	ip_hdr: IPV4_HDR;
	l4_pshdr: L4_PSEUDO_HDR;
	rest_of_data: uint8[(len - (ip_hdr.ver_len & 0xf) * 4 - 4)];
};

type ETHER_PKT(len: uint32) = record {
	eth_hdr: ETHER_HDR;
	l3_pkt: case eth_hdr.type of {
		8 -> ipv4_pkt: IPV4_PKT(len - 14);
	};
};

type UNSUPPORTED_HDR(len: uint32) = record {
	data: uint8[len];
};

type RAW_PKT_HEADER_REC(len: uint32) = record {
	hdr_proto: uint32;
	frame_len: uint32;  
	stripped: uint32;	
	offset: uint8[stripped];
	sampled_pkt: case hdr_proto of {
		# See http://sflow.org/sflow_version_5.txt
		1 -> eth_pkt: ETHER_PKT(len - 12 - stripped);   # ETHERNET-ISO88023
		default -> unsupported_hdr: UNSUPPORTED_HDR(len - 12);
	};

};

type UNSUPPORTED_REC(len: uint32) = record {
	data: uint8[len];
};

type FLOW_RECORD = record {
	enterprise_format: uint32; 
	data_len: uint32; # The length of the rest of this flow record after this field
	# The last 12 bits of enterprise_format determine the format
	rec_body: case enterprise_format & 0xfff of {
		1001 -> ext_switch_data: EXT_SWITCH_DATA_REC;
		1 -> raw_pkt_header: RAW_PKT_HEADER_REC(data_len);
		default -> unsupported_rec: UNSUPPORTED_REC(data_len);
	};
};

type FLOW_RECORDS(num_recs: uint32) = FLOW_RECORD[num_recs];

type FLOW_SAMPLE = record {
	sample_seqnum: uint32;
	src_type_idx: uint32;
	srate: uint32;
	spool: uint32;
	pkt_drops: uint32;
	snmp_if_in: uint32;
	snmp_if_out: uint32;
	num_flow_rec: uint32;
	flow_recs: FLOW_RECORDS(num_flow_rec);
};

type UNSUPPORTED_SAMPLE(len: uint32) = record {
	data: uint8[len];
};

type SFLOW_SAMPLE = record {
	enterprise_format: uint32; 
	sample_len: uint32;
	# The last 12 bits of enterprise_format determine the format
	sample_body: case enterprise_format & 0xfff of {
		1 -> flow_sample: FLOW_SAMPLE;
		2 -> count_sample: UNSUPPORTED_SAMPLE(sample_len);
		default -> unsupported_sample: UNSUPPORTED_SAMPLE(sample_len);
	};
};

type SFLOW_SAMPLES(nsamples: uint32) = SFLOW_SAMPLE[nsamples];

type SFLOW_PDU(is_orig: bool) = record {
	header: SFLOW_HEADER;
	samples: SFLOW_SAMPLES(header.nsamples);
} &byteorder=bigendian;

