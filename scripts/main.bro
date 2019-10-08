##! Implements base functionality for sFlow analysis.
##! Generates the sflow.log file.

module Sflow;

export {
	redef enum Log::ID += { LOG, LOG_SAMPLES };

	type Info: record {
		ts: time           &log; ## Timestamp for when the event happened
		uid: string        &log; ## Unique ID for the sFlow connection
		id: conn_id        &log; ## sFlow connection's 4-tuple 
		version: count     &log; ## sFlow version
		ip_version: count  &log; ## Version of the agent IP address (IPv4 or IPv6) -- see https://www.ietf.org/rfc/rfc3176.txt
		agent_addr: addr   &log; ## Agent's IP address
		subagent_id: count &log; ## Sub-agent ID 
		seq_num: count     &log; ## This datagram's sequence number
		sys_uptime: count  &log; ## System up time
		num_samples: count &log; ## Number of sFlow samples in this datagram
	};

	type InfoSample: record {
		ts: time           &log; ## Timestamp for when the event happened
		uid: string        &log; ## Unique ID for the sFlow connection
		id: conn_id        &log; ## sFlow connection's 4-tuple 
		addr_src: addr     &log; ## Source IP address of the sampled connection 
		addr_dst: addr     &log; ## Destination IP address of the sampled connection
		port_src: count    &log; ## Source port number of the sampled connection
		port_dst: count    &log; ## Destination port number of the sampled connection
		proto: count       &log; ## Transport protocol
		srate: count       &log; ## Current sampling rate
		num_samples: count &log; ## Number of samples reported for this connection
	};
	
	## Event that can be handled to access the sFlow record as it is sent on
	## to the loggin framework.
	global log_sflow: event(rec: Info);
}

## Add in this set the list of ports in which you want 
## the analyzer to look for sFlow traffic
const ports = { 6343/udp };
redef likely_server_ports += { ports };

event bro_init() &priority=5
	{
	Log::create_stream(Sflow::LOG, [$columns=Info, $ev=log_sflow, $path="sflow"]);
	Log::create_stream(Sflow::LOG_SAMPLES, [$columns=InfoSample, $path="sflow_sample"]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_SFLOW, ports);
	}

event sflow_event(c: connection,
                  version: count,
                  ip_version: count,
                  agent_addr: count,
                  subagent_id: count,
                  seq_num: count,
                  sys_uptime: count,
                  num_samples: count)
	{
	local rec: Info;
	rec$ts  = network_time();
	rec$uid = c$uid;
	rec$id  = c$id;
	rec$version = version;
	rec$ip_version = ip_version;
	rec$agent_addr = count_to_v4_addr(agent_addr);
	rec$subagent_id = subagent_id;
	rec$seq_num = seq_num;
	rec$sys_uptime = sys_uptime;
	rec$num_samples = num_samples;

	# Mark the flow as being sflow
        add c$service["sflow"];
	# Write this entry to the sFlow log
	Log::write(Sflow::LOG, rec);
	}

event sflow_pkt_sample(c: connection, 
                       addr_src: count,
                       addr_dst: count,
                       port_src: count,
                       port_dst: count,
                       proto: count,
                       srate: count,
                       num_samples: count) 
	{
	local rec: InfoSample;
	rec$ts  = network_time();
	rec$uid = c$uid;
	rec$id  = c$id;
	rec$addr_src = count_to_v4_addr(addr_src);
	rec$addr_dst = count_to_v4_addr(addr_dst);
	rec$port_src = port_src;
	rec$port_dst = port_dst;
	rec$proto = proto;
	rec$srate = srate;
	rec$num_samples = num_samples;

	# Write this entry to the sFlow samples log
	Log::write(Sflow::LOG_SAMPLES, rec);



	} 

