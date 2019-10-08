# sFlow DPD signature

signature dpd_sflow {
	
	ip-proto == udp
	payload /^\x00\x00\x00\x05/  # currently supports only v5

	enable "sflow"
}
