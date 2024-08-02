#pragma once

#include <netinet/in.h>
#include <rte_ether.h>

#include "dns_format.h"
#include "network_types.h"

namespace {
constexpr size_t REQUEST_MAX_IPS = 4;
} // namespace

/**
 * @brief struct containing the main datapoints required for a DNS query
 */
struct Request {
	rte_ether_addr dst_mac;
	IpAddr src_ip;
	uint8_t num_ips;
	DnsQType q_type;
	DnsName name;
};
