#pragma once

#include <dpdk_wrappers.h>
#include <network_types.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#include "dns_construct_helpers.h"
#include "dns_format.h"

/**
 * @brief Class that contains methods to construct Ipv4/Ipv6 DNS packets
 * Constructs the Ethernet, Ip, Udp, and DNS headers
 */
class DNSPacketConstructor {
public:
	/**
	 * @brief Constructs a Ipv4 DNS packet in pkt
	 *
	 * Constructs the Ethernet, Ip, Udp, and DNS headers
	 * Checksums are not calculated
	 *
	 * @param pkt Pointer to the MBuf to fill
	 * @param src_mac_addr Source MAC address
	 * @param dst_mac_addr Destination MAC address
	 * @param src_ipv4_addr Source Ipv4 address
	 * @param dst_ipv4_addr Destination Ipv4 address
	 * @param src_port Source port must be highter than 49152, destination port is always 53
	 * @param dns_id 16 bits DNS ID
	 * @param domain_name Pointer to buffer with domain name, can have trailing dot
	 * @param len Length of domain_name
	 * @param q_type Question type to ask the resolver
	 * @return size_t
	 */
	static inline size_t ConstructIpv4DNSPacket(RTEMbuf<DefaultPacket>& pkt,
	    const rte_ether_addr& src_mac_addr, const rte_ether_addr& dst_mac_addr,
	    const uint32_t src_ipv4_addr, const uint32_t dst_ipv4_addr, uint16_t src_port,
	    uint16_t dns_id, const char* domain_name, const uint16_t len, DnsQType q_type);

	/**
	 * @brief Constructs a Ipv6 DNS packet in pkt
	 *
	 * Constructs the Ethernet, Ip, Udp, and DNS headers
	 * Checksums are not calculated
	 *
	 * @param pkt
	 * @param src_mac_addr
	 * @param dst_mac_addr
	 * @param src_ipv6_addr
	 * @param dst_ipv6_addr
	 * @param src_port
	 * @param dns_id
	 * @param domain_name
	 * @param len
	 * @param q_type
	 * @return size_t
	 */
	static inline size_t ConstructIpv6DNSPacket(RTEMbuf<DefaultPacket>& pkt,
	    const rte_ether_addr& src_mac_addr, const rte_ether_addr& dst_mac_addr,
	    const in6_addr& src_ipv6_addr, const in6_addr& dst_ipv6_addr, uint16_t src_port,
	    uint16_t dns_id, const char* domain_name, const uint16_t len, DnsQType q_type);

	/**
	 * @brief Get the minimum size of a Ipv4 DNS packet, size is counted from the ethernet
	 * header To get the total size of a DNS packet the domain name length with trailing dot
	 * should be added to this packet size
	 *
	 * @return size_t length
	 */
	static inline size_t GetMinIpv4PacketSize() {
		// Add room for NULL terminator
		return sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr) +
		       sizeof(DnsHeader) + sizeof(QuestionInfo) + 1;
	}

	/**
	 * @brief Get the minimum size of a Ipv6 DNS packet, size is counted from the ethernet
	 * header To get the total size of a DNS packet the domain name length with trailing dot
	 * should be added to this packet size
	 *
	 * @return size_t length
	 */
	static inline size_t GetMinIpv6PacketSize() {
		// Add room for NULL terminator
		return sizeof(rte_ether_hdr) + sizeof(rte_ipv6_hdr) + sizeof(rte_udp_hdr) +
		       sizeof(DnsHeader) + sizeof(QuestionInfo) + 1;
	}

private:
	/**
	 * @brief Constructs an ethernet header in buf
	 *
	 * @param buf Pointer to data buffer
	 * @param src_addr Source MAC address
	 * @param dst_addr Destination MAC address
	 * @param ether_type Type of the l3 header in the packet
	 * @return char* Pointer to new location in buffer
	 */
	static inline char* ConstructEthHdr(char* buf, const rte_ether_addr& src_addr,
	    const rte_ether_addr& dst_addr, const uint16_t ether_type);

	/**
	 * @brief Constructs an Ipv4 header in buf
	 *
	 * @param buf Pointer to data buffer
	 * @param src_addr Source Ipv4 address
	 * @param dst_addr Destination Ipv4 address
	 * @param l4_len Total length of entire L4 payload (UDP header + UDP payload length for
	 * example)
	 * @return char* The new position in buf
	 */
	static inline char* ConstructIpv4Hdr(char* buf, const uint32_t src_addr,
	    const uint32_t dst_addr, uint16_t l4_len);

	/**
	 * @brief Constructs an Ipv6 header in buf
	 *
	 * @param buf Pointer to data buffer
	 * @param src_addr Source Ipv6 address
	 * @param dst_addr Destination Ipv6 address
	 * @param l4_len Total length of entire L4 payload (UDP header + UDP payload length for
	 * example)
	 * @return char* The new position in buf
	 */
	static inline char* ConstructIpv6Hdr(char* buf, const in6_addr& src_addr,
	    const in6_addr& dst_addr, uint16_t l4_len);

	/**
	 * @brief Constructs a UDP header in buf
	 *
	 * @param buf Pointer to data buffer
	 * @param src_port Source UDP port
	 * @param dst_port Destination UDP port
	 * @param l5_len Total length of the UDP payload
	 * @return char* The new position in buf
	 */
	static inline char* ConstructUdpHdr(char* buf, const uint16_t src_port,
	    const uint16_t dst_port, uint16_t l5_len);

	/**
	 * @brief Constructs a DNS header in buf with one question
	 *
	 * @param buf Pointer to data buffer
	 * @param host_name The host name to query
	 * @param host_len The length of host_name
	 * @param id 16 bits DNS identifyer
	 * @param q_type The question type of the query
	 * @return char* The new position in buf
	 */
	static inline char* ConstructDNSHdr(char* buf, const char* host_name, uint16_t host_len,
	    uint16_t id, DnsQType q_type);
};

inline size_t DNSPacketConstructor::ConstructIpv6DNSPacket(RTEMbuf<DefaultPacket>& pkt,
    const rte_ether_addr& src_mac_addr, const rte_ether_addr& dst_mac_addr,
    const in6_addr& src_ipv6_addr, const in6_addr& dst_ipv6_addr, uint16_t src_port,
    uint16_t dns_id, const char* domain_name, const uint16_t len, DnsQType q_type) {
	// Fill buffer
	char* buf = &pkt.data<char>();

	// First fill DNS packet to easily extract the length
	char* dns_start = buf + sizeof(rte_ether_hdr) + sizeof(rte_ipv6_hdr) + sizeof(rte_udp_hdr);
	char* dns_end = ConstructDNSHdr(dns_start, domain_name, len, dns_id, q_type);

	int dns_len = dns_end - dns_start;

	ConstructEthHdr(buf, src_mac_addr, dst_mac_addr, RTE_ETHER_TYPE_IPV6);
	ConstructIpv6Hdr(buf + sizeof(rte_ether_hdr), src_ipv6_addr, dst_ipv6_addr,
	    dns_len + sizeof(rte_udp_hdr));
	ConstructUdpHdr(buf + sizeof(rte_ether_hdr) + sizeof(rte_ipv6_hdr), src_port, 53, dns_len);

	// Set packet flags
	pkt.l2_len = sizeof(rte_ether_hdr);
	pkt.l3_len = sizeof(rte_ipv6_hdr);
	pkt.l4_len = sizeof(rte_udp_hdr);
	pkt.data_len = sizeof(rte_ether_hdr) + sizeof(rte_ipv6_hdr) + sizeof(rte_udp_hdr) + dns_len;
	pkt.pkt_len = sizeof(rte_ether_hdr) + sizeof(rte_ipv6_hdr) + sizeof(rte_udp_hdr) + dns_len;
	pkt.nb_segs = 1;

	return sizeof(rte_ether_hdr) + sizeof(rte_ipv6_hdr) + sizeof(rte_udp_hdr) + dns_len;
}

inline size_t DNSPacketConstructor::ConstructIpv4DNSPacket(RTEMbuf<DefaultPacket>& pkt,
    const rte_ether_addr& src_mac_addr, const rte_ether_addr& dst_mac_addr,
    const uint32_t src_ipv4_addr, const uint32_t dst_ipv4_addr, uint16_t src_port, uint16_t dns_id,
    const char* domain_name, const uint16_t len, DnsQType q_type) {
	// Fill buffer
	char* buf = &pkt.data<char>();

	// First fill DNS packet to easily extract the length
	char* dns_start = buf + sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr);
	char* dns_end = ConstructDNSHdr(dns_start, domain_name, len, dns_id, q_type);

	int dns_len = dns_end - dns_start;

	ConstructEthHdr(buf, src_mac_addr, dst_mac_addr, RTE_ETHER_TYPE_IPV4);
	ConstructIpv4Hdr(buf + sizeof(rte_ether_hdr), src_ipv4_addr, dst_ipv4_addr,
	    dns_len + sizeof(rte_udp_hdr));
	ConstructUdpHdr(buf + sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr), src_port, 53, dns_len);

	// Set packet flags
	pkt.l2_len = sizeof(rte_ether_hdr);
	pkt.l3_len = sizeof(rte_ipv4_hdr);
	pkt.l4_len = sizeof(rte_udp_hdr);
	pkt.data_len = sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr) + dns_len;
	pkt.pkt_len = sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr) + dns_len;
	pkt.nb_segs = 1;

	return sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr) + dns_len;
}

inline char* DNSPacketConstructor::ConstructEthHdr(char* buf, const rte_ether_addr& src_addr,
    const rte_ether_addr& dst_addr, const uint16_t ether_type) {
	rte_ether_hdr* eth_hdr = (rte_ether_hdr*) buf;
	eth_hdr->src_addr = src_addr;
	eth_hdr->dst_addr = dst_addr;
	eth_hdr->ether_type = rte_cpu_to_be_16(ether_type);

	return (char*) (eth_hdr + 1);
}

inline char* DNSPacketConstructor::ConstructIpv4Hdr(char* buf, const uint32_t src_addr,
    const uint32_t dst_addr, uint16_t l4_len) {
	rte_ipv4_hdr* ipv4_hdr = (rte_ipv4_hdr*) buf;

	ipv4_hdr->ihl = RTE_IPV4_MIN_IHL;
	ipv4_hdr->version = IPVERSION;
	ipv4_hdr->type_of_service = 0;
	ipv4_hdr->fragment_offset = 0;
	ipv4_hdr->time_to_live = 64;
	ipv4_hdr->next_proto_id = IPPROTO_UDP;
	ipv4_hdr->packet_id = 0;
	ipv4_hdr->total_length = rte_cpu_to_be_16(l4_len + sizeof(rte_ipv4_hdr));
	ipv4_hdr->src_addr = src_addr;
	ipv4_hdr->dst_addr = dst_addr;
	ipv4_hdr->hdr_checksum = 0;

	return (char*) (ipv4_hdr + 1);
}

inline char* DNSPacketConstructor::ConstructIpv6Hdr(char* buf, const in6_addr& src_addr,
    const in6_addr& dst_addr, uint16_t l4_len) {
	rte_ipv6_hdr* ipv6_hdr = (rte_ipv6_hdr*) buf;

	ipv6_hdr->hop_limits = 128;
	ipv6_hdr->proto = IPPROTO_UDP;
	ipv6_hdr->payload_len = rte_cpu_to_be_16(l4_len + sizeof(rte_ipv6_hdr));
	ipv6_hdr->vtc_flow = rte_cpu_to_be_32(0);

	memcpy(ipv6_hdr->src_addr, &src_addr, sizeof(in6_addr));
	memcpy(ipv6_hdr->dst_addr, &dst_addr, sizeof(in6_addr));

	return (char*) (ipv6_hdr + 1);
}

inline char* DNSPacketConstructor::ConstructUdpHdr(char* buf, const uint16_t src_port,
    const uint16_t dst_port, uint16_t l5_len) {
	rte_udp_hdr* udp_hdr = (rte_udp_hdr*) buf;

	udp_hdr->dst_port = rte_cpu_to_be_16(dst_port);
	udp_hdr->src_port = rte_cpu_to_be_16(src_port);
	udp_hdr->dgram_len = rte_cpu_to_be_16(sizeof(rte_udp_hdr) + l5_len);
	udp_hdr->dgram_cksum = 0;

	return (char*) (udp_hdr + 1);
}

inline char* DNSPacketConstructor::ConstructDNSHdr(char* buf, const char* host_name,
    uint16_t host_len, uint16_t id, DnsQType q_type) {
	// Point DNS header pointer to buffer
	DnsHeader* dns_hdr = (DnsHeader*) buf;

	/*
	                                1  1  1  1  1  1
	  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                      ID                       |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                    QDCOUNT                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                    ANCOUNT                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                    NSCOUNT                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                    ARCOUNT                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	*/

	dns_hdr->id = rte_cpu_to_be_16(id);
	dns_hdr->qr = 0;     // This is a query
	dns_hdr->opcode = 0; // This is a standard query
	dns_hdr->aa = 0;     // Not Authoritative
	dns_hdr->tc = 0;     // This message is not truncated
	dns_hdr->rd = 1;     // Recursion Desired
	dns_hdr->ra = 0;     // Recursion not available
	dns_hdr->z = 0;
	dns_hdr->ad = 0;
	dns_hdr->cd = 0;
	dns_hdr->rcode = 0;
	dns_hdr->q_count = rte_cpu_to_be_16(1); // we have only 1 question
	dns_hdr->ans_count = 0;
	dns_hdr->auth_count = 0;
	dns_hdr->add_count = 0;

	/*
	                                1  1  1  1  1  1
	  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                                               |
	/                     QNAME                     /
	/                                               /
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                     QTYPE                     |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                     QCLASS                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	*/

	char* qname = (char*) (dns_hdr + 1);
	QuestionInfo* qinfo =
	    (struct QuestionInfo*) DNSHelpers::ChangetoDnsNameFormat(qname, host_name, host_len);
	
	qinfo->qtype = rte_cpu_to_be_16((unsigned short) q_type);
	qinfo->qclass = rte_cpu_to_be_16(1); // It's internet

	return (char*) (qinfo + 1);
}
