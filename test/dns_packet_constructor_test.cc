#include "dns_packet_constructor.h"

#include <gtest/gtest.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#include <iostream>

#define SRC_MAC \
	{ 0xab, 0xcd, 0xef, 0x01, 0x02, 0x03 }
#define DST_MAC \
	{ 0x01, 0x02, 0x03, 0xab, 0xdc, 0xef }

#define SRC_IP_IPV4 0x12345678
#define DST_IP_IPV4 0x87654321

#define SRC_IP_IPV6                                                                           \
	{                                                                                     \
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, \
		    0xDD, 0xEE, 0xFF                                                          \
	}
#define DST_IP_IPV6                                                                           \
	{                                                                                     \
		0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, \
		    0x22, 0x11, 0x00                                                          \
	}

#define SRC_PORT 49152

#define DOMAIN_NAME_REG "www.test.test.nu.nl."
#define DOMAIN_NAME_DNS \
	"\x03"          \
	"www\x04"       \
	"test\x04"      \
	"test\x02"      \
	"nu\x02"        \
	"nl"
#define DNS_ID 0x0909

size_t ConstructExamplePacketIpv4(RTEMbuf<DefaultPacket>& pkt) {
	rte_ether_hdr* eth_hdr = &pkt.data<rte_ether_hdr>();
	rte_ipv4_hdr* ip_hdr = (rte_ipv4_hdr*) (eth_hdr + 1);
	rte_udp_hdr* udp_hdr = (rte_udp_hdr*) (ip_hdr + 1);
	DnsHeader* dns_hdr = (DnsHeader*) (udp_hdr + 1);
	char* qname = (char*) (dns_hdr + 1);

	dns_hdr->id = rte_cpu_to_be_16(DNS_ID);
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

	strcpy(qname, DOMAIN_NAME_DNS);
	// Include NULL terminator, must be present in DNS query
	QuestionInfo* qinfo = (QuestionInfo*) (qname + strlen(DOMAIN_NAME_DNS) + 1);
	qinfo->qclass = rte_cpu_to_be_16((unsigned short) DnsQType::A);
	qinfo->qtype = rte_cpu_to_be_16(1);

	const size_t total_dns_len =
	    sizeof(DnsHeader) + strlen(DOMAIN_NAME_DNS) + 1 + sizeof(QuestionInfo);

	eth_hdr->src_addr = SRC_MAC;
	eth_hdr->dst_addr = DST_MAC;
	eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

	ip_hdr->ihl = RTE_IPV4_MIN_IHL;
	ip_hdr->version = IPVERSION;
	ip_hdr->type_of_service = 0;
	ip_hdr->fragment_offset = 0;
	ip_hdr->time_to_live = 64;
	ip_hdr->next_proto_id = IPPROTO_UDP;
	ip_hdr->packet_id = 0;
	ip_hdr->total_length =
	    rte_cpu_to_be_16(sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr) + total_dns_len);
	ip_hdr->src_addr = SRC_IP_IPV4;
	ip_hdr->dst_addr = DST_IP_IPV4;
	ip_hdr->hdr_checksum = 0;

	udp_hdr->dst_port = rte_cpu_to_be_16(53);
	udp_hdr->src_port = rte_cpu_to_be_16(SRC_PORT);
	udp_hdr->dgram_len = rte_cpu_to_be_16(sizeof(rte_udp_hdr) + total_dns_len);
	udp_hdr->dgram_cksum = 0;

	pkt.l2_len = sizeof(rte_ether_hdr);
	pkt.l3_len = sizeof(rte_ipv4_hdr);
	pkt.l4_len = sizeof(rte_udp_hdr);
	pkt.data_len =
	    sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr) + total_dns_len;
	pkt.pkt_len =
	    sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr) + total_dns_len;
	pkt.nb_segs = 1;

	return pkt.pkt_len;
}

size_t ConstructExamplePacketIpv6(RTEMbuf<DefaultPacket>& pkt) {
	rte_ether_hdr* eth_hdr = &pkt.data<rte_ether_hdr>();
	rte_ipv6_hdr* ip_hdr = (rte_ipv6_hdr*) (eth_hdr + 1);
	rte_udp_hdr* udp_hdr = (rte_udp_hdr*) (ip_hdr + 1);
	DnsHeader* dns_hdr = (DnsHeader*) (udp_hdr + 1);
	char* qname = (char*) (dns_hdr + 1);

	dns_hdr->id = rte_cpu_to_be_16(DNS_ID);
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

	strcpy(qname, DOMAIN_NAME_DNS);
	// Include NULL terminator, must be present in DNS query
	QuestionInfo* qinfo = (QuestionInfo*) (qname + strlen(DOMAIN_NAME_DNS) + 1);
	qinfo->qclass = rte_cpu_to_be_16((unsigned short) DnsQType::A);
	qinfo->qtype = rte_cpu_to_be_16(1);

	const size_t total_dns_len =
	    sizeof(DnsHeader) + strlen(DOMAIN_NAME_DNS) + 1 + sizeof(QuestionInfo);

	eth_hdr->src_addr = SRC_MAC;
	eth_hdr->dst_addr = DST_MAC;
	eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);

	ip_hdr->hop_limits = 128;
	ip_hdr->proto = IPPROTO_UDP;
	ip_hdr->payload_len =
	    rte_cpu_to_be_16(sizeof(rte_ipv6_hdr) + sizeof(rte_udp_hdr) + total_dns_len);
	ip_hdr->vtc_flow = rte_cpu_to_be_32(0);

	in6_addr src_addr = {{SRC_IP_IPV6}};
	in6_addr dst_addr = {{DST_IP_IPV6}};

	memcpy(ip_hdr->src_addr, &src_addr, sizeof(in6_addr));
	memcpy(ip_hdr->dst_addr, &dst_addr, sizeof(in6_addr));

	udp_hdr->dst_port = rte_cpu_to_be_16(53);
	udp_hdr->src_port = rte_cpu_to_be_16(SRC_PORT);
	udp_hdr->dgram_len = rte_cpu_to_be_16(sizeof(rte_udp_hdr) + total_dns_len);
	udp_hdr->dgram_cksum = 0;

	pkt.l2_len = sizeof(rte_ether_hdr);
	pkt.l3_len = sizeof(rte_ipv6_hdr);
	pkt.l4_len = sizeof(rte_udp_hdr);
	pkt.data_len =
	    sizeof(rte_ether_hdr) + sizeof(rte_ipv6_hdr) + sizeof(rte_udp_hdr) + total_dns_len;
	pkt.pkt_len =
	    sizeof(rte_ether_hdr) + sizeof(rte_ipv6_hdr) + sizeof(rte_udp_hdr) + total_dns_len;
	pkt.nb_segs = 1;

	return pkt.pkt_len;
}

TEST(DnsPacketConstructorTest, Ipv4Packet) {
	auto mbuf_pool =
	    RTEMempool<DefaultPacket, MbufType::Pkt>::init("MBUF_POOL_RAW_PACKET", 2, 0, 0);

	auto test_pkt = RTEMbufElement<DefaultPacket, MbufType::Pkt>::init(*mbuf_pool);
	auto ref_pkt = RTEMbufElement<DefaultPacket, MbufType::Pkt>::init(*mbuf_pool);

	size_t test_pkt_size = DNSPacketConstructor::ConstructIpv4DNSPacket(test_pkt->get(),
	    SRC_MAC, DST_MAC, SRC_IP_IPV4, DST_IP_IPV4, SRC_PORT, DNS_ID, DOMAIN_NAME_REG,
	    strlen(DOMAIN_NAME_REG), DnsQType::A);

	size_t ref_pkt_size = ConstructExamplePacketIpv4(ref_pkt->get());

	const std::byte* test_pkt_start = test_pkt->get_data().padding.data();
	const std::byte* ref_pkt_start = test_pkt->get_data().padding.data();

	// Check if the size and data contents of the packets are the same
	EXPECT_EQ(test_pkt_size, ref_pkt_size);
	EXPECT_EQ(memcmp(test_pkt_start, ref_pkt_start, test_pkt_size), 0);

	// Check if overload flags are the same
	EXPECT_EQ(test_pkt->get().ol_flags, ref_pkt->get().ol_flags);

	// Checks l2_len, l3_len and l4_len
	EXPECT_EQ(test_pkt->get().tx_offload, ref_pkt->get().tx_offload);

	// Check other lengths
	EXPECT_EQ(test_pkt->get().data_len, ref_pkt->get().data_len);
	EXPECT_EQ(test_pkt->get().pkt_len, ref_pkt->get().pkt_len);
}

TEST(DnsPacketConstructorTest, Ipv6Packet) {
	auto mbuf_pool =
	    RTEMempool<DefaultPacket, MbufType::Pkt>::init("MBUF_POOL_RAW_PACKET", 2, 0, 0);
	ASSERT_EQ(mbuf_pool.has_value(), true);

	auto test_pkt = RTEMbufElement<DefaultPacket, MbufType::Pkt>::init(*mbuf_pool);
	auto ref_pkt = RTEMbufElement<DefaultPacket, MbufType::Pkt>::init(*mbuf_pool);

	ASSERT_EQ(test_pkt.has_value(), true);
	ASSERT_EQ(ref_pkt.has_value(), true);

	size_t test_pkt_size = DNSPacketConstructor::ConstructIpv6DNSPacket(test_pkt->get(),
	    SRC_MAC, DST_MAC, {{SRC_IP_IPV6}}, {{DST_IP_IPV6}}, SRC_PORT, DNS_ID, DOMAIN_NAME_REG,
	    strlen(DOMAIN_NAME_REG), DnsQType::A);

	size_t ref_pkt_size = ConstructExamplePacketIpv6(ref_pkt->get());

	const std::byte* test_pkt_start = test_pkt->get_data().padding.data();
	const std::byte* ref_pkt_start = test_pkt->get_data().padding.data();

	// Check if the size and data contents of the packets are the same
	EXPECT_EQ(test_pkt_size, ref_pkt_size);
	EXPECT_EQ(memcmp(test_pkt_start, ref_pkt_start, test_pkt_size), 0);

	// Check if overload flags are the same
	EXPECT_EQ(test_pkt->get().ol_flags, ref_pkt->get().ol_flags);

	// Checks l2_len, l3_len and l4_len
	EXPECT_EQ(test_pkt->get().tx_offload, ref_pkt->get().tx_offload);

	// Check other lengths
	EXPECT_EQ(test_pkt->get().data_len, ref_pkt->get().data_len);
	EXPECT_EQ(test_pkt->get().pkt_len, ref_pkt->get().pkt_len);
}
