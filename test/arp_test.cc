#include "arp.h"

#include <arpa/inet.h>
#include <dpdk_wrappers.h>
#include <gtest/gtest.h>
#include <rte_arp.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_hexdump.h>
#include <rte_mbuf.h>
#include <stdlib.h>

#include "expected.h"
#include "network_types.h"

namespace {
constexpr in_addr_t OWN_IP = 0x12345;
constexpr in_addr_t GATEWAY_IP = 0x54321;
constexpr rte_ether_addr OWN_MAC = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6};
constexpr rte_ether_addr GATEWAY_MAC = {0x6, 0x5, 0x4, 0x3, 0x2, 0x1};
} // namespace

static void ConstructReferenceRequest(RTEMbuf<DefaultPacket> &pkt) {
	ArpPacket &packet = pkt.data<ArpPacket>();
	packet.arp_hdr.arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
	packet.arp_hdr.arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	packet.arp_hdr.arp_hlen = 6;
	packet.arp_hdr.arp_plen = 4;
	packet.arp_hdr.arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);

	rte_ether_addr_copy(&OWN_MAC, &packet.arp_hdr.arp_data.arp_sha);
	memset(&packet.arp_hdr.arp_data.arp_tha, 0xff, 6);
	packet.arp_hdr.arp_data.arp_sip = OWN_IP;
	packet.arp_hdr.arp_data.arp_tip = GATEWAY_IP;

	memset(&packet.ether_hdr.dst_addr, 0xff, 6);
	rte_ether_addr_copy(&OWN_MAC, &packet.ether_hdr.src_addr);
	packet.ether_hdr.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

	pkt.l2_len = sizeof(rte_ether_hdr);
	pkt.l3_len = sizeof(rte_arp_hdr);
	pkt.data_len = pkt.l2_len + pkt.l3_len;
	pkt.pkt_len = pkt.data_len;
}

static void ConstructReferenceForeignRequest(RTEMbuf<DefaultPacket> &pkt) {
	ArpPacket &packet = pkt.data<ArpPacket>();
	packet.arp_hdr.arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
	packet.arp_hdr.arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	packet.arp_hdr.arp_hlen = 6;
	packet.arp_hdr.arp_plen = 4;
	packet.arp_hdr.arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);

	rte_ether_addr_copy(&GATEWAY_MAC, &packet.arp_hdr.arp_data.arp_sha);
	memset(&packet.arp_hdr.arp_data.arp_tha, 0xff, 6);
	packet.arp_hdr.arp_data.arp_sip = GATEWAY_IP;
	packet.arp_hdr.arp_data.arp_tip = OWN_IP;

	memset(&packet.ether_hdr.dst_addr, 0xff, 6);
	rte_ether_addr_copy(&GATEWAY_MAC, &packet.ether_hdr.src_addr);
	packet.ether_hdr.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

	pkt.l2_len = sizeof(rte_ether_hdr);
	pkt.l3_len = sizeof(rte_arp_hdr);
	pkt.data_len = pkt.l2_len + pkt.l3_len;
	pkt.pkt_len = pkt.data_len;
}

static void ConstructReferenceResponse(RTEMbuf<DefaultPacket> &pkt) {
	ArpPacket &packet = pkt.data<ArpPacket>();
	packet.arp_hdr.arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
	packet.arp_hdr.arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	packet.arp_hdr.arp_hlen = 6;
	packet.arp_hdr.arp_plen = 4;
	packet.arp_hdr.arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

	rte_ether_addr_copy(&GATEWAY_MAC, &packet.arp_hdr.arp_data.arp_tha);
	rte_ether_addr_copy(&OWN_MAC, &packet.arp_hdr.arp_data.arp_sha);
	packet.arp_hdr.arp_data.arp_sip = OWN_IP;
	packet.arp_hdr.arp_data.arp_tip = GATEWAY_IP;

	rte_ether_addr_copy(&GATEWAY_MAC, &packet.ether_hdr.dst_addr);
	rte_ether_addr_copy(&OWN_MAC, &packet.ether_hdr.src_addr);
	packet.ether_hdr.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

	pkt.l2_len = sizeof(rte_ether_hdr);
	pkt.l3_len = sizeof(rte_arp_hdr);
	pkt.data_len = pkt.l2_len + pkt.l3_len;
	pkt.pkt_len = pkt.data_len;
}

static void ConstructReferenceResponseGateway(RTEMbuf<DefaultPacket> &pkt) {
	ArpPacket &packet = pkt.data<ArpPacket>();
	packet.arp_hdr.arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
	packet.arp_hdr.arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	packet.arp_hdr.arp_hlen = 6;
	packet.arp_hdr.arp_plen = 4;
	packet.arp_hdr.arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

	rte_ether_addr_copy(&GATEWAY_MAC, &packet.arp_hdr.arp_data.arp_sha);
	rte_ether_addr_copy(&OWN_MAC, &packet.arp_hdr.arp_data.arp_tha);
	packet.arp_hdr.arp_data.arp_tip = OWN_IP;
	packet.arp_hdr.arp_data.arp_sip = GATEWAY_IP;

	rte_ether_addr_copy(&GATEWAY_MAC, &packet.ether_hdr.src_addr);
	rte_ether_addr_copy(&OWN_MAC, &packet.ether_hdr.dst_addr);
	packet.ether_hdr.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

	pkt.l2_len = sizeof(rte_ether_hdr);
	pkt.l3_len = sizeof(rte_arp_hdr);
	pkt.data_len = pkt.l2_len + pkt.l3_len;
	pkt.pkt_len = pkt.data_len;
}

// Simulate receiving a request packet and generating a response.
TEST(ArpPacketReceiveTest, Request) {
	Arp arp(OWN_IP, OWN_MAC);
	auto arp_mempool = RTEMempool<DefaultPacket, MbufType::Pkt>::init("ARP_POOL", 4, 0, 0);
	ASSERT_EQ(arp_mempool.has_value(), true);

	auto ref_resp = RTEMbufElement<DefaultPacket, MbufType::Pkt>::init(*arp_mempool);
	auto ref_req = RTEMbufElement<DefaultPacket, MbufType::Pkt>::init(*arp_mempool);

	ASSERT_EQ(ref_resp.has_value(), true);
	ASSERT_EQ(ref_req.has_value(), true);

	ConstructReferenceForeignRequest(ref_req->get());
	ConstructReferenceResponse(ref_resp->get());

	tl::expected<RTEMbufElement<DefaultPacket, MbufType::Pkt>, int> test_resp =
	    tl::unexpected<int>(-1);

	const auto send_func = [&test_resp](
				   RTEMbufElement<DefaultPacket, MbufType::Pkt> pkt) -> bool {
		test_resp = std::move(pkt);
		return true;
	};

	auto err = arp.ReceivePacket(ref_req->get(), *arp_mempool, send_func);
	ASSERT_EQ(err, Arp::Error::ARP_OK);
	ASSERT_EQ(test_resp.has_value(), true);

	const auto test_pkt_buf = test_resp->get_data().padding.data();
	const auto ref_pkt_buf = ref_resp->get_data().padding.data();

	ASSERT_EQ(test_resp->get().pkt_len, ref_resp->get().pkt_len);
	ASSERT_EQ(memcmp(test_pkt_buf, ref_pkt_buf, ref_resp->get().pkt_len), 0);
}

// Test generation of an ARP packet to request mac addr.
TEST(ArpPacketConstructorTest, Request) {
	Arp arp(OWN_IP, OWN_MAC);
	auto arp_mempool = RTEMempool<DefaultPacket, MbufType::Pkt>::init("ARP_POOL", 4, 0, 0);
	ASSERT_EQ(arp_mempool.has_value(), true);

	auto ref_pkt = RTEMbufElement<DefaultPacket, MbufType::Pkt>::init(*arp_mempool);
	auto pkts_to_rcv = RTEMbufArray<DefaultPacket, 8, MbufType::Pkt>::init(*arp_mempool, 1);

	ASSERT_EQ(ref_pkt.has_value(), true);
	ASSERT_EQ(pkts_to_rcv.has_value(), true);

	ConstructReferenceRequest(ref_pkt->get());
	ConstructReferenceResponseGateway(pkts_to_rcv->operator[](0));

	auto test_pkt = RTEMbufElement<DefaultPacket, MbufType::Pkt>::init(*arp_mempool);
	ASSERT_EQ(test_pkt.has_value(), true);
	const auto send_func = [&test_pkt](
				   RTEMbufElement<DefaultPacket, MbufType::Pkt> pkt) -> bool {
		test_pkt = std::move(pkt);
		return true;
	};

	const auto recv_func = [&pkts_to_rcv]() { return std::move(*pkts_to_rcv); };

	auto ret = arp.RequestAddr(GATEWAY_IP, *arp_mempool, send_func, recv_func);
	ASSERT_EQ(ret, Arp::Error::ARP_OK);

	const auto test_pkt_buf = test_pkt->get_data().padding.data();
	const auto ref_pkt_buf = ref_pkt->get_data().padding.data();

	ASSERT_EQ(test_pkt->get().pkt_len, ref_pkt->get().pkt_len);
	ASSERT_EQ(memcmp(test_pkt_buf, ref_pkt_buf, ref_pkt->get().pkt_len), 0);

	auto gateway_addr = arp.GetEtherAddr(GATEWAY_IP);
	ASSERT_TRUE(gateway_addr);
	ASSERT_EQ(memcmp(&gateway_addr.value(), &GATEWAY_MAC, 6), 0);
}
