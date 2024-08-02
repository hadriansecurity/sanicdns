#include <arp.h>

std::optional<rte_ether_addr> Arp::GetEtherAddr(const in_addr_t addr) {
	auto it = addr_map.find(addr);
	if (it == addr_map.end())
		return std::nullopt;

	return it->second;
}

void Arp::InsertAddr(const in_addr_t ip, const rte_ether_addr mac) {
	addr_map.insert(std::make_pair(ip, mac));
}

size_t Arp::EraseAddr(const in_addr_t ip) {
	return addr_map.erase(ip);
}

Arp::Error Arp::GenAddrRequest_(const in_addr_t addr, RTEMbuf<DefaultPacket>& resp) {
	rte_arp_hdr arp_data;
	arp_data.arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
	arp_data.arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	arp_data.arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);
	arp_data.arp_hlen = 6;
	arp_data.arp_plen = 4;

	memset(arp_data.arp_data.arp_tha.addr_bytes, 0xff, RTE_ETHER_ADDR_LEN);
	rte_ether_addr_copy(&own_mac, &arp_data.arp_data.arp_sha);
	arp_data.arp_data.arp_sip = own_ip;
	arp_data.arp_data.arp_tip = addr;

	return ConstructARPPacket_(resp, arp_data);
}

Arp::Error Arp::ConstructARPPacket_(RTEMbuf<DefaultPacket>& msg, rte_arp_hdr arp_data) {
	auto& packet = msg.data<ArpPacket>();

	rte_ether_addr_copy(&arp_data.arp_data.arp_tha, &packet.ether_hdr.dst_addr);
	rte_ether_addr_copy(&arp_data.arp_data.arp_sha, &packet.ether_hdr.src_addr);
	packet.ether_hdr.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

	packet.arp_hdr = arp_data;
	msg.l2_len = sizeof(rte_ether_hdr);
	msg.l3_len = sizeof(rte_arp_hdr);
	msg.data_len = msg.l2_len + msg.l3_len;
	msg.pkt_len = msg.data_len;
	return Error::ARP_OK;
}
