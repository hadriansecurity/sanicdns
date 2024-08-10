#include "dns_packet.h"

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <rte_ip.h>

#include <cstring>
#include <glaze/glaze.hpp>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "dns_format.h"
#include "dns_struct_defs.h"
#include "dpdk_wrappers.h"
#include "network_types.h"

using namespace std::literals;

template <class... Ts>
struct overloaded : Ts... {
	using Ts::operator()...;
};

template <class... Ts>
overloaded(Ts...) -> overloaded<Ts...>;

enum class PacketIpType {
	Ipv4,
	Ipv6
};

struct ReferenceRecord {
	DnsQType q_type : 16;
	uint32_t ttl;
	std::string name;

	struct TypeA {
		std::string ipv4_addr;
	} a_record;

	struct TypeAAAA {
		std::string ipv6_addr;
	} aaaa_record;

	struct TypeCName {
		std::string name;
	} cname_record;

	struct TypeDName {
		std::string name;
	} dname_record;

	struct TypeMX {
		std::string name;
		uint16_t preference;
	} mx_record;

	struct TypeNS {
		std::string name;
	} ns_record;

	struct TypePtr {
		std::string name;
	} ptr_record;

	struct TypeSoa {
		std::string m_name;
		std::string r_name;

		uint32_t serial;
		uint32_t refresh;
		uint32_t retry;
		uint32_t expire;
		uint32_t minimum;
	} soa_record;

	struct TypeTxt {
		std::string name;
	} txt_record;
};

struct TestPacket {
	std::string raw;

	PacketIpType ip_type;
	std::string qname;
	DnsQType q_type     : 16;
	DnsRCode error_code : 16;
	uint16_t id;
	uint16_t dst_port;
	std::string src_ip;
	std::string dst_ip;

	std::vector<ReferenceRecord> answer_ref_records;
	std::vector<ReferenceRecord> auth_ref_records;
	std::vector<ReferenceRecord> additional_ref_records;
};

void CheckIP(std::string ref, std::variant<InAddr, In6Addr> ip_to_check) {
	std::visit(overloaded{[&](InAddr ipv4_addr) {
				      in_addr buf;
				      EXPECT_EQ(inet_pton(AF_INET, ref.c_str(), &buf), 1);
				      EXPECT_EQ(buf.s_addr, ipv4_addr.s_addr);
			      },
		       [&](In6Addr ipv6_addr) {
			       in6_addr buf;
			       EXPECT_EQ(inet_pton(AF_INET6, ref.c_str(), &buf), 1);
			       EXPECT_TRUE(memcmp(&buf, &ipv6_addr, sizeof(in6_addr)) == 0);
		       }},
	    ip_to_check);
}

template <size_t N>
void CheckFixedName(const std::string& ref, const FixedName<N>& name_to_check) {
	EXPECT_EQ(ref, static_cast<std::string_view>(name_to_check));
}

void CheckRecord(const ReferenceRecord& reference, const ResourceRecord& test_record) {
	CheckFixedName(reference.name, test_record.name);
	EXPECT_EQ(reference.q_type, test_record.q_type);
	EXPECT_EQ(reference.ttl, test_record.ttl);

	std::visit(
	    overloaded{[&](ARdata r_data) {
			       char ip_buf[INET_ADDRSTRLEN];
			       inet_ntop(AF_INET, &r_data.ipv4_addr, ip_buf, INET_ADDRSTRLEN);
			       EXPECT_STREQ(reference.a_record.ipv4_addr.c_str(), ip_buf);
		       },
		[&](AAAARdata r_data) {
			char ip_buf[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &r_data.ipv6_addr, ip_buf, INET6_ADDRSTRLEN);
			EXPECT_STREQ(reference.aaaa_record.ipv6_addr.c_str(), ip_buf);
		},
		[&](NSRdata r_data) {
			CheckFixedName(reference.ns_record.name, r_data.nameserver);
		},
		[&](MXRdata r_data) {
			EXPECT_EQ(reference.mx_record.preference, r_data.preference);
			CheckFixedName(reference.mx_record.name, r_data.mailserver);
		},
		[&](CNAMERdata r_data) {
			CheckFixedName(reference.cname_record.name, r_data.cname);
		},
		[&](DNAMERdata r_data) {
			CheckFixedName(reference.dname_record.name, r_data.dname);
		},
		[&](PTRRdata r_data) { CheckFixedName(reference.ptr_record.name, r_data.ptr); },
		[&](TXTRdata r_data) { CheckFixedName(reference.txt_record.name, r_data.txt); },
		[&](SOARdata r_data) {
			CheckFixedName(reference.soa_record.m_name, r_data.m_name);
			CheckFixedName(reference.soa_record.r_name, r_data.r_name);

			EXPECT_EQ(reference.soa_record.serial, r_data.interval_settings.serial);
			EXPECT_EQ(reference.soa_record.refresh, r_data.interval_settings.refresh);
			EXPECT_EQ(reference.soa_record.retry, r_data.interval_settings.retry);
			EXPECT_EQ(reference.soa_record.expire, r_data.interval_settings.expire);
			EXPECT_EQ(reference.soa_record.minimum, r_data.interval_settings.minimum);
		},
		[&]([[maybe_unused]] OPTRdata r_data) {}, [&](std::monostate) {}},
	    test_record.r_data);
}

auto ExtractPacket(const TestPacket& packet) {
	auto mbuf_pool_pkt =
	    RTEMempool<DefaultPacket, MbufType::Pkt>::init("MBUF_POOL_RAW_PACKET", 1, 0, 0);
	EXPECT_EQ(mbuf_pool_pkt.has_value(), true);

	auto mbuf_pool_out =
	    RTEMempool<DefaultPacket, MbufType::Raw>::init("MBUF_POOL_OUT_PACKET", 1000, 0, 0, 0);
	EXPECT_EQ(mbuf_pool_out.has_value(), true);

	auto test_pkt = RTEMbufElement<DefaultPacket, MbufType::Pkt>::init(*mbuf_pool_pkt);
	EXPECT_EQ(test_pkt.has_value(), true);

	EXPECT_LT(packet.raw.length(), sizeof(DefaultPacket));

	// Copy data to packet
	char* test_pkt_data = &test_pkt->get().data<char>();
	std::copy(packet.raw.data(), packet.raw.data() + packet.raw.length(), test_pkt_data);

	// Set test packet metadata
	test_pkt->get().packet_type = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_L4_UDP;
	test_pkt->get().l2_len = sizeof(rte_ether_hdr);
	test_pkt->get().l3_len =
	    packet.ip_type == PacketIpType::Ipv4 ? sizeof(rte_ipv4_hdr) : sizeof(rte_ipv6_hdr);
	test_pkt->get().l4_len = sizeof(rte_udp_hdr);
	test_pkt->get().data_len = packet.raw.length();
	test_pkt->get().pkt_len = packet.raw.length();
	test_pkt->get().nb_segs = 1;

	auto parsed = DNSPacket::init(*mbuf_pool_out, *test_pkt);
	return std::pair(std::move(mbuf_pool_out), std::move(parsed));
}

void CheckPacket(const TestPacket& packet) {
	auto [mbuf_pool_out, parsed_packet] = ExtractPacket(packet);

	EXPECT_EQ(parsed_packet.has_value(), true);

	EXPECT_EQ(parsed_packet->ip_data.dst_port, packet.dst_port);
	EXPECT_EQ(parsed_packet->dns_id, packet.id);

	CheckIP(packet.src_ip, parsed_packet->ip_data.src_ip);
	CheckIP(packet.dst_ip, parsed_packet->ip_data.dst_ip);

	CheckFixedName(packet.qname, parsed_packet->question);

	EXPECT_EQ(packet.answer_ref_records.size(), parsed_packet->data.ans.size());
	EXPECT_EQ(packet.additional_ref_records.size(), parsed_packet->data.add.size());
	EXPECT_EQ(packet.auth_ref_records.size(), parsed_packet->data.auth.size());

	std::string out{};
	glz::write_json(*parsed_packet, out);

	std::cout << out << '\n';

	for (uint16_t i = 0; i < packet.answer_ref_records.size(); i++)
		CheckRecord(packet.answer_ref_records[i], parsed_packet->data.ans.get_data(i));

	for (uint16_t i = 0; i < packet.additional_ref_records.size(); i++)
		CheckRecord(packet.additional_ref_records[i], parsed_packet->data.add.get_data(i));

	for (uint16_t i = 0; i < packet.auth_ref_records.size(); i++)
		CheckRecord(packet.auth_ref_records[i], parsed_packet->data.auth.get_data(i));
}

TEST(DnsPacketParserTest, A_record) {
	auto test_packet = TestPacket{// Checks jumps + A record
	    .raw = "\xbc\xd0\x74\x17\xbe\x44\x26\x5a\x4c\x53\x36\x7e\x08\x00\x45\x00"
		   "\x00\x53\xc1\x2f\x40\x00\x40\x11\xf5\x67\xc0\xa8\x01\x01\xc0\xa8"
		   "\x01\xb1\x00\x35\xfb\xb3\x00\x3f\x9d\x81\x22\x13\x81\x80\x00\x01"
		   "\x00\x01\x00\x00\x00\x01\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f"
		   "\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x08"
		   "\x00\x04\x8e\xfa\xb3\x8e\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00"s,

	    .ip_type = PacketIpType::Ipv4,
	    .qname = "google.com.",
	    .q_type = DnsQType::A,
	    .error_code = DnsRCode::NOERROR,
	    .id = 0x2213,
	    .dst_port = 64435,
	    .src_ip = "192.168.1.1",
	    .dst_ip = "192.168.1.177",

	    .answer_ref_records = {ReferenceRecord{.q_type = DnsQType::A,
		.ttl = 8,
		.name = "google.com.",
		.a_record = {"142.250.179.142"}}},
	    .auth_ref_records =
		{

		},
	    .additional_ref_records = {
		ReferenceRecord{.q_type = DnsQType::OPT, .ttl = 0, .name = ""}}};

	CheckPacket(test_packet);
}

TEST(DnsPacketParserTest, CNAME_record) {
	auto test_packet = TestPacket{// Tests CNAME record
	    .raw = "\xbc\xd0\x74\x17\xbe\x44\x26\x5a\x4c\x53\x36\x7e\x08\x00\x45\x00"
		   "\x00\x80\x60\x98\x40\x00\x40\x11\x55\xd2\xc0\xa8\x01\x01\xc0\xa8"
		   "\x01\xb1\x00\x35\xca\xa6\x00\x6c\x2c\x87\x6e\xd5\x81\x80\x00\x01"
		   "\x00\x02\x00\x00\x00\x01\x04\x74\x65\x73\x74\x03\x65\x74\x76\x07"
		   "\x74\x75\x64\x65\x6c\x66\x74\x02\x6e\x6c\x00\x00\x01\x00\x01\xc0"
		   "\x0c\x00\x05\x00\x01\x00\x00\x02\x3c\x00\x18\x07\x65\x74\x76\x73"
		   "\x65\x72\x76\x03\x65\x74\x76\x07\x74\x75\x64\x65\x6c\x66\x74\x02"
		   "\x6e\x6c\x00\xc0\x31\x00\x01\x00\x01\x00\x00\x02\x3c\x00\x04\x83"
		   "\xb4\x7d\x56\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00"s,

	    .ip_type = PacketIpType::Ipv4,
	    .qname = "test.etv.tudelft.nl.",
	    .q_type = DnsQType::A,
	    .error_code = DnsRCode::NOERROR,
	    .id = 0x6ED5,
	    .dst_port = 51878,
	    .src_ip = "192.168.1.1",
	    .dst_ip = "192.168.1.177",

	    .answer_ref_records = {ReferenceRecord{.q_type = DnsQType::CNAME,
				       .ttl = 572,
				       .name = "test.etv.tudelft.nl.",
				       .cname_record = {"etvserv.etv.tudelft.nl."}},
		ReferenceRecord{.q_type = DnsQType::A,
		    .ttl = 572,
		    .name = "etvserv.etv.tudelft.nl.",
		    .a_record = {"131.180.125.86"}}},
	    .auth_ref_records =
		{

		},
	    .additional_ref_records = {
		ReferenceRecord{.q_type = DnsQType::OPT, .ttl = 0, .name = ""}}};

	CheckPacket(test_packet);
}

TEST(DnsPacketParserTest, SOA_AAAA_record) {
	auto test_packet = TestPacket{// Tests SOA and AAAA record
	    .raw = "\xbc\xd0\x74\x17\xbe\x44\x26\x5a\x4c\x53\x36\x7e\x08\x00\x45\x00"
		   "\x01\x69\x3e\x1f\x40\x00\x40\x11\x77\x62\xc0\xa8\x01\x01\xc0\xa8"
		   "\x01\xb1\x00\x35\xf8\x66\x01\x55\x73\xe0\xa6\x88\x81\x80\x00\x01"
		   "\x00\x01\x00\x04\x00\x09\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f"
		   "\x6d\x00\x00\x06\x00\x01\xc0\x0c\x00\x06\x00\x01\x00\x00\x00\x01"
		   "\x00\x26\x03\x6e\x73\x31\xc0\x0c\x09\x64\x6e\x73\x2d\x61\x64\x6d"
		   "\x69\x6e\xc0\x0c\x1b\x8e\xcc\xd5\x00\x00\x03\x84\x00\x00\x03\x84"
		   "\x00\x00\x07\x08\x00\x00\x00\x3c\xc0\x0c\x00\x02\x00\x01\x00\x00"
		   "\x29\x04\x00\x06\x03\x6e\x73\x34\xc0\x0c\xc0\x0c\x00\x02\x00\x01"
		   "\x00\x00\x29\x04\x00\x06\x03\x6e\x73\x32\xc0\x0c\xc0\x0c\x00\x02"
		   "\x00\x01\x00\x00\x29\x04\x00\x06\x03\x6e\x73\x33\xc0\x0c\xc0\x0c"
		   "\x00\x02\x00\x01\x00\x00\x29\x04\x00\x02\xc0\x28\xc0\x28\x00\x01"
		   "\x00\x01\x00\x05\x2b\x67\x00\x04\xd8\xef\x20\x0a\xc0\x28\x00\x1c"
		   "\x00\x01\x00\x05\x40\xac\x00\x10\x20\x01\x48\x60\x48\x02\x00\x32"
		   "\x00\x00\x00\x00\x00\x00\x00\x0a\xc0\x6c\x00\x01\x00\x01\x00\x05"
		   "\x40\xac\x00\x04\xd8\xef\x22\x0a\xc0\x6c\x00\x1c\x00\x01\x00\x05"
		   "\x2f\xe9\x00\x10\x20\x01\x48\x60\x48\x02\x00\x34\x00\x00\x00\x00"
		   "\x00\x00\x00\x0a\xc0\x5a\x00\x01\x00\x01\x00\x05\x43\x12\x00\x04"
		   "\xd8\xef\x26\x0a\xc0\x5a\x00\x1c\x00\x01\x00\x05\x3e\x28\x00\x10"
		   "\x20\x01\x48\x60\x48\x02\x00\x38\x00\x00\x00\x00\x00\x00\x00\x0a"
		   "\xc0\x7e\x00\x01\x00\x01\x00\x05\x2d\x40\x00\x04\xd8\xef\x24\x0a"
		   "\xc0\x7e\x00\x1c\x00\x01\x00\x05\x3e\x28\x00\x10\x20\x01\x48\x60"
		   "\x48\x02\x00\x36\x00\x00\x00\x00\x00\x00\x00\x0a\x00\x00\x29\x10"
		   "\x00\x00\x00\x00\x00\x00\x00"s,

	    .ip_type = PacketIpType::Ipv4,
	    .qname = "google.com.",
	    .q_type = DnsQType::SOA,
	    .error_code = DnsRCode::NOERROR,
	    .id = 0xA688,
	    .dst_port = 63590,
	    .src_ip = "192.168.1.1",
	    .dst_ip = "192.168.1.177",

	    .answer_ref_records = {ReferenceRecord{.q_type = DnsQType::SOA,
		.ttl = 1,
		.name = "google.com.",
		.soa_record = {.m_name = "ns1.google.com.",
		    .r_name = "dns-admin.google.com.",
		    .serial = 462343381,
		    .refresh = 900,
		    .retry = 900,
		    .expire = 1800,
		    .minimum = 60}}},
	    .auth_ref_records = {ReferenceRecord{.q_type = DnsQType::NS,
				     .ttl = 10500,
				     .name = "google.com.",
				     .ns_record = {"ns4.google.com."}},
		ReferenceRecord{.q_type = DnsQType::NS,
		    .ttl = 10500,
		    .name = "google.com.",
		    .ns_record = {"ns2.google.com."}},
		ReferenceRecord{.q_type = DnsQType::NS,
		    .ttl = 10500,
		    .name = "google.com.",
		    .ns_record = {"ns3.google.com."}},
		ReferenceRecord{.q_type = DnsQType::NS,
		    .ttl = 10500,
		    .name = "google.com.",
		    .ns_record = {"ns1.google.com."}}},
	    .additional_ref_records = {ReferenceRecord{.q_type = DnsQType::A,
					   .ttl = 338791,
					   .name = "ns1.google.com.",
					   .a_record = {"216.239.32.10"}},
		ReferenceRecord{.q_type = DnsQType::AAAA,
		    .ttl = 344236,
		    .name = "ns1.google.com.",
		    .aaaa_record = {"2001:4860:4802:32::a"}},
		ReferenceRecord{.q_type = DnsQType::A,
		    .ttl = 344236,
		    .name = "ns2.google.com.",
		    .a_record = {"216.239.34.10"}},
		ReferenceRecord{.q_type = DnsQType::AAAA,
		    .ttl = 339945,
		    .name = "ns2.google.com.",
		    .aaaa_record = {"2001:4860:4802:34::a"}},
		ReferenceRecord{.q_type = DnsQType::A,
		    .ttl = 344850,
		    .name = "ns4.google.com.",
		    .a_record = {"216.239.38.10"}},
		ReferenceRecord{.q_type = DnsQType::AAAA,
		    .ttl = 343592,
		    .name = "ns4.google.com.",
		    .aaaa_record = {"2001:4860:4802:38::a"}},
		ReferenceRecord{.q_type = DnsQType::A,
		    .ttl = 339264,
		    .name = "ns3.google.com.",
		    .a_record = {"216.239.36.10"}},
		ReferenceRecord{.q_type = DnsQType::AAAA,
		    .ttl = 343592,
		    .name = "ns3.google.com.",
		    .aaaa_record = {"2001:4860:4802:36::a"}},
		ReferenceRecord{.q_type = DnsQType::OPT, .ttl = 0, .name = ""}}};

	CheckPacket(test_packet);
}

TEST(DnsPacketParserTest, TXT_record) {
	auto test_packet = TestPacket{// Tests TXT record
	    .raw = "\xbc\xd0\x74\x17\xbe\x44\x26\x5a\x4c\x53\x36\x7e\x08\x00\x45\x00"
		   "\x03\x47\x3a\x72\x40\x00\x40\x11\x79\x31\xc0\xa8\x01\x01\xc0\xa8"
		   "\x01\xb1\x00\x35\xd4\xf4\x03\x33\x7d\x3a\x86\xef\x81\x80\x00\x01"
		   "\x00\x0b\x00\x00\x00\x01\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f"
		   "\x6d\x00\x00\x10\x00\x01\xc0\x0c\x00\x10\x00\x01\x00\x00\x0d\xf9"
		   "\x00\x41\x40\x67\x6c\x6f\x62\x61\x6c\x73\x69\x67\x6e\x2d\x73\x6d"
		   "\x69\x6d\x65\x2d\x64\x76\x3d\x43\x44\x59\x58\x2b\x58\x46\x48\x55"
		   "\x77\x32\x77\x6d\x6c\x36\x2f\x47\x62\x38\x2b\x35\x39\x42\x73\x48"
		   "\x33\x31\x4b\x7a\x55\x72\x36\x63\x31\x6c\x32\x42\x50\x76\x71\x4b"
		   "\x58\x38\x3d\xc0\x0c\x00\x10\x00\x01\x00\x00\x0d\xf9\x00\x2b\x2a"
		   "\x61\x70\x70\x6c\x65\x2d\x64\x6f\x6d\x61\x69\x6e\x2d\x76\x65\x72"
		   "\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x3d\x33\x30\x61\x66\x49\x42"
		   "\x63\x76\x53\x75\x44\x56\x32\x50\x4c\x58\xc0\x0c\x00\x10\x00\x01"
		   "\x00\x00\x0d\xf9\x00\x3c\x3b\x66\x61\x63\x65\x62\x6f\x6f\x6b\x2d"
		   "\x64\x6f\x6d\x61\x69\x6e\x2d\x76\x65\x72\x69\x66\x69\x63\x61\x74"
		   "\x69\x6f\x6e\x3d\x32\x32\x72\x6d\x35\x35\x31\x63\x75\x34\x6b\x30"
		   "\x61\x62\x30\x62\x78\x73\x77\x35\x33\x36\x74\x6c\x64\x73\x34\x68"
		   "\x39\x35\xc0\x0c\x00\x10\x00\x01\x00\x00\x0d\xf9\x00\x2e\x2d\x64"
		   "\x6f\x63\x75\x73\x69\x67\x6e\x3d\x31\x62\x30\x61\x36\x37\x35\x34"
		   "\x2d\x34\x39\x62\x31\x2d\x34\x64\x62\x35\x2d\x38\x35\x34\x30\x2d"
		   "\x64\x32\x63\x31\x32\x36\x36\x34\x62\x32\x38\x39\xc0\x0c\x00\x10"
		   "\x00\x01\x00\x00\x0d\xf9\x00\x45\x44\x67\x6f\x6f\x67\x6c\x65\x2d"
		   "\x73\x69\x74\x65\x2d\x76\x65\x72\x69\x66\x69\x63\x61\x74\x69\x6f"
		   "\x6e\x3d\x77\x44\x38\x4e\x37\x69\x31\x4a\x54\x4e\x54\x6b\x65\x7a"
		   "\x4a\x34\x39\x73\x77\x76\x57\x57\x34\x38\x66\x38\x5f\x39\x78\x76"
		   "\x65\x52\x45\x56\x34\x6f\x42\x2d\x30\x48\x66\x35\x6f\xc0\x0c\x00"
		   "\x10\x00\x01\x00\x00\x0d\xf9\x00\x45\x44\x67\x6f\x6f\x67\x6c\x65"
		   "\x2d\x73\x69\x74\x65\x2d\x76\x65\x72\x69\x66\x69\x63\x61\x74\x69"
		   "\x6f\x6e\x3d\x54\x56\x39\x2d\x44\x42\x65\x34\x52\x38\x30\x58\x34"
		   "\x76\x30\x4d\x34\x55\x5f\x62\x64\x5f\x4a\x39\x63\x70\x4f\x4a\x4d"
		   "\x30\x6e\x69\x6b\x66\x74\x30\x6a\x41\x67\x6a\x6d\x73\x51\xc0\x0c"
		   "\x00\x10\x00\x01\x00\x00\x0d\xf9\x00\x43\x42\x77\x65\x62\x65\x78"
		   "\x64\x6f\x6d\x61\x69\x6e\x76\x65\x72\x69\x66\x69\x63\x61\x74\x69"
		   "\x6f\x6e\x2e\x38\x59\x58\x36\x47\x3d\x36\x65\x36\x39\x32\x32\x64"
		   "\x62\x2d\x65\x33\x65\x36\x2d\x34\x61\x33\x36\x2d\x39\x30\x34\x65"
		   "\x2d\x61\x38\x30\x35\x63\x32\x38\x30\x38\x37\x66\x61\xc0\x0c\x00"
		   "\x10\x00\x01\x00\x00\x0d\xf9\x00\x2e\x2d\x64\x6f\x63\x75\x73\x69"
		   "\x67\x6e\x3d\x30\x35\x39\x35\x38\x34\x38\x38\x2d\x34\x37\x35\x32"
		   "\x2d\x34\x65\x66\x32\x2d\x39\x35\x65\x62\x2d\x61\x61\x37\x62\x61"
		   "\x38\x61\x33\x62\x64\x30\x65\xc0\x0c\x00\x10\x00\x01\x00\x00\x0d"
		   "\xf9\x00\x2c\x2b\x4d\x53\x3d\x45\x34\x41\x36\x38\x42\x39\x41\x42"
		   "\x32\x42\x42\x39\x36\x37\x30\x42\x43\x45\x31\x35\x34\x31\x32\x46"
		   "\x36\x32\x39\x31\x36\x31\x36\x34\x43\x30\x42\x32\x30\x42\x42\xc0"
		   "\x0c\x00\x10\x00\x01\x00\x00\x0d\xf9\x00\x5f\x5e\x61\x74\x6c\x61"
		   "\x73\x73\x69\x61\x6e\x2d\x64\x6f\x6d\x61\x69\x6e\x2d\x76\x65\x72"
		   "\x69\x66\x69\x63\x61\x74\x69\x6f\x6e\x3d\x35\x59\x6a\x54\x6d\x57"
		   "\x6d\x6a\x49\x39\x32\x65\x77\x71\x6b\x78\x32\x6f\x58\x6d\x42\x61"
		   "\x44\x36\x30\x54\x64\x39\x7a\x57\x6f\x6e\x39\x72\x36\x65\x61\x6b"
		   "\x76\x48\x58\x36\x42\x37\x37\x7a\x7a\x6b\x46\x51\x74\x6f\x38\x50"
		   "\x51\x39\x51\x73\x4b\x6e\x62\x66\x34\x49\xc0\x0c\x00\x10\x00\x01"
		   "\x00\x00\x0d\xf9\x00\x24\x23\x76\x3d\x73\x70\x66\x31\x20\x69\x6e"
		   "\x63\x6c\x75\x64\x65\x3a\x5f\x73\x70\x66\x2e\x67\x6f\x6f\x67\x6c"
		   "\x65\x2e\x63\x6f\x6d\x20\x7e\x61\x6c\x6c\x00\x00\x29\x10\x00\x00"
		   "\x00\x00\x00\x00\x00"s,

	    .ip_type = PacketIpType::Ipv4,
	    .qname = "google.com.",
	    .q_type = DnsQType::TXT,
	    .error_code = DnsRCode::NOERROR,
	    .id = 0x86EF,
	    .dst_port = 54516,
	    .src_ip = "192.168.1.1",
	    .dst_ip = "192.168.1.177",

	    .answer_ref_records = {ReferenceRecord{.q_type = DnsQType::TXT,
				       .ttl = 3577,
				       .name = "google.com.",
				       .txt_record = {"globalsign-smime-dv=CDYX+XFHUw2wml6/"
						      "Gb8+59BsH31KzUr6c1l2BPvqKX8="}},
		ReferenceRecord{.q_type = DnsQType::TXT,
		    .ttl = 3577,
		    .name = "google.com.",
		    .txt_record = {"apple-domain-verification=30afIBcvSuDV2PLX"}},
		ReferenceRecord{.q_type = DnsQType::TXT,
		    .ttl = 3577,
		    .name = "google.com.",
		    .txt_record = {"facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95"}},
		ReferenceRecord{.q_type = DnsQType::TXT,
		    .ttl = 3577,
		    .name = "google.com.",
		    .txt_record = {"docusign=1b0a6754-49b1-4db5-8540-d2c12664b289"}},
		ReferenceRecord{.q_type = DnsQType::TXT,
		    .ttl = 3577,
		    .name = "google.com.",
		    .txt_record =
			{"google-site-verification=wD8N7i1JTNTkezJ49swvWW48f8_9xveREV4oB-0Hf5o"}},
		ReferenceRecord{.q_type = DnsQType::TXT,
		    .ttl = 3577,
		    .name = "google.com.",
		    .txt_record =
			{"google-site-verification=TV9-DBe4R80X4v0M4U_bd_J9cpOJM0nikft0jAgjmsQ"}},
		ReferenceRecord{.q_type = DnsQType::TXT,
		    .ttl = 3577,
		    .name = "google.com.",
		    .txt_record =
			{"webexdomainverification.8YX6G=6e6922db-e3e6-4a36-904e-a805c28087fa"}},
		ReferenceRecord{.q_type = DnsQType::TXT,
		    .ttl = 3577,
		    .name = "google.com.",
		    .txt_record = {"docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e"}},
		ReferenceRecord{.q_type = DnsQType::TXT,
		    .ttl = 3577,
		    .name = "google.com.",
		    .txt_record = {"MS=E4A68B9AB2BB9670BCE15412F62916164C0B20BB"}},
		ReferenceRecord{.q_type = DnsQType::TXT,
		    .ttl = 3577,
		    .name = "google.com.",
		    .txt_record =
			{"atlassian-domain-verification="
			 "5YjTmWmjI92ewqkx2oXmBaD60Td9zWon9r6eakvHX6B77zzkFQto8PQ9QsKnbf4I"}},
		ReferenceRecord{.q_type = DnsQType::TXT,
		    .ttl = 3577,
		    .name = "google.com.",
		    .txt_record = {"v=spf1 include:_spf.google.com ~all"}}},
	    .auth_ref_records =
		{

		},
	    .additional_ref_records = {
		ReferenceRecord{.q_type = DnsQType::OPT, .ttl = 0, .name = ""}}};

	CheckPacket(test_packet);
}

TEST(DnsPacketParserTest, LONG_TXT_record) {
	auto test_packet = TestPacket{// Tests long TXT record
	    .raw = "\xbc\xd0\x74\x17\xbe\x44\x30\xde\x4b\xac\x03\x7c\x08\x00\x45\x00"
		   "\x04\x5e\x3b\x5d\x40\x00\x3a\x11\xfa\x1e\x01\x01\x01\x01\xc0\xa8"
		   "\x44\x69\x00\x35\xe8\xc7\x04\x4a\xe6\x45\x6c\x04\x81\x80\x00\x01"
		   "\x00\x01\x00\x00\x00\x01\x04\x74\x65\x73\x74\x0c\x62\x72\x75\x6e"
		   "\x65\x6c\x76\x6f\x6c\x67\x65\x6e\x02\x6e\x6c\x00\x00\x10\x00\x01"
		   "\xc0\x0c\x00\x10\x00\x01\x00\x00\x01\x2c\x04\x05\xff\x47\x32\x46"
		   "\x47\x76\x31\x6d\x38\x7a\x4e\x55\x77\x4c\x4a\x64\x37\x37\x72\x64"
		   "\x30\x78\x55\x74\x5a\x66\x59\x52\x62\x6a\x59\x51\x54\x68\x6b\x39"
		   "\x48\x47\x5a\x41\x31\x58\x66\x76\x41\x33\x78\x4a\x7a\x72\x77\x51"
		   "\x57\x5a\x51\x34\x54\x6d\x6d\x4b\x4b\x30\x68\x32\x6e\x39\x61\x43"
		   "\x79\x52\x77\x6d\x66\x34\x66\x66\x31\x46\x4d\x47\x5a\x74\x6e\x4d"
		   "\x5a\x4c\x32\x78\x75\x66\x38\x78\x64\x45\x53\x6a\x58\x66\x44\x70"
		   "\x56\x6d\x44\x6b\x65\x35\x63\x59\x42\x61\x46\x4a\x52\x72\x66\x54"
		   "\x7a\x64\x66\x76\x6a\x5a\x33\x31\x57\x6a\x6b\x53\x65\x71\x5a\x72"
		   "\x44\x58\x52\x6a\x4d\x33\x46\x4e\x38\x74\x57\x53\x4a\x71\x75\x36"
		   "\x63\x41\x52\x74\x32\x61\x6d\x68\x64\x4b\x53\x74\x5a\x64\x38\x39"
		   "\x6b\x7a\x38\x61\x4e\x76\x32\x65\x33\x4d\x75\x70\x6b\x50\x54\x4b"
		   "\x37\x70\x71\x38\x63\x65\x53\x44\x4d\x4c\x54\x4b\x48\x70\x55\x5a"
		   "\x61\x64\x5a\x33\x78\x4e\x78\x77\x53\x54\x77\x79\x32\x77\x6b\x39"
		   "\x74\x31\x59\x6d\x4a\x79\x38\x30\x4c\x6d\x69\x66\x58\x42\x31\x71"
		   "\x55\x6e\x35\x47\x53\x38\x66\x72\x43\x44\x54\x42\x4a\x33\x72\x35"
		   "\x4e\x4d\x44\x32\x37\x43\x65\x35\x51\x77\x6d\x42\xff\x56\x66\x59"
		   "\x48\x37\x58\x35\x5a\x42\x65\x43\x70\x35\x72\x6d\x4d\x33\x36\x69"
		   "\x53\x70\x70\x45\x58\x50\x59\x33\x79\x65\x66\x65\x43\x34\x70\x4b"
		   "\x78\x61\x56\x4b\x57\x62\x35\x70\x42\x37\x62\x53\x67\x77\x39\x67"
		   "\x65\x4e\x51\x4b\x77\x74\x31\x44\x72\x66\x30\x53\x37\x6b\x34\x62"
		   "\x41\x37\x44\x36\x62\x4b\x78\x41\x64\x43\x55\x72\x45\x4c\x72\x47"
		   "\x64\x55\x77\x61\x78\x33\x4d\x4b\x4c\x4e\x4b\x59\x76\x45\x71\x38"
		   "\x35\x4d\x32\x7a\x71\x78\x69\x37\x70\x33\x55\x7a\x46\x79\x33\x53"
		   "\x6e\x61\x39\x57\x66\x66\x67\x79\x37\x6d\x62\x42\x6a\x44\x58\x37"
		   "\x71\x70\x47\x44\x74\x62\x78\x7a\x68\x35\x55\x52\x31\x31\x38\x71"
		   "\x74\x39\x6e\x55\x5a\x56\x64\x50\x42\x74\x6d\x43\x66\x30\x64\x70"
		   "\x4c\x51\x34\x51\x74\x38\x76\x75\x4a\x65\x31\x74\x64\x32\x32\x7a"
		   "\x66\x36\x51\x74\x65\x55\x78\x55\x53\x61\x50\x55\x31\x4a\x37\x63"
		   "\x57\x7a\x43\x48\x74\x34\x68\x71\x71\x4b\x56\x5a\x43\x44\x4a\x78"
		   "\x51\x62\x67\x64\x45\x32\x32\x32\x4b\x4c\x65\x74\x50\x71\x31\x63"
		   "\x35\x70\x78\x65\x46\x68\x44\x51\x31\x50\x38\x76\x41\x6a\x46\x45"
		   "\x65\x55\x6d\x70\x69\x54\x4d\x70\x77\x6a\x74\x6e\xff\x44\x56\x77"
		   "\x68\x69\x6b\x69\x76\x4e\x75\x7a\x55\x51\x69\x33\x67\x44\x76\x66"
		   "\x4a\x37\x63\x38\x31\x46\x4b\x68\x36\x7a\x74\x31\x36\x6a\x6d\x32"
		   "\x75\x69\x4e\x58\x55\x54\x34\x67\x69\x71\x71\x65\x56\x4b\x36\x4b"
		   "\x57\x35\x31\x67\x66\x5a\x33\x5a\x5a\x54\x46\x56\x55\x63\x62\x51"
		   "\x44\x75\x71\x65\x33\x72\x44\x66\x38\x5a\x76\x4c\x6a\x46\x31\x67"
		   "\x30\x44\x66\x71\x50\x78\x50\x6d\x62\x61\x33\x52\x75\x6a\x4d\x45"
		   "\x69\x32\x72\x33\x67\x53\x52\x66\x7a\x4b\x50\x4e\x42\x45\x6b\x39"
		   "\x52\x46\x64\x55\x71\x77\x59\x75\x7a\x31\x4e\x7a\x69\x32\x46\x6d"
		   "\x44\x34\x75\x57\x70\x44\x36\x42\x36\x54\x6a\x62\x44\x71\x59\x6a"
		   "\x42\x36\x4e\x43\x50\x75\x35\x41\x45\x4d\x43\x6a\x31\x78\x34\x48"
		   "\x78\x71\x48\x65\x37\x50\x45\x48\x75\x6a\x7a\x67\x38\x50\x48\x78"
		   "\x53\x58\x6b\x55\x67\x75\x4d\x6a\x45\x45\x50\x46\x34\x45\x74\x45"
		   "\x74\x66\x43\x6b\x70\x44\x4d\x42\x32\x35\x47\x33\x71\x65\x67\x47"
		   "\x35\x48\x4d\x44\x6e\x5a\x57\x62\x78\x79\x41\x61\x4c\x68\x30\x76"
		   "\x51\x35\x6b\x6d\x36\x47\x76\x56\x53\x75\x6e\x48\x55\x78\x47\x71"
		   "\x54\x30\x5a\x7a\x44\x4e\x41\x4a\x42\x6b\x71\x30\xff\x36\x34\x72"
		   "\x58\x32\x6a\x66\x6e\x53\x74\x38\x47\x74\x4a\x58\x59\x79\x6d\x55"
		   "\x66\x39\x31\x38\x7a\x39\x71\x38\x75\x54\x30\x75\x5a\x50\x7a\x56"
		   "\x71\x34\x51\x5a\x63\x57\x38\x30\x67\x75\x78\x46\x66\x52\x79\x70"
		   "\x66\x72\x6a\x54\x30\x31\x52\x57\x69\x66\x4b\x62\x7a\x70\x58\x33"
		   "\x4a\x44\x79\x33\x66\x78\x38\x5a\x58\x72\x61\x31\x6e\x57\x46\x50"
		   "\x37\x42\x4c\x57\x63\x78\x67\x76\x58\x75\x47\x6e\x45\x33\x48\x39"
		   "\x39\x78\x33\x34\x42\x71\x79\x46\x36\x74\x48\x30\x79\x51\x77\x37"
		   "\x42\x6e\x51\x47\x35\x52\x77\x58\x37\x78\x4b\x76\x31\x76\x4d\x4b"
		   "\x6d\x72\x75\x54\x51\x55\x76\x34\x64\x6a\x36\x35\x6b\x5a\x34\x43"
		   "\x37\x36\x31\x6d\x32\x66\x38\x6e\x46\x4e\x63\x69\x53\x33\x7a\x41"
		   "\x36\x4e\x43\x37\x39\x42\x63\x34\x61\x41\x69\x78\x33\x79\x37\x71"
		   "\x61\x37\x72\x5a\x79\x4b\x75\x61\x78\x4d\x75\x58\x41\x53\x63\x59"
		   "\x76\x4a\x59\x4b\x4e\x74\x74\x31\x62\x62\x4d\x41\x47\x38\x42\x37"
		   "\x31\x51\x43\x72\x58\x6a\x53\x67\x63\x43\x61\x39\x6a\x63\x79\x78"
		   "\x45\x74\x70\x32\x4d\x44\x56\x67\x51\x48\x6a\x75\x56\x71\x6d\x79"
		   "\x42\x52\x32\x31\x38\x32\x4c\x58\x6a\x64\x6d\x43\x04\x54\x48\x4c"
		   "\x61\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00"s,

	    .ip_type = PacketIpType::Ipv4,
	    .qname = "test.brunelvolgen.nl.",
	    .q_type = DnsQType::TXT,
	    .error_code = DnsRCode::NOERROR,
	    .id = 0x6c04,
	    .dst_port = 59591,
	    .src_ip = "1.1.1.1",
	    .dst_ip = "192.168.68.105",

	    .answer_ref_records = {ReferenceRecord{.q_type = DnsQType::TXT,
		.ttl = 300,
		.name = "test.brunelvolgen.nl.",
		.txt_record =
		    {"G2FGv1m8zNUwLJd77rd0xUtZfYRbjYQThk9HGZA1XfvA3xJzrwQWZQ4TmmKK0h2n9aCyRwmf4ff1F"
		     "MGZtnMZL2xuf8xdESjXfDpVmDke5cYBaFJRrfTzdfvjZ31WjkSeqZrDXRjM3FN8tWSJqu6cARt2am"
		     "hdKStZd89kz8aNv2e3MupkPTK7pq8ceSDMLTKHpUZadZ3xNxwSTwy2wk9t1YmJy80LmifXB1qUn5G"
		     "S8frCDTBJ3r5NMD27Ce5QwmBVfYH7X5ZBeCp5rmM36iSppEXPY3yefeC4pKxaVKWb5pB7bSgw9geN"
		     "QKwt1Drf0S7k4bA7D6bKxAdCUrELrGdUwax3MKLNKYvEq85M2zqxi7p3UzFy3Sna9Wffgy7mbBjDX"
		     "7qpGDtbxzh5UR118qt9nUZVdPBtmCf0dpLQ4Qt8vuJe1td22zf6QteUxUSaPU1J7cWzCHt4hqqKVZ"
		     "CDJxQbgdE222KLetPq1c5pxeFhDQ1P8vAjFEeUmpiTMpwjtnDVwhikivNuzUQi3gDvfJ7c81FKh6z"
		     "t16jm2uiNXUT4giqqeVK6KW51gfZ3ZZTFVUcbQDuqe3rDf8ZvLjF1g0DfqPxPmba3RujMEi2r3gSR"
		     "fzKPNBEk9RFdUqwYuz1Nzi2FmD4uWpD6B6TjbDqYjB6NCPu5AEMCj1x4HxqHe7PEHujzg8PHxSXkU"
		     "guMjEEPF4EtEtfCkpDMB25G3qegG5HMDnZWbxyAaLh0vQ5km6GvVSunHUxGqT0ZzDNAJBkq064rX2"
		     "jfnSt8GtJXYymUf918z9q8uT0uZPzVq4QZcW80guxFfRypfrjT01RWifKbzpX3JDy3fx8ZXra1nWF"
		     "P7BLWcxgvXuGnE3H99x34BqyF6tH0yQw7BnQG5RwX7xKv1vMKmruTQUv4dj65kZ4C761m2f8nFNci"
		     "S3zA6NC79Bc4aAix3y7qa7rZyKuaxMuXAScYvJYKNtt1bbMAG8B71QCrXjSgcCa9jcyxEtp2MDVgQ"
		     "HjuVqmyBR2182LXjdmCTHLa"}}},
	    .auth_ref_records =
		{

		},
	    .additional_ref_records = {
		ReferenceRecord{.q_type = DnsQType::OPT, .ttl = 0, .name = ""}}};

	CheckPacket(test_packet);
}

TEST(DnsPacketParserTest, MX_record) {
	auto test_packet = TestPacket{// Tests MX record
	    .raw = "\xbc\xd0\x74\x17\xbe\x44\x26\x5a\x4c\x53\x36\x7e\x08\x00\x45\x00"
		   "\x00\xb0\xab\x69\x40\x00\x40\x11\x0a\xd1\xc0\xa8\x01\x01\xc0\xa8"
		   "\x01\xb1\x00\x35\xf2\x08\x00\x9c\x96\x48\x8d\xde\x81\x80\x00\x01"
		   "\x00\x01\x00\x00\x00\x05\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f"
		   "\x6d\x00\x00\x0f\x00\x01\xc0\x0c\x00\x0f\x00\x01\x00\x00\x01\x0b"
		   "\x00\x09\x00\x0a\x04\x73\x6d\x74\x70\xc0\x0c\xc0\x2a\x00\x01\x00"
		   "\x01\x00\x00\x01\x2c\x00\x04\x8e\xfa\x66\x1a\xc0\x2a\x00\x01\x00"
		   "\x01\x00\x00\x01\x2c\x00\x04\x8e\xfa\x66\x1b\xc0\x2a\x00\x1c\x00"
		   "\x01\x00\x00\x01\x2c\x00\x10\x2a\x00\x14\x50\x40\x25\x04\x02\x00"
		   "\x00\x00\x00\x00\x00\x00\x1a\xc0\x2a\x00\x1c\x00\x01\x00\x00\x01"
		   "\x2c\x00\x10\x2a\x00\x14\x50\x40\x25\x04\x02\x00\x00\x00\x00\x00"
		   "\x00\x00\x1b\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00"s,

	    .ip_type = PacketIpType::Ipv4,
	    .qname = "google.com.",
	    .q_type = DnsQType::MX,
	    .error_code = DnsRCode::NOERROR,
	    .id = 0x8DDE,
	    .dst_port = 61960,
	    .src_ip = "192.168.1.1",
	    .dst_ip = "192.168.1.177",

	    .answer_ref_records = {ReferenceRecord{.q_type = DnsQType::MX,
		.ttl = 267,
		.name = "google.com.",
		.mx_record = {.name = "smtp.google.com.", .preference = 10}}},
	    .auth_ref_records =
		{

		},
	    .additional_ref_records = {ReferenceRecord{.q_type = DnsQType::A,
					   .ttl = 300,
					   .name = "smtp.google.com.",
					   .a_record = {"142.250.102.26"}},
		ReferenceRecord{.q_type = DnsQType::A,
		    .ttl = 300,
		    .name = "smtp.google.com.",
		    .a_record = {"142.250.102.27"}},
		ReferenceRecord{.q_type = DnsQType::AAAA,
		    .ttl = 300,
		    .name = "smtp.google.com.",
		    .aaaa_record = {"2a00:1450:4025:402::1a"}},
		ReferenceRecord{.q_type = DnsQType::AAAA,
		    .ttl = 300,
		    .name = "smtp.google.com.",
		    .aaaa_record = {"2a00:1450:4025:402::1b"}},
		ReferenceRecord{.q_type = DnsQType::OPT, .ttl = 0, .name = ""}}};

	CheckPacket(test_packet);
}

TEST(DnsPacketParserTest, PTR_record) {
	auto test_packet = TestPacket{// Checks PTR record
	    .raw = "\xbc\xd0\x74\x17\xbe\x44\x26\x5a\x4c\x53\x36\x7e\x08\x00\x45\x00"
		   "\x00\x75\x5b\x3f\x40\x00\x40\x11\x5b\x36\xc0\xa8\x01\x01\xc0\xa8"
		   "\x01\xb1\x00\x35\xd8\x67\x00\x61\x39\x88\x55\x86\x81\x80\x00\x01"
		   "\x00\x01\x00\x00\x00\x01\x02\x32\x36\x03\x31\x30\x32\x03\x32\x35"
		   "\x30\x03\x31\x34\x32\x07\x69\x6e\x2d\x61\x64\x64\x72\x04\x61\x72"
		   "\x70\x61\x00\x00\x0c\x00\x01\xc0\x0c\x00\x0c\x00\x01\x00\x00\x09"
		   "\x6e\x00\x15\x09\x72\x62\x2d\x69\x6e\x2d\x66\x32\x36\x05\x31\x65"
		   "\x31\x30\x30\x03\x6e\x65\x74\x00\x00\x00\x29\x10\x00\x00\x00\x00"
		   "\x00\x00\x00"s,

	    .ip_type = PacketIpType::Ipv4,
	    .qname = "26.102.250.142.in-addr.arpa.",
	    .q_type = DnsQType::PTR,
	    .error_code = DnsRCode::NOERROR,
	    .id = 0x5586,
	    .dst_port = 55399,
	    .src_ip = "192.168.1.1",
	    .dst_ip = "192.168.1.177",

	    .answer_ref_records = {ReferenceRecord{.q_type = DnsQType::PTR,
		.ttl = 2414,
		.name = "26.102.250.142.in-addr.arpa.",
		.ptr_record = {"rb-in-f26.1e100.net."}}},
	    .auth_ref_records =
		{

		},
	    .additional_ref_records = {
		ReferenceRecord{.q_type = DnsQType::OPT, .ttl = 0, .name = ""}}};

	CheckPacket(test_packet);
}

TEST(DnsPacketParserTest, OutOfBoundsJump) {
	// Checks if OutOfBounds is returned if a jump in the packet jumps to one byte after the end
	// of the packet
	auto test_packet = TestPacket{
	    .raw = "\xbc\xd0\x74\x17\xbe\x44\x30\xde\x4b\xac\x03\x7c\x08\x00\x45\x00"
		   "\x00\x63\xe2\xd9\x00\x00\x3b\x11\xd6\xf5\xc0\xa8\x00\x01\xc0\xa8"
		   "\x44\x69\x00\x35\xce\x31\x00\x4f\x9d\x06\x7b\xd5\x81\x80\x00\x01"
		   "\x00\x02\x00\x00\x00\x01\x07\x68\x61\x64\x72\x69\x61\x6e\x02\x69"
		   "\x6f\x00\x00\x01\x00\x01\xc0\x47\x00\x01\x00\x01\x00\x00\x0e\x10"
		   "\x00\x04\xc7\x3c\x67\xb0\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10"
		   "\x00\x04\xc7\x3c\x67\x4c\x00\x00\x29\x02\x00\x00\x00\x00\x00\x00\x00"s};

	auto [mbuf_pool_out, parsed_packet] = ExtractPacket(test_packet);
	EXPECT_EQ(parsed_packet.has_value(), false);
	EXPECT_EQ(parsed_packet.error(), DNSParseError::OutOfBounds);
}

TEST(DnsPacketParserTest, OutOfBoundsTrunc) {
	// Checks if OutOfBounds is returned if the packet is truncated one byte before the end of
	// the DNS header
	auto test_packet =
	    TestPacket{.raw = "\xbc\xd0\x74\x17\xbe\x44\x30\xde\x4b\xac\x03\x7c\x08\x00\x45\x00"
			      "\x00\x63\xe2\xd9\x00\x00\x3b\x11\xd6\xf5\xc0\xa8\x00\x01\xc0\xa8"
			      "\x44\x69\x00\x35\xce\x31\x00\x4f\x9d\x06\x7b\xd5\x81\x80\x00\x01"
			      "\x00\x02\x00\x00\x00"s};

	auto [mbuf_pool_out, parsed_packet] = ExtractPacket(test_packet);
	EXPECT_EQ(parsed_packet.has_value(), false);
	EXPECT_EQ(parsed_packet.error(), DNSParseError::OutOfBounds);
}
