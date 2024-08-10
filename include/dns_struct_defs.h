#pragma once

#include <arpa/inet.h>
#include <dns_format.h>
#include <expected.h>
#include <netinet/in.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>

#include <array>
#include <cstring>
#include <span>
#include <variant>

#include "dpdk_wrappers.h"
#include "network_types.h"
#include "spdlog/fmt/bundled/core.h"

namespace {
constexpr uint16_t MAX_RECORDS = 64;
} // namespace

enum class DNSParseError {
	PktError,
	OutOfBounds,
	InvalidQCount,
	NameTooLong,
	MaxJumpsReached,
	AllocationError,
	IpHdrProtoErr,
	EtherHdrProtoErr,
	SrcPortErr,
	MalformedPacket,
	TxtTooLong,
};

// spdlog formatting for DNSParseError
template <>
struct fmt::formatter<DNSParseError> : formatter<string_view> {
	auto format(DNSParseError e, format_context &c) const -> decltype(c.out());
};

struct DnsQuestion {
	DnsName name;
	DnsQType q_type;
};

struct ARdata {
	InAddr ipv4_addr;
};

struct AAAARdata {
	In6Addr ipv6_addr;
};

struct NSRdata {
	DnsName nameserver;
};

struct MXRdata {
	DnsName mailserver;
	uint16_t preference;
};

struct CNAMERdata {
	DnsName cname;
};

struct DNAMERdata {
	DnsName dname;
};

struct PTRRdata {
	DnsName ptr;
};

struct TXTRdata {
	TxtString txt;
};

struct SOARdata {
	DnsName m_name;
	DnsName r_name;

	struct IntervalSettings {
		uint32_t serial;
		uint32_t refresh;
		uint32_t retry;
		uint32_t expire;
		uint32_t minimum;
	} interval_settings;
};

struct OPTRdata { };

using Rdata = std::variant<ARdata, AAAARdata, NSRdata, MXRdata, CNAMERdata, DNAMERdata, PTRRdata,
    TXTRdata, SOARdata, OPTRdata, std::monostate>;

struct ResourceRecord {
	DnsName name;
	DnsQType q_type;
	uint32_t ttl;

	Rdata r_data;
};

struct IpData {
	IpAddr src_ip, dst_ip;
	uint16_t src_port, dst_port;
};

struct DNSPacket {
	static tl::expected<DNSPacket, DNSParseError> init(
	    RTEMempool<DefaultPacket, MbufType::Raw> &mempool, RTEMbufElement<DefaultPacket, MbufType::Pkt>& pkt);

	IpData ip_data;
	uint16_t dns_id;

	DnsName question;
	DnsQType q_type;
	DnsRCode r_code;

	bool rec_capped; // Records had to be truncated

    struct Data {
        RTEMbufArray<ResourceRecord, MAX_RECORDS> ans;
        RTEMbufArray<ResourceRecord, MAX_RECORDS> auth;
        RTEMbufArray<ResourceRecord, MAX_RECORDS> add;
    } data;

	uint16_t GetWorkerId() const {
		return ((dns_id & 0xFC00) >> 10) - 1;
	}

	uint32_t GetBufferLoc() const {
		return static_cast<uint32_t>((ip_data.dst_port & 0x7FFF) - 1024) |
		       static_cast<uint32_t>((dns_id & 0x3FF) << 14);
	}

private:
	DNSPacket(IpData ip_data, uint16_t dns_id, DnsName question, DnsQType q_type,
			DnsRCode r_code, bool rec_capped, RTEMbufArray<ResourceRecord, MAX_RECORDS> &&ans,
			RTEMbufArray<ResourceRecord, MAX_RECORDS> &&auth,
			RTEMbufArray<ResourceRecord, MAX_RECORDS> &&add)
		: ip_data(ip_data),
		dns_id(dns_id),
		question(question),
		q_type(q_type),
		r_code(r_code),
		rec_capped(rec_capped),
        data{
            .ans{std::move(ans)},
            .auth{std::move(auth)},
            .add{std::move(add)},
        } { }
};

struct DNSPacketDistr {
	DNSPacket dns_packet;
	RTEMbufElement<DefaultPacket, MbufType::Pkt> raw_packet;
};
