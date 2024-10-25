#include "dns_packet.h"

#include <expected.h>
#include <expected_helpers.h>
#include <netinet/in.h>
#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_udp.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstring>
#include <exception>

#include "dns_format.h"
#include "dns_struct_defs.h"
#include "dpdk_wrappers.h"
#include "network_types.h"
#include "spdlog/fmt/bundled/core.h"
#include "spdlog/fmt/fmt.h"

auto fmt::formatter<DNSParseError>::format(DNSParseError e, format_context &ctx) const
    -> decltype(ctx.out()) {
	string_view error = "unknown error :(";
	switch (e) {
		case DNSParseError::OutOfBounds:
			error = "out of bounds";
			break;
		case DNSParseError::PktError:
			error = "packet error";
			break;
		case DNSParseError::SrcPortErr:
			error = "source port error";
			break;
		case DNSParseError::TxtTooLong:
			error = "text too long";
			break;
		case DNSParseError::NameTooLong:
			error = "name too long";
			break;
		case DNSParseError::InvalidQCount:
			error = "invalid question count";
			break;
		case DNSParseError::IpHdrProtoErr:
			error = "wrong ip header proto";
			break;
		case DNSParseError::AllocationError:
			error = "allocation error";
			break;
		case DNSParseError::MalformedPacket:
			error = "malformed packet";
			break;
		case DNSParseError::MaxJumpsReached:
			error = "max jumps reached";
			break;
		case DNSParseError::EtherHdrProtoErr:
			error = "ethernet header error";
		case DNSParseError::InvalidChar:
			error = "invalid character detected in packet";
			break;
	}
	return formatter<string_view>::format(error, ctx);
}

template <typename T>
inline tl::expected<const T *, DNSParseError> AdvanceReader(std::span<const std::byte> bytes,
    std::span<const std::byte>::iterator &reader) {
	if (static_cast<std::span<const std::byte>::iterator>(reader + sizeof(T)) > bytes.end())
	    [[unlikely]]
		return tl::unexpected(DNSParseError::OutOfBounds);

	auto ptr = reinterpret_cast<const T *>(reader.base());
	reader += sizeof(T);
	return ptr;
}

bool contains_unprintable_chars_or_space(std::string_view sv) {
	bool result = false;
	for (const auto &c : sv) {
		result |= c < '!' || c > '~';
	}

	return result;
}

tl::expected<DnsName, DNSParseError> ReadFromDNSNameFormat(std::span<const std::byte> bytes,
    std::span<const std::byte>::iterator &reader) {
	DnsName name_parsed;

	// Keep track of jump count to prevent infinite loops
	int jmp_cnt = 0;

	name_parsed.buf[0] = '\0';
	// Number of bytes read to name
	name_parsed.len = 0;
	// Number of bytes stepped forward in packet, start at one to step past NULL terminator
	int count = 1;
	// Save where we started so we can set the iterator to the correct
	// position later.
	auto begin = reader;

	// Check if current character can be safely accessed
	if (reader >= bytes.end())
		return tl::unexpected(DNSParseError::OutOfBounds);

	// After every read/write the packet bounds are checked for the subsequent character,
	// in this way it is always possible to check for / insert NULL terminator

	// Read until \0 terminator is found
	while (static_cast<char>(*reader) != '\0') {
		// Check for jump before every segement, indicated by 0b11xxxxxx byte
		if (static_cast<unsigned char>(*reader) >= 0xC0) [[unlikely]] {
			// Check bounds before incrementing pointer
			if (reader + 1 >= bytes.end()) [[unlikely]]
				return tl::unexpected(DNSParseError::OutOfBounds);
			std::byte msb = *reader;
			std::byte lsb = *(reader + 1);
			uint16_t offset = static_cast<uint16_t>(msb & std::byte{0x3F}) << 8 |
			                  static_cast<uint16_t>(lsb);
			reader = bytes.begin() + offset;

			// Check new location of reader for bounds before reading
			if (reader >= bytes.end() || reader < bytes.begin()) [[unlikely]]
				return tl::unexpected(DNSParseError::OutOfBounds);

			jmp_cnt++;
			if (jmp_cnt > 10) [[unlikely]]
				return tl::unexpected(DNSParseError::MaxJumpsReached);

			continue;
		}

		// Read length of next segment
		const uint8_t len = static_cast<uint8_t>(*(reader));
		if (++reader >= bytes.end()) [[unlikely]]
			return tl::unexpected(DNSParseError::OutOfBounds);
		// Increment count if we haven't jumped yet
		count += !(jmp_cnt);

		// Read segment into buffer
		for (uint8_t p = 0; p < len; p++) {
			name_parsed.buf[name_parsed.len] = static_cast<uint16_t>(*(reader));
			if (++reader >= bytes.end()) [[unlikely]]
				return tl::unexpected(DNSParseError::OutOfBounds);
			if (++name_parsed.len >= DOMAIN_NAME_MAX_SIZE) [[unlikely]]
				return tl::unexpected(DNSParseError::NameTooLong);

			// Increment count if we haven't jumped yet
			count += !(jmp_cnt);
		}

		name_parsed.buf[name_parsed.len] = '.';
		if (++name_parsed.len >= DOMAIN_NAME_MAX_SIZE) [[unlikely]]
			return tl::unexpected(DNSParseError::NameTooLong);
	}

	// Add NULL terminator
	name_parsed.buf[name_parsed.len] = '\0';

	if (contains_unprintable_chars_or_space(std::string_view(name_parsed))) [[unlikely]]
		return tl::unexpected(DNSParseError::InvalidChar);

	// Add one to count if jumped to account for 2 byte offset field instead of 1 byte NULL
	// terminator
	count += (bool) jmp_cnt;

	reader = begin + count;

	return name_parsed;
}

template <size_t N>
tl::expected<FixedName<N>, DNSParseError> ParseFixedName(std::span<const std::byte> bytes,
    std::span<const std::byte>::iterator &reader, uint16_t length) {
	FixedName<N> result;

	// Tag field name length does not take \0 terminator into account
	if (length >= N) [[unlikely]]
		return tl::unexpected(DNSParseError::NameTooLong);
	if (reader + length > bytes.end()) [[unlikely]]
		return tl::unexpected(DNSParseError::OutOfBounds);

	// Copy tag into r_data
	std::copy(reader, reader + length, reinterpret_cast<std::byte *>(result.buf.begin()));
	result.buf[length] = '\0';
	result.len = length;
	reader += length;

	return result;
}

tl::expected<ResourceRecord, DNSParseError> ParseResourceRecord(std::span<const std::byte> bytes,
    std::span<const std::byte>::iterator &reader) {
	ResourceRecord parsed_record;
	parsed_record.name = UNWRAP_OR_RETURN(ReadFromDNSNameFormat(bytes, reader));

	const RData *response = UNWRAP_OR_RETURN(AdvanceReader<RData>(bytes, reader));
	parsed_record.q_type = static_cast<DnsQType>(rte_be_to_cpu_16(response->type));
	parsed_record.ttl = rte_be_to_cpu_32(response->ttl);

	auto rdata_bytes = std::span(reader, rte_be_to_cpu_16(response->data_len));

	// Make sure that the rdata bytes area doesn't go outside the packet byte area
	if (rdata_bytes.end() > bytes.end()) [[unlikely]]
		return tl::unexpected(DNSParseError::OutOfBounds);

	auto begin = reader;
	switch (parsed_record.q_type) {
		case DnsQType::A: {
			ARdata r_data;
			r_data.ipv4_addr =
			    *UNWRAP_OR_RETURN(AdvanceReader<InAddr>(rdata_bytes, reader));
			parsed_record.r_data = r_data;
			break;
		}
		case DnsQType::AAAA: {
			AAAARdata r_data;
			r_data.ipv6_addr =
			    *UNWRAP_OR_RETURN(AdvanceReader<In6Addr>(rdata_bytes, reader));
			parsed_record.r_data = r_data;
			break;
		}
		case DnsQType::NS: {
			NSRdata r_data;
			// Always pass in the full DNS packet as valid area for the
			// ReadFromDNSNameFormat since the reader might jump
			r_data.nameserver = UNWRAP_OR_RETURN(ReadFromDNSNameFormat(bytes, reader));
			parsed_record.r_data = r_data;
			break;
		}
		case DnsQType::MX: {
			MXRdata r_data;
			r_data.preference = rte_be_to_cpu_16(
			    *UNWRAP_OR_RETURN(AdvanceReader<uint16_t>(rdata_bytes, reader)));
			r_data.mailserver = UNWRAP_OR_RETURN(ReadFromDNSNameFormat(bytes, reader));
			parsed_record.r_data = r_data;
			break;
		}
		case DnsQType::CNAME: {
			CNAMERdata r_data;
			r_data.cname = UNWRAP_OR_RETURN(ReadFromDNSNameFormat(bytes, reader));
			parsed_record.r_data = r_data;
			break;
		}
		case DnsQType::DNAME: {
			DNAMERdata r_data;
			r_data.dname = UNWRAP_OR_RETURN(ReadFromDNSNameFormat(bytes, reader));
			parsed_record.r_data = r_data;
			break;
		}
		case DnsQType::PTR: {
			PTRRdata r_data;
			r_data.ptr = UNWRAP_OR_RETURN(ReadFromDNSNameFormat(bytes, reader));
			parsed_record.r_data = r_data;
			break;
		}
		case DnsQType::TXT: {
			TXTRdata r_data;
			r_data.txt.len = 0;

			auto txt_writer = r_data.txt.buf.begin();

			while (reader < rdata_bytes.end()) {
				uint8_t next_string_size =
				    *UNWRAP_OR_RETURN(AdvanceReader<uint8_t>(rdata_bytes, reader));

				if (reader + next_string_size > rdata_bytes.end()) [[unlikely]]
					return tl::unexpected(DNSParseError::OutOfBounds);

				// Also take \0 terminator into account
				if (txt_writer + next_string_size + 1 > r_data.txt.buf.end())
				    [[unlikely]]
					return tl::unexpected(DNSParseError::TxtTooLong);

				std::copy(reader, reader + next_string_size,
				    reinterpret_cast<std::byte *>(txt_writer));

				reader += next_string_size;
				txt_writer += next_string_size;
				r_data.txt.len += next_string_size;
			}

			// Bound validity is already checked
			*txt_writer = '\0';
			parsed_record.r_data = r_data;
			break;
		}
		case DnsQType::SOA: {
			SOARdata r_data;
			r_data.m_name = UNWRAP_OR_RETURN(ReadFromDNSNameFormat(bytes, reader));
			r_data.r_name = UNWRAP_OR_RETURN(ReadFromDNSNameFormat(bytes, reader));

			r_data.interval_settings = *UNWRAP_OR_RETURN(
			    AdvanceReader<SOARdata::IntervalSettings>(bytes, reader));
			r_data.interval_settings.serial =
			    rte_be_to_cpu_32(r_data.interval_settings.serial);
			r_data.interval_settings.refresh =
			    rte_be_to_cpu_32(r_data.interval_settings.refresh);
			r_data.interval_settings.retry =
			    rte_be_to_cpu_32(r_data.interval_settings.retry);
			r_data.interval_settings.expire =
			    rte_be_to_cpu_32(r_data.interval_settings.expire);
			r_data.interval_settings.minimum =
			    rte_be_to_cpu_32(r_data.interval_settings.minimum);

			parsed_record.r_data = r_data;
			break;
		}
		case DnsQType::CAA: {
			CAARdata r_data;
			r_data.flags =
			    *UNWRAP_OR_RETURN(AdvanceReader<uint8_t>(rdata_bytes, reader));

			uint8_t tag_length =
			    *UNWRAP_OR_RETURN(AdvanceReader<uint8_t>(rdata_bytes, reader));

			r_data.tag = UNWRAP_OR_RETURN(
			    ParseFixedName<CAA_TAG_MAX_SIZE>(rdata_bytes, reader, tag_length));

			if (contains_unprintable_chars_or_space(std::string_view(r_data.tag)))
			    [[unlikely]]
				return tl::unexpected(DNSParseError::InvalidChar);

			uint16_t value_len = rdata_bytes.end() - reader;

			// Max length of the value is not specified in the RFC,
			// character string should be sufficient
			r_data.value = UNWRAP_OR_RETURN(ParseFixedName<CHARACTER_STRING_MAX_SIZE>(
			    rdata_bytes, reader, value_len));

			parsed_record.r_data = r_data;
			break;
		}
		case DnsQType::OPT: {
			reader += rte_be_to_cpu_16(response->data_len);

			parsed_record.r_data = OPTRdata{};
			break;
		}
		default:
			reader += rte_be_to_cpu_16(response->data_len);
			parsed_record.r_data = std::monostate();
			break;
	}

	// Check that the actual read bytes are equal to the number of bytes indicated in
	// the RData length section
	if (reader != begin + rte_be_to_cpu_16(response->data_len)) [[unlikely]]
		return tl::unexpected(DNSParseError::MalformedPacket);

	return parsed_record;
}

tl::expected<DNSPacket, DNSParseError> DNSPacket::init(
    RTEMempool<DefaultPacket, MbufType::Raw> &mempool,
    RTEMbufElement<DefaultPacket, MbufType::Pkt> &raw_pkt) {
	auto pkt = raw_pkt.get();
	std::span<const std::byte> packet_bytes(pkt.data().padding.data(), pkt.data_len);

	auto reader = packet_bytes.begin();

	IpData ip_data{};

	const rte_ether_hdr *ether_hdr =
	    UNWRAP_OR_RETURN(AdvanceReader<rte_ether_hdr>(packet_bytes, reader));

	uint16_t ether_type = rte_be_to_cpu_16(ether_hdr->ether_type);
	if (ether_type == RTE_ETHER_TYPE_IPV4) {
		const rte_ipv4_hdr *ip_hdr =
		    UNWRAP_OR_RETURN(AdvanceReader<rte_ipv4_hdr>(packet_bytes, reader));

		ip_data.dst_ip = InAddr{ip_hdr->dst_addr};
		ip_data.src_ip = InAddr{ip_hdr->src_addr};

		if (ip_hdr->next_proto_id != IPPROTO_UDP)
			return tl::unexpected(DNSParseError::IpHdrProtoErr);

	} else if (ether_type == RTE_ETHER_TYPE_IPV6) {
		const rte_ipv6_hdr *ip_hdr =
		    UNWRAP_OR_RETURN(AdvanceReader<rte_ipv6_hdr>(packet_bytes, reader));

		ip_data.dst_ip = *reinterpret_cast<const In6Addr *>(ip_hdr->dst_addr);
		ip_data.src_ip = *reinterpret_cast<const In6Addr *>(ip_hdr->src_addr);

		if (ip_hdr->proto != IPPROTO_UDP)
			return tl::unexpected(DNSParseError::IpHdrProtoErr);

	} else {
		return tl::unexpected(DNSParseError::EtherHdrProtoErr);
	}

	const rte_udp_hdr *udp_hdr =
	    UNWRAP_OR_RETURN(AdvanceReader<rte_udp_hdr>(packet_bytes, reader));

	ip_data.dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
	ip_data.src_port = rte_be_to_cpu_16(udp_hdr->src_port);

	if (ip_data.src_port != 53)
		return tl::unexpected(DNSParseError::SrcPortErr);

	std::span<const std::byte> dns_bytes = std::span(reader, packet_bytes.end());

	const DnsHeader *hdr = UNWRAP_OR_RETURN(AdvanceReader<DnsHeader>(dns_bytes, reader));

	if (rte_be_to_cpu_16(hdr->q_count) != 1) [[unlikely]]
		return tl::unexpected(DNSParseError::InvalidQCount);

	DnsName question = UNWRAP_OR_RETURN(ReadFromDNSNameFormat(dns_bytes, reader));
	const QuestionInfo *question_info =
	    UNWRAP_OR_RETURN(AdvanceReader<QuestionInfo>(dns_bytes, reader));

	uint16_t num_ans = std::min(MAX_RECORDS, rte_be_to_cpu_16(hdr->ans_count));
	uint16_t num_auth = std::min(MAX_RECORDS, rte_be_to_cpu_16(hdr->auth_count));
	uint16_t num_add = std::min(MAX_RECORDS, rte_be_to_cpu_16(hdr->add_count));

	bool records_capped = rte_be_to_cpu_16(hdr->add_count) > MAX_RECORDS ||
	                      rte_be_to_cpu_16(hdr->auth_count) > MAX_RECORDS ||
	                      rte_be_to_cpu_16(hdr->add_count) > MAX_RECORDS;

	auto ans_mbufs_ =
	    RTEMbufArray<ResourceRecord, MAX_RECORDS, MbufType::Raw>::init(mempool, num_ans);
	auto ans_mbufs =
	    UNWRAP_OR_RETURN_ERR(std::move(ans_mbufs_), DNSParseError::AllocationError);

	auto auth_mbufs_ =
	    RTEMbufArray<ResourceRecord, MAX_RECORDS, MbufType::Raw>::init(mempool, num_auth);
	auto auth_mbufs =
	    UNWRAP_OR_RETURN_ERR(std::move(auth_mbufs_), DNSParseError::AllocationError);

	auto add_mbufs_ =
	    RTEMbufArray<ResourceRecord, MAX_RECORDS, MbufType::Raw>::init(mempool, num_add);
	auto add_mbufs =
	    UNWRAP_OR_RETURN_ERR(std::move(add_mbufs_), DNSParseError::AllocationError);

	for (auto &rec : ans_mbufs) {
		rec = UNWRAP_OR_RETURN(ParseResourceRecord(dns_bytes, reader));
	}
	for (auto &rec : auth_mbufs) {
		rec = UNWRAP_OR_RETURN(ParseResourceRecord(dns_bytes, reader));
	}
	for (auto &rec : add_mbufs) {
		rec = UNWRAP_OR_RETURN(ParseResourceRecord(dns_bytes, reader));
	}

	// Construct packet
	auto res = DNSPacket(ip_data, rte_be_to_cpu_16(hdr->id), question,
	    static_cast<DnsQType>(rte_be_to_cpu_16(question_info->qtype)),
	    static_cast<DnsRCode>(hdr->rcode), records_capped, std::move(ans_mbufs),
	    std::move(auth_mbufs), std::move(add_mbufs));

	return res;
}
