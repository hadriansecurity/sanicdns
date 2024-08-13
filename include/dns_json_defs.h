#pragma once

#include <netinet/in.h>

#include <cstring>
#include <glaze/glaze.hpp>
#include <string>

#include "dns_format.h"
#include "dns_packet_constructor.h"
#include "dns_struct_defs.h"
#include "encode_dns_char_string.h"

/**
 * Definitions for resource records
 */

template <>
struct glz::meta<ARdata> {
	static constexpr auto value{&ARdata::ipv4_addr};
};

template <>
struct glz::meta<AAAARdata> {
	static constexpr auto value{&AAAARdata::ipv6_addr};
};

template <>
struct glz::meta<NSRdata> {
	static constexpr auto value{&NSRdata::nameserver};
};

template <>
struct glz::meta<MXRdata> {
    static constexpr auto value = [](const auto &self) -> auto {
        return fmt::format("{} {}", self.preference, self.mailserver);
    };
};

template <>
struct glz::meta<CNAMERdata> {
	static constexpr auto value{&CNAMERdata::cname};
};

template <>
struct glz::meta<DNAMERdata> {
	static constexpr auto value{&DNAMERdata::dname};
};

template <>
struct glz::meta<PTRRdata> {
	static constexpr auto value{&PTRRdata::ptr};
};

template <>
struct glz::meta<struct TXTRdata> {
	static constexpr auto value = [](const auto &self) -> auto {
        return encode_dns_char_string(self.txt);
    };
};

template <>
struct glz::meta<SOARdata> {
    static constexpr auto value = [](const auto &self) -> auto {
        return fmt::format("{} {} {} {} {} {} {}", self.m_name, self.r_name, self.interval_settings.serial, self.interval_settings.refresh, self.interval_settings.retry, self.interval_settings.expire, self.interval_settings.minimum);
    };
};

template <>
struct glz::meta<struct CAARdata> {
    static constexpr auto value = [](const auto &self) -> auto {
        auto value_encoded = encode_dns_char_string(self.value, true);
        return fmt::format("{} {} {}", self.flags, self.tag, value_encoded);
	};
};

template <>
struct glz::meta<ResourceRecord> {
	using T = ResourceRecord;
	static constexpr auto value =
	    glz::object("name", &T::name, "type", &T::q_type, "ttl", &T::ttl, "data", &T::r_data);
};

/**
 * Definitions for IPv4 and IPv6 addresses
 */

template <>
struct glz::meta<in_addr> {
	static constexpr auto value = [](const auto &self) -> auto {
		FixedName<INET_ADDRSTRLEN> val;

		inet_ntop(AF_INET, &self, val.buf.data(), INET_ADDRSTRLEN);
		val.len = std::char_traits<char>::length(val.buf.data());
		return val;
	};
};

template <>
struct glz::meta<in6_addr> {
	static constexpr auto value = [](const auto &self) -> auto {
		FixedName<INET6_ADDRSTRLEN> val;

		inet_ntop(AF_INET6, &self, val.buf.data(), INET6_ADDRSTRLEN);
		val.len = std::char_traits<char>::length(val.buf.data());
		return val;
	};
};

/**
 * Definition for dns_packet
 */

template <>
struct glz::meta<DNSPacket::Data> {
    using T = DNSPacket::Data;
    static constexpr auto value = glz::object("answers", &T::ans, "authorities", &T::auth, "additionals", &T::add);
};

template <>
struct glz::meta<DNSPacket> {
	using T = DNSPacket;
	static constexpr auto value = glz::object("name", &T::question, "type", &T::q_type, "status",
	    &T::r_code, "data", &T::data);
};
