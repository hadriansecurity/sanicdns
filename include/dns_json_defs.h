#pragma once

#include <netinet/in.h>

#include <cstring>
#include <glaze/glaze.hpp>
#include <string>

#include "dns_format.h"
#include "dns_struct_defs.h"

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
	static constexpr auto value{&TXTRdata::txt};
};

template <>
struct glz::meta<ResourceRecord> {
	using T = ResourceRecord;
	static constexpr auto value =
	    glz::object("n", &T::name, "t", &T::q_type, "ttl", &T::ttl, "d", &T::r_data);
};

/**
 * Definitions for IPv4 and IPv6 addresses
 */

template <>
struct glz::meta<in_addr> {
	static constexpr auto value = [](auto &self) -> auto {
		FixedName<INET_ADDRSTRLEN> val;

		inet_ntop(AF_INET, &self, val.buf.data(), INET_ADDRSTRLEN);
		val.len = std::char_traits<char>::length(val.buf.data());
		return val;
	};
};

template <>
struct glz::meta<in6_addr> {
	static constexpr auto value = [](auto &self) -> auto {
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
struct glz::meta<DNSPacket> {
	using T = DNSPacket;
	static constexpr auto value = glz::object("q", &T::question, "t", &T::q_type, "r",
	    &T::r_code, "ans", &T::ans, "auth", &T::auth, "add", &T::add);
};
