#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <sys/socket.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <glaze/glaze.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

#include "expected_helpers.h"
#include "fixed_name.hpp"

#define ETHER_ADDRSTRLEN 18

struct Ipv4Header {
	struct rte_ether_hdr ether_hdr;
	struct rte_ipv4_hdr ipv4_hdr;
};

struct UdpIpv4Header {
	struct rte_ether_hdr ether_hdr;
	struct rte_ipv4_hdr ipv4_hdr;
	struct rte_udp_hdr udp_hdr;
};

struct TcpIpv4Header {
	struct rte_ether_hdr ether_hdr;
	struct rte_ipv4_hdr ipv4_hdr;
	struct rte_udp_hdr tcp_hdr;
};

struct UdpIpv6Header {
	struct rte_ether_hdr ether_hdr;
	struct rte_ipv6_hdr ipv6_hdr;
	struct rte_udp_hdr udp_hdr;
};

struct TcpIpv6Header {
	struct rte_ether_hdr ether_hdr;
	struct rte_ipv6_hdr ipv6_hdr;
	struct rte_udp_hdr tcp_hdr;
};

template <size_t Size>
struct GenericPacket {
	// GenericPacket() { }
	std::array<std::byte, Size> padding;
};

using DefaultPacket = GenericPacket<RTE_MBUF_DEFAULT_BUF_SIZE>;

struct InAddr : in_addr {
	static std::optional<InAddr> init(std::string_view str_addr) {
		auto name_nullterm =
		    UNWRAP_OR_RETURN_VAL(FixedName<INET_ADDRSTRLEN>::init(str_addr), std::nullopt);

		InAddr addr{};
		int res = inet_pton(AF_INET, name_nullterm.c_str(), &addr);

		if (!res) [[unlikely]]
			return std::nullopt;

		return addr;
	}

	FixedName<INET_ADDRSTRLEN> str() const {
		FixedName<INET_ADDRSTRLEN> val;

		inet_ntop(AF_INET, &s_addr, val.buf.data(), INET_ADDRSTRLEN);
		val.len = std::char_traits<char>::length(val.buf.data());
		return val;
	}

	bool operator==(const in_addr &other) const {
		return s_addr == other.s_addr;
	}
};

struct In6Addr : in6_addr {
	static std::optional<In6Addr> init(std::string_view str_addr) {
		auto name_nullterm =
		    UNWRAP_OR_RETURN_VAL(FixedName<INET6_ADDRSTRLEN>::init(str_addr), std::nullopt);

		In6Addr addr{};
		int res = inet_pton(AF_INET6, name_nullterm.c_str(), &addr);

		if (!res) [[unlikely]]
			return std::nullopt;

		return addr;
	}

	FixedName<INET6_ADDRSTRLEN> str() const {
		FixedName<INET6_ADDRSTRLEN> val;

		inet_ntop(AF_INET6, this, val.buf.data(), INET6_ADDRSTRLEN);
		val.len = std::char_traits<char>::length(val.buf.data());
		return val;
	}

	bool operator==(const in6_addr &other) const {
		return std::ranges::equal(s6_addr, other.s6_addr);
	}
};

struct EtherAddr : rte_ether_addr {
	static std::optional<EtherAddr> init(std::string_view str_addr) {
		auto name_nullterm =
		    UNWRAP_OR_RETURN_VAL(FixedName<ETHER_ADDRSTRLEN>::init(str_addr), std::nullopt);

		EtherAddr addr{};
		int res = rte_ether_unformat_addr(name_nullterm.c_str(), &addr);

		if (res) [[unlikely]]
			return std::nullopt;

		return addr;
	}

	FixedName<ETHER_ADDRSTRLEN> str() const {
		FixedName<ETHER_ADDRSTRLEN> val;

		rte_ether_format_addr(val.buf.data(), ETHER_ADDRSTRLEN, this);
		val.len = std::char_traits<char>::length(val.buf.data());
		return val;
	}

	bool operator==(const rte_ether_addr &other) const {
		return std::ranges::equal(addr_bytes, other.addr_bytes);
	}
};

using IpAddr = std::variant<InAddr, In6Addr>;

template <>
struct glz::meta<InAddr> {
	static constexpr auto value = [](auto &self) -> auto { return self.str(); };
};

template <>
struct glz::meta<In6Addr> {
	static constexpr auto value = [](auto &self) -> auto { return self.str(); };
};

template <>
struct glz::meta<EtherAddr> {
	static constexpr auto value = [](auto &self) -> auto { return self.str(); };
};
