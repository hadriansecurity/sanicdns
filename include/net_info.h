#pragma once

#include <linux/ethtool.h>
#include <net/if.h>
#include <fixed_name.hpp>
#include <network_types.h>
#include <linux/if_arp.h>
#include <expected.h>
#include <optional>
#include <rte_ether.h>

namespace net_info {

struct RouteInfo {
	FixedName<IFNAMSIZ> if_name{};
	std::optional<InAddr> source_addr{};
	std::optional<InAddr> gateway_addr{};
};

tl::expected<RouteInfo, std::string> get_route_info(std::optional<FixedName<IFNAMSIZ>> if_name = std::nullopt);
tl::expected<EtherAddr, std::string> get_mac_address(FixedName<IFNAMSIZ> iface, const InAddr& in_addr);
tl::expected<ethtool_channels, std::string> get_channel_count(FixedName<IFNAMSIZ> iface);

}
