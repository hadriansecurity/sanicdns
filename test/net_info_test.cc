#include "net_info.h"

#include <gtest/gtest.h>
#include <linux/if.h>

#include <glaze/glaze.hpp>
#include <optional>

#include "expected_helpers.h"
#include "fixed_name.hpp"
#include "network_types.h"
#include "spdlog/spdlog.h"

tl::expected<EtherAddr, const char*> get_mac_address_commandline(FixedName<IFNAMSIZ> iface,
    const InAddr& ip) {
	std::array<char, 128> buffer;
	std::string result;
	std::ostringstream command;
	command << "ip neigh show " << inet_ntoa(ip);

	FILE* pipe = popen(command.str().c_str(), "r");
	if (!pipe) {
		return tl::unexpected("popen error");
	}

	while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
		result += buffer.data();
	}

	pclose(pipe);

	std::istringstream ss(result);
	std::string line;
	while (std::getline(ss, line)) {
		std::istringstream line_ss(line);
		std::string token;
		while (line_ss >> token) {
			if (token == "lladdr") {
				EtherAddr addr;
				line_ss >> token;
				std::sscanf(token.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
				    &addr.addr_bytes[0], &addr.addr_bytes[1], &addr.addr_bytes[2],
				    &addr.addr_bytes[3], &addr.addr_bytes[4], &addr.addr_bytes[5]);
				return addr;
			}
		}
	}

	return tl::unexpected("MAC address not found");
}

tl::expected<net_info::RouteInfo, std::string> get_default_route_info_commandline() {
	std::array<char, 128> buffer;
	std::string result;
	std::ostringstream command;
	command << "ip route show default";

	FILE* pipe = popen(command.str().c_str(), "r");
	if (!pipe) {
		return tl::unexpected("popen error");
	}

	while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
		result += buffer.data();
	}

	pclose(pipe);

	std::istringstream ss(result);
	std::string line;
	if (std::getline(ss, line)) {
		net_info::RouteInfo route_info;
		std::istringstream line_ss(line);
		std::string token;
		while (line_ss >> token) {
			if (token == "dev") {
				line_ss >> token;
				route_info.if_name = UNWRAP_OR_RETURN_ERR(
				    FixedName<IFNAMSIZ>::init(token), "Failed to parse IP");
			} else if (token == "via") {
				line_ss >> token;
				route_info.gateway_addr = InAddr::init(token);
			}
		}

		if (route_info.if_name.len > 0) {
			// Get the source IP address associated with the interface
			std::ostringstream addr_command;
			addr_command << "ip addr show dev " << route_info.if_name.c_str();

			FILE* addr_pipe = popen(addr_command.str().c_str(), "r");
			if (!addr_pipe) {
				return tl::unexpected("popen error");
			}

			std::string addr_result;
			while (fgets(buffer.data(), buffer.size(), addr_pipe) != nullptr) {
				addr_result += buffer.data();
			}

			pclose(addr_pipe);

			std::istringstream addr_ss(addr_result);
			std::string addr_line;
			while (std::getline(addr_ss, addr_line)) {
				std::istringstream addr_line_ss(addr_line);
				while (addr_line_ss >> token) {
					if (token == "inet") {
						addr_line_ss >> token;
						auto pos = token.find('/');
						if (pos != std::string::npos) {
							token = token.substr(0, pos);
						}
						route_info.source_addr = InAddr::init(token);
						break;
					}
				}
				if (route_info.source_addr) {
					break;
				}
			}

			return route_info;
		} else {
			return tl::unexpected("Default route interface not found");
		}
	}

	return tl::unexpected("Failed to get default route information");
}

TEST(NetInfoTest, TestGetMacAddr) {
	auto route_info_commandline = get_default_route_info_commandline();
	ASSERT_TRUE(route_info_commandline.has_value());
	ASSERT_TRUE(route_info_commandline->gateway_addr.has_value());

	auto if_name = route_info_commandline->if_name;
	auto ip = route_info_commandline->gateway_addr.value();

	auto mac_addr = net_info::get_mac_address(if_name, ip);
	EXPECT_TRUE(mac_addr.has_value());

	auto mac_addr_commandline = get_mac_address_commandline(if_name, ip);
	EXPECT_TRUE(mac_addr_commandline.has_value());

	EXPECT_EQ(*mac_addr, *mac_addr_commandline);
}

TEST(NetInfoTest, TestGetRouteInfo) {
	auto route_info = net_info::get_route_info();
	ASSERT_TRUE(route_info.has_value());

	auto route_info_commandline = get_default_route_info_commandline();
	ASSERT_TRUE(route_info_commandline.has_value());

	spdlog::info(glz::write_json(route_info));

	EXPECT_EQ(route_info->if_name, route_info_commandline->if_name);

	ASSERT_TRUE(route_info->gateway_addr.has_value());
	ASSERT_TRUE(route_info_commandline->gateway_addr.has_value());
	EXPECT_EQ(route_info->gateway_addr.value(), route_info_commandline->gateway_addr.value());

	ASSERT_TRUE(route_info->source_addr.has_value());
	ASSERT_TRUE(route_info_commandline->source_addr.has_value());
	EXPECT_EQ(route_info->source_addr.value(), route_info_commandline->source_addr.value());
}
