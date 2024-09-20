#include "net_info.h"

#include <linux/ethtool.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <spdlog/spdlog.h>
#include <sys/ioctl.h>

#include <cstring>
#include <glaze/glaze.hpp>
#include <optional>
#include <string>

#include "expected.h"
#include "expected_helpers.h"
#include "fixed_name.hpp"
#include "spdlog/fmt/bundled/core.h"

#define BUFFER_SIZE 8192

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-compare"
#endif

tl::expected<EtherAddr, std::string> net_info::get_mac_address(FixedName<IFNAMSIZ> iface,
    const InAddr &ip) {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		return tl::unexpected("Cannot open socket");
	}

	struct arpreq req;
	memset(&req, 0, sizeof(req));

	struct sockaddr_in *sin = (struct sockaddr_in *) &req.arp_pa;
	sin->sin_family = AF_INET;
	sin->sin_addr = ip;

	memcpy(req.arp_dev, iface.buf.data(), IFNAMSIZ);

	if (ioctl(sock, SIOCGARP, &req) < 0) {
		close(sock);
		return tl::unexpected("ioctl error");
	}

	EtherAddr addr;
	memcpy((void *) &addr, (void *) req.arp_ha.sa_data, RTE_ETHER_ADDR_LEN);

	close(sock);

	return addr;
}

tl::expected<FixedName<IFNAMSIZ>, std::string> get_if_to_use(
    std::optional<FixedName<IFNAMSIZ>> user_if,
    std::optional<FixedName<IFNAMSIZ>> default_interface) {
	if (user_if.has_value())
		return user_if.value();

	if (default_interface.has_value())
		return default_interface.value();

	return tl::unexpected(
	    "Cannot find default interface and user did not provide interface name");
}

tl::expected<net_info::RouteInfo, std::string> net_info::get_route_info(
    std::optional<FixedName<IFNAMSIZ>> if_name) {
	int received_bytes = 0, msg_len = 0, route_attribute_len = 0;
	int sock = -1;
	uint32_t msgseq = 0;
	struct nlmsghdr *nlh, *nlmsg;
	struct rtmsg *route_entry;
	// This struct contain route attributes (route type)
	struct rtattr *route_attribute;
	char msgbuf[BUFFER_SIZE], buffer[BUFFER_SIZE];
	char *ptr = buffer;
	struct timeval tv;
	std::optional<FixedName<IFNAMSIZ>> default_interface;
	std::map<FixedName<IFNAMSIZ>, RouteInfo> routes_map;

	if ((sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
		return tl::unexpected("cannot open socket");
	}

	memset(msgbuf, 0, sizeof(msgbuf));
	memset(buffer, 0, sizeof(buffer));

	/* point the header and the msg structure pointers into the buffer */
	nlmsg = (struct nlmsghdr *) msgbuf;

	/* Fill in the nlmsg header*/
	nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	nlmsg->nlmsg_type = RTM_GETROUTE; // Get the routes from kernel routing table .
	nlmsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; // The message is a request for dump.
	nlmsg->nlmsg_seq = msgseq++;                     // Sequence of the message packet.
	nlmsg->nlmsg_pid = getpid();                     // PID of process sending the request.

	/* 1 Sec Timeout to avoid stall */
	tv.tv_sec = 1;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &tv, sizeof(struct timeval));
	/* send msg */
	if (send(sock, nlmsg, nlmsg->nlmsg_len, 0) < 0) {
		close(sock);
		return tl::unexpected("send failed");
	}

	/* receive response */
	do {
		received_bytes = recv(sock, ptr, sizeof(buffer) - msg_len, 0);
		if (received_bytes < 0) {
			close(sock);
			return tl::unexpected("recv failed");
		}

		nlh = (struct nlmsghdr *) ptr;

		/* Check if the header is valid */
		if ((NLMSG_OK(nlmsg, received_bytes) == 0) || (nlmsg->nlmsg_type == NLMSG_ERROR)) {
			close(sock);
			return tl::unexpected("error in received packet");
		}

		/* If we received all data break */
		if (nlh->nlmsg_type == NLMSG_DONE)
			break;
		else {
			ptr += received_bytes;
			msg_len += received_bytes;
		}

		/* Break if its not a multi part message */
		if ((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0)
			break;
	} while (
	    (nlmsg->nlmsg_seq != msgseq) || (nlmsg->nlmsg_pid != static_cast<uint32_t>(getpid())));

	/* parse response */
	for (; NLMSG_OK(nlh, received_bytes); nlh = NLMSG_NEXT(nlh, received_bytes)) {
		RouteInfo route_info{};
		InAddr dst_addr{};

		/* Get the route data */
		route_entry = (struct rtmsg *) NLMSG_DATA(nlh);

		/* We are just interested in main routing table */
		if (route_entry->rtm_table != RT_TABLE_MAIN)
			continue;

		route_attribute = (struct rtattr *) RTM_RTA(route_entry);
		route_attribute_len = RTM_PAYLOAD(nlh);

		// spdlog::info("iter");

		/* Loop through all attributes */
		for (; RTA_OK(route_attribute, route_attribute_len);
		     route_attribute = RTA_NEXT(route_attribute, route_attribute_len)) {
			InAddr addr_buf{};
			switch (route_attribute->rta_type) {
				case RTA_OIF:
					if_indextoname(*(int *) RTA_DATA(route_attribute),
					    route_info.if_name.buf.data());
					route_info.if_name.len = std::char_traits<char>::length(
					    route_info.if_name.buf.data());
					// spdlog::info(route_info.if_name.c_str());
					break;
				case RTA_GATEWAY:
					memcpy(&addr_buf, RTA_DATA(route_attribute),
					    sizeof(InAddr));
					route_info.gateway_addr = addr_buf;
					// spdlog::info("Gateway: {}", addr_buf.str());
					break;
				case RTA_PREFSRC:
					memcpy(&addr_buf, RTA_DATA(route_attribute),
					    sizeof(InAddr));
					route_info.source_addr = addr_buf;
					// spdlog::info("Source: {}", addr_buf.str());
					break;
				case RTA_DST:
					memcpy(&dst_addr, RTA_DATA(route_attribute),
					    sizeof(InAddr));
					// spdlog::info("Dest: {}", dst_addr.str());
				default:
					break;
			}
		}

		routes_map[route_info.if_name].if_name = route_info.if_name;

		if (route_info.source_addr.has_value())
			routes_map[route_info.if_name].source_addr = route_info.source_addr;
		if (route_info.gateway_addr.has_value())
			routes_map[route_info.if_name].gateway_addr = route_info.gateway_addr;

		if (dst_addr.s_addr == 0x00 && route_info.if_name.len > 0)
			default_interface = route_info.if_name;
	}

	auto iface = UNWRAP_OR_RETURN(get_if_to_use(if_name, default_interface));

	close(sock);

	if (!routes_map.contains(iface)) {
		spdlog::warn("Cannot get routes for {}, returning empty RouteInfo", iface);
		return net_info::RouteInfo{.if_name = iface};
	}

	return routes_map[iface];
}

tl::expected<ethtool_channels, std::string> net_info::get_channel_count(FixedName<IFNAMSIZ> iface) {
	int if_idx = if_nametoindex(iface.c_str());
	if (if_idx < 0) {
		return tl::unexpected(fmt::format("Cannot get index for {}", iface));
	}

	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (fd == -1) {
		return tl::unexpected("Cannot create ethtool socket");
	}

	struct ifreq ifr = {};
	std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ);
	ifr.ifr_ifindex = if_idx;

	struct ethtool_channels ethchannels = {};
	ethchannels.cmd = ETHTOOL_GCHANNELS;
	ifr.ifr_data = reinterpret_cast<char *>(&ethchannels);

	if (ioctl(fd, SIOCETHTOOL, &ifr) != 0) {
		close(fd);
		return tl::unexpected("Error receiving from ethtool socket");
	}

	close(fd);
	return ethchannels;
}
