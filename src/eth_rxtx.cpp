#include "eth_rxtx.h"

#include <net/if.h>
#include <network_types.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_pause.h>
#include <rte_udp.h>

#include <chrono>
#include <iostream>
#include <optional>
#include <thread>

#include "expected.h"
#include "expected_helpers.h"
#include "spdlog/spdlog.h"

#define MAX_PATTERN_NUM 5

std::optional<uint16_t> GetPortByName(std::string_view device_name) {
	uint16_t portid;
	if (rte_eth_dev_get_port_by_name(device_name.data(), &portid))
		return std::nullopt;

	return portid;
}

std::optional<rte_ether_addr> GetPortMac(const uint16_t portid) {
	rte_ether_addr addr;
	int retval = rte_eth_macaddr_get(portid, &addr);
	if (retval)
		return std::nullopt;

	return addr;
}

void PrintOffloadFlags(rte_eth_dev_info &dev_info) {
	spdlog::info("Available RX offloads:");
	for (uint64_t flag = 1; flag; flag = flag << 1) {
		if (dev_info.rx_offload_capa & flag)
			spdlog::info("\t{}", rte_eth_dev_rx_offload_name(flag));
	}

	spdlog::info("Available TX offloads:");
	for (uint64_t flag = 1; flag; flag = flag << 1) {
		if (dev_info.tx_offload_capa & flag)
			spdlog::info("\t{}", rte_eth_dev_tx_offload_name(flag));
	}
}

template <class opts>
EthRxTx<opts>::~EthRxTx() {
	if (!_valid)
		return;

	int res = rte_eth_dev_stop(portid);
	if (res) {
		spdlog::error("Cannot stop ethernet device: {}", rte_strerror(res));
		return;
	}

	rte_eth_dev_close(portid);
}

template <class opts>
tl::expected<EthRxTx<opts>, std::string> EthRxTx<opts>::init(const EthDevConf &config,
    std::string_view device_name, rte_mempool *mempool) {
	const auto portid =
	    UNWRAP_OR_RETURN_ERR(GetPortByName(device_name), "Cannot get port by name");

	const auto addr = UNWRAP_OR_RETURN_ERR(GetPortMac(portid), "Cannot get port MAC");

	struct rte_eth_dev_info dev_info;

	int retval = rte_eth_dev_info_get(portid, &dev_info);
	if (retval != 0)
		return tl::unexpected(
		    fmt::format("Failed to get device info: {}", rte_strerror(rte_errno)));

	retval = rte_eth_stats_reset(portid);
	if (retval != 0) {
		spdlog::warn("Failed to reset ethernet stats: {}", retval);
		spdlog::warn("Ethernet statistic might be inaccurate!");
	}

	PrintOffloadFlags(dev_info);

	struct rte_eth_conf port_conf;
	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	spdlog::info("Driver name: {}", dev_info.driver_name);

	// Check if all required tx offloads are available and print formatted error message if
	// necessary
	if ((dev_info.tx_offload_capa & dev_tx_offloads) != dev_tx_offloads) {
		uint64_t not_available_offloads =
		    (dev_info.tx_offload_capa & dev_tx_offloads) ^ dev_tx_offloads;

		// Exit and show which offloads are not available
		std::string offload_msg = "Tx offloads ";
		for (uint64_t flag = 1; flag; flag <<= 1) {
			if (not_available_offloads & flag) {
				offload_msg.append(rte_eth_dev_tx_offload_name(flag));
				offload_msg.append(", ");
			}
		}
		offload_msg.append("not available");

		return tl::unexpected(offload_msg);
	}
	port_conf.txmode.offloads |= dev_tx_offloads;

	// Check if all required tx offloads are available and print formatted error message if
	// necessary
	if ((dev_info.rx_offload_capa & dev_rx_offloads) != dev_rx_offloads) {
		uint64_t not_available_offloads =
		    (dev_info.tx_offload_capa & dev_rx_offloads) ^ dev_rx_offloads;

		// Exit and show which offloads are not available
		std::string offload_msg = "Rx offloads ";
		for (uint64_t flag = 1; flag; flag <<= 1) {
			if (not_available_offloads & flag) {
				offload_msg.append(rte_eth_dev_rx_offload_name(flag));
				offload_msg.append(", ");
			}
		}
		offload_msg.append("not available");

		return tl::unexpected(offload_msg);
	}
	port_conf.rxmode.offloads |= dev_rx_offloads;

	if (config.nb_rx_queues > dev_info.max_rx_queues)
		return tl::unexpected(fmt::format("Max {} rx queues available, {} requested",
		    dev_info.max_rx_queues, config.nb_rx_queues));

	if (config.nb_tx_queues > dev_info.max_tx_queues)
		return tl::unexpected(fmt::format("Max {} tx queues available, {} requested",
		    dev_info.max_tx_queues, config.nb_tx_queues));

	if (config.nb_tx_descrs < dev_info.tx_desc_lim.nb_min ||
	    config.nb_tx_descrs > dev_info.tx_desc_lim.nb_max)
		return tl::unexpected(fmt::format("Invalid number of tx descriptors ({}), "
						  "must be in range {} to {}",
		    config.nb_tx_descrs, dev_info.tx_desc_lim.nb_min, dev_info.tx_desc_lim.nb_max));

	if (config.nb_rx_descrs < dev_info.rx_desc_lim.nb_min ||
	    config.nb_rx_descrs > dev_info.rx_desc_lim.nb_max)
		return tl::unexpected(fmt::format("Invalid number of rx descriptors ({}), "
						  "must be in range {} to {}",
		    config.nb_rx_descrs, dev_info.rx_desc_lim.nb_min, dev_info.rx_desc_lim.nb_max));

	if (config.enable_rss) {
		port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
		port_conf.rx_adv_conf.rss_conf.rss_hf = 0x7ef8;
	}

	// Descriptor limits already checked, not necessary
	// retval = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &config.nb_rx_descrs,
	// &config.nb_tx_descrs); if (retval != 0) 	throw std::runtime_error("Cannot configure
	// ethernet device");

	spdlog::info("Configuring ethernet device");

	/* Configure the Ethernet device. */
	retval =
	    rte_eth_dev_configure(portid, config.nb_rx_queues, config.nb_tx_queues, &port_conf);
	if (retval != 0)
		return tl::unexpected(
		    fmt::format("Cannot configure ethernet device: {}", rte_strerror(rte_errno)));

	struct rte_eth_rxconf rxconf;
	rxconf = dev_info.default_rxconf;
	/* Allocate and set up RX queus for Ethernet port. */
	for (uint16_t q = 0; q < config.nb_rx_queues; q++) {
		retval = rte_eth_rx_queue_setup(portid, q, config.nb_rx_descrs,
		    rte_eth_dev_socket_id(portid), &rxconf, mempool);
		if (retval != 0)
			return tl::unexpected(fmt::format("Cannot initialize rx queue {}: {}", q,
			    rte_strerror(rte_errno)));
	}

	struct rte_eth_txconf txconf;
	txconf = dev_info.default_txconf;
	/* Allocate and set up TX queus for Ethernet port. */
	for (uint16_t q = 0; q < config.nb_tx_queues; q++) {
		retval = rte_eth_tx_queue_setup(portid, q, config.nb_tx_descrs,
		    rte_eth_dev_socket_id(portid), &txconf);
		if (retval != 0)
			return tl::unexpected(fmt::format("Cannot initialize tx queue {}: {}", q,
			    rte_strerror(rte_errno)));
	}

	spdlog::info("Starting ethernet device");

	/* Starting Ethernet port */
	retval = rte_eth_dev_start(portid);
	/* >8 End of starting of ethernet port. */
	if (retval < 0)
		return tl::unexpected(fmt::format("Cannot start ethernet port {}: {}", portid,
		    rte_strerror(rte_errno)));

	// while (1) {
	// 	rte_eth_link link_info{};
	// 	retval = rte_eth_link_get(portid, &link_info);
	// 	if (retval != 0)
	// 		return tl::unexpected(fmt::format("Cannot get link info for port {}: {}",
	// 		    portid, rte_strerror(rte_errno)));

	// 	if (link_info.link_status == RTE_ETH_LINK_UP)
	// 		break;

	// 	rte_pause();
	// }

	/* Display the port MAC address. */
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
	       " %02" PRIx8 "\n",
	    portid, RTE_ETHER_ADDR_BYTES(&addr));

	/* Using promiscuous mode packets are received with any destination MAC */
	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(portid);
	if (retval != 0)
		return tl::unexpected(fmt::format("Cannot enable promiscuous mode for port {}: {}",
		    portid, rte_strerror(rte_errno)));

	return EthRxTx{config, portid, addr, std::vector<Stats>(RTE_MAX_LCORE)};
}

// TODO: move generating flow to a dedicated class, this function is i40e specific

template <class opts>
tl::expected<void, std::string> EthRxTx<opts>::GenerateDNSFlow(uint16_t queue_id, uint16_t src_port,
    uint16_t src_mask, uint16_t dst_port, uint16_t dst_mask, uint16_t dns_id,
    uint16_t dns_id_mask) {
	rte_flow_attr attr;
	rte_flow_item pattern[MAX_PATTERN_NUM];
	rte_flow_action action[MAX_PATTERN_NUM];
	rte_flow_action_queue queue = {.index = queue_id};
	rte_flow_item_eth eth_spec;
	rte_flow_item_eth eth_mask;
	rte_flow_item_ipv4 ipv4_spec;
	rte_flow_item_ipv4 ipv4_mask;
	rte_flow_item_ipv6 ipv6_spec;
	rte_flow_item_ipv6 ipv6_mask;
	rte_flow_item_udp udp_spec;
	rte_flow_item_udp udp_mask;
	rte_flow_item_raw raw_spec;
	rte_flow_item_raw raw_mask;
	rte_flow_error error;

	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));

	/*
	 * set the rule attribute.
	 * in this case only ingress packets will be checked.
	 */
	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;

	/*
	 * create the action sequence.
	 * one action only,  move packet to queue
	 */

	action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action[0].conf = &queue;
	// action[0].type = RTE_FLOW_ACTION_TYPE_DROP;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	/*
	 * Set the first level of the pattern (eth).
	 * set to allow all
	 */
	memset(&eth_spec, 0, sizeof(struct rte_flow_item_eth));
	memset(&eth_mask, 0, sizeof(struct rte_flow_item_eth));
	eth_spec.type = 0;
	eth_mask.type = 0;
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[0].spec = &eth_spec;
	pattern[0].mask = &eth_mask;

	/*
	 * Setting the second level of the pattern (ipv4).
	 * Set to allow all
	 */
	memset(&ipv4_spec, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&ipv4_mask, 0, sizeof(struct rte_flow_item_ipv4));
	ipv4_spec.hdr.dst_addr = 0;
	ipv4_mask.hdr.dst_addr = 0;
	ipv4_spec.hdr.src_addr = 0;
	ipv4_mask.hdr.src_addr = 0;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[1].spec = &ipv4_spec;
	pattern[1].mask = &ipv4_mask;

	/*
	 * Setting the third level of the pattern (udp).
	 * Set the ports and masks as the user has setup
	 */
	memset(&udp_spec, 0, sizeof(struct rte_flow_item_udp));
	memset(&udp_mask, 0, sizeof(struct rte_flow_item_udp));
	udp_spec.hdr.src_port = rte_cpu_to_be_16(src_port);
	udp_mask.hdr.src_port = rte_cpu_to_be_16(src_mask);
	udp_spec.hdr.dst_port = rte_cpu_to_be_16(dst_port);
	udp_mask.hdr.dst_port = rte_cpu_to_be_16(dst_mask);
	pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
	pattern[2].spec = &udp_spec;
	pattern[2].mask = &udp_mask;

	memset(&raw_spec, 0, sizeof(struct rte_flow_item_raw));
	memset(&raw_mask, 0, sizeof(struct rte_flow_item_raw));

	const rte_be16_t dns_id_be = rte_cpu_to_be_16(dns_id);
	const rte_be16_t dns_id_mask_be = rte_cpu_to_be_16(dns_id_mask);

	const uint8_t *search_pattern_spec = (uint8_t *) &dns_id_be;
	const uint8_t *search_pattern_mask = (uint8_t *) &dns_id_mask_be;

	raw_spec.relative = 1;
	raw_spec.search = 0;
	raw_spec.reserved = 0;
	raw_spec.offset = 0;
	raw_spec.limit = 0;
	raw_spec.length = 2;
	raw_spec.pattern = search_pattern_spec;

	raw_mask.relative = 1;
	raw_mask.search = 1;
	raw_mask.reserved = 0x3FFFFFFF;
	raw_mask.offset = 0xFFFFFFFF;
	raw_mask.limit = 0xFFFF;
	raw_mask.length = 0xFFFF;
	raw_mask.pattern = search_pattern_mask;
	pattern[3].type = RTE_FLOW_ITEM_TYPE_RAW;
	pattern[3].spec = &raw_spec;
	pattern[3].mask = &raw_mask;

	/* the final level must be always type end */
	pattern[4].type = RTE_FLOW_ITEM_TYPE_END;

	int res = rte_flow_validate(portid, &attr, pattern, action, &error);
	if (res) {
		return tl::unexpected(
		    fmt::format("Failed to validate ipv4 flow rule: {}", error.message));
	}

	flow_configurations.push_back(rte_flow_create(portid, &attr, pattern, action, &error));
	if (flow_configurations.back() == NULL) {
		return tl::unexpected(fmt::format("Failed to create ipv4 flow rule"));
	}

	/*
	 * Setting the new second level of the pattern (ipv6).
	 * Set to allow all
	 */
	memset(&ipv6_spec, 0, sizeof(struct rte_flow_item_ipv6));
	memset(&ipv6_mask, 0, sizeof(struct rte_flow_item_ipv6));
	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
	pattern[1].spec = &ipv6_spec;
	pattern[1].mask = &ipv6_mask;

	res = rte_flow_validate(portid, &attr, pattern, action, &error);
	if (res) {
		return tl::unexpected(
		    fmt::format("Failed to validate ipv6 flow rule: ", error.message));
	}

	flow_configurations.push_back(rte_flow_create(portid, &attr, pattern, action, &error));
	if (flow_configurations.back() == NULL) {
		return tl::unexpected(fmt::format("Failed to create ipv6 flow rule"));
	}

	// Success
	return {};
}

template <class opts>
void EthRxTx<opts>::PrintStats() {
	rte_eth_stats port_stats;
	rte_eth_stats_get(portid, &port_stats);

	spdlog::info("RX bytes: {}", port_stats.ibytes);
	spdlog::info("RX packets: {}", port_stats.ipackets);
	spdlog::info("RX errors: {}", port_stats.ierrors);

	spdlog::info("TX bytes: {}", port_stats.obytes);
	spdlog::info("TX packets: {}", port_stats.opackets);
	spdlog::info("TX errors: {}", port_stats.oerrors);

	Stats total_stats = {0, 0, 0, 0, 0, 0};
	for (const Stats &q_stats : stats) {
		total_stats.num_total += q_stats.num_total;
		total_stats.num_bad_ip_cksum += q_stats.num_bad_ip_cksum;
		total_stats.num_bad_l4_cksum += q_stats.num_bad_l4_cksum;
		total_stats.num_sent += q_stats.num_sent;
		total_stats.num_bytes_sent += q_stats.num_bytes_sent;
	}

	spdlog::info("Total Mpackets received: {}",
	    static_cast<double>(total_stats.num_total) / 1e6);
	spdlog::info("Total Mpackets sent: {}", static_cast<double>(total_stats.num_sent) / 1e6);
	spdlog::info("Total Gbytes sent: {}",
	    static_cast<double>(total_stats.num_bytes_sent) / 1e9);
	spdlog::info("Bad IP cksum: {}", total_stats.num_bad_ip_cksum);
	spdlog::info("Bad L4 cksum: {}", total_stats.num_bad_l4_cksum);
}

#include "eth_rxtx_opts.h"
template class EthRxTx<NIC_OPTS>;
