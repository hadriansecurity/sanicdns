#pragma once

#include <dpdk_wrappers.h>
#include <network_types.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_hexdump.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include <new>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "spdlog/spdlog.h"

#define CACHELINE_SIZE 64

/**
 * @brief Struct containing stats information
 */
struct alignas(CACHELINE_SIZE) Stats {
	size_t num_bad_l4_cksum;
	size_t num_bad_ip_cksum;
	size_t num_bad_tx_cksum;
	size_t num_total;
	size_t num_sent;
	size_t num_bytes_sent;
};

/**
 * @brief Struct containing configuration information for the ethernet device
 */
struct EthDevConf {
	uint16_t nb_tx_queues;
	uint16_t nb_rx_queues;

	uint16_t nb_tx_descrs;
	uint16_t nb_rx_descrs;

	bool enable_rss;
};

enum class L3Type {
	Ipv4,
	Ipv6
};

enum class L4Type {
	UDP,
	TCP
};

/**
 * @brief This class is responsible for transmitting and receiving packets from the NIC
 *
 * The network card specified by device_name is initialized in the constructor.
 *
 * @tparam opts is used to pass compilation options to the class, see eth_rxtx_opts.h
 */
template <class opts>
class EthRxTx {
public:
	/**
	 * @brief Construct a new Eth Rx Tx object and initialize the device
	 *
	 * The constructor will throw an exception when the device initialisation
	 * cannot be completed or any of the rx/tx offloads is not available
	 *
	 * @param config Configuration structure for the class
	 * @param device_name PCI device name, 0000:06:00.0 for example
	 * @param pool_size Size of the mempool backing the device
	 */
	static tl::expected<EthRxTx, std::string> init(const EthDevConf &config,
	    std::string_view device_name, rte_mempool *mempool);

	EthRxTx(const EthRxTx &) = delete;
	EthRxTx &operator=(const EthRxTx &) = delete;
	EthRxTx &operator=(EthRxTx &&other) = delete;

	// Move constructor is required for init function.
	EthRxTx(EthRxTx &&other)
	    : config(other.config),
	      portid(other.portid),
	      addr(other.addr),
	      stats(std::move(other.stats)),
	      flow_configurations(std::move(other.flow_configurations)),
	      _valid(other._valid) {
		other._valid = false;
	}

	/**
	 * @brief Destroy the Eth Rx Tx object
	 *
	 */
	~EthRxTx();

	/**
	 * @brief Send packets to a specific TX queue
	 *
	 * This function transmits a maximum of num_pkts, can be less.
	 * InsertPktOlFlags and PreparePackets must be called on all packets first
	 *
	 * @param queue_id The TX queue id to transmit packets on
	 * @param pkts An array of rte_mbuf pointers that contain the packets to be transmitted
	 * @param num_pkts Number of packets to send
	 * @return uint16_t Number of packets transmitted
	 */
	template <typename Elem, size_t Size>
	std::pair<uint16_t, RTEMbufArray<Elem, Size, MbufType::Pkt>> SendPackets(
	    const uint16_t queue_id, RTEMbufArray<Elem, Size, MbufType::Pkt> &&pkts) {
		auto raw_ptr = reinterpret_cast<rte_mbuf **>(pkts.data());

		uint16_t nb_tx = rte_eth_tx_burst(portid, queue_id, raw_ptr, pkts.size());
		stats[queue_id].num_sent += nb_tx;

		auto [sent, free] = pkts.split(nb_tx);
		sent.release();
		return {nb_tx, std::move(free)};
	}

	template <typename Elem>
	uint16_t SendPacket(const uint16_t queue_id, RTEMbufElement<Elem, MbufType::Pkt> &&pkt) {
		rte_mbuf *raw_ptr = &pkt.get();
		pkt.release();

		auto nb_prepared = rte_eth_tx_prepare(portid, queue_id, &raw_ptr, 1);

		if (nb_prepared != 1) [[unlikely]] {
			return 0;
		}

		auto nb_tx = rte_eth_tx_burst(portid, queue_id, &raw_ptr, 1);

		stats[queue_id].num_sent += nb_tx;

		return nb_tx;
	}

	/**
	 * @brief Receive packets from a specified RX queue
	 *
	 * Receive as much packets as possible from the specified RX queue.
	 * On a RX IP checksum error RTE_MBUF_F_TX_IP_CKSUM will be set in the packet ol_flags,
	 * on an invalid UDP checksum RTE_MBUF_F_TX_UDP_CKSUM will be set.
	 *
	 * @param queue_id The RX queue to receive packets from
	 * @param pkts An array of rte_mbuf pointers that will contain the pointers to the received
	 * packets
	 * @param max_rcv The maximum number of packets to receive
	 * @return uint16_t
	 */
	template <size_t Size>
	RTEMbufArray<DefaultPacket, Size, MbufType::Pkt> RcvPackets(const uint16_t queue_id) {
		const uint16_t max_rcv = Size;
		uint16_t nb_to_receive = max_rcv;

		std::array<RTEMbuf<DefaultPacket> *, Size> raw_pkts;
		auto nb_rx =
		    rte_eth_rx_burst(portid, queue_id, (rte_mbuf **) &raw_pkts[0], nb_to_receive);

		RTEMbufArray<DefaultPacket, Size, MbufType::Pkt> pkts(
		    std::span(raw_pkts.begin(), nb_rx));

		for (auto &pkt : pkts) {
			// Check if any of the checksums have to be computed in software
			if constexpr ((!opts::offload_rx_ipv4_cksum) ||
				      (!opts::offload_rx_l4_cksum)) {
				// Check for valid Ipv4 cksum when the L3 type is Ipv4
				uint32_t ptype_masked_l3 = pkt.packet_type & RTE_PTYPE_L3_MASK;
				uint32_t ptype_masked_l4 = pkt.packet_type & RTE_PTYPE_L4_MASK;

				if (ptype_masked_l3 == RTE_PTYPE_L3_IPV4 ||
				    ptype_masked_l3 == RTE_PTYPE_L3_IPV4_EXT ||
				    ptype_masked_l3 == RTE_PTYPE_L3_IPV4_EXT_UNKNOWN) {
					UdpIpv4Header &udp_ipv4_hdr =
					    pkt.template data<UdpIpv4Header>();
					rte_ipv4_hdr *ip_hdr = &udp_ipv4_hdr.ipv4_hdr;
					void *l4_hdr = (void *) &udp_ipv4_hdr.udp_hdr;

					// Packet is Ipv4
					// Check Ipv4 checksum in software if not offloaded to
					// hardware
					if constexpr (!(opts::offload_rx_ipv4_cksum)) {
						bool ipv4_chsum_bad =
						    (ptype_masked_l3 == RTE_PTYPE_L3_IPV4 ||
							ptype_masked_l3 == RTE_PTYPE_L3_IPV4_EXT ||
							ptype_masked_l3 ==
							    RTE_PTYPE_L3_IPV4_EXT_UNKNOWN) &&
						    rte_ipv4_cksum(ip_hdr);

						pkt.ol_flags &= ~(RTE_MBUF_F_RX_IP_CKSUM_MASK);
						pkt.ol_flags |= ipv4_chsum_bad
						                    ? RTE_MBUF_F_RX_IP_CKSUM_BAD
						                    : RTE_MBUF_F_RX_IP_CKSUM_GOOD;
					}

					if constexpr (!(opts::offload_rx_l4_cksum)) {
						uint16_t cksum =
						    __rte_ipv4_udptcp_cksum(ip_hdr, l4_hdr);

						bool l4_cksum_bad =
						    (ptype_masked_l4 == RTE_PTYPE_L4_UDP ||
							ptype_masked_l4 == RTE_PTYPE_L4_TCP) &&
						    (cksum != 0xFFFF);

						pkt.ol_flags &= ~(RTE_MBUF_F_RX_L4_CKSUM_MASK);
						pkt.ol_flags |= l4_cksum_bad
						                    ? RTE_MBUF_F_RX_L4_CKSUM_BAD
						                    : RTE_MBUF_F_RX_L4_CKSUM_GOOD;
					}
				} else if (ptype_masked_l3 == RTE_PTYPE_L3_IPV6 ||
					   ptype_masked_l3 == RTE_PTYPE_L3_IPV6_EXT ||
					   ptype_masked_l3 == RTE_PTYPE_L3_IPV6_EXT_UNKNOWN) {
					// Packet is Ipv6
					UdpIpv6Header &udp_ipv6_hdr =
					    pkt.template data<UdpIpv6Header>();

					rte_ipv6_hdr *ip_hdr = &udp_ipv6_hdr.ipv6_hdr;
					void *l4_hdr = (void *) &udp_ipv6_hdr.udp_hdr;

					if constexpr (!(opts::offload_rx_l4_cksum)) {
						uint16_t cksum =
						    __rte_ipv6_udptcp_cksum(ip_hdr, l4_hdr);
						bool l4_cksum_bad =
						    (ptype_masked_l4 == RTE_PTYPE_L4_UDP ||
							ptype_masked_l4 == RTE_PTYPE_L4_TCP) &&
						    (cksum != 0xFFFF);

						pkt.ol_flags &= ~(RTE_MBUF_F_RX_L4_CKSUM_MASK);
						pkt.ol_flags |= l4_cksum_bad
						                    ? RTE_MBUF_F_RX_L4_CKSUM_BAD
						                    : RTE_MBUF_F_RX_L4_CKSUM_GOOD;
					}
				}
			}

			stats[queue_id].num_bad_ip_cksum +=
			    ((pkt.ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) ==
				RTE_MBUF_F_RX_IP_CKSUM_BAD);
			stats[queue_id].num_bad_l4_cksum +=
			    ((pkt.ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK) ==
				RTE_MBUF_F_RX_L4_CKSUM_BAD);
		}

		stats[queue_id].num_total += pkts.size();

		return pkts;
	}

	/**
	 * @brief Prepares the packets for transmit
	 *
	 * @param queue_id The TX queue id to transmit packets on
	 * @param pkts An array of rte_mbuf pointers that contain the packets to be transmitted
	 * @param num_pkts Number of packets to send
	 * @return uint16_t Number of packets prepared, equal to num_pkts without errors
	 */
	template <typename Elem, size_t Size>
	void PreparePackets(const uint16_t queue_id,
	    RTEMbufArray<Elem, Size, MbufType::Pkt> &to_prepare) {
		auto raw_ptr = reinterpret_cast<rte_mbuf **>(to_prepare.data());

		uint16_t nb_prepared =
		    rte_eth_tx_prepare(portid, queue_id, raw_ptr, to_prepare.size());
		if (nb_prepared != to_prepare.size())
			spdlog::warn("{} packets prepared, {} requested", nb_prepared,
			    to_prepare.size());
	}

	/**
	 * @brief Get the Mac address of the interface
	 *
	 * @return rte_ether_addr
	 */
	rte_ether_addr GetMacAddr() {
		return addr;
	}

	/**
	 * @brief Generates a receive queue flow based on UDP src/dst ports and DNS id for both Ipv4
	 * and Ipv6
	 *
	 * This function uses rte_flow to direct packets that match the specified UDP src/dest
	 * ports and the specified DNS id.
	 *
	 * The mask for the UDP ports can either be 0x0000 or 0xFFFF and cannot be set per bit.
	 * 0xFFFF matches the exact UDP port in this case, 0x0000 ignores the port setting
	 *
	 * The DNS id can be matched per bit based on the mask and id settings
	 *
	 * @param queue_id The RX queue id to direct packets to
	 * @param src_port UDP source port to match based on src_mask
	 * @param src_mask Mask for UDP source port (either 0 or 0xFFFF)
	 * @param dst_port UDP destination port to match based on src_mask
	 * @param dst_mask Mask for UDP destination port (either 0 or 0xFFFF)
	 * @param dns_id DNS id to match based on dns_id_mask
	 * @param dns_id_mask DNS id mask, can be set per bit
	 */
	[[nodiscard]] tl::expected<void, std::string> GenerateDNSFlow(uint16_t queue_id, uint16_t src_port, uint16_t src_mask,
	    uint16_t dst_port, uint16_t dst_mask, uint16_t dns_id, uint16_t dns_id_mask);

	/**
	 * @brief Print the total statistics of the ethernet device
	 */
	void PrintStats();

	/**
	 * @brief Prepares the packets with correct checksum data
	 *
	 * Inserts the correct offload flags into the packet based on opts, the required flags
	 are
	 * calculated in compile-time When the offload is not assigned to hardware the
	 *
	 * @tparam l3_type Specify the layer 3 type of the packet, see L3Type
	 * @tparam l4_type Specify the layer 4 type of the packet, see L4Type
	 * @param pkt
	 */
	template <typename Elem, L3Type l3_type, L4Type l4_type>
	static inline void PreparePktCksums(RTEMbuf<Elem> &pkt) {
		// Flag is packet is ipv4 or ipv6, enable ipv4 tx checksum offload if set in opts
		constexpr uint64_t l3_offloads =
		    (l3_type == L3Type::Ipv4 ? RTE_MBUF_F_TX_IPV4 : 0) |
		    (l3_type == L3Type::Ipv6 ? RTE_MBUF_F_TX_IPV6 : 0) |
		    (l3_type == L3Type::Ipv4 && opts::offload_tx_ipv4_cksum ? RTE_MBUF_F_TX_IP_CKSUM
									    : 0);

		// Enable udp/tcp offload if set in opts
		constexpr uint64_t l4_offloads =
		    (l4_type == L4Type::UDP && opts::offload_tx_l4_cksum ? RTE_MBUF_F_TX_UDP_CKSUM
									 : 0) |
		    (l4_type == L4Type::TCP && opts::offload_tx_l4_cksum ? RTE_MBUF_F_TX_TCP_CKSUM
									 : 0);

		pkt.ol_flags |= (l3_offloads | l4_offloads);

		// Insert software ipv4 checksum if required
		if constexpr (l3_type == L3Type::Ipv4 && (!opts::offload_tx_ipv4_cksum)) {
			auto &ip_hdr = pkt.template data<Ipv4Header>();

			ip_hdr.ipv4_hdr.hdr_checksum = 0;
			ip_hdr.ipv4_hdr.hdr_checksum = rte_ipv4_cksum(&ip_hdr.ipv4_hdr);
		}

		// Insert Ipv4 UDP header if required
		if constexpr (l3_type == L3Type::Ipv4 && l4_type == L4Type::UDP &&
			      (!opts::offload_tx_l4_cksum)) {
			auto &udp_hdr = pkt.template data<UdpIpv4Header>();

			udp_hdr.udp_hdr.dgram_cksum = 0;
			udp_hdr.udp_hdr.dgram_cksum =
			    rte_ipv4_udptcp_cksum(&udp_hdr.ipv4_hdr, (void *) &udp_hdr.udp_hdr);
		}

		// Insert Ipv4 TCP header if required
		if constexpr (l3_type == L3Type::Ipv4 && l4_type == L4Type::TCP &&
			      (!opts::offload_tx_l4_cksum)) {
			auto &tcp_hdr = pkt.template data<TcpIpv4Header>();

			tcp_hdr->tcp_hdr.cksum = 0;
			tcp_hdr->tcp_hdr.cksum =
			    rte_ipv4_udptcp_cksum(&tcp_hdr.ipv4_hdr, (void *) &tcp_hdr.tcp_hdr);
		}

		// Insert Ipv6 UDP header if required
		if constexpr (l3_type == L3Type::Ipv6 && l4_type == L4Type::UDP &&
			      (!opts::offload_tx_l4_cksum)) {
			auto &udp_hdr = pkt.template data<UdpIpv6Header>();

			udp_hdr.udp_hdr.dgram_cksum = 0;
			udp_hdr.udp_hdr.dgram_cksum =
			    rte_ipv6_udptcp_cksum(&udp_hdr.ipv6_hdr, (void *) &udp_hdr.udp_hdr);
		}

		// Insert Ipv6 TCP header if required
		if constexpr (l3_type == L3Type::Ipv6 && l4_type == L4Type::TCP &&
			      (!opts::offload_tx_l4_cksum)) {
			auto &tcp_hdr = pkt.template data<TcpIpv6Header>();

			tcp_hdr.tcp_hdr.cksum = 0;
			tcp_hdr.tcp_hdr.cksum =
			    rte_ipv6_udptcp_cksum(&tcp_hdr.ipv6_hdr, (void *) &tcp_hdr.tcp_hdr);
		}
	}

	uint16_t GetPortId() const {
		return portid;
	}

private:
	/**
	 * @brief Constructor
	 */
	EthRxTx(const EthDevConf &config, uint16_t portid, rte_ether_addr addr,
	    std::vector<Stats> &&stats)
	    : config(config),
	      portid(portid),
	      addr(addr),
	      stats(stats),
	      flow_configurations{},
	      _valid{true} { }

	/**
	 * @brief The user defined config is saved
	 */
	const EthDevConf config;

	/**
	 * @brief The user defined port id is saved here
	 */
	const uint16_t portid;

	/**
	 * @brief The MAC address of the device
	 */
	const struct rte_ether_addr addr;

	/**
	 * @brief A per-core statistics map
	 */
	std::vector<Stats> stats;

	/**
	 * @brief An array with all active flow settings
	 */
	std::vector<rte_flow *> flow_configurations;

	bool _valid;

	/**
	 * @brief Compile-time evaluated variable containing all device TX offload flags based on
	 * opts
	 */
	static constexpr uint64_t dev_tx_offloads =
	    (opts::offload_tx_ipv4_cksum ? RTE_ETH_TX_OFFLOAD_IPV4_CKSUM : 0) |
	    (opts::offload_tx_l4_cksum
		    ? (RTE_ETH_TX_OFFLOAD_UDP_CKSUM | RTE_ETH_TX_OFFLOAD_TCP_CKSUM)
		    : 0) |
	    (opts::offload_tx_mbuf_fast_free ? RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE : 0);

	/**
	 * @brief Compile-time evaluated variable containing all device RX offload flags based on
	 * opts
	 */
	static constexpr uint64_t dev_rx_offloads =
	    (opts::offload_rx_ipv4_cksum ? RTE_ETH_RX_OFFLOAD_IPV4_CKSUM : 0) |
	    (opts::offload_rx_l4_cksum
		    ? (RTE_ETH_RX_OFFLOAD_UDP_CKSUM | RTE_ETH_RX_OFFLOAD_UDP_CKSUM)
		    : 0);
};

#include "eth_rxtx_opts.h"
