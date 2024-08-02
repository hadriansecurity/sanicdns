#pragma once

#include <arpa/inet.h>
#include <dpdk_wrappers.h>
#include <network_types.h>
#include <rte_arp.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <stdint.h>

#include <chrono>
#include <iostream>
#include <optional>
#include <tuple>
#include <unordered_map>
#include <utility>

struct ArpPacket {
	struct rte_ether_hdr ether_hdr;
	struct rte_arp_hdr arp_hdr;
};

/**
 * @brief This class is repsonsible for managing ARP requests. Generates an ARP
 * response based on a request.
 */

class Arp {
public:
	Arp(const in_addr_t own_ip, const rte_ether_addr own_mac)
	    : own_ip(own_ip), own_mac(own_mac) { }

	enum class Error {
		ARP_OK = 0,
		INVALID_MESSAGE,
		UNKNOWN_PROTOCOL,
		UNKNOWN_OP,
		PACKET_CONSTRUCTION,
		IO_ERROR,
		NO_RESPONSE,
	};

	/*
	 * @brief Converts an Error enum value to its string representation.
	 *
	 * @param e The Error.
	 */
	static constexpr const char *ErrorToString(Error e) {
		switch (e) {
			case Error::ARP_OK:
				return "ARP OK";
			case Error::INVALID_MESSAGE:
				return "Invalid Message";
			case Error::UNKNOWN_PROTOCOL:
				return "Unknown protocol";
			case Error::UNKNOWN_OP:
				return "Unknown operation";
			case Error::PACKET_CONSTRUCTION:
				return "Packet construction";
			case Error::IO_ERROR:
				return "IO error";
			case Error::NO_RESPONSE:
				return "No response :( ";
			default:
				return "Unknown error";
		}
	}

	/**
	 * @brief Receive an ARP packet and generate an optional response.
	 *
	 * @param arp_pkt The received ARP packet.
	 * @param resp mbuf for the response.
	 * @param send Function with signature ``[] (rte_mbuf*) -> bool`` that
	 * sends a single packet over the active network interface.
	 *
	 * @return An error code.
	 */

	template <typename Send>
	requires std::invocable<Send, RTEMbufElement<DefaultPacket, MbufType::Pkt>>
	Error ReceivePacket(RTEMbuf<DefaultPacket> &pkt,
	    RTEMempool<DefaultPacket, MbufType::Pkt> &mpool, Send send) {
		const auto &arp_pkt = pkt.data<ArpPacket>();

		// std::cout << std::hex << rte_be_to_cpu_16(arp_pkt.ether_hdr.ether_type) <<
		// std::dec << "\n";

		if (rte_be_to_cpu_16(arp_pkt.ether_hdr.ether_type) != RTE_ETHER_TYPE_ARP)
			return Error::UNKNOWN_PROTOCOL;

		if (rte_be_to_cpu_16(arp_pkt.arp_hdr.arp_hardware) != RTE_ARP_HRD_ETHER)
			return Error::UNKNOWN_PROTOCOL;

		if (arp_pkt.arp_hdr.arp_hlen != 6)
			return Error::INVALID_MESSAGE;

		if (rte_be_to_cpu_16(arp_pkt.arp_hdr.arp_protocol) != RTE_ETHER_TYPE_IPV4)
			return Error::UNKNOWN_PROTOCOL;

		if (arp_pkt.arp_hdr.arp_plen != 4)
			return Error::INVALID_MESSAGE;

		switch (rte_be_to_cpu_16(arp_pkt.arp_hdr.arp_opcode)) {
			case RTE_ARP_OP_REQUEST: {
				const auto sip = arp_pkt.arp_hdr.arp_data.arp_sip;
				const auto sha = arp_pkt.arp_hdr.arp_data.arp_sha;
				addr_map.insert(std::make_pair(sip, sha));

				if (arp_pkt.arp_hdr.arp_data.arp_tip != own_ip)
					return Error::INVALID_MESSAGE;

				rte_arp_hdr arp_data;
				arp_data.arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
				arp_data.arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
				arp_data.arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
				arp_data.arp_hlen = 6;
				arp_data.arp_plen = 4;

				rte_ether_addr_copy(&arp_pkt.arp_hdr.arp_data.arp_sha,
				    &arp_data.arp_data.arp_tha);
				rte_ether_addr_copy(&own_mac, &arp_data.arp_data.arp_sha);
				arp_data.arp_data.arp_sip = own_ip;
				arp_data.arp_data.arp_tip = arp_pkt.arp_hdr.arp_data.arp_sip;

				auto resp =
				    RTEMbufElement<DefaultPacket, MbufType::Pkt>::init(mpool);
				if (!resp)
					return Error::PACKET_CONSTRUCTION;

				if (ConstructARPPacket_(resp->get(), arp_data) != Error::ARP_OK)
					return Error::PACKET_CONSTRUCTION;

				const auto send_res = send(std::move(*resp));
				if (!send_res)
					return Error::IO_ERROR;

				return Error::ARP_OK;
			}
			case RTE_ARP_OP_REPLY: {
				const auto sip = arp_pkt.arp_hdr.arp_data.arp_sip;
				const auto sha = arp_pkt.arp_hdr.arp_data.arp_sha;
				addr_map.insert(std::make_pair(sip, sha));
				return Error::ARP_OK;
			}
		}
		return Error::UNKNOWN_OP;
	}

	/**
	 * @brief Perform entire request sequence for an IPv4 address.
	 *
	 * If a the requested (ip, mac) pair already exists it is deleted and retrieved again.
	 *
	 * @param addr The IPv4 address.
	 * @param mmpool An rte_mempool used to allocate packets.
	 * @param send Function with signature ``[] (rte_mbuf*) -> bool`` that
	 * sends a single packet over the active network interface.
	 * @param recv Function with signature ``[] (rte_mbuf**, uint16_t)`` ->
	 * uint16_t that receives a single packet on the active network interface.
	 *
	 * @return An error code.
	 */
	template <typename Send, typename Recv>
	requires std::invocable<Send, RTEMbufElement<DefaultPacket, MbufType::Pkt>> &&
	         std::invocable<Recv>
	Error RequestAddr(const in_addr_t addr, RTEMempool<DefaultPacket, MbufType::Pkt> &mpool,
	    Send &send, Recv &recv) {
		// First erase the address if it already exists in the map
		EraseAddr(addr);

		size_t max_retry = 20;
		const size_t timeout_ms = 500;

		bool found = false;

		// Loop until the correct MAC has been found or until the max number of retries has
		// been reached
		while (max_retry-- && !found) {
			// First construct and send the ARP request
			auto req_buf = RTEMbufElement<DefaultPacket, MbufType::Pkt>::init(mpool);
			if (!req_buf)
				return Error::PACKET_CONSTRUCTION;

			const auto gen_res = GenAddrRequest_(addr, req_buf->get());
			if (gen_res != Error::ARP_OK)
				return gen_res;

			const auto send_res = send(std::move(*req_buf));
			if (!send_res)
				return Error::IO_ERROR;

			// Record current time as a reference for the loop
			auto start = std::chrono::steady_clock::now();
			size_t duration_ms = 0;

			// Loop for timeout_ms, receive packets continuously
			do {
				auto recvd = recv();

				for (auto &pkt : recvd) {
					// Do not handle erroneous packets, we are only interested
					// in valid ARP packets
					ReceivePacket(pkt, mpool, send);

					// Check if the requested address has already been inserted
					// into map
					if (GetEtherAddr(addr)) {
						found = true;
						break;
					}
				}

				auto now = std::chrono::steady_clock::now();
				duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
				    now - start)
				                  .count();

				// Stay in the loop when the timeout has not been reached yet and
				// the correct packet has not been found yet
			} while (duration_ms < timeout_ms && !found);
		}

		return found ? Error::ARP_OK : Error::NO_RESPONSE;
	}

	/**
	 * @brief Get the Ethernet address for a particular address.
	 *
	 * @param addr The address needed to be resolved.
	 *
	 * @return optional Ethernet address for the Ipv4 address. If
	 * std::nullopt is returned, address should be looked up explictely.
	 */
	std::optional<rte_ether_addr> GetEtherAddr(const in_addr_t addr);

	/**
	 * @brief Manually insert an (ip, mac) pair.
	 *
	 * @param ip The Ipv4 address.
	 * @param mac The MAC address.
	 */
	void InsertAddr(const in_addr_t ip, const rte_ether_addr mac);

	/**
	 * @brief Erases the (ip, mac) pair identified by ip, if it exists
	 *
	 * @param ip The Ipv4 address.
	 *
	 * @return Number of elements removed from map (0 or 1)
	 */
	size_t EraseAddr(const in_addr_t ip);

private:
	/**
	 * @brief Construct an ARP request by encapsulating it in an Ethernet
	 * packet.
	 *
	 * @param msg The message buffer to use.
	 * @param arp_data The ARP data to embed.
	 *
	 * @return Error code.
	 */

	Error ConstructARPPacket_(RTEMbuf<DefaultPacket> &msg, rte_arp_hdr arp_data);

	/**
	 * @brief Generate an ARP request packet for a particular address.
	 *
	 * @param addr The address the request should be generated for.
	 * @param resp mbuf to store the request in.
	 *
	 * @return Error code.
	 */

	Error GenAddrRequest_(const in_addr_t addr, RTEMbuf<DefaultPacket> &resp);

	std::unordered_map<in_addr_t, rte_ether_addr> addr_map;
	const in_addr_t own_ip;
	const rte_ether_addr own_mac;
};
