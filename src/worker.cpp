#include "worker.h"

#include <rte_common.h>
#include <rte_hexdump.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <spdlog/spdlog.h>

#include <glaze/glaze.hpp>
#include <optional>
#include <stack>
#include <tuple>
#include <variant>

#include "dns_format.h"
#include "dns_packet.h"
#include "dns_packet_constructor.h"
#include "dns_struct_defs.h"
#include "dpdk_wrappers.h"
#include "expected_helpers.h"
#include "intrusive_list.h"
#include "network_types.h"
#include "scanner_config.h"

struct RequestContainer {
	RequestContainer()
	    : ready_for_send_node(this), timeout_node(this), request(std::nullopt) { }

	Node<RequestContainer> ready_for_send_node;
	Node<RequestContainer> timeout_node;

	std::optional<RTEMbufElement<Request>> request;
	std::chrono::time_point<std::chrono::steady_clock> time_sent;
	InAddr resolver;
	size_t num_tries;
	size_t loc;
};

struct WorkerContext {
	static tl::expected<WorkerContext, int> init(uint16_t worker_id,
	    const WorkerParams &param) {
		WorkerContext ctx{worker_id, param};

		for (size_t i = 0; i < param.num_containers; i++) {
			ctx.request_containers[i].loc = i;
			ctx.available_container_stack.push(ctx.request_containers.data() + i);
		}

		ctx.pkt_distributors.reserve(param.num_workers);
		for (size_t i = 0; i < param.num_workers; i++) {
			auto dns_array = UNWRAP_OR_RETURN(
			    (RTEMbufArray<DNSPacketDistr, RX_PKT_BURST>::init(param.dns_mempool)));
			ctx.pkt_distributors.emplace_back(std::move(dns_array));
		}

		return ctx;
	}

	uint16_t worker_id;
	uint16_t queue_id;

	size_t resolver_count;

	IntrusiveList<RequestContainer, &RequestContainer::ready_for_send_node> ready_for_send_list;
	IntrusiveList<RequestContainer, &RequestContainer::timeout_node> timeout_list;

	std::vector<RequestContainer, RteAllocator<RequestContainer>> request_containers;
	std::stack<RequestContainer *,
	    std::vector<RequestContainer *, RteAllocator<RequestContainer *>>>
	    available_container_stack;
	std::vector<RTEMbufArray<DNSPacketDistr, RX_PKT_BURST>> pkt_distributors;

private:
	WorkerContext(uint16_t worker_id, const WorkerParams &param)
	    : worker_id(worker_id),
	      queue_id(worker_id + (NIC_OPTS::queue_for_main_thread ? 1 : 0)),
	      request_containers(param.num_containers) { }
};

std::pair<uint16_t, uint16_t> PackPacketParams(uint16_t worker_id, uint32_t buffer_loc) {
	// Use upper 6 bits of dns id for worker id
	uint16_t dns_id = (worker_id + 1) << 10;

	// Store upper 10 bits of buffer_loc in dns id
	dns_id |= (buffer_loc & static_cast<uint32_t>(0x000FFC000)) >> 14;

	// Store lower 14 bits of buffer_loc in udp_src, 1024 should be the minimum port number
	uint16_t udp_port = (buffer_loc & static_cast<uint32_t>(0x00003FFF)) + 1024;

	return std::make_pair(udp_port, dns_id);
}

RTEMbufArray<DefaultPacket, TX_PKT_BURST, MbufType::Pkt> ConsumeReadyForSendAndPrepare(
    NICType &rxtx_if, RTEMempool<DefaultPacket, MbufType::Pkt> &mempool, WorkerContext &ctx,
    WorkerParams &param, uint16_t max_to_prepare) {
	auto current_time = std::chrono::steady_clock::now();

	// Get packets or return empty MbufArray
	auto packets = ({
		tl::expected res = RTEMbufArray<DefaultPacket, TX_PKT_BURST, MbufType::Pkt>::init(
		    mempool, max_to_prepare);
		if (!res) {
			return RTEMbufArray<DefaultPacket, TX_PKT_BURST, MbufType::Pkt>::init(
			    mempool, 0)
			    .value();
		}
		std::move(*res);
	});

	const rte_ether_addr src_mac = rxtx_if.GetMacAddr();

	size_t tx_write_cnt = 0;
	for (auto it = ctx.ready_for_send_list.begin(); it != ctx.ready_for_send_list.end();) {
		if (tx_write_cnt >= packets.size())
			break;

		if (!it->request) {
			ctx.available_container_stack.push(&it.front());
			it = ctx.ready_for_send_list.erase(it);
			spdlog::error("Request container without request in ready for send queue");
			continue;
		}
		Request &req = it->request->get_data();

		auto [udp_port, dns_id] = PackPacketParams(ctx.worker_id, it->loc);

		param.counters[ctx.worker_id].retry += (it->num_tries != 0);

		ctx.resolver_count++;
		ctx.resolver_count %= param.resolvers.size();

		it->resolver = param.resolvers[ctx.resolver_count];

		DNSPacketConstructor::ConstructIpv4DNSPacket(packets[tx_write_cnt], src_mac,
		    req.dst_mac, std::get<InAddr>(req.src_ip).s_addr, it->resolver.s_addr, udp_port,
		    dns_id, req.name.buf.data(), req.name.len, req.q_type);

		rxtx_if.PreparePktCksums<DefaultPacket, L3Type::Ipv4, L4Type::UDP>(
		    packets[tx_write_cnt]);

		tx_write_cnt++;
		it->time_sent = current_time;

		ctx.timeout_list.push_back(*it);
		it = ctx.ready_for_send_list.erase(it);
	}

	auto [constructed_packets, _] = packets.split(tx_write_cnt);

	rxtx_if.PreparePackets(ctx.queue_id, constructed_packets);

	return std::move(constructed_packets);
}

void ProcessTimeouts(WorkerContext &ctx, WorkerParams &param) {
	auto current_time = std::chrono::steady_clock::now();

	for (auto it = ctx.timeout_list.begin(); it != ctx.timeout_list.end();) {
		auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
		    current_time - it->time_sent);

		if (static_cast<uint64_t>(elapsed_ms.count()) < param.timeout_ms)
			break;

		if (++it->num_tries > param.max_retries) {
			spdlog::warn("{} has reached max retries",
			    it->request->get().name.buf.data());

			it->request = std::nullopt;
			it->num_tries = 0;

			param.counters[ctx.worker_id].max_retry++;

			ctx.available_container_stack.push(&it.front());
		} else {
			ctx.ready_for_send_list.push_back(*it);
		}

		it = ctx.timeout_list.erase(it);
	}
}

void AddRequestsToReadyForSend(WorkerContext &ctx,
    RTEMbufArray<Request, TX_PKT_BURST> &request_buf) {
	while (!ctx.available_container_stack.empty()) {
		RequestContainer *free_container = ctx.available_container_stack.top();
		auto request = ({
			std::optional res = request_buf.pop();
			if (!res)
				break;
			std::move(*res);
		});

		if (request.get_data().num_ips == 0 || request.get_data().num_ips > REQUEST_MAX_IPS)
		    [[unlikely]] {
			spdlog::warn("Dropping request, invalid number of IPs");
			continue;
		}

		free_container->num_tries = 0;

		free_container->request = std::move(request);

		ctx.ready_for_send_list.push_back(*free_container);
		ctx.available_container_stack.pop();
	}
}

void HandleParsedPacket(WorkerContext &ctx, WorkerParams &param, const DNSPacket &pkt,
    RTEMbuf<DefaultPacket> &raw_pkt, std::shared_ptr<spdlog::logger> out_logger) {
	switch (pkt.r_code) {
		case DnsRCode::NOERROR:
			param.counters[ctx.worker_id].noerror++;
			break;
		case DnsRCode::SERVFAIL:
			param.counters[ctx.worker_id].servfail++;
			break;
		case DnsRCode::NXDOMAIN:
			param.counters[ctx.worker_id].nxdomain++;
			break;
		default:
			param.counters[ctx.worker_id].rcode_other++;
			break;
	}

	if (pkt.GetBufferLoc() >= ctx.request_containers.size()) [[unlikely]] {
		spdlog::warn("packet has out of bounds request buffer location: {}",
		    pkt.GetBufferLoc());
		return;
	}

	auto &request_container = ctx.request_containers[pkt.GetBufferLoc()];
	if (!request_container.request) [[unlikely]] {
		spdlog::warn("packet with name {} in location {:x} already processed!",
		    pkt.question, pkt.GetBufferLoc());
		return;
	}

	if (request_container.request->get().q_type != pkt.q_type) [[unlikely]] {
		spdlog::warn("packet with name {} has q type mismatch!", pkt.question);
		return;
	}

	if (request_container.resolver.s_addr != std::get<InAddr>(pkt.ip_data.src_ip).s_addr)
	    [[unlikely]] {
		spdlog::warn("packet with name {} has IP mismatch!", pkt.question);
		return;
	}

	if (request_container.request->get().name != pkt.question) [[unlikely]] {
		spdlog::warn("packet with name {} has name mismatch with request {}", pkt.question,
		    request_container.request->get().name);
		return;
	}

	param.counters[ctx.worker_id].num_resolved++;

	request_container.request = std::nullopt;
	request_container.num_tries = 0;

	ctx.timeout_list.delete_elem(request_container);
	ctx.ready_for_send_list.delete_elem(request_container);
	ctx.available_container_stack.push(&request_container);

	if (param.rcode_filters) {
		const auto &v = param.rcode_filters.value();

		if (!std::count(v.begin(), v.end(), pkt.r_code))
			return;
	}

	if (!param.output_raw) {
		std::string out = glz::write_json(pkt);

		out_logger->info(out);
	} else {
		auto dns_offset = sizeof(rte_ether_hdr) + sizeof(rte_udp_hdr);
		dns_offset += std::holds_alternative<InAddr>(pkt.ip_data.dst_ip)
		                  ? sizeof(rte_ipv4_hdr)
		                  : sizeof(rte_ipv6_hdr);

		auto pkt_begin = raw_pkt.data().padding.data();
		auto dns_begin = pkt_begin + dns_offset;
		auto pkt_end = pkt_begin + raw_pkt.data_len;

		// Reset transaction ID to 0
		auto dns_header = reinterpret_cast<DnsHeader *>(dns_begin);
		dns_header->id = 0;

		out_logger->info("{:02x}", fmt::join(reinterpret_cast<unsigned char *>(dns_begin),
					       reinterpret_cast<unsigned char *>(pkt_end), ""));
	}
}

void RX(WorkerContext &ctx, NICType &rxtx_if, uint16_t worker_id, WorkerParams &param,
    std::shared_ptr<spdlog::logger> out_logger) {
	auto pkts = rxtx_if.RcvPackets<RX_PKT_BURST>(ctx.queue_id);
	param.counters[ctx.worker_id].rcvd_pkts += pkts.size();

	std::optional<RTEMbufElement<DefaultPacket, MbufType::Pkt>> p;
	while ((p = pkts.pop())) {
		if ((p->get().ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) ==
			RTE_MBUF_F_RX_IP_CKSUM_BAD ||
		    (p->get().ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK) == RTE_MBUF_F_RX_IP_CKSUM_BAD)
			continue;

		auto parsed_packet = ({
			auto res = DNSPacket::init(param.raw_mempool, *p);
			if (!res) {
				auto pkt_begin = p->get().data().padding.data();
				auto pkt_end = pkt_begin + p->get().data_len;

				auto pkt_formatted =
				    fmt::join(reinterpret_cast<unsigned char *>(pkt_begin),
					reinterpret_cast<unsigned char *>(pkt_end), "");

				spdlog::warn("error parsing packet: {}, raw pkt: {:02x}",
				    res.error(), std::move(pkt_formatted));

				param.counters[worker_id].parse_fail++;
				continue;
			}
			std::move(*res);
		});

		if (parsed_packet.GetWorkerId() >= param.num_workers) [[unlikely]] {
			spdlog::warn("packet worker id {} is larger than number of workers",
			    parsed_packet.GetWorkerId());
			param.counters[worker_id].parse_fail++;
			continue;
		}

		param.counters[worker_id].parse_success++;

		if constexpr (!NIC_OPTS::hw_flowsteering) {
			if (worker_id != parsed_packet.GetWorkerId()) {
				auto &dns_dist = ctx.pkt_distributors[parsed_packet.GetWorkerId()];

				auto dns_packet_distr =
				    DNSPacketDistr{.dns_packet = std::move(parsed_packet),
					.raw_packet = std::move(*p)};

				// Distributing the packet on the ring requires it to be wrapped in
				// an mbuf. We can avoid the allocation in the fast path, but here
				// it is required.
				auto wrapped_packet = ({
					auto res = RTEMbufElement<DNSPacketDistr>::init(
					    param.dns_mempool, std::move(dns_packet_distr));
					if (!res) {
						spdlog::warn("worker {}: dropping packet due to "
							     "allocation failure {}",
						    worker_id, res.error());
						continue;
					}
					std::move(*res);
				});

				auto dns_push = dns_dist.push(std::move(wrapped_packet));
				if (dns_push)
					spdlog::warn("worker {}: distribution buffer is full, "
						     "dropping packet");

				continue;
			}
		}

		if (worker_id != parsed_packet.GetWorkerId()) [[unlikely]] {
			spdlog::warn("packet worker id {} differs from ours: {}",
			    parsed_packet.GetWorkerId(), worker_id);
			param.counters[worker_id].other_worker_id++;
			continue;
		}

		// Fast path - the packet does not need to be distributed on a ring.
		HandleParsedPacket(ctx, param, parsed_packet, p->get(), out_logger);
	}

	// With flowsteering there is nothing left to do.
	// Without flowsteering we continue on the slow path.
	if constexpr (NIC_OPTS::hw_flowsteering)
		return;

	// Distribute the packets in the distribution buffer on to each other worker's ring.
	for (size_t remote = 0; remote < param.num_workers; remote++) {
		// Packets meant for our worker use fast path - even when flow steering is disabled.
		if (remote == ctx.worker_id)
			continue;

		auto &dns_ring = param.distribution_rings[remote];
		auto &dns_buf = ctx.pkt_distributors[remote];
		if (dns_buf.size() == 0)
			continue;

		auto dns_remainder = dns_ring.enqueue_burst(std::move(dns_buf));
		ctx.pkt_distributors[remote] = std::move(dns_remainder);
	}

	// Dequeue all outstanding packets and continue packet receive process.
	auto &dns_ring = param.distribution_rings[worker_id];
	auto rx_dns = dns_ring.dequeue_burst<RX_PKT_BURST>();
	for (auto &p : rx_dns)
		HandleParsedPacket(ctx, param, p.dns_packet, p.raw_packet.get(), out_logger);
}

int Worker(std::stop_token stop_token, uint16_t worker_id, WorkerParams param) {
	const size_t num_containers = param.num_containers;
	auto ctx = ({
		auto res = WorkerContext::init(worker_id, param);
		if (!res) {
			spdlog::error("worker {}: failed to init WorkerContext: {}", worker_id,
			    res.error());
			param.workers_finished.count_down();
			return -1;
		}
		std::move(*res);
	});

	std::chrono::time_point<std::chrono::steady_clock> next_send_time =
	    std::chrono::steady_clock::now();

	auto request_buf = RTEMbufArray<Request, TX_PKT_BURST>::init(param.request_mempool).value();
	auto prepared_packet_buf =
	    RTEMbufArray<DefaultPacket, TX_PKT_BURST, MbufType::Pkt>::init(param.pkt_mempool)
		.value();

	auto out_logger = spdlog::get("output_log");

	bool finished_set = false;

	while (!param.workers_finished.try_wait()) {
		bool worker_finished = ctx.available_container_stack.size() == num_containers &&
		                       param.domains_finished.try_wait() &&
		                       request_buf.size() == 0 && param.ring.empty();

		if ((stop_token.stop_requested() || worker_finished) && !finished_set) {
			finished_set = true;
			param.workers_finished.count_down();
		}

		auto current_time = std::chrono::steady_clock::now();
		std::ignore = request_buf.insert(
		    param.ring.dequeue_burst<TX_PKT_BURST>(request_buf.free_cnt()));

		ProcessTimeouts(ctx, param);

		AddRequestsToReadyForSend(ctx, request_buf);

		if (current_time >= next_send_time) {
			auto prepared_packets = ConsumeReadyForSendAndPrepare(param.rxtx_if,
			    param.pkt_mempool, ctx, param, prepared_packet_buf.free_cnt());

			size_t ps_per_req = 1000'000'000'000 / param.rate_lim_pps;
			next_send_time =
			    current_time +
			    std::chrono::nanoseconds((ps_per_req * prepared_packets.size()) / 1000);

			std::ignore = prepared_packet_buf.insert(std::move(prepared_packets));
		}

		// for (auto& packet: prepared_packet_buf) {
		//  	char* data = rte_pktmbuf_mtod(&packet, char*);
		//  	rte_memdump(stdout, "PACKET", data, packet.data_len);
		// }

		// if (prepared_packet_buf.size() > 1)
		// 	std::ignore = prepared_packet_buf.pop();

		auto [num_sent, unsent_packets] =
		    param.rxtx_if.SendPackets(ctx.queue_id, std::move(prepared_packet_buf));
		prepared_packet_buf = std::move(unsent_packets);

		param.counters[worker_id].sent_pkts += num_sent;

		RX(ctx, param.rxtx_if, worker_id, param, out_logger);
	}

	return 0;
}
