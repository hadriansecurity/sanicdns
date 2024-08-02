#pragma once

#include <dpdk_wrappers.h>
#include <request.h>

#include <latch>
#include <stop_token>

#include "counters.h"
#include "dns_format.h"
#include "dns_packet.h"
#include "eth_rxtx.h"

struct WorkerParams {
	const uint16_t num_workers;
	const uint32_t num_containers;
	const uint32_t rate_lim_pps;
	const uint32_t timeout_ms;
	const uint32_t max_retries;

	std::vector<PerCoreCounters, RteAllocator<PerCoreCounters>> &counters;
	const std::vector<InAddr> &resolvers;
	const std::optional<std::vector<DnsRCode>> &rcode_filters;

	std::latch &workers_finished;
	std::latch &domains_finished;
	RTERing<Request> &ring;
	NICType &rxtx_if;
	RTEMempool<DefaultPacket, MbufType::Raw> &raw_mempool;
	RTEMempool<DefaultPacket, MbufType::Pkt> &pkt_mempool;
	RTEMempool<Request> &request_mempool;
	bool output_raw;

	RTEMempool<DNSPacketDistr, MbufType::Raw> &dns_mempool;
	std::vector<RTERing<DNSPacketDistr>> &distribution_rings;
};

int Worker(std::stop_token stop_token, uint16_t worker_id, WorkerParams worker_params);
