#pragma once

#include "eth_rxtx.h"

// Skip documentation of all configurations

/// \cond DO_NOT_DOCUMENT
struct I40E_OPTS {
	static constexpr bool offload_tx_mbuf_fast_free = true;

	static constexpr bool offload_tx_ipv4_cksum = true;
	static constexpr bool offload_tx_l4_cksum = true;

	static constexpr bool offload_rx_ipv4_cksum = true;
	static constexpr bool offload_rx_l4_cksum = false;

	static constexpr bool make_af_xdp_socket = false;
	static constexpr bool request_arp = true;
	static constexpr bool hw_flowsteering = true;

	static constexpr bool queue_for_main_thread = true;
};

struct AF_XDP_OPTS {
	static constexpr bool offload_tx_mbuf_fast_free = false;

	static constexpr bool offload_tx_ipv4_cksum = false;
	static constexpr bool offload_tx_l4_cksum = false;

	static constexpr bool offload_rx_ipv4_cksum = false;
	static constexpr bool offload_rx_l4_cksum = false;

	static constexpr bool make_af_xdp_socket = true;
	static constexpr bool request_arp = false;
	static constexpr bool hw_flowsteering = false;

	static constexpr bool queue_for_main_thread = false;
};

/// \endcond

#ifdef NIC_AF_XDP
	using NIC_OPTS = AF_XDP_OPTS;
	constexpr auto NIC_NAME = "AF_XDP";
#elif NIC_I40E
	using NIC_OPTS = I40E_OPTS;
	constexpr auto NIC_NAME = "I40E";
#endif

using NICType = EthRxTx<NIC_OPTS>;

// template class EthRxTx<AF_XDP_OPTS>;
// template class EthRxTx<I40E_OPTS>;
