#pragma once

#include <rte_ether.h>

#include <cstddef>
#include <string_view>

namespace {

constexpr size_t TX_PKT_BURST = 32;
constexpr size_t RX_PKT_BURST = 64;
constexpr size_t DNS_RING_SIZE = 256;

constexpr size_t DNS_MEMPOOL_SIZE = (1 << 16) - 1;
constexpr size_t RXTX_POOL_SIZE = (1 << 16) - 1;

constexpr size_t COUNTER_LOG_TIME_MS = 10'000;
constexpr size_t TERMINAL_TUI_TIME_MS = 200;
} // namespace
