#include <curses.h>
#include <expected_helpers.h>
#include <fcntl.h>
#include <ncurses.h>
#include <net/if.h>
#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_hexdump.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_ring_core.h>
#include <signal.h>
#include <spdlog/fmt/bundled/core.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <time.h>

#include <algorithm>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <glaze/glaze.hpp>
#include <iostream>
#include <optional>
#include <ratio>
#include <thread>
#include <tuple>

#include "ProgramOptions.hxx"
#include "arp.h"
#include "dns_format.h"
#include "dpdk_wrappers.h"
#include "eth_rxtx.h"
#include "eth_rxtx_opts.h"
#include "fixed_name.hpp"
#include "fmt_helpers.h"
#include "input_reader.h"
#include "net_info.h"
#include "network_types.h"
#include "parse_helpers.h"
#include "request.h"
#include "scanner_config.h"
#include "spdlog/fmt/bundled/core.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/spdlog.h"
#include "thread_manager.h"
#include "version.h"
#include "worker.h"

namespace {
std::atomic_bool sigint_received = false;

// Print "error:" in red
const char* error_str = "\033[1;31merror:\033[0m";
} // namespace

void SigintHandler([[maybe_unused]] int s) {
	// printf("Caught signal %d\n", s);
	sigint_received = true;
}

template <class opts>
Arp::Error RequestGatewayMac(Arp& arp, EthRxTx<opts>& rxtx,
    RTEMempool<DefaultPacket, MbufType::Pkt>& mpool, InAddr gateway_ip) {
	const auto send_func = [&](RTEMbufElement<DefaultPacket, MbufType::Pkt>&& pkt) {
		return rxtx.SendPacket(0, std::move(pkt)) == 1;
	};

	const auto recv_func = [&] { return rxtx.template RcvPackets<8>(0); };

	return arp.RequestAddr(gateway_ip.s_addr, mpool, send_func, recv_func);
}

struct UserConfig {
	bool headless;

	uint16_t cores;
	uint32_t rate;
	uint32_t num_concurrent;
	uint32_t timeout_ms;
	uint32_t num_retries;

	std::optional<InAddr> gateway_ip;
	std::optional<InAddr> static_ip;

	std::optional<EtherAddr> gateway_mac;

	std::optional<std::string> device_name;
	std::string input_file;
	std::string xdp_path;
	std::vector<InAddr> resolvers;
	std::optional<std::vector<DnsRCode>> rcode_filters;

	std::optional<DnsName> prefix;
	std::optional<DnsName> postfix;

	std::optional<std::string> log_path;
	std::string output_path;
	bool output_raw;
	bool no_huge;
	bool debug;
	bool skip_queue_count_check;

	DnsQType q_type;
};

std::optional<UserConfig> InitConfigFromArgs(int argc, char** argv) {
	po::parser parser;

	auto& help = parser["help"].abbreviation('h').description("print this help screen");

	auto& version = parser["version"].description("print the version and exit");

	auto& headless = parser["headless"].description("run in headless mode (no terminal UI)");

	auto& cores = parser["cores"]
	                  .abbreviation('w')
	                  .description("number of cores to use (default: 2)")
	                  .type(po::u32)
	                  .fallback(2);

	auto& rate = parser["rate"]
	                 .abbreviation('r')
	                 .description("scan rate in [packets per second] (default: 1000)")
	                 .type(po::u32)
	                 .fallback(1000);

	auto& num_concurrent =
	    parser["num-concurrent"]
		.abbreviation('c')
		.description("max number of concurrent DNS requests\n  (default: rate)")
		.type(po::u32)
		.fallback(200);

	auto& timeout_ms = parser["timeout"]
	                       .abbreviation('t')
	                       .description("timeout [ms] (default: 15'000)")
	                       .type(po::u32)
	                       .fallback(15'000);

	auto& num_retries = parser["num-retries"]
	                        .description("number of retries (default: 10)")
	                        .type(po::u32)
	                        .fallback(10);

	auto& gateway_ip = parser["gateway-ip"]
	                       .abbreviation('g')
	                       .description("IP address of gateway")
	                       .type(po::string);

	auto& static_ip = parser["static-ip"]
	                      .abbreviation('s')
	                      .description("own (static) IP address")
	                      .type(po::string);

	auto& gateway_mac = parser["gateway-mac"]
	                        .abbreviation('m')
	                        .description("gateway mac, ARP will be used if no MAC is specified")
	                        .type(po::string);

	auto& device_name = parser["device-name"]
	                        .abbreviation('d')
	                        .description("Device name (example: 0000:2e:00:0)")
	                        .type(po::string);

	auto& input_file = parser["input-file"]
	                       .abbreviation('i')
	                       .description("Path of input file with domains")
	                       .type(po::string);

#ifdef NIC_AF_XDP
	auto& xdp_path = parser["xdp-path"]
	                     .abbreviation('x')
	                     .description("Path to XDP program")
	                     .type(po::string)
	                     .fallback("/usr/local/bin/sanicdns_xdp.c.o");
#endif

	auto& resolvers =
	    parser["resolvers"]
		.description("Resolvers, either:\n   1. Comma-seperated "
			     "list of IP's\n   2. File with a resolver specified on each line")
		.type(po::string);

	auto& rcodes_filters = parser["rcodes"]
	                           .description("Only output results with these DNS return codes\n"
						"    Example: --rcodes NOERROR,SERVFAIL")
	                           .type(po::string);

	auto& prefix = parser["prefix"]
	                   .description("Prefix to add to each line of the input")
	                   .type(po::string);

	auto& postfix = parser["postfix"]
	                    .description("Postfix to add to each line of the input")
	                    .type(po::string);

	auto& log_path =
	    parser["log-path"]
		.abbreviation('l')
		.description("Log file path, logging will be enabled when a log path is set")
		.type(po::string);

	auto& output_path = parser["output-path"]
	                        .abbreviation('o')
	                        .description("output path (default: output.txt)")
	                        .type(po::string)
	                        .fallback("output.txt");

	auto& output_raw = parser["output-raw"].description(
	    "output raw DNS packets in hex (from DNS header to end of packet)");

	auto& no_huge = parser["no-huge"].description("Don't use huge pages");

	auto& debug = parser["debug"].description("Print debug information");

	auto& skip_queue_count_check = parser["skip-queue-count-check"].description(
	    "Skip check if worker count is equal to the number of workers");

	auto& q_type = parser["q-type"]
	                   .abbreviation('q')
	                   .description("Question type\n (A, NS, CNAME, DNAME, SOA, "
					"PTR, MX, TXT, AAAA, CAA, OPT)")
	                   .type(po::string)
	                   .fallback("A");

	if (!parser(argc, argv))
		return std::nullopt;

	if (help.was_set()) {
		std::cout << parser << "\n";
		return std::nullopt;
	}

	if (version.was_set()) {
		std::cout << fmt::format("sanicdns {}, built for NIC type: {}", SANICDNS_VERSION,
				 NIC_NAME)
			  << std::endl;
		return std::nullopt;
	}

	UserConfig config{};

	config.headless = headless.was_set();

	const uint32_t hw_concurrency = std::thread::hardware_concurrency();
	config.cores = cores.get().u32;
	if (config.cores < 2 || config.cores > hw_concurrency) {
		fmt::print("{} minimum number of cores is 2, max is {}\n", error_str,
		    hw_concurrency);
		return std::nullopt;
	}

	config.rate = rate.get().u32;
	if (config.rate < 100) {
		fmt::print("{} minimum rate limit is 100[pps]", error_str);
		return std::nullopt;
	}

	config.num_concurrent = num_concurrent.get().u32;
	if (!num_concurrent.was_set())
		config.num_concurrent = config.rate / 2;

	config.timeout_ms = timeout_ms.get().u32;
	config.num_retries = num_retries.get().u32;

	// Parse gateway IP
	if (gateway_ip.was_set()) {
		std::optional res = InAddr::init(gateway_ip.get().string);
		if (!res) {
			fmt::print("{} cannot parse IP {}\n", error_str, gateway_ip.get().string);
			return std::nullopt;
		}
		config.gateway_ip = res;
	}

	if (static_ip.was_set()) {
		std::optional res = InAddr::init(static_ip.get().string);
		if (!res) {
			fmt::print("{} cannot parse IP {}\n", error_str, static_ip.get().string);
			return std::nullopt;
		}
		config.static_ip = res;
	}

	if (gateway_mac.was_set()) {
		auto res = EtherAddr::init(gateway_mac.get().string);
		if (!res) {
			fmt::print("{} cannot parse MAC {}\n", error_str, gateway_mac.get().string);
			return std::nullopt;
		}
		config.gateway_mac = res;
	}

	if (device_name.was_set()) {
		config.device_name = device_name.get().string;
	}

	if (!input_file.was_set()) {
		fmt::print("{} provide an input file\n", error_str);
		return std::nullopt;
	}
	config.input_file = input_file.get().string;

#ifdef NIC_AF_XDP
	config.xdp_path = xdp_path.get().string;
#endif

	if (!resolvers.was_set()) {
		fmt::print("{} provide resolvers\n", error_str);
		return std::nullopt;
	}
	config.resolvers = ({
		tl::expected res = ParseResolvers(resolvers.get().string);
		if (!res) {
			fmt::print("{} parsing resolvers: {}\n", error_str, res.error());
			return std::nullopt;
		}
		std::move(*res);
	});

	if (rcodes_filters.was_set()) {
		config.rcode_filters = ({
			tl::expected res = ParseDNSReturnCodes(rcodes_filters.get().string);
			if (!res) {
				fmt::print("{} parsing DNS return codes: {}\n", error_str,
				    res.error());
				return std::nullopt;
			}
			std::move(*res);
		});
	}

	config.prefix = std::nullopt;
	if (prefix.was_set()) {
		auto tmp = DnsName::init(prefix.get().string);
		if (!tmp) {
			fmt::print("{} prefix too long\n", error_str);
			return std::nullopt;
		}
		config.prefix = tmp.value();
	}

	config.postfix = std::nullopt;
	if (postfix.was_set()) {
		auto tmp = DnsName::init(postfix.get().string);
		if (!tmp) {
			fmt::print("{} postfix too long\n", error_str);
			return std::nullopt;
		}
		config.postfix = tmp.value();
	}

	config.log_path = std::nullopt;
	if (log_path.was_set())
		config.log_path = log_path.get().string;

	config.output_path = output_path.get().string;
	config.output_raw = output_raw.was_set();
	config.no_huge = no_huge.was_set();
	config.debug = debug.was_set();
	config.skip_queue_count_check = skip_queue_count_check.was_set();

	config.q_type = ({
		std::optional res = GetQTypeFromString(q_type.get().string);
		if (!res) {
			fmt::print("{} invalid question type {}, choose from A, NS, CNAME, "
				   "DNAME, SOA, PTR, MX, TXT, AAAA, CAA, OPT\n",
			    error_str, q_type.get().string);
			return std::nullopt;
		}
		std::move(*res);
	});

	return config;
}

struct EthernetConfig {
	std::string device_name;

	// If nullopt, destination MAC has to be retrieved through ARP
	std::optional<EtherAddr> dst_mac;

	InAddr src_ip;
	InAddr dst_ip;
};

std::optional<EthernetConfig> GetEthernetConfig(const UserConfig& user_config) {
	std::optional<net_info::RouteInfo> route_info;

	EthernetConfig to_ret{};

	// Fetch the kernel network routes when AF_XDP is enabled and initialize the device name
	if (NIC_OPTS::make_af_xdp_socket) {
		std::optional<FixedName<IFNAMSIZ>> dev_name_linux{};
		if (user_config.device_name.has_value()) {
			dev_name_linux = FixedName<IFNAMSIZ>::init(user_config.device_name.value());
		}

		route_info = ({
			tl::expected res = net_info::get_route_info(dev_name_linux);
			if (!res) {
				fmt::print("{} get_route_info: {}\n", error_str, res.error());
				return std::nullopt;
			}
			std::move(*res);
		});

		spdlog::info("Got route info: {}", glz::write_json(route_info.value()));
		to_ret.device_name = std::string_view(route_info->if_name);
	} else if (user_config.device_name.has_value()) {
		to_ret.device_name = user_config.device_name.value();
	} else {
		fmt::print("{} Enter device name\n", error_str);
		return std::nullopt;
	}

	if (user_config.static_ip) {
		to_ret.src_ip = user_config.static_ip.value();
	} else if (route_info.has_value() && route_info->source_addr.has_value()) {
		to_ret.src_ip = route_info->source_addr.value();
	} else {
		fmt::print("{}: Enter static IP manually\n", error_str);
		return std::nullopt;
	}

	if (user_config.gateway_ip) {
		to_ret.dst_ip = user_config.gateway_ip.value();
	} else if (route_info.has_value() && route_info->gateway_addr.has_value()) {
		to_ret.dst_ip = route_info->gateway_addr.value();
	} else {
		fmt::print("{}: Enter gateway IP manually\n", error_str);
		return std::nullopt;
	}

	std::optional<EtherAddr> mac_addr_os_arp_table{};
	if constexpr (NIC_OPTS::make_af_xdp_socket) {
		auto dev_name = UNWRAP_OR_RETURN_VAL_AND_LOG(
		    FixedName<IFNAMSIZ>::init(to_ret.device_name), std::nullopt);
		auto res = net_info::get_mac_address(dev_name, to_ret.dst_ip);
		if (!res)
			spdlog::warn("Cannot get MAC of {}: {}\n", to_ret.dst_ip.str(),
			    res.error());

		if (res)
			mac_addr_os_arp_table = res.value();
	}

	if (user_config.gateway_mac) {
		to_ret.dst_mac = user_config.gateway_mac.value();
	} else if (NIC_OPTS::request_arp) {
		to_ret.dst_mac = std::nullopt; // Request ARP when network is configured
	} else if (mac_addr_os_arp_table) {
		to_ret.dst_mac = mac_addr_os_arp_table;
	} else {
		fmt::print("{}: Enter gateway MAC manually\n", error_str);
		return std::nullopt;
	}

	return to_ret;
}

tl::expected<void, std::string> VerifyQueues(FixedName<IFNAMSIZ> dev_name, const uint16_t num_cores,
    const uint16_t total_queues) {
	auto channel_count = net_info::get_channel_count(dev_name);
	if (!channel_count.has_value()) {
		return tl::unexpected(
		    fmt::format("{}, channel_count error: {}\n An invalid argument or inappropriate ioctl "
			    "for device error can indicate "
			    "insufficient multiqueue support. In this case you can opt to disable the queue check "
			    "using --skip-queue-count-check.",
			    error_str, channel_count.error()));
	}

	uint32_t combined_channels = channel_count.value().combined_count;

	// Seems to be the DPDK logic
	if (combined_channels == 0)
		combined_channels = 1;

	if (total_queues != combined_channels) {
		return tl::unexpected(fmt::format(
		    "{} Running sanicdns with '-w {}' requires {} queues (current {}). "
		    "Configure using 'sudo ethtool -L {} combined {}'\n",
		    error_str, num_cores, total_queues, combined_channels, dev_name, total_queues));
	}

	return {};
}

rte_malloc_socket_stats GetMemoryUsage() {
	rte_malloc_socket_stats sock_stats{};

	for (int socket_id = 0; socket_id < RTE_MAX_NUMA_NODES; socket_id++) {
		rte_malloc_socket_stats sock_stats_node;
		int ret = rte_malloc_get_socket_stats(socket_id, &sock_stats_node);
		if (ret == 0) {
			sock_stats.heap_allocsz_bytes += sock_stats_node.heap_allocsz_bytes;
			sock_stats.heap_freesz_bytes += sock_stats_node.heap_freesz_bytes;
		}
	}

	return sock_stats;
}

std::string FormatCounters(const PerCoreCounters& total_count,
    const PerCoreCounters& total_count_per_s, const bool debug) {
	using namespace fmt_helpers;

	std::string out;
	out += fmt::format("Resolved:\t{}domains\t- {}domains/second\n",
	    fmt_count(total_count.num_resolved), fmt_count(total_count_per_s.num_resolved));
	out += fmt::format("Retry:\t{}pkts\t- {}pps\n", fmt_count(total_count.retry),
	    fmt_count(total_count_per_s.retry));
	out += fmt::format("Max retry:\t{}pkts\t- {}pps\n", fmt_count(total_count.max_retry),
	    fmt_count(total_count_per_s.max_retry));
	out += "-----------------------------------\n";
	out += fmt::format("Input lines rejected:\t{}lines\t- {}lines/second\n",
	    fmt_count(total_count.lines_rejected), fmt_count(total_count_per_s.max_retry));
	out += "-----------------------------------\n";
	out += fmt::format("TX:\t{}pkts\t- {}pps\n", fmt_count(total_count.sent_pkts),
	    fmt_count(total_count_per_s.sent_pkts));
	out += fmt::format("RX:\t{}pkts\t- {}pps\n", fmt_count(total_count.rcvd_pkts),
	    fmt_count(total_count_per_s.rcvd_pkts));
	out += "-----------------------------------\n";
	out += fmt::format("Parse fail:\t{}pkts\t- {}pps\n", fmt_count(total_count.parse_fail),
	    fmt_count(total_count_per_s.parse_fail));
	out += fmt::format("Parse success:\t{}pkts\t- {}pps\n",
	    fmt_count(total_count.parse_success), fmt_count(total_count_per_s.parse_success));
	out += "-----------------------------------\n";
	out += "DNS error codes:\n";
	out += fmt::format("NOERROR:\t{}pkts\t- {}pps\n", fmt_count(total_count.noerror),
	    fmt_count(total_count_per_s.noerror));
	out += fmt::format("NXDOMAIN:\t{}pkts\t- {}pps\n", fmt_count(total_count.nxdomain),
	    fmt_count(total_count_per_s.nxdomain));
	out += fmt::format("SERVFAIL:\t{}pkts\t- {}pps\n", fmt_count(total_count.servfail),
	    fmt_count(total_count_per_s.servfail));
	out += fmt::format("Other:\t{}pkts\t- {}pps\n", fmt_count(total_count.rcode_other),
	    fmt_count(total_count_per_s.rcode_other));

	if (!debug)
		return out;
	out += "-----------------------------------\n";

	auto usage = GetMemoryUsage();
	out += fmt::format("Memory usage: {}B\n", fmt_count(usage.heap_allocsz_bytes));
	out += fmt::format("Memory free: {}B\n", fmt_count(usage.heap_freesz_bytes));

	return out;
}

static std::vector<std::string> init_eal_args(const UserConfig& user_config,
    const EthernetConfig& ethernet_config) {
	std::vector<std::string> args;

	if (user_config.no_huge)
		args.emplace_back("--no-huge");

	// Cores is always larger than 2, subtract 1 for main thread
	const int num_workers = user_config.cores - 1;
	const int total_queues = num_workers + (NIC_OPTS::queue_for_main_thread ? 1 : 0);

	spdlog::info("total_queues: {}", total_queues);
	if constexpr (NIC_OPTS::make_af_xdp_socket)
		args.emplace_back(
		    fmt::format("--vdev=net_af_xdp,iface={},xdp_prog={},queue_count={}",
			ethernet_config.device_name, user_config.xdp_path, total_queues));

	return args;
}

int main(int argc, char** argv) {
	auto user_config = UNWRAP_OR_RETURN_VAL(InitConfigFromArgs(argc, argv), -1);

	// Init loggers
	std::vector<spdlog::sink_ptr> sinks{};
	if (user_config.headless) {
		sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
	}
	if (user_config.log_path) {
		sinks.push_back(std::make_shared<spdlog::sinks::basic_file_sink_mt>(
		    user_config.log_path.value(), true));
	}

	auto logger = std::make_shared<spdlog::logger>("", begin(sinks), end(sinks));
	logger->set_level(spdlog::level::debug);
	spdlog::set_default_logger(logger);

	auto output_logger = spdlog::basic_logger_mt("output_log", user_config.output_path, true);
	output_logger->set_pattern("%v");

	auto ethernet_config = UNWRAP_OR_RETURN_VAL(GetEthernetConfig(user_config), -1);

	spdlog::info("User config: {}", glz::write_json(user_config));
	spdlog::info("Ethernet config: {}", glz::write_json(ethernet_config));

	// Cores is always larger than 2, subtract 1 for main thread
	const uint16_t num_workers = user_config.cores - 1;
	const uint16_t total_queues = num_workers + (NIC_OPTS::queue_for_main_thread ? 1 : 0);

	if (NIC_OPTS::make_af_xdp_socket && (!user_config.skip_queue_count_check)) {
		auto dev_name = UNWRAP_OR_RETURN_VAL(
		    FixedName<IFNAMSIZ>::init(ethernet_config.device_name), -1);
		auto res = VerifyQueues(dev_name, user_config.cores, total_queues);
		if (!res) {
			fmt::print("{} {}", error_str, res.error());
			return -1;
		}
	} else if (user_config.skip_queue_count_check) {
		spdlog::warn("Queue count check is disabled! This means sanicdns NOT verify if the amount of queues match the amount of workers. "
				"In case you have more queues than workers, please use RSS to make sure redudant queues are unused like so:\n"
				"sudo ethtool -X [interface] equal [num workers]. Not doing this WILL result in SEVERELY degraded performance!");
		rte_delay_ms(2000);
	}

	auto dpdk_args = init_eal_args(user_config, ethernet_config);

	if (NIC_OPTS::make_af_xdp_socket && !std::filesystem::exists(user_config.xdp_path)) {
		fmt::print("{} Cannot find XDP path {}\n", error_str, user_config.xdp_path);
		return -1;
	}

	std::vector<char*> dpdk_args_argv;
	dpdk_args_argv.push_back(argv[0]);
	for (auto& arg : dpdk_args)
		dpdk_args_argv.push_back(arg.data());

	auto eal_guard_ = ({
		tl::expected res = EALGuard::init(dpdk_args_argv.size(), dpdk_args_argv.data());
		if (!res) {
			fmt::print("{} Failed to initialize EAL\n", error_str);
			return -1;
		}
		std::move(*res);
	});

	ThreadManager thread_manager;

	signal(SIGINT, SigintHandler);

	std::unique_ptr<FILE, int (*)(FILE*)> fptr(fopen(user_config.input_file.data(), "rt"),
	    [](FILE* fp) -> int {
		    if (fp)
			    return ::fclose(fp);
		    return EOF;
	    });

	if (fptr.get() == NULL) {
		fmt::print("{} File {} cannot be opened\n", error_str, user_config.input_file);
		return -1;
	}

	InputReader input_reader(fptr.get());

	/****************************************
	***** Init Mempools, Ring and Rxtx *****
	****************************************/
	auto rxtx_pool = ({
		tl::expected res = RTEMempool<DefaultPacket, MbufType::Pkt>::init("RXTX_POOL",
		    RXTX_POOL_SIZE, 512, 0);
		if (!res) {
			fmt::print("{} Failed to initialize rxtx_pool: {}\n", error_str,
			    rte_strerror(res.error()));
			return -1;
		}
		std::move(*res);
	});

	EthDevConf eth_config{};

	eth_config.nb_rx_descrs = 512;
	eth_config.nb_tx_descrs = 512;

	eth_config.nb_tx_queues = total_queues;
	eth_config.nb_rx_queues = total_queues;

	const auto nic_id =
	    NIC_OPTS::make_af_xdp_socket ? "net_af_xdp" : ethernet_config.device_name;

	auto rxtx_if = ({
		tl::expected res = NICType::init(eth_config, nic_id, rxtx_pool.get());
		if (!res) {
			fmt::print("{} Failed to initialize NIC: {}\n", error_str, res.error());
			return -1;
		}
		std::move(*res);
	});

	// Wait a bit for AF_XDP socket to initialise
	if constexpr (NIC_OPTS::make_af_xdp_socket)
		rte_delay_ms(4000);

	const uint32_t request_mempool_size = std::max(user_config.num_concurrent, 1023u);

	auto request_mempool = ({
		tl::expected res =
		    RTEMempool<Request>::init("request_mempool", request_mempool_size, 512, 0, 0);
		if (!res) {
			fmt::print("{} Failed to initialize request mempool: {}\n", error_str,
			    rte_strerror(res.error()));
			return -1;
		}
		std::move(*res);
	});

	auto dispatch_ring = ({
		tl::expected res = RTERing<Request>::init("request_dispatch_ring", request_mempool,
		    std::bit_ceil(10 * num_workers * TX_PKT_BURST),
		    RING_F_SP_ENQ | RING_F_MC_HTS_DEQ);
		if (!res) {
			fmt::print("{} Failed to initialize dispatch ring: {}\n", error_str,
			    rte_strerror(res.error()));
			return -1;
		}
		std::move(*res);
	});

	auto dns_mempool = ({
		tl::expected res =
		    RTEMempool<DefaultPacket>::init("dns_mempool", DNS_MEMPOOL_SIZE, 512, 0, 0);
		if (!res) {
			fmt::print("{} Failed to initialize dns mempool: {}\n", error_str,
			    rte_strerror(res.error()));
			return -1;
		}
		std::move(*res);
	});

	auto parsed_mempool = ({
		tl::expected res = RTEMempool<DNSPacketDistr>::init("parsed_dns_mempool",
		    DNS_MEMPOOL_SIZE, 512, 0, 0);
		if (!res) {
			fmt::print("{} Failed to initialize parsed mempool: {}\n", error_str,
			    rte_strerror(res.error()));
			return -1;
		}
		std::move(*res);
	});

	std::vector<RTERing<DNSPacketDistr>> distribution_rings;
	distribution_rings.reserve(num_workers);
	for (uint16_t i = 0; i < num_workers; i++) {
		auto dns_ring = UNWRAP_OR_RETURN_RAW((RTERing<DNSPacketDistr>::init(
		    fmt::format("distribution_ring_{}", i), parsed_mempool, DNS_RING_SIZE, 0)));
		distribution_rings.push_back(std::move(dns_ring));
	}

	if constexpr (NIC_OPTS::hw_flowsteering) {
		for (uint16_t i = 0; i < num_workers; i++) {
			auto res =
			    rxtx_if.GenerateDNSFlow(i + 1, 0, 0, 0, 0, (i + 1) << 10, 0xFC00);
			if (!res) {
				fmt::print("{} Failed to generate DNS flow for {}: {}\n", error_str,
				    i, res.error());
				return -1;
			}
		}
	}

	Arp arp(ethernet_config.src_ip.s_addr, rxtx_if.GetMacAddr());

	if (!ethernet_config.dst_mac) {
		spdlog::info("Requesting gateway MAC through ARP");
		if (auto e = RequestGatewayMac(arp, rxtx_if, rxtx_pool, ethernet_config.dst_ip);
		    e != Arp::Error::ARP_OK) {
			fmt::print("{} Failed to request gateway MAC: {}\n", error_str,
			    Arp::ErrorToString(e));
			return -1;
		}
	} else {
		arp.InsertAddr(ethernet_config.dst_ip.s_addr, ethernet_config.dst_mac.value());
	}

	auto _dst_mac = arp.GetEtherAddr(ethernet_config.dst_ip.s_addr);
	if (!_dst_mac) {
		fmt::print("{} could not find gateway MAC\n", error_str);
		return -1;
	}
	auto dst_mac = std::move(*_dst_mac);

	spdlog::info("Gateway mac: {:x}",
	    fmt::join(dst_mac.addr_bytes, dst_mac.addr_bytes + RTE_ETHER_ADDR_LEN, ", "));

	auto start = std::chrono::steady_clock::now();

	/*************************
	***** Start workers *****
	*************************/
	std::latch workers_finished(num_workers);
	std::latch domains_finished(1);

	// Reserve a PerCoreCounter for the main thread as well
	std::vector<PerCoreCounters, RteAllocator<PerCoreCounters>> counters(num_workers + 1);
	PerCoreCounters& main_core_counters = counters[num_workers];

	WorkerParams shared_worker_params = {
	    .num_workers = num_workers,
	    .num_containers = (100 + (user_config.num_concurrent / num_workers)),
	    .rate_lim_pps = user_config.rate / num_workers,
	    .timeout_ms = user_config.timeout_ms,
	    .max_retries = user_config.num_retries,
	    .counters = counters,
	    .resolvers = user_config.resolvers,
	    .rcode_filters = user_config.rcode_filters,
	    .workers_finished = workers_finished,
	    .domains_finished = domains_finished,
	    .ring = dispatch_ring,
	    .rxtx_if = rxtx_if,
	    .raw_mempool = dns_mempool,
	    .pkt_mempool = rxtx_pool,
	    .request_mempool = request_mempool,
	    .output_raw = user_config.output_raw,
	    .dns_mempool = parsed_mempool,
	    .distribution_rings = distribution_rings,
	};

	for (uint16_t i = 0; i < num_workers; i++) {
		auto res = thread_manager.LaunchThread(Worker, i, shared_worker_params);
		if (res != ThreadManager::LaunchThreadResult::Success) {
			fmt::print("{} Launching thread {} failed\n", error_str, i);
			return -1;
		}
	}

	// EthDevConf eth_config2{};

	// eth_config2.nb_rx_descrs = 4096;
	// eth_config2.nb_tx_descrs = 4096;

	// eth_config2.nb_tx_queues = 1;
	// eth_config2.nb_rx_queues = 1;

	// auto rxtx_if2 = ({
	// 	tl::expected res =
	// 	    EthRxTx<I40E_OPTS>::init(eth_config2, "0000:2e:00.0", rxtx_pool.get());
	// 	if (!res) {
	// 		fmt::print("{} Failed to initialize NIC: {}", error_str, res.error());
	// 		return -1;
	// 	}
	// 	std::move(*res);
	// });

	// std::ignore = thread_manager.LaunchThread(
	//     [](std::stop_token stp, EthRxTx<I40E_OPTS>& rxtx_if2,
	// 	RTEMempool<DefaultPacket, MbufType::Pkt>& rxtx_pool) {
	// 	    uint64_t total_packets{};
	// 	    while (!stp.stop_requested()) {
	// 		    auto recvd = rxtx_if2.RcvPackets<RX_PKT_BURST>(0);
	//             if(recvd.size())
	//                 spdlog::info("{}", recvd.size());

	// 		    for (auto& pkt : recvd) {
	// 			    auto eth_hdr = &pkt.data<struct rte_ether_hdr>();
	// 			    rte_ipv4_hdr* ipv4_hdr = (rte_ipv4_hdr*) (eth_hdr + 1);
	// 			    rte_udp_hdr* udp_hdr = (rte_udp_hdr*) (ipv4_hdr + 1);
	// 			    DnsHeader* dns_hdr = (DnsHeader*) (udp_hdr + 1);

	// 			    std::swap(eth_hdr->src_addr, eth_hdr->dst_addr);
	// 			    auto src_ip_old = ipv4_hdr->src_addr;
	// 			    ipv4_hdr->src_addr = ipv4_hdr->dst_addr;
	// 			    ipv4_hdr->dst_addr = src_ip_old;

	// 			    auto src_port_old = udp_hdr->src_port;
	// 			    udp_hdr->src_port = udp_hdr->dst_port;
	// 			    udp_hdr->dst_port = src_port_old;

	// 			    dns_hdr->qr = 1;
	// 			    dns_hdr->rcode = (unsigned char) DnsRCode::NXDOMAIN;

	// 			    pkt.l2_len = sizeof(rte_ether_hdr);
	// 			    pkt.l3_len = sizeof(rte_ipv4_hdr);
	// 			    pkt.l4_len = sizeof(rte_udp_hdr);

	// 			    pkt.nb_segs = 1;

	// 			    rxtx_if2
	// 				.PreparePktCksums<DefaultPacket, L3Type::Ipv4, L4Type::UDP>(
	// 				    pkt);
	// 			    total_packets++;

	//                 spdlog::info("a");
	// 		    }

	// 		    rxtx_if2.PreparePackets(0, recvd);
	// 		    rxtx_if2.SendPackets(0, std::move(recvd));
	// 	    }

	// 	    spdlog::info("Pkts: {}", total_packets);
	// 	    return 0;
	//     },
	//     std::ref(rxtx_if2), std::ref(rxtx_pool));

	/***************************************************
	***** Main loop dispatches domains to workers *****
	***************************************************/
	RTEMbufArray<Request, TX_PKT_BURST> filled_request_buffer =
	    RTEMbufArray<Request, TX_PKT_BURST>::init(request_mempool, 0).value();

	std::chrono::time_point<std::chrono::steady_clock> next_log_time =
	    std::chrono::steady_clock::now();

	std::chrono::time_point<std::chrono::steady_clock> next_tui_time =
	    std::chrono::steady_clock::now();
	PerCoreCounters last_total_count{};

	if (!user_config.headless)
		initscr();

	while (!workers_finished.try_wait()) {
		if (sigint_received.load(std::memory_order_relaxed)) {
			// Request all threads to stop
			thread_manager.request_stop();
			break;
		}

		[&] {
			// Get some new requests to fill
			auto new_mbufs = ({
				tl::expected res = RTEMbufArray<Request, TX_PKT_BURST>::init(
				    request_mempool, TX_PKT_BURST);
				if (!res) {
					return;
				}
				std::move(*res);
			});

			size_t max_iters =
			    std::min(filled_request_buffer.free_cnt(), new_mbufs.size());
			size_t i = 0;
			for (i = 0; i < max_iters; i++) {
				Request& request = new_mbufs.get_data(i);
				ReadDomainResult res;
				do {
					DomainInputInfo domain_info;
					domain_info.buf = request.name.buf.data();

					res = ReadDomainResult::Success;
					res = input_reader.GetDomain(domain_info);

					if (res == ReadDomainResult::FileEnd) {
						if (!domains_finished.try_wait())
							domains_finished.count_down();
						break;
					}

					request.name.len = domain_info.len;

					if (user_config.prefix) {
						request.name = ({
							std::optional tmp =
							    user_config.prefix.value() +
							    static_cast<std::string_view>(
								request.name);
							if (!tmp) {
								res = ReadDomainResult::NotValid;
								continue;
							}
							std::move(*tmp);
						});
					}

					if (user_config.postfix) {
						request.name = ({
							std::optional tmp =
							    request.name +
							    static_cast<std::string_view>(
								user_config.postfix.value());
							if (!tmp) {
								res = ReadDomainResult::NotValid;
								continue;
							}
							std::move(*tmp);
						});
					}

					// Keep track of the number invalid lines
					if (res == ReadDomainResult::NotValid)
						main_core_counters.lines_rejected++;

					if (request.name.buf[request.name.len - 1] != '.') {
						request.name.buf[request.name.len] = '.';
						request.name.buf[++request.name.len] = '\0';
					}

					request.src_ip = ethernet_config.src_ip;
					request.num_ips = REQUEST_MAX_IPS;
					request.dst_mac = dst_mac;

					request.q_type = user_config.q_type;

				} while (res == ReadDomainResult::NotValid);

				if (res != ReadDomainResult::Success)
					break;
			}

			auto [filled, _] = new_mbufs.split(i);
			std::ignore = filled_request_buffer.insert(std::move(filled));
		}();

		auto not_enqueued_requests =
		    dispatch_ring.enqueue_burst(std::move(filled_request_buffer));
		filled_request_buffer = std::move(not_enqueued_requests);

		std::chrono::time_point<std::chrono::steady_clock> current_time =
		    std::chrono::steady_clock::now();

		if (current_time > next_log_time) {
			next_log_time =
			    current_time + std::chrono::milliseconds(COUNTER_LOG_TIME_MS);

			PerCoreCounters total_count;
			for (auto& core_counter : counters)
				total_count += core_counter;

			std::string str = glz::write_json(total_count);
			spdlog::info(str);
		}

		if (current_time > next_tui_time && !user_config.headless) {
			clear();

			PerCoreCounters total_count;
			for (auto& core_counter : counters)
				total_count += core_counter;

			constexpr auto tui_delay = std::chrono::milliseconds(TERMINAL_TUI_TIME_MS);

			const double time_since_last_tui_update =
			    std::chrono::duration<double>(current_time - next_tui_time + tui_delay)
				.count();

			PerCoreCounters total_count_per_s =
			    (total_count - last_total_count) / time_since_last_tui_update;

			std::string counters_formatted =
			    FormatCounters(total_count, total_count_per_s, user_config.debug);

			printw("%s", counters_formatted.c_str());
			refresh();

			next_tui_time = current_time + tui_delay;
			last_total_count = total_count;
		}
	}

	if (!user_config.headless) {
		// End window and print last counter values to stdout
		endwin();

		PerCoreCounters total_count;
		for (auto& core_counter : counters)
			total_count += core_counter;

		std::string counters_formatted =
		    FormatCounters(total_count, PerCoreCounters{}, user_config.debug);
		std::cout << counters_formatted;
	}

	thread_manager.request_stop();

	// Join all threads
	thread_manager.join();

	auto stop = std::chrono::steady_clock::now();
	auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);

	// std::cout << "\nRxTx if stats:\n\n";

	rxtx_if.PrintStats();
	// rxtx_if2.PrintStats();

	std::cout << "\n\nRunning scanner took " << duration.count() << " ms\n";
}
