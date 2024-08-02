#include <benchmark/benchmark.h>
#include <iostream>
#include <string>
#include <string.h>
#include <vector>
#include <memory>
#include <stdlib.h>
#include <chrono>
#include "dns_packet_constructor.h"
#include <rte_eal.h>
#include <rte_ether.h>

#define NUM_PACKETS_TO_GENERATE 200000

struct Ipv4PacketParams
{
    rte_ether_addr src_mac;
    rte_ether_addr dst_mac;

    uint32_t src_ip_ipv4;
    uint32_t dst_ip_ipv4;

    in6_addr src_ip_ipv6;
    in6_addr dst_ip_ipv6;

    uint16_t src_port;

    uint16_t dns_id;
};

class MyFixture : public benchmark::Fixture {
public:
    std::vector<Ipv4PacketParams> params;
    //std::vector<rte_mbuf> mbufs;
    std::unique_ptr<rte_mbuf* []> mbufs;
    rte_mempool* mbuf_pool;

    void SetUp(const ::benchmark::State& state) {
        // Reset RNG
        srand(0);
        params.resize(NUM_PACKETS_TO_GENERATE);

        for(auto& packet_param : params)
        {
            for(int i = 0; i < RTE_ETHER_ADDR_LEN; i++){
                packet_param.src_mac.addr_bytes[i] = rand() % 0xFF;
                packet_param.dst_mac.addr_bytes[i] = rand() % 0xFF;
            }

            for(int i = 0; i < 4; i++)
            {
                packet_param.src_ip_ipv6.s6_addr32[i] = rand() % 0xFFFFFFFF;
                packet_param.dst_ip_ipv6.s6_addr32[i] = rand() % 0xFFFFFFFF;
            }

            packet_param.src_ip_ipv4 = rand() % 0xFFFFFFFF;
            packet_param.dst_ip_ipv4 = rand() % 0xFFFFFFFF;

            packet_param.src_port = rand() % 0xFFFF;
            
            packet_param.dns_id = rand() % 0xFFFF;
        }
        
        // Make Mempool to store packets
        mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_PACKETS_TO_GENERATE, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

        if(mbuf_pool == NULL)
            throw std::runtime_error("Couldn't allocate mempools");

        mbufs = std::make_unique<rte_mbuf* []>(NUM_PACKETS_TO_GENERATE);
        
        if(mbufs == NULL)
            throw std::runtime_error("Couldn't allocate vector for mbufs");

        if(rte_pktmbuf_alloc_bulk(mbuf_pool, mbufs.get(), NUM_PACKETS_TO_GENERATE))
            throw std::runtime_error("Couldn't allocate mbufs");
    }

    void TearDown(const ::benchmark::State& state) {
        rte_mempool_free(mbuf_pool);
    }
};

BENCHMARK_DEFINE_F(MyFixture, BM_ConstructIpv4Packet)(benchmark::State& state) {
    for(auto _ : state)
    {
        auto start = std::chrono::high_resolution_clock::now();
        size_t total_bytes = 0;

        for(size_t i = 0; i < NUM_PACKETS_TO_GENERATE; i++)
        {
            total_bytes += DNSPacketConstructor::ConstructIpv4DNSPacket(mbufs.get()[i], params[i].src_mac, params[i].dst_mac, params[i].src_ip_ipv4, params[i].dst_ip_ipv4,
                                                                        params[i].src_port, params[i].dns_id, "", 0, DnsQType::T_A);
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed_seconds =
        std::chrono::duration_cast<std::chrono::duration<double>>(
            end - start);

        state.SetIterationTime(elapsed_seconds.count());

        double packets_per_second = (double)NUM_PACKETS_TO_GENERATE / elapsed_seconds.count();
        double gbytes_per_second = (double)(total_bytes) / (elapsed_seconds.count() * 1e9);

        state.counters.insert({{"Pkts/s", packets_per_second},
                                {"GBytes/s", gbytes_per_second}});
    }
}

BENCHMARK_DEFINE_F(MyFixture, BM_ConstructIpv6Packet)(benchmark::State& state) {
    for(auto _ : state)
    {
        auto start = std::chrono::high_resolution_clock::now();
        size_t total_bytes = 0;

        for(size_t i = 0; i < NUM_PACKETS_TO_GENERATE; i++)
        {
            total_bytes += DNSPacketConstructor::ConstructIpv6DNSPacket(mbufs.get()[i], params[i].src_mac, params[i].dst_mac, params[i].src_ip_ipv6, params[i].dst_ip_ipv6,
                                                                        params[i].src_port, params[i].dns_id, "", 0, DnsQType::T_A);
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed_seconds =
        std::chrono::duration_cast<std::chrono::duration<double>>(
            end - start);

        state.SetIterationTime(elapsed_seconds.count());

        double packets_per_second = (double)NUM_PACKETS_TO_GENERATE / elapsed_seconds.count();
        double gbytes_per_second = (double)(total_bytes) / (elapsed_seconds.count() * 1e9);

        state.counters.insert({{"Pkts/s", packets_per_second},
                                {"GBytes/s", gbytes_per_second}});
    }
}

BENCHMARK_REGISTER_F(MyFixture, BM_ConstructIpv4Packet)->UseManualTime();
BENCHMARK_REGISTER_F(MyFixture, BM_ConstructIpv6Packet)->UseManualTime();

int main(int argc, char** argv) {                                     
    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv)) return 1;

    rte_eal_init(argc, argv);

    ::benchmark::RunSpecifiedBenchmarks();

    rte_eal_cleanup();

    ::benchmark::Shutdown();
    return 0;
  }