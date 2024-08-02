#include <benchmark/benchmark.h>
#include <iostream>
#include <string>
#include <string.h>
#include <vector>
#include <stdlib.h>
#include <chrono>
#include "dns_packet_parser.h"

#define NUM_DOMAINS_TO_GENERATE 200000
#define DOMAIN_NAME_MAX_SIZE 256
#define SEG_LEN_MIN 3
#define SEG_LEN_MAX 15

// Does not include jumps

class MyFixture : public benchmark::Fixture {
public:

    std::vector<std::string> test_domains;
    size_t num_segments_per_domain;
    size_t total_size_domains;

    void SetUp(const ::benchmark::State& state) {
        num_segments_per_domain = state.range(0);

        total_size_domains = 0;
        test_domains.resize(NUM_DOMAINS_TO_GENERATE);

        // Generate some pseudorandom domains
        srand(0);
        for(auto& test_domain : test_domains)
        {
            for(size_t segment = 0; segment < num_segments_per_domain; segment++)
            {
                size_t num_chars_per_segment = (rand() % (SEG_LEN_MAX - SEG_LEN_MIN)) + SEG_LEN_MIN;
                test_domain.push_back((char)num_chars_per_segment);
                for(size_t char_cnt = 0; char_cnt < num_chars_per_segment; char_cnt++)
                {
                    // Far from perfect random character initialisation but that's not an issue
                    char rand_char = (rand() % ('z' - 'a')) + 'a';
                    test_domain.push_back(rand_char);
                }
                total_size_domains += num_chars_per_segment + 1;
            }
        }
    }

    void TearDown(const ::benchmark::State& state) {
        test_domains = {};
    }
};

BENCHMARK_DEFINE_F(MyFixture, BM_DomainToDNSFormat)(benchmark::State& state) {
    for(auto _ : state)
    {
        auto start = std::chrono::high_resolution_clock::now();

        char out_buf[DOMAIN_NAME_MAX_SIZE];
        uint16_t len;
        uint16_t count;

        for(auto& test_domain : test_domains)
        {
            auto res = DNSParseHelpers::ReadFromDNSNameFormat(&test_domain.front(), &test_domain.back() + 2, &test_domain.front(), out_buf, len, count);
            if(res != DNSParseResult::Succes)
                throw std::runtime_error("Parse failure");
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed_seconds =
        std::chrono::duration_cast<std::chrono::duration<double>>(
            end - start);

        state.SetIterationTime(elapsed_seconds.count());

        double domains_per_second = (double)NUM_DOMAINS_TO_GENERATE / elapsed_seconds.count();
        double gbytes_per_second = (double)(total_size_domains) / (elapsed_seconds.count() * 1e9);

        state.counters.insert({{"Domains/s", domains_per_second},
                                {"GBytes/s", gbytes_per_second},
                                {"Nb segments", num_segments_per_domain}});
    }
}

BENCHMARK_REGISTER_F(MyFixture, BM_DomainToDNSFormat)->ArgsProduct({{1, 2, 3, 4, 5}})->UseManualTime();

BENCHMARK_MAIN();
