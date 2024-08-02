#include <benchmark/benchmark.h>
#include <iostream>
#include <string>
#include <string.h>
#include <vector>
#include <fstream>
#include <fcntl.h>
#include <sys/mman.h>
#include <chrono>
#include "input_reader.h"

#define NUM_DOMAINS_TO_GENERATE 2000000
#define NAME "/reader_benchmark"

class MyFixture : public benchmark::Fixture {
public:
    char* buf;
    FILE* buf_fptr;
    int fd;
    size_t buffer_size;
    size_t num_chars_per_domain;

    void SetUp(const ::benchmark::State& state) {
        num_chars_per_domain = state.range(0);
        buffer_size = NUM_DOMAINS_TO_GENERATE * (num_chars_per_domain + 1);

        shm_unlink(NAME);

        fd = shm_open(NAME, O_CREAT | O_EXCL | O_RDWR, 0600);
        if(fd < 0)
            throw std::runtime_error("Cannot create fd using shm");

        if(ftruncate64(fd, buffer_size) < 0)
            throw std::runtime_error("Cannot truncate fd");

        buf = (char*)mmap(0, buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if(buf == NULL)
            throw std::runtime_error("mmap failed");

        for(char* curr_write_ptr = buf; curr_write_ptr < buf + buffer_size; curr_write_ptr += (num_chars_per_domain + 1))
        {
            memset(curr_write_ptr, 'a', num_chars_per_domain);
            memset(curr_write_ptr + num_chars_per_domain, '\n', 1);
        }

        buf_fptr = fdopen(fd, "r");
        if(buf_fptr == NULL)
            throw std::runtime_error("Cannot open file created using shm");
    }

    void TearDown(const ::benchmark::State& state) {
        munmap(buf, buffer_size);
        close(fd);
        fclose(buf_fptr);
        shm_unlink(NAME);
    }
};

BENCHMARK_DEFINE_F(MyFixture, BM_StringCreation)(benchmark::State& state) {
    for(auto _ : state)
    {
        InputReader reader(MyFixture::buf_fptr);

        DomainInputInfo domain_info;
        char buf[DOMAIN_NAME_MAX_SIZE];
        domain_info.buf = buf;

        int valid_cnt = 0;

        auto start = std::chrono::high_resolution_clock::now();

        // Loop over every domain found with ReadTestDomainsFromFile
        // and check if input reader yields the same result

        // Input reader works asynchronously, wait for result to be available
        ReadDomainResult res = ReadDomainResult::NotAvailable;
        while(res != ReadDomainResult::FileEnd)
        {
            res = reader.GetDomain(domain_info);

            // Keep track of the number of valid domains to prevent optimalisation
            valid_cnt += (res == ReadDomainResult::Success);
        }

        // Ensure no optimization
        benchmark::DoNotOptimize(valid_cnt);

        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed_seconds =
        std::chrono::duration_cast<std::chrono::duration<double>>(
            end - start);

        state.SetIterationTime(elapsed_seconds.count());

        double domains_per_second = (double)NUM_DOMAINS_TO_GENERATE / elapsed_seconds.count();
        double gbytes_per_second = (double)buffer_size / (elapsed_seconds.count() * 1e9);

        state.counters.insert({{"Domains/s", domains_per_second},
                                {"GBytes/s", gbytes_per_second},
                                {"Domain size", num_chars_per_domain}});
    }
}

BENCHMARK_REGISTER_F(MyFixture, BM_StringCreation)->RangeMultiplier(2)->
                                                    Args( { 1 } )->
                                                    Args( { 5 } )->
                                                    Args( { 10 } )->
                                                    Args( { 20 } )->
                                                    Args( { 50 } )->
                                                    Args( { 100 } )->
                                                    Args( { 150 } )->
                                                    Args( { 200 } )->
                                                    UseManualTime();

BENCHMARK_MAIN();