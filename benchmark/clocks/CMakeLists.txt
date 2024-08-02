add_executable(
    clocks_benchmark
    clocks_benchmark.cc
)

target_link_libraries(
    clocks_benchmark
    benchmark::benchmark
    DPDK::dpdk
)
