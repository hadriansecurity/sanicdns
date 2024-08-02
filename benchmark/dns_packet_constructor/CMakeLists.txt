add_executable(
    dns_construct_helpers_benchmark
    dns_construct_helpers_benchmark.cc
)

add_executable(
    dns_packet_constructor_benchmark
    dns_packet_constructor_benchmark.cc
)

target_link_libraries(
    dns_construct_helpers_benchmark
    benchmark::benchmark
    gtest_main
    dns_packet_constructor
)

target_link_libraries(
    dns_packet_constructor_benchmark
    benchmark::benchmark
    gtest_main
    dns_packet_constructor
)
