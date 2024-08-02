add_executable(
    dns_packet_parser_benchmark
    dns_packet_parser_benchmark.cc
)

add_executable(
    dns_parse_helpers_benchmark
    dns_parse_helpers_benchmark.cc
)

target_link_libraries(
    dns_packet_parser_benchmark
    benchmark::benchmark
    gtest_main
    dns_packet_parser
)

target_link_libraries(
    dns_parse_helpers_benchmark
    benchmark::benchmark
    gtest_main
    dns_packet_parser
)

