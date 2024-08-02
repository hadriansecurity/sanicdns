add_executable(
    input_reader_benchmark
    input_reader_benchmark.cc
)

target_link_libraries(
    input_reader_benchmark
    benchmark::benchmark
    gtest_main
    input_processor
)

#gtest_discover_tests(input_reader_test WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})