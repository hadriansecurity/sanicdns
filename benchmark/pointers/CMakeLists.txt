add_executable(
    pointers_benchmark
    pointers_benchmark.cc
)

target_link_libraries(
    pointers_benchmark
    benchmark::benchmark
)
