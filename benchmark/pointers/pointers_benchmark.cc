#include <benchmark/benchmark.h>
#include <memory>
#include <atomic>

static void TimeRegularPointer(benchmark::State& state) {
  // Code inside this loop is measured repeatedly
  int* my_int = new int;
  *my_int = 3;

  for (auto _ : state) {
    
    my_int = [&state](int* my_int) {
        benchmark::DoNotOptimize(*my_int);
        
        return my_int;
    }(my_int);

    benchmark::DoNotOptimize(*my_int);
  }

  delete my_int;
}

BENCHMARK(TimeRegularPointer);

static void TimeUniquePointer(benchmark::State& state) {
  // Code inside this loop is measured repeatedly
  auto my_int = std::make_unique<int>();
  *my_int = 3;

  for (auto _ : state) {
    
    my_int = [&state](std::unique_ptr<int> my_int) {
        benchmark::DoNotOptimize(*my_int);
        return std::move(my_int);
    }(std::move(my_int));

    benchmark::DoNotOptimize(*my_int);
  }
}

BENCHMARK(TimeUniquePointer);

static void TimeSharedPointer(benchmark::State& state) {
  // Code inside this loop is measured repeatedly
  auto my_int = std::make_shared<int>();
  *my_int = 3;

  for (auto _ : state) {
    
    my_int = [&state](std::shared_ptr<int> my_int) {
        benchmark::DoNotOptimize(*my_int);
        return my_int;
    }(my_int);

    benchmark::DoNotOptimize(*my_int);
  }
}

BENCHMARK(TimeSharedPointer);

BENCHMARK_MAIN();