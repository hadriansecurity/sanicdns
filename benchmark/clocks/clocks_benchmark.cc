#include <benchmark/benchmark.h>
#include <rte_cycles.h>
#include <chrono>
#include <cstdio>
#include <ctime>

static void SteadyClock(benchmark::State& state) {
  // Code inside this loop is measured repeatedly
  for (auto _ : state) {
    // Make sure the variable is not optimized away by compiler
    auto clock_result = std::chrono::steady_clock::now();
    benchmark::DoNotOptimize(
      clock_result
    );
  }
}

// Register the function as a benchmark
BENCHMARK(SteadyClock);

static void SystemClock(benchmark::State& state) {
  // Code inside this loop is measured repeatedly
  for (auto _ : state) {
    // Make sure the variable is not optimized away by compiler
    auto clock_result = std::chrono::system_clock::now();
    benchmark::DoNotOptimize(
      clock_result
    );
  }
}

BENCHMARK(SystemClock);

static void HighResolutionClock(benchmark::State& state) {
  // Code inside this loop is measured repeatedly
  for (auto _ : state) {
    // Make sure the variable is not optimized away by compiler
    auto clock_result = std::chrono::high_resolution_clock::now();
    benchmark::DoNotOptimize(
      clock_result
    );
  }
}

BENCHMARK(HighResolutionClock);

static void ClockClock(benchmark::State& state) {
  // Code inside this loop is measured repeatedly
  for (auto _ : state) {
    // Make sure the variable is not optimized away by compiler
    clock_t clock_result = std::clock();
    benchmark::DoNotOptimize(
      clock_result
    );
  }
}

BENCHMARK(ClockClock);

static void TimeClock(benchmark::State& state) {
  // Code inside this loop is measured repeatedly
  for (auto _ : state) {
    // Make sure the variable is not optimized away by compiler
    time_t clock_result = std::time(NULL);
    benchmark::DoNotOptimize(
      clock_result
    );
  }
}

BENCHMARK(TimeClock);

struct CoarseClock {

  // An arithmetic type or a class emulating an arithmetic type.
  // The representation type of C1::duration.
  using rep = std::time_t;

	// A specialization of std::ratio.
  // The tick period of the clock in seconds.
  using period = std::ratio<1, 1>;

  // The duration type of the clock.
  using duration = std::chrono::duration<rep, period>;

  // The std::chrono::time_point type of the clock.
  using time_point = std::chrono::time_point<CoarseClock>;

  // true if t1 <= t2 is always true and the time between clock ticks
  // is constant, otherwise false
  const static bool is_steady{true};

  // Returns a time_point object representing the current point in time.
  static time_point now() {
    return time_point{
      std::chrono::seconds{std::time(NULL)}
    };
  }

};

static void CoarseClock(benchmark::State& state) {
  // Code inside this loop is measured repeatedly
  for (auto _ : state) {
    // Make sure the variable is not optimized away by compiler
    CoarseClock::time_point clock_result = CoarseClock::now();
    benchmark::DoNotOptimize(
        clock_result
    );
  }
}

BENCHMARK(CoarseClock);

static void RDTSC(benchmark::State& state) {
  // Code inside this loop is measured repeatedly
  for (auto _ : state) {
    // Make sure the variable is not optimized away by compiler
    uint64_t clock_result = rte_rdtsc();
    benchmark::DoNotOptimize(
        clock_result
    );
  }
}

BENCHMARK(RDTSC);

BENCHMARK_MAIN();