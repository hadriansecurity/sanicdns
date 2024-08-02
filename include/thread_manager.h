#pragma once

#include <rte_eal.h>
#include <rte_lcore.h>

#include <atomic>
#include <functional>
#include <iostream>
#include <latch>
#include <memory>
#include <stdexcept>
#include <stop_token>
#include <tuple>
#include <vector>

template <typename F, typename... Ts>
concept IsValidArguments =
    (std::is_invocable_r_v<int, std::decay_t<F>, std::decay_t<Ts>...> ||
	std::is_invocable_r_v<int, std::decay_t<F>, std::stop_token, std::decay_t<Ts>...>);

/**
 * @brief DPDK Thread manager class for a thread-per-core model
 *
 * DPDK deploys worker threads when launched, this class can be used
 * to run threads on these DPDK worker threads. This class can only be used
 * on the main lcore of the program.
 *
 * This class is designed to be used in a thread-per-core topology,
 * every thread that is spawned with this class is guaranteed to run on
 * a different physical processor.
 *
 * The class tries to mimic the std::jthread API for launching threads, the
 * completion of threads is awaited when the destructor is called.
 *
 */
class ThreadManager {
public:
	enum class LaunchThreadResult {
		Success,
		MaxLCoreReached,
		NotMainLCore,
		RemoteLaunchFail,
	};

	/**
	 * @brief Construct a new Thread Manager object
	 *
	 */
	ThreadManager() : _stop_source{} {
		// Indicate that main lcore thread is the only one running
		running_threads.push_back({rte_lcore_id()});
	}

	/**
	 * @brief Destroy the Thread Manager object
	 *
	 * Requests stopping all threads and waits for the threads to exit
	 */
	~ThreadManager() {
		request_stop();
		join();
	}

	/**
	 * @brief Wait until the LCores have exited
	 *
	 */
	void join() {
		rte_eal_mp_wait_lcore();
	}

	/**
	 * @brief The thread manager cannot be copied
	 *
	 */
	ThreadManager(const ThreadManager&) = delete;
	/**
	 * @brief The thread manager cannot be moved
	 *
	 */
	ThreadManager(const ThreadManager&&) = delete;

	/**
	 * @brief Launch a new thread on a new lcore
	 *
	 * Throws a runtime error when no lcore is available for the thread
	 *
	 * @tparam F Template for lambda to be called
	 * @tparam Ts Parameter pack template for arguments for F
	 * @param f **Captureless** lambda to be ran on the new thread
	 * @param args Parameters to apply to f in the new thread
	 */
	template <typename F, typename... Ts>
	requires IsValidArguments<F, Ts...>
	[[nodiscard]] LaunchThreadResult LaunchThread(F&& f, Ts&&... args);

	/**
	 * @brief Get the total number of usable hardware threads available on the system
	 *
	 * @return unsigned Total number of usable hardware threads available on the system
	 */
	unsigned GetTotalThreads() const {
		// Subtract one for the main lcore, this thread cannot be used
		return rte_lcore_count() - 1;
	}

	/**
	 * @brief Get the number of unused hardware threads
	 *
	 * @return unsigned Number of unused hardware threads
	 */
	unsigned GetUnusedThreads() const {
		return rte_lcore_count() - running_threads.size();
	}

	/**
	 * @brief Get the stop source object
	 *
	 * @return stop_source
	 */
	[[nodiscard]] std::stop_source get_stop_source() {
		return _stop_source;
	};

	/**
	 * @brief Get a new stop_token from _stop_source
	 *
	 * @return std::stop_token
	 */
	[[nodiscard]] std::stop_token get_stop_token() const {
		return _stop_source.get_token();
	};

	/**
	 * @brief Request the threads to stop through the _stop_source object
	 *
	 * @return true if the ThreadManager object has a stop-state and this invocation made a stop
	 * request
	 * @return false otherwise
	 */
	bool request_stop() noexcept {
		return get_stop_source().request_stop();
	}

private:
	/**
	 * @brief Struct containing all parameters the lcore needs to run the thread
	 *
	 * Can be used as a workaround to the DPDK API to pass all parameters for the thread using a
	 * single void pointer
	 *
	 * @tparam F Template for lambda to be called
	 * @tparam Ts Parameter pack template for arguments for F
	 */
	template <typename F, typename... Ts>
	struct LCoreParams;

	/**
	 * @brief Function that can be called from the DPDK API to unpack all arguments from
	 * LCoreParams and call F
	 *
	 * @tparam F Template for lambda to be called
	 * @tparam Ts Parameter pack template for arguments for F
	 * @param arg Pointer to a shared pointer containing the LCoreParams
	 * @return int Return value of F
	 */
	template <typename F, typename... Ts>
	static int LCoreReceiver(void* arg);

	/**
	 * @brief Vector of all lcore-id's currently in use
	 *
	 */
	std::vector<unsigned> running_threads;

	std::stop_source _stop_source;
};

template <typename F, typename... Ts>
struct ThreadManager::LCoreParams {
	LCoreParams(F&& f, const std::stop_source& _stop_source, Ts&&... args)
	    : f(std::forward<F>(f)),
	      m_args(std::forward<Ts>(args)...),
	      start_thread(2),
	      _stop_source(_stop_source) { }

	F f;

	// Store the arguments in the tuple, move if possible
	std::tuple<std::decay_t<Ts>...> m_args;

	// Use an std::latch to synchronize the exit of this function to when the LCoreReceiver is
	// ready, both the calling thread and the callee should be ready. Therefore the latch is
	// initialized to 2
	std::latch start_thread;

	// The stop source can be passed by constant reference since the original stop source object
	// is guaranteed to outlive the threads
	const std::stop_source& _stop_source;
};

// The lambda and function arguments are forwarded using rvalue references
template <typename F, typename... Ts>
requires IsValidArguments<F, Ts...>
ThreadManager::LaunchThreadResult ThreadManager::LaunchThread(F&& f, Ts&&... args) {
	// Threads can only be launched from the main lcore
	if (rte_lcore_id() != rte_get_main_lcore())
		return ThreadManager::LaunchThreadResult::NotMainLCore;

	// Get the id of the next lcore
	unsigned lcore_id_to_run = rte_get_next_lcore(running_threads.back(), true, false);

	// rte_get_next_lcore returns RTE_MAX_LCORE when there are no hardware threads available
	// anymore
	if (lcore_id_to_run == RTE_MAX_LCORE)
		return ThreadManager::LaunchThreadResult::MaxLCoreReached;

	// Add the new lcore id to the list of running lcores
	running_threads.push_back(lcore_id_to_run);

	// Wrap an LCoreParams object in a shared pointer to safely pass it to the other thread
	std::shared_ptr<LCoreParams<F, Ts...>> lcore_params =
	    std::make_shared<LCoreParams<F, Ts...>>(std::forward<F>(f), _stop_source,
		std::forward<Ts>(args)...);

	int res = rte_eal_remote_launch(LCoreReceiver<F, Ts...>, (void*) (&lcore_params),
	    lcore_id_to_run);

	if (res)
		return ThreadManager::LaunchThreadResult::RemoteLaunchFail;

	// Wait until the LCoreReceiver is ready
	lcore_params->start_thread.arrive_and_wait();

	return ThreadManager::LaunchThreadResult::Success;
}

template <typename F, typename... Ts>
int ThreadManager::LCoreReceiver(void* arg) {
	// Make a copy of the shared pointer to guarantee access to data, reference count will be
	// incremented
	std::shared_ptr<LCoreParams<F, Ts...>> params_wrapper =
	    *((std::shared_ptr<LCoreParams<F, Ts...>>*) (arg));

	params_wrapper->start_thread.arrive_and_wait();

	int retval;

	if constexpr (std::is_invocable_r_v<int, std::decay_t<F>, std::stop_token,
			  std::decay_t<Ts>...>) {
		// Obtain a stop token from the stop source
		std::stop_token _stop_token = params_wrapper->_stop_source.get_token();

		// The actual function arguments are only available as a tuple, construct a lambda
		// that invokes the function with the stop token. The function arguments in the
		// original can be unpacked by calling this lambda with std::apply
		auto lambda_with_token = [_stop_token = std::move(_stop_token),
					     f = std::forward<F>(params_wrapper->f)](
					     auto&&... args) -> int {
			return std::invoke(f, std::move(_stop_token),
			    std::forward<decltype(args)>(args)...);
		};

		// Apply original function arguments to lambda, original function will be called
		// with a movable stop token
		retval =
		    std::apply(std::move(lambda_with_token), std::move(params_wrapper->m_args));

	} else {
		retval = std::apply(std::forward<F>(params_wrapper->f),
		    std::move(params_wrapper->m_args));
	}

	return retval;
}
