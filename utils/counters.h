#pragma once

#include <stdint.h>

#include <cstdint>
#include <type_traits>

// alignas(64) to prevent false sharing
struct alignas(64) PerCoreCounters {
	uint64_t lines_rejected{};
	uint64_t sent_pkts{};

	uint64_t retry{};
	uint64_t max_retry{};

	uint64_t rcvd_pkts{};

	uint64_t parse_success{};
	uint64_t parse_fail{};
	uint64_t other_worker_id{};

	uint64_t noerror{};
	uint64_t nxdomain{};
	uint64_t servfail{};
	uint64_t rcode_other{};

	uint64_t num_resolved{};

	template <typename F>
	requires(std::is_invocable_r_v<uint64_t, F, uint64_t, uint64_t>)
	void apply(F&& f, const PerCoreCounters& other) {
		lines_rejected = f(lines_rejected, other.lines_rejected);
		sent_pkts = f(sent_pkts, other.sent_pkts);

		retry = f(retry, other.retry);

		rcvd_pkts = f(rcvd_pkts, other.rcvd_pkts);

		parse_success = f(parse_success, other.parse_success);
		parse_fail = f(parse_fail, other.parse_fail);
		other_worker_id = f(other_worker_id, other.other_worker_id);

		noerror = f(noerror, other.noerror);
		nxdomain = f(nxdomain, other.nxdomain);
		servfail = f(servfail, other.servfail);
		rcode_other = f(rcode_other, other.rcode_other);

		num_resolved = f(num_resolved, other.num_resolved);
	}

	template <typename F>
	requires(std::is_invocable_r_v<uint64_t, F, uint64_t>)
	void apply(F&& f) {
		apply([f](uint64_t a, uint64_t b) { return f(a); }, PerCoreCounters{});
	}

	PerCoreCounters& operator+=(const PerCoreCounters& other) {
		apply([](uint64_t a, uint64_t b) { return a + b; }, other);

		return *this;
	}

	PerCoreCounters& operator-=(const PerCoreCounters& other) {
		apply([](uint64_t a, uint64_t b) { return a - b; }, other);

		return *this;
	}

	PerCoreCounters operator+(const PerCoreCounters& rhs) const {
		auto ret = *this;
		ret += rhs;
		return ret;
	}

	PerCoreCounters operator-(const PerCoreCounters& rhs) const {
		auto ret = *this;
		ret -= rhs;
		return ret;
	}

	PerCoreCounters& operator*=(const double factor) {
		apply([factor](uint64_t a) {
			return static_cast<uint64_t>(static_cast<double>(a) * factor);
		});

		return *this;
	}
	PerCoreCounters& operator/=(const double factor) {
		apply([factor](uint64_t a) {
			return static_cast<uint64_t>(static_cast<double>(a) / factor);
		});

		return *this;
	}

	PerCoreCounters operator*(const double factor) const {
		auto ret = *this;
		ret *= factor;
		return ret;
	}

	PerCoreCounters operator/(const double factor) const {
		auto ret = *this;
		ret /= factor;
		return ret;
	}
};
