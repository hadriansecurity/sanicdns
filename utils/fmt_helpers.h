#pragma once

#include "spdlog/fmt/bundled/core.h"

namespace fmt_helpers {

/**
 * @brief Helper struct for formatting large values.
 */
struct fmt_count {
	fmt_count(size_t count) : count(count) { }
	size_t count;
};

} // namespace fmt_helpers

// Specialize the fmt::formatter for fmt_helpers::fmt_count
template <>
struct fmt::formatter<fmt_helpers::fmt_count> {
	// Parse format specifications
	constexpr auto parse(format_parse_context& ctx) -> decltype(ctx.begin()) {
		return ctx.end();
	}

	// Format the fmt_count object
	template <typename FormatContext>
	auto format(const fmt_helpers::fmt_count& count, FormatContext& ctx)
	    -> decltype(ctx.out()) {
		double count_dbl = count.count;
		std::string formatted;

		if (count_dbl > 1e9) {
			formatted = fmt::format("{:.3f}G", count_dbl / 1e9);
		} else if (count_dbl > 1e6) {
			formatted = fmt::format("{:.3f}M", count_dbl / 1e6);
		} else if (count_dbl > 1e3) {
			formatted = fmt::format("{:.3f}k", count_dbl / 1e3);
		} else {
			formatted = fmt::format("{}", count_dbl);
		}

		return fmt::format_to(ctx.out(), "{}", formatted);
	}
};
