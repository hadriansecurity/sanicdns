#pragma once

#include <expected.h>
#include <expected_helpers.h>

#include <array>
#include <cstdint>
#include <fixed_name.hpp>
#include <string_view>

namespace _detail {
static constexpr size_t char_encoding_max_size = 4;

struct CharEncoding {
	char encoded[char_encoding_max_size];
	uint8_t len;

	operator std::string_view() const {
		return std::string_view(encoded, len);
	}
};

static constexpr char to_decimal_char(int n) {
	return static_cast<char>('0' + n);
}

static constexpr std::array<char, 3> to_decimal(int n) {
	return {to_decimal_char(n / 100), to_decimal_char((n / 10) % 10), to_decimal_char(n % 10)};
}

static constexpr std::array<CharEncoding, 256> char_map = []() {
	std::array<CharEncoding, 256> map{};
	for (int i = 0; i < 256; ++i) {
		if (i >= 32 && i <= 126 && i != '"' && i != '\\') {
			map[i] = {{static_cast<char>(i)}, 1};
		} else {
			auto decimal = to_decimal(i);
			map[i] = {{'\\', decimal[0], decimal[1], decimal[2]}, 4};
		}
	}
	map['"'] = {{'\\', '"'}, 2};
	map['\\'] = {{'\\', '\\'}, 2};
	return map;
}();
} // namespace _detail

template <size_t N>
static FixedName<N * _detail::char_encoding_max_size> encode_dns_char_string(FixedName<N> in,
    bool add_quotes = false) {
	FixedName<N * _detail::char_encoding_max_size> out;

	if (add_quotes)
		out += "\"";

	for (unsigned char c : std::string_view(in)) {
		const auto& encoding = _detail::char_map[c];
		out += encoding;
	}

	if (add_quotes)
		out += "\"";

	return out;
}