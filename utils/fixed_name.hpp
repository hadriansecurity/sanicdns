#pragma once

#include <string_view>
#include <array>
#include <optional>
#include <glaze/glaze.hpp>

/**
 * @brief Fixed-size, null-terminated string container.
 * 
 * @tparam N Maximum size of the buffer (including the null terminator).
 */
template <size_t N>
struct FixedName {
    std::array<char, N> buf{};
    size_t len{};

    /**
     * @brief Default constructor for FixedName.
     */

    FixedName() = default;

    /**
     * @brief Constructs a FixedName from a string literal.
     * 
     * @param str The input string literal.
     */
    template <size_t M>
    requires(M <= N)
    constexpr FixedName(const char(&str)[M]) {
        std::copy_n(str, M, buf.begin());
        len = M - 1; // Exclude the null terminator from the length
    }

    /**
     * @brief Provides a string view for serialization.
     */
    struct glaze {
        static constexpr auto value = [](const FixedName& self) -> auto { return std::string_view(self.buf.data(), self.len); };
    };

    /**
     * @brief Equality operator for FixedName.
     * 
     * @param other Another FixedName object.
     * @return true if equal, false otherwise.
     */
    bool operator==(const FixedName &other) const {
        return std::string_view(other.buf.data(), other.len) == std::string_view(buf.data(), len);
    }

    /**
     * @brief Three-way comparison operator for FixedName.
     * 
     * @param other Another FixedName object.
     * @return std::strong_ordering result of the comparison.
     */
    auto operator<=>(const FixedName &other) const {
        return std::string_view(buf.data(), len) <=> std::string_view(other.buf.data(), other.len);
    }

    /**
     * @brief Converts FixedName to std::string_view.
     * 
     * @return std::string_view of the FixedName.
     */
    explicit operator std::string_view() const {
        return std::string_view(buf.data(), len);
    }

    /**
     * @brief Get a c-style string view from the buffer.
     *
     * @return const char* of the FixedName
     */
    const char* c_str() const {
        return buf.data();
    }

    /**
     * @brief Concatenates two FixedName objects.
     * 
     * @param other Another FixedName object.
     * @return std::optional<FixedName> containing the concatenated result, or std::nullopt if the result exceeds the buffer size.
     */
    std::optional<FixedName> operator+(std::string_view other) const {
	    if (len + other.size() + 1 > N) { // +1 for the null terminator
		    return std::nullopt;
	    }

	    FixedName result;
	    result.len = len + other.size();
	    std::copy(buf.begin(), buf.begin() + len, result.buf.begin());
	    std::copy(other.begin(), other.end(), result.buf.begin() + len);
	    result.buf[result.len] = '\0'; // Ensure null-termination

	    return result;
    }

    /**
     * @brief Initializes a FixedName from a string view.
     * 
     * @param str The input string view.
     * @return std::optional<FixedName> containing the initialized FixedName, or std::nullopt if the input string exceeds the buffer size.
     */
    static std::optional<FixedName> init(std::string_view str) {
        if (str.size() + 1 > N) { // +1 for the null terminator
            return std::nullopt;
        }

        FixedName fn;
        fn.len = str.size();
        std::copy(str.begin(), str.end(), fn.buf.begin());
        fn.buf[fn.len] = '\0'; // Ensure null-termination

        return fn;
    }
};

template <size_t N>
struct std::hash<FixedName<N>> {
    std::size_t operator()(const FixedName<N>& k) const {
        return hash(std::string_view(k));
    }
};
