#pragma once

#include <expected.h>

#include <concepts>

template <typename T>
concept OptionalOrExpectedCompatible = requires(T obj) {
	{ obj.has_value() } -> std::same_as<bool>;
	{ static_cast<bool>(obj) };
	{ *obj };
};

#define UNWRAP_OR_RETURN_AND_LOG(operation)                                                       \
	({                                                                                        \
		tl::expected _result = (operation);                                               \
		if (!_result) {                                                                   \
			spdlog::error("at {} in {}:{} {} returned error", __FUNCTION__, __FILE__, \
			    __LINE__, #operation);                                                \
			return tl::unexpected(_result.error());                                   \
		}                                                                                 \
		std::move(*_result);                                                              \
	})

#define UNWRAP_OR_RETURN_VAL_AND_LOG(operation, val)                                              \
	({                                                                                        \
		auto _result = (operation);                                                       \
		static_assert(OptionalOrExpectedCompatible<decltype(_result)>);                   \
		if (!_result) {                                                                   \
			spdlog::error("at {} in {}:{} {} returned error", __FUNCTION__, __FILE__, \
			    __LINE__, #operation);                                                \
			return val;                                                               \
		}                                                                                 \
		std::move(*_result);                                                              \
	})

#define UNWRAP_OR_RETURN_ERR_AND_LOG(operation, val)                                              \
	({                                                                                        \
		auto _result = (operation);                                                       \
		static_assert(OptionalOrExpectedCompatible<decltype(_result)>);                   \
		if (!_result) {                                                                   \
			spdlog::error("at {} in {}:{} {} returned error", __FUNCTION__, __FILE__, \
			    __LINE__, #operation);                                                \
			return tl::unexpected(val);                                               \
		}                                                                                 \
		std::move(*_result);                                                              \
	})

#ifdef EXPECTED_HELPERS_ALWAYS_LOG
#define UNWRAP_OR_RETURN_ERR UNWRAP_OR_RETURN_ERR_AND_LOG
#define UNWRAP_OR_RETURN_VAL UNWRAP_OR_RETURN_VAL_AND_LOG
#define UNWRAP_OR_RETURN UNWRAP_OR_RETURN_AND_LOG
#else
#define UNWRAP_OR_RETURN(operation)                             \
	({                                                      \
		tl::expected _result = (operation);             \
		if (!_result)                                   \
			return tl::unexpected(_result.error()); \
		std::move(*_result);                            \
	})

#define UNWRAP_OR_RETURN_RAW(operation)             \
	({                                          \
		tl::expected _result = (operation); \
		if (!_result)                       \
			return _result.error();     \
		std::move(*_result);                \
	})

#define UNWRAP_OR_RETURN_VAL(operation, val)                                    \
	({                                                                      \
		auto _result = (operation);                                     \
		static_assert(OptionalOrExpectedCompatible<decltype(_result)>); \
		if (!_result)                                                   \
			return val;                                             \
		std::move(*_result);                                            \
	})

#define UNWRAP_OR_RETURN_ERR(operation, err)                                    \
	({                                                                      \
		auto _result = (operation);                                     \
		static_assert(OptionalOrExpectedCompatible<decltype(_result)>); \
		if (!_result)                                                   \
			return tl::unexpected(err);                             \
		std::move(*_result);                                            \
	})
#endif
