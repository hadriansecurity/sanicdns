#include <gtest/gtest.h>
#include <intrusive_list.h>
#include <parse_helpers.h>
#include <rte_byteorder.h>
#include <rte_ether.h>

#include <algorithm>
#include <array>
#include <bit>
#include <fixed_name.hpp>
#include <functional>
#include <latch>
#include <optional>
#include <random>
#include <thread>

#include "dns_format.h"
#include "network_types.h"

/*************************************
 ******** intrusive_list test ********
 **************************************/

// Most basic struct that can be used with the intrusive linked list
struct Data {
	Data() : node(this) { }

	Node<Data> node;
};

enum class VerifyResult {
	OK,
	MISMATCHED_SIZE,
	OUT_OF_BOUNDS,
	INCORRECT_ORDER,
	IN_LIST_ERROR
};

// Verify that the list order and size is equal to the reference order. Returns true when okay
template <typename T, Node<T> T::*Member, size_t N>
VerifyResult VerifyList(const std::array<Data, N>& owner_array,
    const IntrusiveList<T, Member>& list, const std::vector<size_t>& reference_order) {
	// First verify list size
	if (list.size() != reference_order.size())
		return VerifyResult::MISMATCHED_SIZE;

	// Check that the elements in reference_order will not trigger an out of bounds read of
	// owner_array
	const auto max_index_it = std::max_element(reference_order.begin(), reference_order.end());

	// Read the max index from max_index_it if reference_order is not empty, otherwise use 0
	const size_t max_index = max_index_it != reference_order.end() ? *max_index_it : 0;
	if (max_index >= owner_array.size())
		return VerifyResult::OUT_OF_BOUNDS;

	// Iterate over list and check the order against the reference_order
	size_t reference_count = 0;
	for (auto& list_item : list) {
		if (reference_count >= reference_order.size())
			return VerifyResult::OUT_OF_BOUNDS;

		auto& reference_item = owner_array[reference_order[reference_count++]];

		// Check that the list_item and reference_item point to the same memory location
		if (&list_item != &reference_item)
			return VerifyResult::INCORRECT_ORDER;
	}

	// Check that the in_list method is valid for all entries of owner_array
	for (size_t i = 0; i < owner_array.size(); i++) {
		bool in_list_result = list.in_list(owner_array[i]);
		bool in_reference_order = std::find(reference_order.begin(), reference_order.end(),
					      i) != reference_order.end();

		if (in_list_result != in_reference_order)
			return VerifyResult::IN_LIST_ERROR;
	}

	return VerifyResult::OK;
}

TEST(IntrusiveListTest, TestEmpty) {
	IntrusiveList<Data, &Data::node> list;

	EXPECT_EQ(list.size(), 0);
	EXPECT_EQ(list.begin(), list.end());
}

TEST(IntrusiveListTest, TestMoveConstructor) {
	std::array<Data, 10> data_arr;

	IntrusiveList<Data, &Data::node> list;
	EXPECT_EQ(list.begin(), list.end());
	auto list2 = std::move(list);

	EXPECT_EQ(list2.size(), 0);
	EXPECT_EQ(list2.begin(), list2.end());

	auto order = {8ul, 3ul, 7ul, 2ul, 6ul, 1ul, 0ul, 9ul, 4ul};
	for (auto index : order)
		list.push_back(data_arr[index]);

	EXPECT_EQ(VerifyList(data_arr, list, order), VerifyResult::OK);

	list2 = std::move(list);
	EXPECT_EQ(VerifyList(data_arr, list2, order), VerifyResult::OK);

	EXPECT_EQ(list.size(), 0);
	EXPECT_EQ(list.begin(), list.end());

	std::array<Data, 10> new_data_arr;
	for (auto index : order)
		list.push_back(new_data_arr[index]);
	EXPECT_NE(list.size(), 0);
	EXPECT_EQ(VerifyList(new_data_arr, list, order), VerifyResult::OK);
}

TEST(IntrusiveListTest, ListTestBasic) {
	// Create Data array of 10 long
	std::array<Data, 10> data_arr;

	IntrusiveList<Data, &Data::node> list;
	for (auto index : {8, 4, 7, 2, 6, 1, 0, 9})
		list.push_back(data_arr[index]);

	// Index sequence in list is 8, 4, 7, 2, 6, 1, 0, 9
	EXPECT_EQ(VerifyList(data_arr, list, {8, 4, 7, 2, 6, 1, 0, 9}), VerifyResult::OK);

	// Remove element 8, 6 and 2. list sequence is 4, 7, 1, 0, 9
	list.delete_elem(data_arr[8]);
	list.delete_elem(data_arr[6]);
	list.delete_elem(data_arr[2]);

	EXPECT_EQ(VerifyList(data_arr, list, {4, 7, 1, 0, 9}), VerifyResult::OK);

	// Remove remaining elements, list is empty
	list.delete_elem(data_arr[0]);
	list.delete_elem(data_arr[4]);
	list.delete_elem(data_arr[9]);
	list.delete_elem(data_arr[1]);
	list.delete_elem(data_arr[7]);

	EXPECT_EQ(VerifyList(data_arr, list, {}), VerifyResult::OK);
}

TEST(IntrusiveListTest, MultipleInsertionsDeletions) {
	// Create Data array of 10 long
	std::array<Data, 10> data_arr;

	IntrusiveList<Data, &Data::node> list;
	for (auto index : {8, 4, 7, 2, 6, 1, 0, 9})
		list.push_back(data_arr[index]);

	// Index sequence in list is 8, 4, 7, 2, 6, 1, 0, 9

	// Insert element 2, 6, 1, 9 and 8 again. Should not make any changes
	list.push_back(data_arr[2]);
	list.push_back(data_arr[6]);
	list.push_back(data_arr[1]);
	list.push_back(data_arr[9]);
	list.push_back(data_arr[8]);
	EXPECT_EQ(VerifyList(data_arr, list, {8, 4, 7, 2, 6, 1, 0, 9}), VerifyResult::OK);

	// Delete element 7 two times, should not cause any problems
	list.delete_elem(data_arr[7]);
	list.delete_elem(data_arr[7]);
	EXPECT_EQ(VerifyList(data_arr, list, {8, 4, 2, 6, 1, 0, 9}), VerifyResult::OK);

	// Erase 8, 4, 2
	for (auto it = list.begin(); &*it != &data_arr[6];) {
		it = list.erase(it);
	}

	EXPECT_EQ(VerifyList(data_arr, list, {6, 1, 0, 9}), VerifyResult::OK);
}

TEST(IntrusiveListTest, VerifyListTest) {
	// Create Data array of 10 long
	std::array<Data, 10> data_arr;

	IntrusiveList<Data, &Data::node> list;
	for (auto index : {8, 4, 7, 2, 6, 1, 0, 9})
		list.push_back(data_arr[index]);

	// Index sequence in list is 8, 4, 7, 2, 6, 1, 0, 9

	// Pass list with wrong size
	EXPECT_EQ(VerifyList(data_arr, list, {8, 4, 7, 2, 6, 1, 0}), VerifyResult::MISMATCHED_SIZE);
	// Pass list with wrong order
	EXPECT_EQ(VerifyList(data_arr, list, {8, 4, 7, 2, 6, 1, 9, 0}),
	    VerifyResult::INCORRECT_ORDER);
	EXPECT_EQ(VerifyList(data_arr, list, {9, 4, 7, 2, 6, 1, 0, 8}),
	    VerifyResult::INCORRECT_ORDER);
	// Pass list with out of order element
	EXPECT_EQ(VerifyList(data_arr, list, {9, 4, 7, 2, 10, 1, 0, 8}),
	    VerifyResult::OUT_OF_BOUNDS);
}

template <typename T>
struct FixedNameTests : public ::testing::Test {
	static constexpr auto ArraySize = T::Val;
};

namespace _detail {
template <size_t N>
struct V {
	static constexpr auto Val = N;
};
using ArraySizes = ::testing::Types<V<10>, V<34>, V<128>, V<604>, V<1026>, V<2033>, V<3099>>;
} // namespace _detail

TYPED_TEST_SUITE(FixedNameTests, _detail::ArraySizes);

TYPED_TEST(FixedNameTests, FixedNameInitialization) {
	constexpr auto ArraySize = TestFixture::ArraySize;
	using FixedNameType = FixedName<ArraySize>;

	// Test empty string initialization
	auto empty_opt = FixedNameType::init("");
	ASSERT_TRUE(empty_opt.has_value());
	EXPECT_EQ(empty_opt->len, 0);
	EXPECT_EQ(std::string_view(*empty_opt), "");

	// Test maximum size string initialization (excluding null terminator)
	std::string max_str(ArraySize - 1, 'a');
	auto max_opt = FixedNameType::init(max_str);
	ASSERT_TRUE(max_opt.has_value());
	EXPECT_EQ(max_opt->len, max_str.size());
	EXPECT_EQ(std::string_view(*max_opt), max_str);

	// Test too long string initialization
	std::string too_long_str(ArraySize, 'a');
	auto too_long_opt = FixedNameType::init(too_long_str);
	ASSERT_FALSE(too_long_opt.has_value());
}

TYPED_TEST(FixedNameTests, FixedNameConcatenation) {
	constexpr auto ArraySize = TestFixture::ArraySize;
	using FixedNameType = FixedName<ArraySize>;

	{
		// Test concatenation within bounds
		auto hello = FixedNameType("Hello");

		auto combined_opt = hello + "World";
		if (ArraySize >= 11) { // "HelloWorld" + null terminator fits within 11 chars
			ASSERT_TRUE(combined_opt.has_value());
			EXPECT_EQ(combined_opt->len, 10);
			EXPECT_EQ(std::string_view(*combined_opt), "HelloWorld");
		} else {
			ASSERT_FALSE(combined_opt.has_value());
		}
	}
	{
		// Test concatenation that exceeds buffer size by one character
		std::string almost_full(ArraySize - 2,
		    'a'); // leaving 1 space for 'b' and 1 for null terminator
		auto almost_full_opt = FixedNameType::init(almost_full);
		ASSERT_TRUE(almost_full_opt.has_value());

		auto combined_opt = *almost_full_opt + "b";
		ASSERT_TRUE(combined_opt.has_value());

		auto overflow_too_full_opt = *combined_opt + "c";
		ASSERT_FALSE(overflow_too_full_opt.has_value());
	}
}

TYPED_TEST(FixedNameTests, FixedNameAppend) {
	constexpr auto ArraySize = TestFixture::ArraySize;
	using FixedNameType = FixedName<ArraySize>;

	{
		// Test append within bounds
		auto hello = FixedNameType("Hello");

		auto success = hello += "World";
		if (ArraySize >= 11) { // "HelloWorld" + null terminator fits within 11 chars
			ASSERT_TRUE(success);
			EXPECT_EQ(hello.len, 10);
			EXPECT_EQ(std::string_view(hello), "HelloWorld");
		} else {
			ASSERT_FALSE(success);
		}
	}
	{
		// Test append that exceeds buffer size by one character
		std::string almost_full(ArraySize - 2,
		    'a'); // leaving 1 space for 'b' and 1 for null terminator
		auto almost_full_opt = FixedNameType::init(almost_full);

		ASSERT_TRUE(almost_full_opt.has_value());

		bool success = *almost_full_opt += "b";
		ASSERT_TRUE(success);

		success = *almost_full_opt += "c";
		ASSERT_FALSE(success);
	}
}

std::optional<std::vector<InAddr>> GetRefResolverList(std::vector<std::string> input) {
	std::vector<InAddr> to_ret;
	for (auto& resolver_str : input) {
		auto in_addr_opt = InAddr::init(resolver_str);
		if (!in_addr_opt.has_value())
			return std::nullopt;

		to_ret.push_back(in_addr_opt.value());
	}

	return to_ret;
}

TEST(ParseResolversTest, TestCommaSeperatedGood) {
	auto out = ParseResolvers("1.2.3.4,4.3.2.1,4.4.4.4,1.5.4.122");

	ASSERT_TRUE(out.has_value());

	auto ref_list = GetRefResolverList({"1.2.3.4", "4.3.2.1", "4.4.4.4", "1.5.4.122"});

	ASSERT_TRUE(ref_list.has_value());

	ASSERT_EQ(out.value(), ref_list.value());
}

TEST(ParseResolversTest, TestCommaSeperatedBad) {
	auto out = ParseResolvers("1.2.3.4,4.3.2.1,4.444.4.4,1.5.4.122");

	ASSERT_FALSE(out.has_value());

	ASSERT_STREQ(out.error().c_str(),
	    "Invalid IP address in list / cannot open file: 4.444.4.4");
}

TEST(ParseResolversTest, TestFileGood) {
	auto out = ParseResolvers("resolvers_good.txt");

	ASSERT_TRUE(out.has_value());

	auto ref_list = GetRefResolverList({"1.2.3.4", "44.44.33.22", "123.123.123.123",
	    "55.44.3.2", "50.60.70.80", "192.168.1.1", "99.0.99.0"});

	ASSERT_TRUE(ref_list.has_value());

	ASSERT_EQ(out.value(), ref_list.value());
}

TEST(ParseResolversTest, TestFileBad) {
	auto out = ParseResolvers("resolvers_bad.txt");

	ASSERT_FALSE(out.has_value());

	ASSERT_STREQ(out.error().c_str(), "Invalid IP address at line 6: 192a.168.1.1");
}

TEST(NetworkTypesTest, TestInAddr) {
	EXPECT_EQ(InAddr::init("1234.123.12.3"), std::nullopt);
	EXPECT_EQ(InAddr::init("123.123.123.1234"), std::nullopt);
	EXPECT_EQ(InAddr::init("256.123.123.123"), std::nullopt);

	EXPECT_EQ(InAddr::init("12.33.4.222"), in_addr(rte_be_to_cpu_32(0x0c2104de)));

	// Should also work correctly without null termination
	std::string_view view{"123.12.44.322"};
	view.remove_suffix(1);

	EXPECT_EQ(InAddr::init(view), in_addr(rte_be_to_cpu_32(0x7b0c2c20)));

	EXPECT_EQ(InAddr::init(view)->str(), *FixedName<INET_ADDRSTRLEN>::init("123.12.44.32"));
}

TEST(NetworkTypesTest, TestIn6Addr) {
	EXPECT_EQ(In6Addr::init("FE80:CD00:0000:0CDE:1257:0000:211E:729R"), std::nullopt);
	EXPECT_EQ(In6Addr::init("FE80:CD00:0000:0CDE:1257:0000:211E:729EE"), std::nullopt);
	EXPECT_EQ(In6Addr::init("fe80:cd00:0000:0cde:1257:0000:211e::29e"), std::nullopt);

	auto ref_addr = in6_addr({0xfe, 0x80, 0xcd, 0x00, 0x00, 0x00, 0x0c, 0xde, 0x12, 0x57, 0x00,
	    0x00, 0x21, 0x1e, 0xa2, 0x9e});

	EXPECT_EQ(In6Addr::init("fe80:cd00:0000:0cde:1257:0000:211e:a29e"), ref_addr);

	// Should also work correctly without null termination
	std::string_view view{"fe80:cd00:0000:0cde:1257:0000:211e:a29e4"};
	view.remove_suffix(1);

	EXPECT_EQ(In6Addr::init(view), ref_addr);

	EXPECT_EQ(In6Addr::init(view)->str(),
	    *FixedName<INET6_ADDRSTRLEN>::init("fe80:cd00:0:cde:1257:0:211e:a29e"));
}

TEST(NetworkTypesTest, TestEtherAddr) {
	EXPECT_EQ(EtherAddr::init("00:1A:2B:3C:4D:"), std::nullopt);
	EXPECT_EQ(EtherAddr::init("01:23:45:67:89:6AA"), std::nullopt);
	EXPECT_EQ(EtherAddr::init("08;00:27:5B:2B:44"), std::nullopt);

	EXPECT_EQ(EtherAddr::init("00:0C:29:58:8C:9E"),
	    rte_ether_addr({0x00, 0x0c, 0x29, 0x58, 0x8c, 0x9e}));

	// Should also work correctly without null termination
	std::string_view view{"00:0c:29:58:8c:9eA"};
	view.remove_suffix(1);

	EXPECT_EQ(EtherAddr::init(view), rte_ether_addr({0x00, 0x0c, 0x29, 0x58, 0x8c, 0x9e}));

	EXPECT_EQ(EtherAddr::init(view)->str(),
	    *FixedName<ETHER_ADDRSTRLEN>::init("00:0C:29:58:8C:9E"));
}

TEST(ParseDNSReturnCodesTest, TestGood) {
	auto out = ParseDNSReturnCodes("   NOERROR,SERVFAIL  ,BADKEY  ");

	EXPECT_TRUE(out.has_value());

	auto expected_res = std::vector<DnsRCode>{
	    DnsRCode::NOERROR,
	    DnsRCode::SERVFAIL,
	    DnsRCode::BADKEY,
	};
	EXPECT_EQ(out, expected_res);
}

TEST(ParseDNSReturnCodesTest, TestBad) {
	auto out = ParseDNSReturnCodes("NOERROR,SERVFAIL,BADKEYy");

	EXPECT_FALSE(out.has_value());

	EXPECT_EQ(out.error(), std::string("Cannot read DNS return code BADKEYy"));
}

TEST(ParseDNSReturnCodesTest, TestEmpty) {
	auto out = ParseDNSReturnCodes(" ");

	EXPECT_FALSE(out.has_value());

	EXPECT_EQ(out.error(), std::string("No DNS return codes found"));
}
