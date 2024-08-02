#include <dpdk_wrappers.h>
#include <gtest/gtest.h>

#include <cstddef>
#include <optional>
#include <string>

#include "expected.h"
#include "network_types.h"
#include "spdlog/spdlog.h"

namespace {
constexpr unsigned int ARRAY_SIZE = 1024;
constexpr unsigned int MEMPOOL_SIZE = 4096;
constexpr unsigned int RING_SIZE = 1024;
constexpr unsigned int RING_FLAGS = RING_F_SP_ENQ | RING_F_SC_DEQ;
} // namespace

struct TestObject {
	TestObject(int val_i) : val(std::make_optional(val_i)) {
		obj_count++;
	}

	TestObject() : TestObject(0) { }

	TestObject(const TestObject& other) : TestObject(other.val.value()) {
		copy_constructor_count++;
	}

	TestObject(TestObject&& other) : val(std::optional<int>(other.val.value())) {
		move_constructor_count++;
		other.val = std::nullopt;
	}

	TestObject& operator=(TestObject&& other) {
		// Current object value is being destroyed
		if (val)
			obj_count--;

		val = std::optional<int>(other.val.value());
		other.val = std::nullopt;

		move_count++;
		return *this;
	}

	TestObject& operator=(const TestObject& other) {
		// Current object value is being destroyed
		if (!val)
			obj_count++;

		val = std::optional<int>(other.val.value());

		copy_count++;
		return *this;
	}

	~TestObject() {
		if (val)
			obj_count--;

		val = std::nullopt;
	}

	std::optional<int> val;
	static size_t obj_count;
	static size_t copy_constructor_count;
	static size_t move_constructor_count;
	static size_t move_count;
	static size_t copy_count;
};

size_t TestObject::obj_count = 0;
size_t TestObject::copy_constructor_count = 0;
size_t TestObject::move_constructor_count = 0;
size_t TestObject::move_count = 0;
size_t TestObject::copy_count = 0;

template <MbufType type>
void RTEMbufElementTest(RTEMempool<TestObject, type> mempool) {
	TestObject::obj_count = 0;
	TestObject::copy_constructor_count = 0;
	TestObject::move_constructor_count = 0;

	using MbufElemType = RTEMbufElement<TestObject, type>;
	// Do two iterations to test that the mempool
	// elements can be reused
	for (int iter = 0; iter < 2; iter++) {
		std::vector<MbufElemType, RteAllocator<MbufElemType>> mbufs;
		for (size_t i = 0; i < MEMPOOL_SIZE; i++) {
			auto res = MbufElemType::init(mempool);
			EXPECT_EQ(res.has_value(), true);
			res->get_data().val = i;
			mbufs.emplace_back(std::move(*res));
		}

		EXPECT_EQ(rte_mempool_in_use_count(mempool.get()), MEMPOOL_SIZE);
		EXPECT_EQ(TestObject::obj_count, MEMPOOL_SIZE);

		auto res = MbufElemType::init(mempool);
		EXPECT_EQ(res.has_value(), false);

		for (size_t i = 0; i < MEMPOOL_SIZE; i++)
			EXPECT_EQ(mbufs[i].get_data().val, i);
	}
	EXPECT_EQ(rte_mempool_in_use_count(mempool.get()), 0);
	EXPECT_EQ(TestObject::obj_count, 0);
}

TEST(DPDKWrappers, RTEMbufElementTest) {
	// Set of general tests that can be performed for both MbufType::Raw and MbufType::Pkt
	{
		auto mempool =
		    RTEMempool<TestObject, MbufType::Raw>::init("mempool", MEMPOOL_SIZE, 0, 0, 0);
		ASSERT_EQ(mempool.has_value(), true);
		RTEMbufElementTest<MbufType::Raw>(std::move(*mempool));
	}
	{
		auto mempool =
		    RTEMempool<TestObject, MbufType::Pkt>::init("mempool", MEMPOOL_SIZE, 0, 0);
		ASSERT_EQ(mempool.has_value(), true);
		RTEMbufElementTest<MbufType::Pkt>(std::move(*mempool));
	}
}

template <MbufType type>
void RTEMbufArrayTest(RTEMempool<TestObject, type> mempool) {
	TestObject::obj_count = 0;
	TestObject::copy_constructor_count = 0;

	// Test constructor with only size
	{
		constexpr size_t to_alloc = 242;
		auto mbuf_arr = RTEMbufArray<TestObject, ARRAY_SIZE, type>::init(mempool, to_alloc);
		EXPECT_EQ(mbuf_arr.has_value(), true);
		EXPECT_EQ(mbuf_arr->size(), to_alloc);

		// Check amount of elements that have been retrieved from mempool
		EXPECT_EQ(rte_mempool_in_use_count(mempool.get()), to_alloc);

		EXPECT_EQ(TestObject::obj_count, to_alloc);
		EXPECT_EQ(TestObject::copy_constructor_count, 0);

		for (size_t i = 0; i < to_alloc; i++)
			mbuf_arr->get_data(i).val = i;

		for (size_t i = 0; i < to_alloc; i++)
			EXPECT_EQ(mbuf_arr->get_data(i).val, i);
	}
	EXPECT_EQ(TestObject::obj_count, 0);
	// All elements should have been returned to mempool
	EXPECT_EQ(rte_mempool_in_use_count(mempool.get()), 0);

	// Test constructor with size and default element
	{
		constexpr size_t to_alloc = 124;
		constexpr int val = 1523;
		auto mbuf_arr = RTEMbufArray<TestObject, ARRAY_SIZE, type>::init(mempool, to_alloc,
		    TestObject(val));
		EXPECT_EQ(mbuf_arr.has_value(), true);
		EXPECT_EQ(mbuf_arr->size(), to_alloc);

		// Check amount of elements that have been retrieved from mempool
		EXPECT_EQ(rte_mempool_in_use_count(mempool.get()), to_alloc);

		EXPECT_EQ(TestObject::obj_count, to_alloc);

		EXPECT_EQ(TestObject::copy_constructor_count, to_alloc);

		for (size_t i = 0; i < to_alloc; i++)
			EXPECT_EQ(mbuf_arr->get_data(i).val, val);
	}
	EXPECT_EQ(TestObject::obj_count, 0);
	// All elements should have been returned to mempool
	EXPECT_EQ(rte_mempool_in_use_count(mempool.get()), 0);

	// Test allocating too much from mempool
	{
		auto mbuf_arr = RTEMbufArray<TestObject, MEMPOOL_SIZE + 1, type>::init(mempool,
		    MEMPOOL_SIZE + 1);

		EXPECT_EQ(mbuf_arr.has_value(), false);
	}

	// All elements should have been returned to mempool
	EXPECT_EQ(rte_mempool_in_use_count(mempool.get()), 0);

	// Test split function
	{
		constexpr size_t to_alloc = 544;
		auto mbuf_arr = RTEMbufArray<TestObject, ARRAY_SIZE, type>::init(mempool, to_alloc);
		EXPECT_EQ(mbuf_arr.has_value(), true);

		ASSERT_EQ(mbuf_arr->size(), to_alloc);
		ASSERT_EQ(mempool.count(), to_alloc);

		mbuf_arr->get_data(0).val = 0xB00B135;

		auto second = [&]() -> decltype(mbuf_arr) {
			auto [first, second] = mbuf_arr->split(to_alloc / 2);
			[&] {
				ASSERT_EQ(first.size(), to_alloc / 2);
				ASSERT_EQ(second.size(), to_alloc - first.size());
				ASSERT_EQ(mbuf_arr->size(), 0);
				ASSERT_EQ(mempool.count(), to_alloc);

				ASSERT_EQ(first.get_data(0).val, 0xB00B135);
			}();
			return std::move(second);
		}();

		ASSERT_EQ(mempool.count(), to_alloc / 2);
	}
	ASSERT_EQ(mempool.count(), 0);

	// Test insert function
	{
		constexpr size_t to_alloc = 344;
		auto mbuf_arr = RTEMbufArray<TestObject, ARRAY_SIZE, type>::init(mempool, to_alloc);
		EXPECT_EQ(mbuf_arr.has_value(), true);

		for (size_t i = 0; i < to_alloc; i++)
			mbuf_arr->get_data(i).val = i;

		constexpr size_t to_alloc_insert_1 = 112;
		auto to_insert_1 =
		    RTEMbufArray<TestObject, ARRAY_SIZE, type>::init(mempool, to_alloc_insert_1);
		EXPECT_EQ(to_insert_1.has_value(), true);

		for (size_t i = 0; i < to_alloc_insert_1; i++)
			to_insert_1->get_data(i).val = to_alloc + i;

		static_assert(to_alloc + to_alloc_insert_1 < ARRAY_SIZE);

		auto ret_insert_1 = mbuf_arr->insert(std::move(*to_insert_1));
		EXPECT_EQ(mbuf_arr->size(), to_alloc + to_alloc_insert_1);
		EXPECT_EQ(ret_insert_1.size(), 0);

		for (size_t i = 0; i < to_alloc + to_alloc_insert_1; i++)
			EXPECT_EQ(mbuf_arr->get_data(i).val, i);

		auto to_insert_2 =
		    RTEMbufArray<TestObject, ARRAY_SIZE, type>::init(mempool, ARRAY_SIZE);
		EXPECT_EQ(to_insert_1.has_value(), true);

		auto ret_insert_2 = mbuf_arr->insert(std::move(*to_insert_2));
		EXPECT_EQ(mbuf_arr->size(), ARRAY_SIZE);
		EXPECT_EQ(ret_insert_2.size(), to_alloc + to_alloc_insert_1);
	}

	ASSERT_EQ(mempool.count(), 0);

	// Test that elements are reusable
	{
		using MbufArrayType = RTEMbufArray<TestObject, ARRAY_SIZE, type>;

		// Use all elements in the mempool twice to check that
		// the destructed elements are usable
		for (int iter = 0; iter < 2; iter++) {
			int cnt = 0;
			std::vector<MbufArrayType, RteAllocator<MbufArrayType>> mbufs;
			tl::expected<MbufArrayType, int> res = tl::unexpected<int>(0);
			while ((res = MbufArrayType::init(mempool, ARRAY_SIZE, cnt++))) {
				mbufs.emplace_back(std::move(res.value()));
			}

			for (size_t i = 0; i < mbufs.size(); i++) {
				for (size_t j = 0; j < mbufs[i].size(); j++)
					EXPECT_EQ(mbufs[i].get_data(j).val, i);
			}
		}
	}

	// Test pop function
	{
		constexpr size_t to_alloc = 532;
		auto mbuf_arr = RTEMbufArray<TestObject, ARRAY_SIZE, type>::init(mempool, to_alloc);
		EXPECT_EQ(mbuf_arr.has_value(), true);

		for (size_t i = 0; i < to_alloc; i++)
			mbuf_arr->get_data(i).val = i;

		for (size_t i = 0; i < to_alloc; i++) {
			auto elem = mbuf_arr->pop();
			EXPECT_EQ(elem.has_value(), true);
			EXPECT_EQ(elem->get_data().val, to_alloc - i - 1);
		}

		auto elem = mbuf_arr->pop();
		EXPECT_EQ(elem.has_value(), false);
	}

	// Test push function
	{
		constexpr size_t to_alloc = ARRAY_SIZE;
		auto mbuf_arr = RTEMbufArray<TestObject, ARRAY_SIZE, type>::init(mempool, to_alloc);
		EXPECT_EQ(mbuf_arr.has_value(), true);

		auto mbuf_arr2 = RTEMbufArray<TestObject, ARRAY_SIZE, type>::init(mempool);
		EXPECT_EQ(mbuf_arr2.has_value(), true);

		for (size_t i = 0; i < to_alloc; i++)
			mbuf_arr->get_data(i).val = i;

		for (size_t i = 0; i < to_alloc; i++) {
			auto elem = mbuf_arr->pop();
			EXPECT_EQ(elem.has_value(), true);
			EXPECT_EQ(elem->get_data().val, to_alloc - i - 1);

			auto push = mbuf_arr2->push(std::move(*elem));
			EXPECT_EQ(push.has_value(), false);
			EXPECT_EQ(mbuf_arr2->size(), i + 1);
		}

		auto elem = mbuf_arr->pop();
		EXPECT_EQ(elem.has_value(), false);

		mbuf_arr = RTEMbufArray<TestObject, ARRAY_SIZE, type>::init(mempool, to_alloc);
		EXPECT_EQ(mbuf_arr.has_value(), true);

		elem = mbuf_arr->pop();
		EXPECT_EQ(elem.has_value(), true);

		auto push_res = mbuf_arr2->push(std::move(*elem));
		EXPECT_EQ(push_res.has_value(), true);
	}
}

TEST(DPDKWrappers, RTEPktMbufArrayTest) {
	// Set of general tests that can be performed for both MbufType::Raw and MbufType::Pkt
	{
		auto mempool =
		    RTEMempool<TestObject, MbufType::Raw>::init("mempool", MEMPOOL_SIZE, 0, 0, 0);
		ASSERT_EQ(mempool.has_value(), true);
		RTEMbufArrayTest<MbufType::Raw>(std::move(*mempool));
	}
	{
		auto mempool =
		    RTEMempool<TestObject, MbufType::Pkt>::init("mempool", MEMPOOL_SIZE, 0, 0);
		ASSERT_EQ(mempool.has_value(), true);
		RTEMbufArrayTest<MbufType::Pkt>(std::move(*mempool));
	}

	// Test operator[] for MbufType::Raw
	{
		constexpr size_t to_alloc = 973;
		auto mempool =
		    RTEMempool<TestObject, MbufType::Raw>::init("mempool", MEMPOOL_SIZE, 0, 0, 0);
		ASSERT_EQ(mempool.has_value(), true);
		auto mbuf_arr =
		    RTEMbufArray<TestObject, ARRAY_SIZE, MbufType::Raw>::init(*mempool, to_alloc);
		ASSERT_EQ(mbuf_arr.has_value(), true);

		for (size_t i = 0; i < to_alloc; i++)
			(*mbuf_arr)[i].val = i;

		for (size_t i = 0; i < to_alloc; i++)
			EXPECT_EQ((*mbuf_arr)[i].val, i);
	}

	// Test operator[] for MbufType::Pkt
	{
		constexpr size_t to_alloc = 973;
		auto mempool =
		    RTEMempool<TestObject, MbufType::Pkt>::init("mempool", MEMPOOL_SIZE, 0, 0);
		ASSERT_EQ(mempool.has_value(), true);
		auto mbuf_arr =
		    RTEMbufArray<TestObject, ARRAY_SIZE, MbufType::Pkt>::init(*mempool, to_alloc);
		ASSERT_EQ(mbuf_arr.has_value(), true);

		for (size_t i = 0; i < to_alloc; i++) {
			RTEMbuf<TestObject>& mbuf_obj = (*mbuf_arr)[i];
			mbuf_obj.data().val = i;
		}

		for (size_t i = 0; i < to_alloc; i++) {
			RTEMbuf<TestObject>& mbuf_obj = (*mbuf_arr)[i];
			EXPECT_EQ(mbuf_obj.data().val, i);
		}
	}

	// Test making pktmbuf using span
	{
		constexpr size_t to_alloc = 242;
		auto mempool =
		    RTEMempool<DefaultPacket, MbufType::Pkt>::init("mempool2", MEMPOOL_SIZE, 0, 0);
		ASSERT_EQ(mempool.has_value(), true);
		{
			std::array<RTEMbuf<DefaultPacket>*, ARRAY_SIZE> objects;
			int res = rte_pktmbuf_alloc_bulk(mempool->get(), (rte_mbuf**) &objects[0],
			    to_alloc);

			EXPECT_EQ(res, 0);

			EXPECT_EQ(mempool->count(), to_alloc);

			auto objects_span = std::span{&objects[0], to_alloc};

			RTEMbufArray<DefaultPacket, ARRAY_SIZE, MbufType::Pkt> mbuf_arr(
			    std::move(objects_span));
		}

		// All packets should have been freed from the mempool
		EXPECT_EQ(mempool->count(), 0);
	}

	// Test release function
	{
		constexpr size_t to_alloc = 124;
		auto mempool =
		    RTEMempool<DefaultPacket, MbufType::Pkt>::init("mempool", MEMPOOL_SIZE, 0, 0);
		ASSERT_EQ(mempool.has_value(), true);
		std::array<RTEMbuf<DefaultPacket>*, ARRAY_SIZE> objects_to_free;
		{
			auto mbuf_arr =
			    RTEMbufArray<DefaultPacket, ARRAY_SIZE, MbufType::Pkt>::init(*mempool,
				to_alloc);
			EXPECT_EQ(mbuf_arr.has_value(), true);

			EXPECT_EQ(mbuf_arr->size(), to_alloc);

			EXPECT_EQ(mempool->count(), to_alloc);

			std::copy(mbuf_arr->data(), mbuf_arr->data() + mbuf_arr->size(),
			    objects_to_free.begin());

			mbuf_arr->release();
		}

		// All packets should be still in use
		EXPECT_EQ(mempool->count(), to_alloc);

		rte_pktmbuf_free_bulk((rte_mbuf**) &objects_to_free[0], to_alloc);

		// All packets should have been freed from the mempool
		EXPECT_EQ(mempool->count(), 0);
	}

	// Test regular iterator and const iterator
	{
		constexpr size_t to_alloc = 544;
		auto mempool =
		    RTEMempool<TestObject, MbufType::Pkt>::init("mempool", MEMPOOL_SIZE, 0, 0);
		ASSERT_EQ(mempool.has_value(), true);
		auto mbuf_arr =
		    RTEMbufArray<TestObject, ARRAY_SIZE, MbufType::Pkt>::init(*mempool, to_alloc);
		EXPECT_EQ(mbuf_arr.has_value(), true);

		EXPECT_EQ(mbuf_arr->size(), to_alloc);

		int val_cnt = 0;
		for (auto& obj : *mbuf_arr)
			obj.data().val = val_cnt++;

		for (size_t i = 0; i < to_alloc; i++)
			EXPECT_EQ((*mbuf_arr)[i].data().val, i);

		auto mbuf_arr_const = RTEMbufArray<TestObject, ARRAY_SIZE, MbufType::Pkt>::init(
		    *mempool, to_alloc, 10);
		EXPECT_EQ(mbuf_arr.has_value(), true);
		for (const auto& obj : *mbuf_arr_const)
			EXPECT_EQ(obj.data().val, 10);
	}
}

template <MbufType type>
void RTERingTest(RTEMempool<TestObject, type>& mempool, RTERing<TestObject, type>& ring) {
	// Test adding and removing individual elements
	TestObject::obj_count = 0;
	TestObject::copy_constructor_count = 0;
	{
		constexpr size_t to_add = 973;

		for (size_t i = 0; i < to_add; i++) {
			auto elem = RTEMbufElement<TestObject, type>::init(mempool);
			ASSERT_EQ(elem.has_value(), true);
			elem->get_data().val = i;
			auto ret = ring.enqueue(std::move(*elem));
			EXPECT_EQ(ret, std::nullopt);
		}

		EXPECT_EQ(ring.count(), to_add);
		EXPECT_EQ(TestObject::obj_count, to_add);

		for (size_t i = 0; i < to_add; i++) {
			auto elem = ring.dequeue();
			EXPECT_EQ(elem.has_value(), true);
			EXPECT_EQ(elem->get_data().val, i);
		}

		auto elem = ring.dequeue();
		EXPECT_EQ(elem.has_value(), false);
		EXPECT_EQ(ring.count(), 0);
		EXPECT_EQ(TestObject::obj_count, 0);
		EXPECT_EQ(mempool.count(), 0);
	}

	// Try to overfill ring
	{
		EXPECT_EQ(ring.count(), 0);
		for (size_t i = 0; i < ring.capacity(); i++) {
			auto elem = RTEMbufElement<TestObject, type>::init(mempool);
			ASSERT_EQ(elem.has_value(), true);
			auto ret = ring.enqueue(std::move(*elem));
			EXPECT_EQ(ret, std::nullopt);
		}
		EXPECT_EQ(ring.count(), ring.capacity());

		auto elem = RTEMbufElement<TestObject, type>::init(mempool);
		ASSERT_EQ(elem.has_value(), true);
		auto ret = ring.enqueue(std::move(*elem));
		EXPECT_EQ(ret, true);
	}

	EXPECT_EQ(mempool.count(), ring.count());

	// while(ring.dequeue());
}

template <MbufType type, size_t N>
void RTERingArrayTest(RTEMempool<TestObject, type>& mempool, RTERing<TestObject, type>& ring) {
	// Test with a bunch of array sizes
	constexpr size_t to_alloc = static_cast<size_t>(0.75 * N);
	const size_t queue_limit = std::min(ring.capacity(), to_alloc);

	auto mbuf_arr = RTEMbufArray<TestObject, N, type>::init(mempool, to_alloc);
	EXPECT_EQ(mbuf_arr.has_value(), true);
	mbuf_arr->get_data(0).val = 0xB00B135;

	// Test we can enqueue an array.
	{
		auto not_enqueued = ring.enqueue_burst(std::move(*mbuf_arr));
		ASSERT_EQ(not_enqueued.size() + ring.count(), to_alloc);
	}

	ASSERT_EQ(mempool.count(), queue_limit);

	// Test the first element can be recovered successfully.
	{
		auto dequeued = ring.dequeue();
		ASSERT_EQ(dequeued, true);
		ASSERT_EQ(dequeued->get_data().val, 0xB00B135);
	}

	// Test the second element can be recovered successfully.
	{
		auto dequeued = ring.dequeue();
		ASSERT_EQ(dequeued, true);
		ASSERT_EQ(dequeued->get_data().val, 0x0);
	}

	// Test we can dequeue all of the remaining packets into an array.
	{
		auto dequeued = ring.template dequeue_burst<ARRAY_SIZE>();
		ASSERT_EQ(dequeued.size(), queue_limit - 2);
		ASSERT_EQ(ring.count(), 0);
	}

	ASSERT_EQ(mempool.count(), 0);
}

TEST(DPDKWrappers, RTERingTest) {
	// Set of general tests that can be performed for both MbufType::Raw and MbufType::Pkt
	{
		auto mempool =
		    RTEMempool<TestObject, MbufType::Raw>::init("mempool", MEMPOOL_SIZE, 0, 0, 0);
		ASSERT_EQ(mempool.has_value(), true);
		auto ring = RTERing<TestObject, MbufType::Raw>::init("ring", *mempool, RING_SIZE,
		    RING_FLAGS);
		EXPECT_EQ(ring.has_value(), true);
		RTERingTest<MbufType::Raw>(*mempool, *ring);
	}
	{
		auto mempool =
		    RTEMempool<TestObject, MbufType::Pkt>::init("mempool", MEMPOOL_SIZE, 0, 0);
		ASSERT_EQ(mempool.has_value(), true);
		auto ring = RTERing<TestObject, MbufType::Pkt>::init("ring", RING_SIZE, RING_FLAGS);
		EXPECT_EQ(ring.has_value(), true);
		RTERingTest<MbufType::Pkt>(*mempool, *ring);
	}

	// Test ring destructor by placing ring in different scope.
	{
		auto mempool =
		    RTEMempool<TestObject, MbufType::Raw>::init("mempool", MEMPOOL_SIZE, 0, 0, 0);
		ASSERT_EQ(mempool.has_value(), true);
		{
			auto ring = RTERing<TestObject, MbufType::Raw>::init("ring", *mempool,
			    RING_SIZE, RING_FLAGS);
			EXPECT_EQ(ring.has_value(), true);
			EXPECT_EQ(ring->count(), 0);
			EXPECT_EQ(mempool->count(), 0);

			for (size_t i = 0; i < ring->capacity(); i++) {
				auto elem =
				    RTEMbufElement<TestObject, MbufType::Raw>::init(*mempool);
				auto ret = ring->enqueue(std::move(*elem));
				EXPECT_EQ(ret, std::nullopt);
			}

			EXPECT_EQ(ring->count(), ring->capacity());
			EXPECT_EQ(mempool->count(), ring->count());
		}

		EXPECT_EQ(mempool->count(), 0);
	}
}

template <typename T>
struct ArrayTests : public ::testing::Test {
	static constexpr auto ArraySize = T::Val;
	static constexpr auto PoolSize = ArraySize * 2;
};

namespace _detail {
template <size_t N>
struct V {
	static constexpr auto Val = N;
};
using ArraySizes = ::testing::Types<V<5>, V<34>, V<128>, V<604>, V<1026>, V<2033>, V<3099>>;
} // namespace _detail

TYPED_TEST_SUITE(ArrayTests, _detail::ArraySizes);

TYPED_TEST(ArrayTests, RTERingArrayTest) {
	constexpr auto ArraySize = TestFixture::ArraySize;
	constexpr auto PoolSize = TestFixture::PoolSize;

	{
		auto mempool =
		    RTEMempool<TestObject, MbufType::Raw>::init("mempool", PoolSize, 0, 0, 0);
		EXPECT_EQ(mempool.has_value(), true);
		auto ring = RTERing<TestObject, MbufType::Raw>::init("ring", *mempool, RING_SIZE,
		    RING_FLAGS);
		EXPECT_EQ(ring.has_value(), true);
		RTERingArrayTest<MbufType::Raw, ArraySize>(*mempool, *ring);
	}
	{
		auto mempool =
		    RTEMempool<TestObject, MbufType::Pkt>::init("mempool", PoolSize, 0, 0, 0);
		EXPECT_EQ(mempool.has_value(), true);
		auto ring = RTERing<TestObject, MbufType::Pkt>::init("ring", RING_SIZE, RING_FLAGS);
		EXPECT_EQ(ring.has_value(), true);
		RTERingArrayTest<MbufType::Pkt, ArraySize>(*mempool, *ring);
	}
}
