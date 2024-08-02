#include "thread_manager.h"

#include <gtest/gtest.h>

#include <iostream>

#include "spdlog/spdlog.h"

// Class that keeps track of how many times it has been moved and copied
class TestClass {
public:
	TestClass() : copy_count(0), move_count(0) { }

	TestClass(const TestClass& other) {
		copy_count = other.copy_count + 1;
		move_count = other.move_count;
	}

	TestClass(TestClass&& other) {
		copy_count = other.copy_count;
		move_count = other.move_count + 1;
	}

	size_t GetCopyCount() const {
		return copy_count;
	}
	size_t GetMoveCount() const {
		return move_count;
	}

private:
	size_t copy_count;
	size_t move_count;
};

TEST(ThreadManagerTest, CopyMoveTest) {
	TestClass a;
	TestClass b;
	TestClass c;
	TestClass d;

	ThreadManager manager;

	// Check if copying, moving and referencing works as expected without stop token
	auto res = manager.LaunchThread(
	    [](TestClass a, TestClass b, TestClass& c, const TestClass& d) -> int {
		    // a should have been copied and moved 2 times: 1x to the LCoreParams and 1x
		    // into this function
		    EXPECT_EQ(a.GetCopyCount(), 0);
		    EXPECT_EQ(a.GetMoveCount(), 2);

		    // b should have been copied 1x to the LCoreParams and moved 1x into this
		    // function
		    EXPECT_EQ(b.GetCopyCount(), 1);
		    EXPECT_EQ(b.GetMoveCount(), 1);

		    EXPECT_EQ(c.GetCopyCount(), 0);
		    EXPECT_EQ(c.GetMoveCount(), 0);

		    EXPECT_EQ(d.GetCopyCount(), 0);
		    EXPECT_EQ(d.GetMoveCount(), 0);

		    return 0;
	    },
	    std::move(a), b, std::ref(c), std::ref(d));

	EXPECT_EQ(res, ThreadManager::LaunchThreadResult::Success);
}

TEST(ThreadManagerTest, CopyMoveTestToken) {
	TestClass a;
	TestClass b;
	TestClass c;
	TestClass d;

	ThreadManager manager;

	// Check if copying, moving and referencing works as expected without stop token
	auto res = manager.LaunchThread(
	    [](std::stop_token _stop_token, TestClass a, TestClass b, TestClass& c,
		const TestClass& d) -> int {
		    // a should have been copied and moved 2 times: 1x to the LCoreParams and 1x
		    // into this function
		    EXPECT_EQ(a.GetCopyCount(), 0);
		    EXPECT_EQ(a.GetMoveCount(), 2);

		    // b should have been copied 1x to the LCoreParams and moved 1x into this
		    // function
		    EXPECT_EQ(b.GetCopyCount(), 1);
		    EXPECT_EQ(b.GetMoveCount(), 1);

		    EXPECT_EQ(c.GetCopyCount(), 0);
		    EXPECT_EQ(c.GetMoveCount(), 0);

		    EXPECT_EQ(d.GetCopyCount(), 0);
		    EXPECT_EQ(d.GetMoveCount(), 0);

		    while (!_stop_token.stop_requested())
			    ;

		    return 0;
	    },
	    std::move(a), b, std::ref(c), std::ref(d));

	EXPECT_EQ(res, ThreadManager::LaunchThreadResult::Success);
	// Also check that the stop is requested in destructor
}

int BasicFunction() {
	return 0;
}

TEST(ThreadManagerTest, BasicTestTemp) {
	std::atomic<int> result = 0;

	ThreadManager manager;

	// Launch a thread with a temporary to check forwarding, return result using atomic
	// reference. Spinlock stop_token to check the thread exits successfully when request_stop
	// is called
	auto res = manager.LaunchThread(
	    [](std::stop_token _stop_token, std::atomic<int>& result, int a) -> int {
		    result = a;

		    while (!_stop_token.stop_requested()) { }
		    return 0;
	    },
	    std::ref(result), 2);

	EXPECT_EQ(res, ThreadManager::LaunchThreadResult::Success);

	manager.request_stop();
	manager.join();

	EXPECT_EQ(result, 2);
}

TEST(ThreadManagerTest, BasicTestArgs) {
	ThreadManager manager;

	std::string teststr("test2");

	// Launch a thread with multiple arguments and without stop token
	auto res = manager.LaunchThread(
	    [](std::string a, int b, double c, std::string& d) -> int {
		    EXPECT_EQ(a, "test");
		    EXPECT_EQ(b, 6);
		    EXPECT_EQ(c, 6.342);
		    EXPECT_EQ(d, "test2");

		    return 0;
	    },
	    std::string("test"), 6, 6.342, std::ref(teststr));

	EXPECT_EQ(res, ThreadManager::LaunchThreadResult::Success);

	manager.request_stop();
	manager.join();
}

TEST(ThreadManagerTest, BasicTestNonTemp) {
	ThreadManager manager;
	// LaunchThread should also bind to non-temporary function
	auto res = manager.LaunchThread(BasicFunction);
	EXPECT_EQ(res, ThreadManager::LaunchThreadResult::Success);

	manager.request_stop();
	manager.join();
}

TEST(ThreadManagerTest, MaxThreadsTest) {
	std::atomic<int> count = 0;

	ThreadManager manager;

	auto max_treads = manager.GetTotalThreads();

	// Check that we can have all threads add one to count
	for (size_t i = 0; i < max_treads; i++) {
		auto res = manager.LaunchThread(
		    [](std::stop_token _stop_token, std::atomic<int>& count) -> int {
			    count++;

			    while (!_stop_token.stop_requested()) { }
			    return 0;
		    },
		    std::ref(count));

		EXPECT_EQ(manager.GetUnusedThreads(), max_treads - i - 1);
		EXPECT_EQ(res, ThreadManager::LaunchThreadResult::Success);
	}

	auto res = manager.LaunchThread([]() -> int { return 0; });
	EXPECT_EQ(res, ThreadManager::LaunchThreadResult::MaxLCoreReached);

	manager.request_stop();
	manager.join();

	EXPECT_EQ(count, max_treads);
}
