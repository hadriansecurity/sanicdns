add_executable(
	arp_test
	arp_test.cc
)

target_link_libraries(
	arp_test
	gtest_main
	arp
	DPDK::dpdk
)

gtest_discover_tests(arp_test EXTRA_ARGS --no-huge)
