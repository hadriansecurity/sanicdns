#include <gtest/gtest.h>
#include <rte_eal.h>

int main(int argc, char **argv) {
	::testing::InitGoogleTest(&argc, argv);

	rte_eal_init(argc, argv);

	int retval = RUN_ALL_TESTS();

	rte_eal_cleanup();

	return retval;
}
