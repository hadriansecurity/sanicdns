#include <gtest/gtest.h>
#include <rte_eal.h>

#include <vector>

int main(int argc, char **argv) {
	::testing::InitGoogleTest(&argc, argv);

	// The unit tests don't use a physical NIC, so prevent EAL from probing the
	// PCI bus. Without this, EAL probes whatever NIC the host exposes (e.g. the
	// Azure MANA adapter on GitHub's runners), and those third-party poll-mode
	// drivers leak memory during probe, which trips LeakSanitizer and fails the
	// tests in Debug/ASan builds.
	std::vector<char *> eal_args(argv, argv + argc);
	char no_pci[] = "--no-pci";
	eal_args.push_back(no_pci);
	int eal_argc = static_cast<int>(eal_args.size());
	char **eal_argv = eal_args.data();

	rte_eal_init(eal_argc, eal_argv);

	int retval = RUN_ALL_TESTS();

	rte_eal_cleanup();

	return retval;
}
