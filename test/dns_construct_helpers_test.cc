#include "dns_construct_helpers.h"

#include <gtest/gtest.h>

TEST(DnsHelperTest, DNSNameTest) {
	std::vector<std::pair<std::string, std::string>> test_expected;

	test_expected.push_back(
	    std::make_pair(std::string("www.google.com"), std::string("\x03"
								      "www\x06"
								      "google\x03"
								      "com")));
	test_expected.push_back(
	    std::make_pair(std::string("www.google.com."), std::string("\x03"
								       "www\x06"
								       "google\x03"
								       "com")));
	test_expected.push_back(std::make_pair(std::string("testadmin.hadrian.www.google.com"),
	    std::string("\x09"
			"testadmin\x07"
			"hadrian\x03"
			"www\x06"
			"google\x03"
			"com")));
	test_expected.push_back(std::make_pair(std::string("a.b.c.d.e.f.g.h.i.j.k."),
	    std::string("\1a\1b\1c\1d\1e\1f\1g\1h\1i\1j\1k")));
	test_expected.push_back(std::make_pair(std::string(""), std::string("")));
	test_expected.push_back(std::make_pair(std::string("."), std::string("")));
	test_expected.push_back(std::make_pair(std::string("....."), std::string("\0\0\0\0")));

	for (auto elem : test_expected) {
		char buf[256];
		char* new_buf_pos =
		    DNSHelpers::ChangetoDnsNameFormat(buf, elem.first.c_str(), elem.first.length());

		EXPECT_STREQ(buf, elem.second.c_str());

		// NULL terminator has to be included
		EXPECT_EQ(*(new_buf_pos - 1), '\0');
	}
}
