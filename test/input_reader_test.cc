#include "input_reader.h"

#include <gtest/gtest.h>

#include <fstream>
#include <iostream>
#include <string>
#include <vector>

struct test_domain {
	std::string domain_name;
	bool is_valid;
};

void ReadTestDomainsFromFile(std::vector<test_domain>& test_domains, const std::string& file_name) {
	// Open file
	std::ifstream infile(file_name);

	// Read file line by line
	std::string line;
	while (std::getline(infile, line)) {
		test_domains.push_back({line, true});

		// Check for every character in the line if it is valid
		for (const char& test_char : test_domains.back().domain_name) {
			test_domains.back().is_valid &= (test_char >= 'a' && test_char <= 'z') ||
			                                (test_char >= '0' && test_char <= '9') ||
			                                test_char == '-' || test_char == '.';
		}

		// Check if the domain name exceeds the maximum size
		if (test_domains.back().domain_name.length() > DOMAIN_NAME_MAX_SIZE - 1) {
			test_domains.back().is_valid = false;

			// The input reader limits the length of the domain name to
			// DOMAIN_NAME_MAX_SIZE including null terminator
			test_domains.back().domain_name.resize(DOMAIN_NAME_MAX_SIZE - 1);
		}
	}

	// Close file
	infile.close();
}

// Demonstrate basic file read
TEST(InputReaderTest, FileTestBasic) {
	// First read file lines with basic and slow function
	std::string file_name = "test_files/FileTestBasic.txt";

	std::vector<test_domain> test_domains;
	ReadTestDomainsFromFile(test_domains, file_name);

	// Open file for use in the input reader
	FILE* ptr = fopen(file_name.c_str(), "r");
	if (ptr == NULL)
		throw std::runtime_error("Cannot open file");

	InputReader reader(ptr);

	DomainInputInfo domain_info;
	char buf[DOMAIN_NAME_MAX_SIZE];
	domain_info.buf = buf;

	// Loop over every domain found with ReadTestDomainsFromFile
	// and check if input reader yields the same result
	for (const test_domain& domain : test_domains) {
		// Input reader works asynchronously, wait for result to be available
		ReadDomainResult res = ReadDomainResult::NotAvailable;
		while (res == ReadDomainResult::NotAvailable) {
			res = reader.GetDomain(domain_info);
		}

		// File end is only expected after all domains from the test
		// array are finshed
		if (res == ReadDomainResult::FileEnd)
			throw std::runtime_error("File end not expected already");

		EXPECT_STREQ(domain_info.buf, domain.domain_name.c_str());
		EXPECT_EQ(domain.is_valid, res == ReadDomainResult::Success ? true : false);
	}

	// Check if the last result is FileEnd
	ReadDomainResult res = ReadDomainResult::NotAvailable;
	while (res == ReadDomainResult::NotAvailable) {
		res = reader.GetDomain(domain_info);
	}
	EXPECT_EQ(res, ReadDomainResult::FileEnd);

	fclose(ptr);
}

TEST(InputReaderTest, BlockSizeTest) {
	// Initializing reader with power of two block size should not throw an error
	{ InputReader reader_blk(stdin, 1024); }
	{ InputReader reader_blk(stdin, 2048); }
	{ InputReader reader_blk(stdin, 16384); }

	// Initializing reader with block size != power of two should throw an error
	{ EXPECT_THROW(InputReader reader_blk(stdin, 123), std::length_error); }
	{ EXPECT_THROW(InputReader reader_blk(stdin, 1533), std::length_error); }
	{ EXPECT_THROW(InputReader reader_blk(stdin, 764523), std::length_error); }
}
