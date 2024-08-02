#pragma once

#include <expected.h>

#include <glaze/core/read.hpp>
#include <glaze/glaze.hpp>
#include <vector>

#include "dns_format.h"
#include "network_types.h"

inline tl::expected<std::vector<InAddr>, std::string> ParseResolvers(std::string input) {
	std::vector<InAddr> resolvers;
	std::ifstream file(input);

	if (file.is_open()) {
		// The input is a filename
		std::string line;
		int lineNumber = 0;
		while (std::getline(file, line)) {
			lineNumber++;
			line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());
			if (line.empty()) {
				continue;
			}
			auto addr_opt = InAddr::init(line);
			if (!addr_opt.has_value()) {
				return tl::unexpected("Invalid IP address at line " +
						      std::to_string(lineNumber) + ": " + line);
			}
			resolvers.push_back(addr_opt.value());
		}
	} else {
		// The input is a comma-separated list of resolvers
		std::istringstream stream(input);
		std::string token;
		while (std::getline(stream, token, ',')) {
			token.erase(std::remove_if(token.begin(), token.end(), ::isspace),
			    token.end());
			if (token.empty()) {
				continue;
			}
			auto addr_opt = InAddr::init(token);
			if (!addr_opt.has_value()) {
				return tl::unexpected(
				    "Invalid IP address in list / cannot open file: " + token);
			}
			resolvers.push_back(addr_opt.value());
		}
	}

	if (resolvers.empty()) {
		return tl::unexpected("No valid IP addresses found.");
	}

	return resolvers;
}

inline tl::expected<std::vector<DnsRCode>, std::string> ParseDNSReturnCodes(std::string input) {
	std::vector<DnsRCode> return_codes;

	// The input is a comma-separated list of resolvers
	std::istringstream stream(input);
	std::string token;
	while (std::getline(stream, token, ',')) {
		token.erase(std::remove_if(token.begin(), token.end(), ::isspace), token.end());
		if (token.empty()) {
			continue;
		}
		auto res = GetRCodeFromMessage(token);
		if (!res)
			return tl::unexpected("Cannot read DNS return code " + token);

		return_codes.push_back(res.value());
	}

	if (return_codes.empty())
		return tl::unexpected("No DNS return codes found");

	return return_codes;
}
