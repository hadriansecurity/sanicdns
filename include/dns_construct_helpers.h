#pragma once
#include "spdlog/spdlog.h"
#include <string.h>

#include <algorithm>

/**
 * @brief Class containing helper functions for constructing a DNS packet
 *
 */
class DNSHelpers {
public:
	static inline char* ChangetoDnsNameFormat(char* dns, const char* host, int host_len);
};

/**
 * @brief This function converts www.google.com to 3www6google3com
 *
 * @param dns Pointer to the current position in the DNS packet
 * @param host Pointer to the original host character buffer, can have trailing dot
 * @param host_len The length of the host character buffer
 * @return char* New buffer position in DNS buffer
 */
char* DNSHelpers::ChangetoDnsNameFormat(char* dns, const char* host, int host_len) {
	int lock = 0, i;

	// Do not count room for an extra character when the last character is a .
	int final_len = host_len + (host[std::max(host_len - 1, 0)] != '.');

	// Cast to unsigned char to prevent overflows
	unsigned char* u_dns = (unsigned char*) dns;

	for (i = 0; i < final_len; i++) {
		if (host[i] == '.' || host[i] == '\0') {
			*u_dns++ = i - lock;
			memcpy(u_dns, host + sizeof(unsigned char) * lock,
			    sizeof(unsigned char) * (i - lock));
			u_dns += i - lock;
			lock = i + 1;
		}
	}
	*u_dns++ = '\0';

	return (char*) u_dns;
}
