#pragma once

// Including \0 terminators
#define DOMAIN_NAME_MAX_SIZE 256
#define CHARACTER_STRING_MAX_SIZE 1800
#define CAA_TAG_MAX_SIZE 16

#include <stdint.h>

#include <array>
#include <optional>
#include <string_view>

#include "fixed_name.hpp"

/**
 * @brief Question types for a DNS request
 */
enum class DnsQType {
	A = 1,      // Ipv4 address
	NS = 2,     // Nameserver
	CNAME = 5,  // Canonical name
	SOA = 6,    // Start of authority zone
	PTR = 12,   // Domain name pointer
	MX = 15,    // Mail server
	TXT = 16,   // Txt record
	AAAA = 28,  // Ipv6 address
	DNAME = 39, // Delegation name record
	OPT = 41,    // Edns opt record
    CAA = 257,  // Certificate Authority Authorization
};

template <>
struct glz::meta<DnsQType> {
	using enum DnsQType;
	static constexpr auto value =
	    enumerate(A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, DNAME, CAA, OPT);
};

/**
 * @brief Get printable question type message
 *
 * @param q_type DnsQType to get message for
 * @return const char* DnsQType message
 */
inline const char* GetQTypeMessage(const DnsQType q_type) {
	switch (q_type) {
		case DnsQType::A:
			return "A";
			break;
		case DnsQType::NS:
			return "NS";
			break;
		case DnsQType::CNAME:
			return "CNAME";
			break;
		case DnsQType::DNAME:
			return "DNAME";
			break;
		case DnsQType::SOA:
			return "SOA";
			break;
		case DnsQType::PTR:
			return "PTR";
			break;
		case DnsQType::MX:
			return "MX";
			break;
		case DnsQType::TXT:
			return "TXT";
			break;
		case DnsQType::AAAA:
			return "AAAA";
			break;
		case DnsQType::OPT:
			return "OPT";
			break;

		default:
			return "unknown";
			break;
	}
}

/**
 * @brief Convert QType string representation to its enum equivalent.
 *
 * @param q_type QType to get enum value for
 * @return DnsQType equivalent of q_type
 */
inline std::optional<DnsQType> GetQTypeFromString(std::string_view q_type) {
	if (q_type == "A") {
		return DnsQType::A;
	} else if (q_type == "NS") {
		return DnsQType::NS;
	} else if (q_type == "CNAME") {
		return DnsQType::CNAME;
	} else if (q_type == "DNAME") {
		return DnsQType::DNAME;
	} else if (q_type == "SOA") {
		return DnsQType::SOA;
	} else if (q_type == "PTR") {
		return DnsQType::PTR;
	} else if (q_type == "MX") {
		return DnsQType::MX;
	} else if (q_type == "TXT") {
		return DnsQType::TXT;
	} else if (q_type == "AAAA") {
		return DnsQType::AAAA;
	} else if (q_type == "OPT") {
		return DnsQType::OPT;
	}

	return std::nullopt;
}

/**
 * @brief Error codes for a DNS request
 */
enum class DnsRCode {
	NOERROR = 0,
	FORMERROR = 1,
	SERVFAIL = 2,
	NXDOMAIN = 3,
	NOTIMP = 4,
	REFUSED = 5,
	YXDOMAIN = 6,
	XYRRSET = 7,
	NXRRSET = 8,
	NOTAUTH = 9,
	NOTZONE = 10,
	DSOTYPENI = 11,
	BADVERS = 16,
	BADKEY = 17,
	BADTIME = 18,
	BADMODE = 19,
	BADNAM = 20,
	BADALG = 21,
	BADTRUNC = 22,
	BADCOOKIE = 23
};

template <>
struct glz::meta<DnsRCode> {
	using enum DnsRCode;
	static constexpr auto value =
	    enumerate(NOERROR, FORMERROR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED,
		YXDOMAIN, XYRRSET, NXRRSET, NOTAUTH, NOTZONE, DSOTYPENI, BADVERS,
		BADKEY, BADTIME, BADMODE, BADNAM, BADALG, BADTRUNC, BADCOOKIE);
};

/**
 * @brief Get printable error code message
 *
 * @param r_code DnsRCode to get message for
 * @return const char* DnsRCode message
 */
inline const char* GetRCodeMessage(const DnsRCode r_code) {
	switch (r_code) {
		case DnsRCode::NOERROR:
			return "NOERROR";
			break;
		case DnsRCode::FORMERROR:
			return "FORMERROR";
			break;
		case DnsRCode::SERVFAIL:
			return "SERVFAIL";
			break;
		case DnsRCode::NXDOMAIN:
			return "NXDOMAIN";
			break;
		case DnsRCode::NOTIMP:
			return "NOTIMP";
			break;
		case DnsRCode::REFUSED:
			return "REFUSED";
			break;
		case DnsRCode::YXDOMAIN:
			return "YXDOMAIN";
			break;
		case DnsRCode::XYRRSET:
			return "XYRRSET";
			break;
		case DnsRCode::NOTAUTH:
			return "NOTAUTH";
			break;
		case DnsRCode::NOTZONE:
			return "NOTZONE";
			break;
		case DnsRCode::DSOTYPENI:
			return "DSOTYPENI";
			break;
		case DnsRCode::BADVERS:
			return "BADVERS";
			break;
		case DnsRCode::BADKEY:
			return "BADKEY";
			break;
		case DnsRCode::BADTIME:
			return "BADTIME";
			break;
		case DnsRCode::BADMODE:
			return "BADMODE";
			break;
		case DnsRCode::BADNAM:
			return "BADNAM";
			break;
		case DnsRCode::BADALG:
			return "BADALG";
			break;
		case DnsRCode::BADTRUNC:
			return "BADTRUNC";
			break;
		case DnsRCode::BADCOOKIE:
			return "BADCOOKIE";
			break;

		default:
			return "unknown";
			break;
	}
}

/**
 * @brief Get DnsRCode from error message string
 *
 * @param error_msg std::string_view containing the error message
 * @return DnsRCode corresponding to the error message
 */
inline std::optional<DnsRCode> GetRCodeFromMessage(std::string_view error_msg) {
	if (error_msg == "NOERROR")
		return DnsRCode::NOERROR;
	else if (error_msg == "FORMERROR")
		return DnsRCode::FORMERROR;
	else if (error_msg == "SERVFAIL")
		return DnsRCode::SERVFAIL;
	else if (error_msg == "NXDOMAIN")
		return DnsRCode::NXDOMAIN;
	else if (error_msg == "NOTIMP")
		return DnsRCode::NOTIMP;
	else if (error_msg == "REFUSED")
		return DnsRCode::REFUSED;
	else if (error_msg == "YXDOMAIN")
		return DnsRCode::YXDOMAIN;
	else if (error_msg == "XYRRSET")
		return DnsRCode::XYRRSET;
	else if (error_msg == "NOTAUTH")
		return DnsRCode::NOTAUTH;
	else if (error_msg == "NOTZONE")
		return DnsRCode::NOTZONE;
	else if (error_msg == "DSOTYPENI")
		return DnsRCode::DSOTYPENI;
	else if (error_msg == "BADVERS")
		return DnsRCode::BADVERS;
	else if (error_msg == "BADKEY")
		return DnsRCode::BADKEY;
	else if (error_msg == "BADTIME")
		return DnsRCode::BADTIME;
	else if (error_msg == "BADMODE")
		return DnsRCode::BADMODE;
	else if (error_msg == "BADNAM")
		return DnsRCode::BADNAM;
	else if (error_msg == "BADALG")
		return DnsRCode::BADALG;
	else if (error_msg == "BADTRUNC")
		return DnsRCode::BADTRUNC;
	else if (error_msg == "BADCOOKIE")
		return DnsRCode::BADCOOKIE;

	return std::nullopt;
}

/**
 * @brief Constant sized fields of the resource record structure
 */
struct [[gnu::packed]] RData {
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
};

/**
 * @brief Constant sized fields of query structure
 */
struct [[gnu::packed]] QuestionInfo {
	unsigned short qtype;
	unsigned short qclass;
};

using DnsName = FixedName<DOMAIN_NAME_MAX_SIZE>;
using TxtString = FixedName<CHARACTER_STRING_MAX_SIZE>;
using CAATag = FixedName<CAA_TAG_MAX_SIZE>;

/**
 * @brief DNS header structure
 */
struct [[gnu::packed]] DnsHeader {
	unsigned short id; // identification number

	unsigned char rd     : 1; // recursion desired
	unsigned char tc     : 1; // truncated message
	unsigned char aa     : 1; // authoritive answer
	unsigned char opcode : 4; // purpose of message
	unsigned char qr     : 1; // query/response flag

	unsigned char rcode : 4; // response code
	unsigned char cd    : 1; // checking disabled
	unsigned char ad    : 1; // authenticated data
	unsigned char z     : 1; // its z! reserved
	unsigned char ra    : 1; // recursion available

	unsigned short q_count;    // number of question entries
	unsigned short ans_count;  // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count;  // number of resource entries
};
