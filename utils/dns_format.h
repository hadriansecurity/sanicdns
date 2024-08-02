#pragma once

#define DOMAIN_NAME_MAX_SIZE 256
#define CHARACTER_STRING_MAX_SIZE 1800

#include <stdint.h>

#include <array>
#include <optional>
#include <string_view>

#include "fixed_name.hpp"

/**
 * @brief Question types for a DNS request
 */
enum class DnsQType {
	T_A = 1,      // Ipv4 address
	T_NS = 2,     // Nameserver
	T_CNAME = 5,  // Canonical name
	T_SOA = 6,    // Start of authority zone
	T_PTR = 12,   // Domain name pointer
	T_MX = 15,    // Mail server
	T_TXT = 16,   // Txt record
	T_AAAA = 28,  // Ipv6 address
	T_DNAME = 39, // Delegation name record
	T_OPT = 41    // Edns opt record
};

template <>
struct glz::meta<DnsQType> {
	using enum DnsQType;
	static constexpr auto value =
	    enumerate(T_A, T_NS, T_CNAME, T_SOA, T_PTR, T_MX, T_TXT, T_AAAA, T_DNAME, T_OPT);
};

/**
 * @brief Get printable question type message
 *
 * @param q_type DnsQType to get message for
 * @return const char* DnsQType message
 */
inline const char* GetQTypeMessage(const DnsQType q_type) {
	switch (q_type) {
		case DnsQType::T_A:
			return "T_A";
			break;
		case DnsQType::T_NS:
			return "T_NS";
			break;
		case DnsQType::T_CNAME:
			return "T_CNAME";
			break;
		case DnsQType::T_DNAME:
			return "T_DNAME";
			break;
		case DnsQType::T_SOA:
			return "T_SOA";
			break;
		case DnsQType::T_PTR:
			return "T_PTR";
			break;
		case DnsQType::T_MX:
			return "T_MX";
			break;
		case DnsQType::T_TXT:
			return "T_TXT";
			break;
		case DnsQType::T_AAAA:
			return "T_AAAA";
			break;
		case DnsQType::T_OPT:
			return "T_OPT";
			break;

		default:
			return "T_unknown";
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
	if (q_type == "T_A") {
		return DnsQType::T_A;
	} else if (q_type == "T_NS") {
		return DnsQType::T_NS;
	} else if (q_type == "T_CNAME") {
		return DnsQType::T_CNAME;
	} else if (q_type == "T_DNAME") {
		return DnsQType::T_DNAME;
	} else if (q_type == "T_SOA") {
		return DnsQType::T_SOA;
	} else if (q_type == "T_PTR") {
		return DnsQType::T_PTR;
	} else if (q_type == "T_MX") {
		return DnsQType::T_MX;
	} else if (q_type == "T_TXT") {
		return DnsQType::T_TXT;
	} else if (q_type == "T_AAAA") {
		return DnsQType::T_AAAA;
	} else if (q_type == "T_OPT") {
		return DnsQType::T_OPT;
	}

	return std::nullopt;
}

/**
 * @brief Error codes for a DNS request
 */
enum class DnsRCode {
	R_NOERROR = 0,
	R_FORMERROR = 1,
	R_SERVFAIL = 2,
	R_NXDOMAIN = 3,
	R_NOTIMP = 4,
	R_REFUSED = 5,
	R_YXDOMAIN = 6,
	R_XYRRSET = 7,
	R_NXRRSET = 8,
	R_NOTAUTH = 9,
	R_NOTZONE = 10,
	R_DSOTYPENI = 11,
	R_BADVERS = 16,
	R_BADKEY = 17,
	R_BADTIME = 18,
	R_BADMODE = 19,
	R_BADNAM = 20,
	R_BADALG = 21,
	R_BADTRUNC = 22,
	R_BADCOOKIE = 23
};

template <>
struct glz::meta<DnsRCode> {
	using enum DnsRCode;
	static constexpr auto value =
	    enumerate(R_NOERROR, R_FORMERROR, R_SERVFAIL, R_NXDOMAIN, R_NOTIMP, R_REFUSED,
		R_YXDOMAIN, R_XYRRSET, R_NXRRSET, R_NOTAUTH, R_NOTZONE, R_DSOTYPENI, R_BADVERS,
		R_BADKEY, R_BADTIME, R_BADMODE, R_BADNAM, R_BADALG, R_BADTRUNC, R_BADCOOKIE);
};

/**
 * @brief Get printable error code message
 *
 * @param r_code DnsRCode to get message for
 * @return const char* DnsRCode message
 */
inline const char* GetRCodeMessage(const DnsRCode r_code) {
	switch (r_code) {
		case DnsRCode::R_NOERROR:
			return "R_NOERROR";
			break;
		case DnsRCode::R_FORMERROR:
			return "R_FORMERROR";
			break;
		case DnsRCode::R_SERVFAIL:
			return "R_SERVFAIL";
			break;
		case DnsRCode::R_NXDOMAIN:
			return "R_NXDOMAIN";
			break;
		case DnsRCode::R_NOTIMP:
			return "R_NOTIMP";
			break;
		case DnsRCode::R_REFUSED:
			return "R_REFUSED";
			break;
		case DnsRCode::R_YXDOMAIN:
			return "R_YXDOMAIN";
			break;
		case DnsRCode::R_XYRRSET:
			return "R_XYRRSET";
			break;
		case DnsRCode::R_NOTAUTH:
			return "R_NOTAUTH";
			break;
		case DnsRCode::R_NOTZONE:
			return "R_NOTZONE";
			break;
		case DnsRCode::R_DSOTYPENI:
			return "R_DSOTYPENI";
			break;
		case DnsRCode::R_BADVERS:
			return "R_BADVERS";
			break;
		case DnsRCode::R_BADKEY:
			return "R_BADKEY";
			break;
		case DnsRCode::R_BADTIME:
			return "R_BADTIME";
			break;
		case DnsRCode::R_BADMODE:
			return "R_BADMODE";
			break;
		case DnsRCode::R_BADNAM:
			return "R_BADNAM";
			break;
		case DnsRCode::R_BADALG:
			return "R_BADALG";
			break;
		case DnsRCode::R_BADTRUNC:
			return "R_BADTRUNC";
			break;
		case DnsRCode::R_BADCOOKIE:
			return "R_BADCOOKIE";
			break;

		default:
			return "R_unknown";
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
	if (error_msg == "R_NOERROR")
		return DnsRCode::R_NOERROR;
	else if (error_msg == "R_FORMERROR")
		return DnsRCode::R_FORMERROR;
	else if (error_msg == "R_SERVFAIL")
		return DnsRCode::R_SERVFAIL;
	else if (error_msg == "R_NXDOMAIN")
		return DnsRCode::R_NXDOMAIN;
	else if (error_msg == "R_NOTIMP")
		return DnsRCode::R_NOTIMP;
	else if (error_msg == "R_REFUSED")
		return DnsRCode::R_REFUSED;
	else if (error_msg == "R_YXDOMAIN")
		return DnsRCode::R_YXDOMAIN;
	else if (error_msg == "R_XYRRSET")
		return DnsRCode::R_XYRRSET;
	else if (error_msg == "R_NOTAUTH")
		return DnsRCode::R_NOTAUTH;
	else if (error_msg == "R_NOTZONE")
		return DnsRCode::R_NOTZONE;
	else if (error_msg == "R_DSOTYPENI")
		return DnsRCode::R_DSOTYPENI;
	else if (error_msg == "R_BADVERS")
		return DnsRCode::R_BADVERS;
	else if (error_msg == "R_BADKEY")
		return DnsRCode::R_BADKEY;
	else if (error_msg == "R_BADTIME")
		return DnsRCode::R_BADTIME;
	else if (error_msg == "R_BADMODE")
		return DnsRCode::R_BADMODE;
	else if (error_msg == "R_BADNAM")
		return DnsRCode::R_BADNAM;
	else if (error_msg == "R_BADALG")
		return DnsRCode::R_BADALG;
	else if (error_msg == "R_BADTRUNC")
		return DnsRCode::R_BADTRUNC;
	else if (error_msg == "R_BADCOOKIE")
		return DnsRCode::R_BADCOOKIE;

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
