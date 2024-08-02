#pragma once

#define DOMAIN_NAME_MAX_SIZE 256

#include <liburing.h>
#include <stdlib.h>

#include <array>
#include <memory>
#include <string>

/**
 * @brief Type trait that determines if the template parameter val is a power of two during compile
 * time
 * @tparam val
 */
template <size_t val>
struct IsPowerOfTwoStatic {
	/**
	 * The value that contains the result of the calculation
	 */
	static const bool res = !(val & 0x01) && IsPowerOfTwoStatic<(val >> 1)>::res;
};
// Skip documentation of template specialisations
/// \cond DO_NOT_DOCUMENT
template <>
struct IsPowerOfTwoStatic<1> {
	static const bool res = true;
};
template <>
struct IsPowerOfTwoStatic<0> {
	static const bool res = false;
};
/// \endcond

/**
 * Enum that represents the result of a domain read
 */
enum struct ReadDomainResult {
	Success,
	NotAvailable,
	FileEnd,
	NotValid
};

/**
 * Enum that represents the result of a buffer refresh
 */
enum struct GetBufferResult {
	Success,
	NotAvailable
};

struct DomainInputInfo {
	char* buf;
	size_t len;
};

/**
 * @brief InputReader class used for extracting domains from a file pointer
 *
 * This class reads domains seperated by a newline character from a specified file
 * pointer. The class also checks all characters in the domain for validity, only
 * a-z, 0-9, - and . are allowed. Note that uppercase characters are not allowed
 */
class InputReader {
public:
	/**
	 * @brief Construct a new Input Reader object using a block size of 1MB
	 *
	 * @param read_file File pointer to read domains from
	 * @see InputReader(FILE* read_file, const size_t block_size)
	 */
	InputReader(FILE* read_file);

	/**
	 * @brief Construct a new Input Reader object
	 *
	 * @param read_file File pointer to read domains from
	 * @param block_size The block size to use when reading the file, @see block_size
	 */
	InputReader(FILE* read_file, const size_t block_size);

	/**
	 * @brief Read a new domain from read_file
	 *
	 * @param domain_info Reference to a domain_info object, the caller is responsible for
	 * ensuring enough allocated memory is available in domain_info.buf
	 * @return ReadDomainResult::Success means the domain in domain_info doesn't contain invalid
	 * characters
	 * @return ReadDomainResult::NotAvailable means there was no new data available from
	 * read_file, domain_info should not be used
	 * @return ReadDomainResult::FileEnd indicates that the input file has been read completely
	 * and the InputReader object can be destroyed
	 * @return ReadDomainResult::NotValid means that the result read into domain_info comtains
	 * invalid characters and/or the domain is too long
	 */
	ReadDomainResult GetDomain(DomainInputInfo& domain_info);

	/**
	 * @brief Destroy the Input Reader object
	 */
	~InputReader();

private:
	static_assert(IsPowerOfTwoStatic<DOMAIN_NAME_MAX_SIZE>::res,
	    "DOMAIN_NAME_MAX_SIZE must be a power of two");

	/**
	 * @brief Refresh the process buffer
	 *
	 * This funcion can be called when the process buffer has been processed,
	 * it will refresh the buffer with new data from read_file
	 *
	 * @return GetBufferResult
	 */
	GetBufferResult RefreshBuffers();

	/**
	 *  Represents the size in bytes which is read from read_file every block
	 */
	const size_t block_size;

	/**
	 * @brief Points to the data currently being processed in process_buf
	 */
	char* process_buf_curr_ptr;
	/**
	 * @brief Points to the end of the data currently being processed in process_buf
	 *
	 * This pointer points to the data \b after the last element that can be legally accessed
	 */
	char* process_buf_end_ptr;

	/**
	 * @brief Points to the data block in process_buf that is being processed with simd
	 * instructions
	 *
	 * The SIMD buffer is used to process parts of the process_buf using optimized string
	 * processing instructions
	 */
	char* simd_buf_curr_ptr;
	/**
	 * @brief Points to the end of the data block in process_buf that is being processed with
	 * simd instructions
	 *
	 * This pointer points to the data \b after the last element that can be legally accessed
	 */
	char* simd_buf_end_ptr;

	/**
	 * @brief Contains true for invalid characters in the SIMD buffer
	 *
	 * The LSB and the MSB correspond tot to the first and last character in the SIMD
	 * buffer respectively
	 */
	unsigned long long simd_invalid_chars;
	/**
	 * @brief Contains true for newlines and null terminators in the SIMD buffer
	 *
	 * The LSB and the MSB correspond tot to the first and last character in the SIMD
	 * buffer respectively
	 */
	unsigned long long simd_newlines;

	/**
	 * @brief Points to the file being read
	 */
	const FILE* read_file;

	/**
	 * @brief File descriptor of read_file
	 */
	int read_file_fd;

	/**
	 * @brief Tracks the offset in bytes in the processed file
	 */
	size_t offset_tracker;

	/**
	 * @brief Contains all data of the io_uring instance used to read the file
	 *
	 */
	io_uring ring;

	/**
	 * @brief Contains an array of size block_size, used for the data currently being processed
	 *
	 * When new data is requested and available, the process_buf and read_buf pointers are
	 * swapped
	 */
	std::unique_ptr<char[], decltype(&::free)> process_buf;
	/**
	 * @brief Contains an array of size block_size, used for reading in data from read_file
	 *
	 * When new data is requested and available, the process_buf and read_buf pointers are
	 * swapped
	 */
	std::unique_ptr<char[], decltype(&::free)> read_buf;

	/**
	 * @brief Contains a pointer to the domain name in process_buf currently being read
	 */
	char* domain_begin_ptr;
	/**
	 * @brief Used for tracking if any invalid characters have been found in the current domain
	 */
	bool current_domain_valid;

	/**
	 * @brief Buffer that can be used to store parts of a domain when a buffer refresh occurs
	 *
	 * When the buffers are refreshed the data of the previous buffer cannot be accessed
	 * anymore. The first part of a domain that is contained in two blocks is stored here
	 */
	std::array<char, DOMAIN_NAME_MAX_SIZE> curr_domain;
	/**
	 * @brief Contains the number of valid characters present is curr_domain
	 */
	int curr_domain_written;
};
