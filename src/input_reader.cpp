#include "input_reader.h"

#include <rte_cpuflags.h>
#include <stdio.h>
#include <string.h>
#include <x86intrin.h>

#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>

#include "stdlib.h"

#define RING_QUEUE_DEPTH 1

/**
 * @brief This function checks if the supplied value is a power of two
 *
 * @param[in] val The parameter to check if it is a power of two or not
 * @return true Parameter val is a power of two
 * @return false Paramerter val is not a power of two
 */
bool IsPowerOfTwo(size_t val) {
	if (val == 0)
		return false;
	else if (val == 1)
		return true;
	return !(val & (size_t) 0x01) && IsPowerOfTwo(val >> 1);
}

InputReader::InputReader(FILE* read_file) : InputReader(read_file, 1048576) { }

InputReader::InputReader(FILE* read_file, const size_t block_size)
    : block_size(block_size),
      process_buf_curr_ptr(NULL),
      process_buf_end_ptr(NULL),
      simd_buf_curr_ptr(NULL),
      simd_buf_end_ptr(NULL),
      read_file(read_file),
      read_file_fd(fileno(read_file)),
      offset_tracker(0),
      process_buf((char*) aligned_alloc(16, block_size), &::free),
      read_buf((char*) aligned_alloc(16, block_size), &::free),
      domain_begin_ptr(NULL),
      current_domain_valid(true),
      curr_domain_written(0) {
	// Check if the SSE4.2 instruction set is present, it is necessary for string processing
	// instructions
	if (!rte_cpu_get_flag_enabled(rte_cpu_flag_t::RTE_CPUFLAG_SSE4_2))
		throw std::runtime_error("SSE4.2 instructions not supported on this CPU");

	// The block size should be a power of two to make alignment easier
	if (!IsPowerOfTwo(block_size))
		throw std::length_error("Block size must be power of two");

	// The block size has to be larger than the maximum domain length
	if (block_size < DOMAIN_NAME_MAX_SIZE)
		throw std::length_error("Block size must be larger than DOMAIN_NAME_MAX_SIZE");

	io_uring_params params;

	memset(&params, 0, sizeof(params));

	// Initialize io_uring
	int ret = io_uring_queue_init_params(RING_QUEUE_DEPTH, &ring, &params);
	if (ret)
		throw std::runtime_error("Cannot initialize io-uring");

	read_file_fd = fileno(read_file);

	// Register the file descriptor in io_uring to minimize overhead
	// ret = io_uring_register_files(&ring, &fd, 1);
	// if (ret)
	// 	throw std::runtime_error("Failed to register file FD in ring");

	// Initialize the first read request to kickstart the loop
	io_uring_sqe* sqe = io_uring_get_sqe(&ring);
	if (sqe == NULL)
		throw std::runtime_error("No space available in ring");

	io_uring_prep_read(sqe, read_file_fd, read_buf.get(), block_size, 0);
	// sqe->flags |= IOSQE_FIXED_FILE;

	// The submit function should return that one SQE submission has been made
	if (io_uring_submit(&ring) != 1)
		throw std::runtime_error("Failed SQE submission");
}

GetBufferResult InputReader::RefreshBuffers() {
	// First check if a new buffer is available
	io_uring_cqe* cqe;
	if (io_uring_peek_cqe(&ring, &cqe))
		// No completions, return not available
		return GetBufferResult::NotAvailable;

	// Check for read errors
	if (cqe->res < 0)
		throw std::runtime_error("Io_uring read operation failed");

	// Load the read buffer into the process buffer and vice versa by swapping the pointers
	std::swap(read_buf, process_buf);

	// Check how many bytes have been read
	size_t num_chars_read_from_file = cqe->res;

	// Update the current and end pointer of the process buffer
	process_buf_curr_ptr = process_buf.get();
	process_buf_end_ptr = process_buf_curr_ptr + num_chars_read_from_file;

	// Keep track of the offset in the file for the next read operation
	offset_tracker += num_chars_read_from_file;

	// Let io_uring know that the cqe has been processed
	io_uring_cqe_seen(&ring, cqe);

	// Get a new submission entry from the ring
	io_uring_sqe* sqe = io_uring_get_sqe(&ring);
	if (sqe == NULL)
		throw std::runtime_error("No space available in ring");

	// Prepare sqe for read operation
	io_uring_prep_read(sqe, read_file_fd, read_buf.get(), block_size, 0);
	// sqe->flags |= IOSQE_FIXED_FILE;
	sqe->off = offset_tracker;

	// Submit the sqe and check if the submission was successfull
	if (io_uring_submit(&ring) != 1)
		throw std::runtime_error("Failed SQE submission");

	return GetBufferResult::Success;
}

InputReader::~InputReader() {
	io_uring_queue_exit(&ring);
}

/// \cond DO_NOT_DOCUMENT
union m128i_chararr {
	char chararr[16];
	__m128i m128i;
};

union m128i_unsignedll {
	unsigned long long unsignedll;
	__m128i m128i;
};
/// \endcond

ReadDomainResult InputReader::GetDomain(DomainInputInfo& domain_info) {
	GetBufferResult res = GetBufferResult::Success;
	while (1) {
		// First check if the process buffer needs to be refreshed
		if (process_buf_curr_ptr == process_buf_end_ptr) {
			// First write the remainder of the previous process_buf into the current
			// domain
			int chars_to_write =
			    std::min(std::max(process_buf_end_ptr - domain_begin_ptr, (long int) 0),
				(long int) (DOMAIN_NAME_MAX_SIZE - curr_domain_written - 1));
			memcpy(curr_domain.data() + curr_domain_written, domain_begin_ptr,
			    chars_to_write);
			curr_domain_written += chars_to_write;

			// Get a new process buffer and return if no new data is available
			res = RefreshBuffers();
			if (res == GetBufferResult::NotAvailable)
				return ReadDomainResult::NotAvailable;
			// Zero bytes read, end of file
			if (process_buf_curr_ptr == process_buf_end_ptr)
				return ReadDomainResult::FileEnd;

			// New domain begin pointer is at the start of the process buffer
			domain_begin_ptr = process_buf_curr_ptr;
		}

		// Check if the SIMD buffer has to be refreshed
		if (simd_buf_curr_ptr == simd_buf_end_ptr) {
			// Define the constants for filtering invalid characters
			const m128i_chararr valid_chars = {"azAZ09..--__"};
			const int op_valid_chars = _SIDD_CMP_RANGES | _SIDD_NEGATIVE_POLARITY;

			// Filtering for \n and \0 directly is not possible since implicit
			// string length is used for performance reasons. All characters except
			// \n and \0 are selected and the output is negated
			const m128i_chararr end_of_line_chars = {
			    {('\0' + 1), ('\n' - 1), ('\n' + 1), (char) 0xFF}};
			const int op_end_of_line = _SIDD_CMP_RANGES | _SIDD_NEGATIVE_POLARITY;

			m128i_unsignedll invalid_char_res;
			m128i_unsignedll newline_res;

			// Process all 64 bytes of the simd buffer for newlines and invalid
			// characterrs in batches of 16 bytes
			__m128i simd_data =
			    _mm_loadu_si128(reinterpret_cast<__m128i_u*>(process_buf_curr_ptr));
			invalid_char_res.m128i =
			    _mm_cmpistrm(valid_chars.m128i, simd_data, op_valid_chars);
			newline_res.m128i =
			    _mm_cmpistrm(end_of_line_chars.m128i, simd_data, op_end_of_line);

			simd_data = _mm_loadu_si128(
			    reinterpret_cast<__m128i_u*>(process_buf_curr_ptr + 16));
			invalid_char_res.m128i |=
			    _mm_cmpistrm(valid_chars.m128i, simd_data, op_valid_chars) << 16;
			newline_res.m128i |=
			    _mm_cmpistrm(end_of_line_chars.m128i, simd_data, op_end_of_line) << 16;

			simd_data = _mm_loadu_si128(
			    reinterpret_cast<__m128i_u*>(process_buf_curr_ptr + 32));
			invalid_char_res.m128i |=
			    _mm_cmpistrm(valid_chars.m128i, simd_data, op_valid_chars) << 32;
			newline_res.m128i |=
			    _mm_cmpistrm(end_of_line_chars.m128i, simd_data, op_end_of_line) << 32;

			simd_data = _mm_loadu_si128(
			    reinterpret_cast<__m128i_u*>(process_buf_curr_ptr + 48));
			invalid_char_res.m128i |=
			    _mm_cmpistrm(valid_chars.m128i, simd_data, op_valid_chars) << 48;
			newline_res.m128i |=
			    _mm_cmpistrm(end_of_line_chars.m128i, simd_data, op_end_of_line) << 48;

			simd_invalid_chars = invalid_char_res.unsignedll;
			simd_newlines = newline_res.unsignedll;

			simd_buf_curr_ptr = process_buf_curr_ptr;
			simd_buf_end_ptr = std::min(process_buf_curr_ptr + 64, process_buf_end_ptr);
		}

		// Get the location of the next newline character and the next invalid character
		int loc_false_char_ctz = __builtin_ctzll(simd_invalid_chars);
		int loc_newline_ctz = __builtin_ctzll(simd_newlines);

		int loc_false_char = simd_invalid_chars ? loc_false_char_ctz : 64;
		int loc_newline = simd_newlines ? loc_newline_ctz : 64;

		// The location of the next valid character shouldn't be smaller than
		// the location of the next newline, otherwise the domain is
		// not valid
		current_domain_valid &= loc_false_char >= loc_newline;

		// Check if the newline location exceeds the end of the SIMD buffer
		// otherwise indicate buffer refresh by updating pointers
		if (simd_buf_curr_ptr + loc_newline < simd_buf_end_ptr) {
			// First copy the first part of the domain to the buffer
			memcpy(domain_info.buf, curr_domain.data(), curr_domain_written);

			// Write the domain to the domain buffer, take any previously written
			// characters into account and also an optional trailing dot.
			const int max_size_domain_with_null =
			    DOMAIN_NAME_MAX_SIZE - curr_domain_written - 2;
			const int chars_to_write_unbounded =
			    loc_newline + (simd_buf_curr_ptr - domain_begin_ptr);
			const int& chars_to_write =
			    std::min(chars_to_write_unbounded, max_size_domain_with_null);

			// Check if the number of chars to write doesn't point to the maximum number
			// of chars
			current_domain_valid &= &chars_to_write_unbounded == &chars_to_write;

			const int total_length = chars_to_write + curr_domain_written;

			memcpy(domain_info.buf + curr_domain_written, domain_begin_ptr,
			    chars_to_write);
			domain_info.buf[total_length] = '\0';

			domain_info.len = total_length;

			// Reset character count for new domain
			curr_domain_written = 0;

			// Filter out the current newline and invalic character bits to be able to
			// detect the next domain
			simd_invalid_chars &= ((unsigned long long) 0xFFFFFFFFFFFFFFFE)
			                      << loc_newline;
			simd_newlines &= ((unsigned long long) 0xFFFFFFFFFFFFFFFE) << loc_newline;

			// Update the begin pointer to the next domain
			domain_begin_ptr = simd_buf_curr_ptr + loc_newline + 1;

			ReadDomainResult to_return = current_domain_valid
			                                 ? ReadDomainResult::Success
			                                 : ReadDomainResult::NotValid;

			// Reset the domain valid flag
			current_domain_valid = true;

			return to_return;
		} else {
			simd_buf_curr_ptr = simd_buf_end_ptr;
			process_buf_curr_ptr = simd_buf_end_ptr;
		}
	}

	return ReadDomainResult::Success;
}
