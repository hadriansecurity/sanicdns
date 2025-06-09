#include "input_reader.h"

#include <cassert>
#include <rte_cpuflags.h>
#include <stdio.h>
#include <string.h>

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
  return !(val & (size_t)0x01) && IsPowerOfTwo(val >> 1);
}

InputReader::InputReader(FILE *read_file) : InputReader(read_file, 16384) {}

InputReader::InputReader(FILE *read_file, const size_t block_size)
    : block_size(block_size), simd_buf_curr_ptr(NULL), simd_buf_end_ptr(NULL),
      read_file(read_file), read_file_fd(fileno(read_file)), offset_tracker(0),
      process_buf(block_size), read_buf(block_size),
      process_buf_curr_cursor(process_buf.end()),
      domain_begin_cursor(process_buf.end()), current_domain_valid(true),
      curr_domain_cursor(curr_domain.begin()) {

  // The block size should be a power of two to make alignment easier
  if (!IsPowerOfTwo(block_size))
    throw std::length_error("Block size must be power of two");

  // The block size has to be larger than the maximum domain length
  if (block_size < DOMAIN_NAME_MAX_SIZE)
    throw std::length_error(
        "Block size must be larger than DOMAIN_NAME_MAX_SIZE");

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
  io_uring_sqe *sqe = io_uring_get_sqe(&ring);
  if (sqe == NULL)
    throw std::runtime_error("No space available in ring");

  io_uring_prep_read(sqe, read_file_fd, read_buf.data(), block_size, 0);
  // sqe->flags |= IOSQE_FIXED_FILE;

  // The submit function should return that one SQE submission has been made
  if (io_uring_submit(&ring) != 1)
    throw std::runtime_error("Failed SQE submission");
}

GetBufferResult InputReader::RefreshBuffers() {
  // First check if a new buffer is available
  io_uring_cqe *cqe;
  if (io_uring_peek_cqe(&ring, &cqe))
    // No completions, return not available
    return GetBufferResult::NotAvailable;

  // Check for read errors
  if (cqe->res < 0)
    throw std::runtime_error("Io_uring read operation failed");

  // Load the read buffer into the process buffer and vice versa by swapping the
  // pointers
  std::swap(read_buf, process_buf);

  // Check how many bytes have been read
  size_t num_chars_read_from_file = cqe->res;

  // Update the current and end pointer of the process buffer
  assert(num_chars_read_from_file <= process_buf.size());
  process_buf.resize(num_chars_read_from_file);
  process_buf_curr_cursor = process_buf.begin();

  // Keep track of the offset in the file for the next read operation
  offset_tracker += num_chars_read_from_file;

  // Let io_uring know that the cqe has been processed
  io_uring_cqe_seen(&ring, cqe);

  // Get a new submission entry from the ring
  io_uring_sqe *sqe = io_uring_get_sqe(&ring);
  if (sqe == NULL)
    throw std::runtime_error("No space available in ring");

  // Prepare sqe for read operation
  read_buf.resize(block_size);
  io_uring_prep_read(sqe, read_file_fd, read_buf.data(), read_buf.size(), 0);
  // sqe->flags |= IOSQE_FIXED_FILE;
  sqe->off = offset_tracker;

  // Submit the sqe and check if the submission was successfull
  if (io_uring_submit(&ring) != 1)
    throw std::runtime_error("Failed SQE submission");

  return GetBufferResult::Success;
}

InputReader::~InputReader() { io_uring_queue_exit(&ring); }

/// \cond DO_NOT_DOCUMENT
union m128i_chararr {};

union m128i_unsignedll {
  unsigned long long unsignedll;
};
/// \endcond

ReadDomainResult InputReader::GetDomain(DomainInputInfo &domain_info) {
  GetBufferResult res = GetBufferResult::Success;
  while (1) {
    // First check if the process buffer needs to be refreshed
    if (process_buf_curr_cursor == process_buf.end()) {
      // First write the remainder of the previous process_buf into the current
      if ((process_buf.end() - domain_begin_cursor) <
          (curr_domain.end() - curr_domain_cursor))
        curr_domain_cursor = std::copy(domain_begin_cursor, process_buf.end(),
                                       curr_domain_cursor);

      // Get a new process buffer and return if no new data is available
      res = RefreshBuffers();
      if (res == GetBufferResult::NotAvailable)
        return ReadDomainResult::NotAvailable;
      // Zero bytes read, end of file
      if (process_buf_curr_cursor == process_buf.end())
        return ReadDomainResult::FileEnd;

      // New domain begin pointer is at the start of the process buffer
      domain_begin_cursor = process_buf.begin();
      process_buf_curr_cursor = process_buf.begin();
    }

    if (*process_buf_curr_cursor == '\n') {
      // First copy the (possibly partial) domain into the domain buffer.
      curr_domain_cursor = std::copy(
          domain_begin_cursor, process_buf_curr_cursor, curr_domain_cursor);
      *curr_domain_cursor++ = '\0';

      // Then copy it into the user provided buffer.
      auto end =
          std::copy(curr_domain.begin(), curr_domain_cursor, domain_info.buf);
      domain_info.len = end - domain_info.buf - 1;
      auto result = current_domain_valid ? ReadDomainResult::Success
                                         : ReadDomainResult::NotValid;

      // Reset cursors
      curr_domain_cursor = curr_domain.begin();
      process_buf_curr_cursor++;
      domain_begin_cursor = process_buf_curr_cursor;
      return result;
    }

    current_domain_valid &=
        (*process_buf_curr_cursor >= 'A' && *process_buf_curr_cursor <= 'Z') ||
        (*process_buf_curr_cursor >= 'a' && *process_buf_curr_cursor <= 'z') ||
        (*process_buf_curr_cursor >= '0' && *process_buf_curr_cursor <= '9') ||
        *process_buf_curr_cursor == '-' || *process_buf_curr_cursor == '.' ||
        *process_buf_curr_cursor == '_';

    process_buf_curr_cursor++;
  }

  return ReadDomainResult::NotAvailable;
}
