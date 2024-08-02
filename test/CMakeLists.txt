set(
    SOURCES_TESTS 
    "${CMAKE_CURRENT_SOURCE_DIR}/arp_test.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/dns_construct_helpers_test.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/dns_packet_constructor_test.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/dns_packet_test.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/dpdk_wrappers_test.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/net_info_test.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/test_main.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/thread_manager_test.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/utils_test.cc"
)

add_executable(
    tests
    ${SOURCES_TESTS}
)

target_link_libraries(
    tests
    gtest
    "${PROJ_NAME}_libs"
)

gtest_discover_tests(tests EXTRA_ARGS --no-huge)

# List of test files to copy
set(TEST_FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/resources/resolvers_good.txt"
    "${CMAKE_CURRENT_SOURCE_DIR}/resources/resolvers_bad.txt"
    "${CMAKE_CURRENT_SOURCE_DIR}/resources/FileTestBasic.txt"
)

# Copy each test file to the build directory
foreach(TEST_FILE ${TEST_FILES})
    configure_file(${TEST_FILE} ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)
endforeach()
