cmake_minimum_required(VERSION 3.18.4)
include(ExternalProject)

# Set Project Name
set(PROJ_NAME sanicdns)
project("${PROJ_NAME}_project")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_GENERATOR Ninja)

# Options
option(OPTIMIZE_FOR_NATIVE "Build with -march=native" OFF)
option(FORCE_COLORED_OUTPUT "Always produce ANSI-colored output (GNU/Clang only)." FALSE)
option(BUILD_STATIC "Build a statically linked executable" OFF)
option(BUILD_TESTS "Build a statically linked executable" OFF)

if (${BUILD_STATIC})
    message("Building statically linked executable")
    set (CMAKE_LINK_SEARCH_START_STATIC ON)
    set (CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_STATIC_LIBRARY_SUFFIX})
    set(BUILD_SHARED_LIBS OFF)
    link_libraries(-static)
else ()
    message("Building dynamically linked executable")
    set (CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_SHARED_LIBRARY_SUFFIX} ${CMAKE_STATIC_LIBRARY_SUFFIX})
endif()

# link_libraries(${NUMA_LIBRARY} atomic curses uring bpf xdp z zstd elf)

add_definitions(-DSPDLOG_NO_EXCEPTIONS)

# Path Definitions
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules/")

# Compiler Flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mssse3 -msse4.2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror -mssse3 -msse4.2")

if(OPTIMIZE_FOR_NATIVE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
endif()

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} -fsanitize=address")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
endif()

# Find NUMA
find_package(NUMA REQUIRED)

# archive lzma
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

# Find DPDK
find_package(dpdk REQUIRED)

# Force Colored Output
if (${FORCE_COLORED_OUTPUT})
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
       add_compile_options (-fdiagnostics-color=always)
    elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
       add_compile_options (-fcolor-diagnostics)
    endif ()
endif ()

# Source Files for libs
set(
    SOURCES_LIBS 
    "${CMAKE_CURRENT_SOURCE_DIR}/src/arp.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/dns_packet.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/eth_rxtx.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/input_reader.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/net_info.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/worker.cpp"
)

# Source Files
set(SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp")

# Generate version file
add_custom_target(version
	${CMAKE_COMMAND} -D SRC=${CMAKE_SOURCE_DIR}/include/version.h.in
			-D DST=${CMAKE_SOURCE_DIR}/include/version.h
			-P ${CMAKE_SOURCE_DIR}/cmake/GenerateVersion.cmake
)

# Subdirectories
cmake_policy(SET CMP0077 NEW)
set(INSTALL_GTEST OFF)
set(gtest_disable_pthreads OFF)
set(MSVC OFF)
set(BUILD_GMOCK ON)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/utils)

set(BENCHMARK_ENABLE_TESTING OFF)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/lib/benchmark)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/lib/googletest)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/lib/glaze)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/lib/spdlog)

# Tests
enable_testing()
include(GoogleTest)

# Tests
if (${BUILD_TESTS})
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/test)
endif()

add_library("${PROJ_NAME}_libs" STATIC ${SOURCES_LIBS})

# Target Definitions
add_executable (${PROJ_NAME} ${SOURCES})
install(TARGETS ${PROJ_NAME})

target_include_directories("${PROJ_NAME}_libs"  PUBLIC
                            "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_link_libraries("${PROJ_NAME}_libs" PUBLIC
    xdp
    atomic
    curses
    uring
    bpf
    elf
    z
    zstd
    DPDK::dpdk
    glaze::glaze
    spdlog
    ${NUMA_LIBRARY}
)

target_link_libraries(${PROJ_NAME} PUBLIC
    "${PROJ_NAME}_libs"
)

add_dependencies(${PROJ_NAME} version)

###############################################################################
## XDP program ################################################################
###############################################################################

if("${NIC_TYPE}" STREQUAL "AF_XDP")
	message("Configuring for AF_XDP")
	target_compile_definitions("${PROJ_NAME}_libs" PUBLIC NIC_AF_XDP)
	ExternalProject_Add(
	    xdp_build
	    SOURCE_DIR ${CMAKE_SOURCE_DIR}/xdp
	    BINARY_DIR ${CMAKE_BINARY_DIR}/xdp
	    INSTALL_COMMAND ""  # Skip the install step
	)
elseif("${NIC_TYPE}" STREQUAL "I40E")
	message("Configuring for XL710")
	target_compile_definitions("${PROJ_NAME}_libs" PUBLIC NIC_I40E)
else()
	message(FATAL_ERROR "Invalid NIC type detected: ${NIC_TYPE}")
endif()
