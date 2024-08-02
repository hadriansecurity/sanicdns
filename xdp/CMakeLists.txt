project(xdp_build_project)

cmake_minimum_required(VERSION 3.18.4) # setting this is required
set(LIB_NAME sanicdns_xdp)

###############################################################################
## file globbing ##############################################################
###############################################################################

set(SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/sanicdns_xdp.c")

###############################################################################
## target definitions #########################################################
###############################################################################

# Reset CMAKE_BUILD_TYPE
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_C_COMPILER clang)

add_library(${LIB_NAME} OBJECT ${SOURCES})

target_compile_options(${LIB_NAME} PRIVATE -Wall -g -O2 -target bpf -D__TARGET_ARCH_x86_64)
