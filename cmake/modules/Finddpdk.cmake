#
# This file is open source software, licensed to you under the terms
# of the Apache License, Version 2.0 (the "License").  See the NOTICE file
# distributed with this work for additional information regarding copyright
# ownership.  You may not use this file except in compliance with the License.
#
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#

#
# Copyright (C) 2018 Scylladb, Ltd.
#

find_package (PkgConfig REQUIRED)
pkg_check_modules (dpdk_PC libdpdk)

# we cannot use ${dpdk_PC_STATIC_LDFLAGS} directly, because we want to
# export DPDK as a bundle of static libraries, so need to find the
# individual paths to all .a files
find_path (dpdk_INCLUDE_DIR
  NAMES rte_atomic.h
  HINTS
    ${dpdk_PC_INCLUDE_DIRS}
  PATH_SUFFIXES
    dpdk)

set(rte_libs
    bus_pci
    bus_vdev
    cfgfile
    cmdline
    cryptodev
    dmadev
    eal
    ethdev
    hash
    kvargs
    mbuf
    mempool
    mempool_ring
    meter
    net
    net_af_xdp
    net_bnxt
    net_cxgbe
    net_e1000
    net_ena
    net_enic
    net_i40e
    net_ixgbe
    net_nfp
    net_qede
    net_ring
    net_sfc
    net_vmxnet3
    pci
    rcu
    ring
    security
    telemetry
    timer
    vhost
)

# Only necessary when linking statically
if (${BUILD_STATIC})
  set(rte_libs
      ${rte_libs}
      common_nfp
      log
      vdpa_nfp
  )
endif()

# sfc_efx driver can only build on x86 and aarch64
if (CMAKE_SYSTEM_PROCESSOR MATCHES "amd64|x86_64|aarch64")
  list (APPEND rte_libs
    common_sfc_efx)
endif ()

list (APPEND dpdk_REQUIRED
  dpdk_INCLUDE_DIR)

foreach (lib ${rte_libs})
  string(TOUPPER ${lib} upper_lib)
  set(library_name "dpdk_${upper_lib}_LIBRARY")
  find_library (${library_name}
    NAME rte_${lib}
    HINTS
      ${dpdk_PC_STATIC_LIBRARY_DIRS})
  list (APPEND dpdk_REQUIRED
    ${library_name})
  list (APPEND dpdk_LIBRARIES
    ${library_name})

  if (NOT ${library_name})
    continue()
  endif ()

  set (library_path ${${library_name}})
  list (APPEND _dpdk_linker_files ${library_path})
  set (dpdk_lib dpdk::${lib})
  list (APPEND _dpdk_libraries ${dpdk_lib})

  if (dpdk_INCLUDE_DIR AND NOT (TARGET ${dpdk_lib}))
    add_library (${dpdk_lib} UNKNOWN IMPORTED)
    set_target_properties (${dpdk_lib}
      PROPERTIES
        IMPORTED_LOCATION ${library_path}
        INTERFACE_INCLUDE_DIRECTORIES ${dpdk_INCLUDE_DIR})
  endif ()
endforeach ()

include (FindPackageHandleStandardArgs)
find_package_handle_standard_args (dpdk
  REQUIRED_VARS
    ${dpdk_REQUIRED})

if (dpdk_FOUND AND NOT (TARGET dpdk))
  get_filename_component (library_suffix "${dpdk_EAL_LIBRARY}" LAST_EXT)
  # strictly speaking, we should have being using check_c_compiler_flag()
  # here, but we claim Seastar as a project written in CXX language, and
  # C is not enabled, so CXX is used here instead.
  include(CheckCXXCompilerFlag)
  check_cxx_compiler_flag("-Wno-volatile" _warning_supported_volatile)
  if(_warning_supported_volatile)
    # include/generic/rte_spinlock.h increments volatiled-qualified type with
    # "++". but this is deprecated by GCC, so silence it.
    set(compile_options
      INTERFACE_COMPILE_OPTIONS "-Wno-volatile")
  endif()
  if (library_suffix STREQUAL CMAKE_STATIC_LIBRARY_SUFFIX)
    # No pmd driver code will be pulled in without "--whole-archive". To
    # avoid exposing that to seastar users, combine dpdk into a single
    # .o file.
    set (dpdk_object_path "${CMAKE_BINARY_DIR}/dpdk.o")
    add_custom_command (
      OUTPUT ${dpdk_object_path}
      COMMAND ${CMAKE_CXX_COMPILER}
        -r # create a relocatable object
        -o ${dpdk_object_path}
        -Wl,--whole-archive ${_dpdk_linker_files}
      DEPENDS
        ${_dpdk_linker_files})
    add_custom_target (dpdk_object
      DEPENDS ${dpdk_object_path})

    add_library (dpdk OBJECT IMPORTED)
    add_dependencies (dpdk dpdk_object)
    set_target_properties (dpdk
      PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${dpdk_INCLUDE_DIR}
        IMPORTED_OBJECTS ${dpdk_object_path}
        ${compile_options})
    # we include dpdk in seastar already, so no need to expose it with
    # dpdk_LIBRARIES
    set (dpdk_LIBRARIES "")
    add_library (DPDK::dpdk ALIAS dpdk)
  else ()
    set (dpdk_LIBRARIES ${dpdk_PC_LDFLAGS})
    add_library (DPDK::dpdk INTERFACE IMPORTED)
    set_target_properties (DPDK::dpdk
      PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${dpdk_PC_INCLUDE_DIRS}"
        INTERFACE_LINK_LIBRARIES "${_dpdk_libraries}"
        ${compile_options})
  endif()
endif ()
