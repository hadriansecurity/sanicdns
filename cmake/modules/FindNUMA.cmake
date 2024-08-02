# Module for locating libnuma
#
# Read-only variables:
#   NUMA_FOUND
#     Indicates that the library has been found.
#
#   NUMA_INCLUDE_DIRS
#     Points to the libnuma include directory.
#
#   NUMA_LIBRARY_DIR
#     Points to the directory that contains the libraries.
#     The content of this variable can be passed to link_directories.
#
#   NUMA_LIBRARY
#     Points to the libnuma that can be passed to target_link_libararies.

include(FindPackageHandleStandardArgs)

find_path(NUMA_INCLUDE_DIRS
  NAMES numa.h
  HINTS ${NUMA_ROOT_DIR}
  PATH_SUFFIXES include
  DOC "NUMA include directory")

# First, try to find the static library
find_library(NUMA_STATIC_LIBRARY
  NAMES libnuma.a
  HINTS ${NUMA_ROOT_DIR}
  DOC "NUMA static library")

# If static library is not found, look for the shared library
if(NOT NUMA_STATIC_LIBRARY)
  find_library(NUMA_SHARED_LIBRARY
    NAMES numa
    HINTS ${NUMA_ROOT_DIR}
    DOC "NUMA shared library")
endif()

# Set NUMA_LIBRARY to the static library if found, otherwise to the shared library
if(NUMA_STATIC_LIBRARY)
  set(NUMA_LIBRARY ${NUMA_STATIC_LIBRARY})
  set(NUMA_LIBRARY_TYPE STATIC)
else()
  set(NUMA_LIBRARY ${NUMA_SHARED_LIBRARY})
  set(NUMA_LIBRARY_TYPE SHARED)
endif()

if(NUMA_LIBRARY)
  get_filename_component(NUMA_LIBRARY_DIR ${NUMA_LIBRARY} PATH)
endif()

mark_as_advanced(NUMA_INCLUDE_DIRS NUMA_LIBRARY_DIR NUMA_LIBRARY NUMA_STATIC_LIBRARY NUMA_SHARED_LIBRARY)

find_package_handle_standard_args(Numa REQUIRED_VARS NUMA_INCLUDE_DIRS NUMA_LIBRARY)

if(NUMA_FOUND)
  if(NOT TARGET Numa::Numa)
    add_library(Numa::Numa ${NUMA_LIBRARY_TYPE} IMPORTED)
  endif()
  if(NUMA_INCLUDE_DIRS)
    set_target_properties(Numa::Numa PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${NUMA_INCLUDE_DIRS}")
  endif()
  if(EXISTS "${NUMA_LIBRARY}")
    set_target_properties(Numa::Numa PROPERTIES
      IMPORTED_LINK_INTERFACE_LANGUAGES "C"
      IMPORTED_LOCATION "${NUMA_LIBRARY}")
  endif()
endif()
