find_package(Git)

if(GIT_EXECUTABLE)
	execute_process(
		COMMAND ${GIT_EXECUTABLE} describe --tags --dirty
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
		OUTPUT_VARIABLE SANICDNS_VERSION
		RESULT_VARIABLE ERROR_CODE
		OUTPUT_STRIP_TRAILING_WHITESPACE
	)
endif()


if(SANICDNS_VERSION STREQUAL "")
	set(SANICDNS_VERSION 0.0.0-unknown)
	message(WARNING "Failed to determine version from Git tags. Using default version \"${FOO_VERSION}\".")
endif()

message("Building sanicdns version ${SANICDNS_VERSION}")

