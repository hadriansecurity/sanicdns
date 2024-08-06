find_package(Sphinx REQUIRED)
find_package(Doxygen REQUIRED)
find_program(BREATHE_APIDOC_EXECUTABLE "breathe-apidoc")

# set input and output files
set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)
set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
set(DOXYGEN_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/doxygen)

# Define where Doxygen outputs the XML files
set(
    DOXYGEN_INPUT_DIR
    "${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/utils"
    )

# request to configure the file
configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
message("Doxygen build started")

# copy the Google Cloud docs config to the build directory
# so Github can upload the documentation
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/app.yaml ${CMAKE_CURRENT_BINARY_DIR}/app.yaml COPYONLY)

# Remove old API docs folder
file(REMOVE_RECURSE ${CMAKE_CURRENT_SOURCE_DIR}/api/)

add_custom_target(doxygen_generate ALL
    COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${DOXYGEN_OUT}
    COMMENT "Generating API documentation with Doxygen"
    VERBATIM
)

set(SPHINX_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/source)
set(SPHINX_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/sphinx)
set(SPHINX_INDEX_FILE ${SPHINX_BUILD_DIR}/html/index.html)
set(BREATHE_XML_DIR "${DOXYGEN_OUTPUT_DIR}/xml")
set(SPHINX_CONFIG_FILE "${SPHINX_SOURCE_DIR}/conf.py")

# Gather all Sphinx source files
file(GLOB_RECURSE SPHINX_SOURCE_FILES
    "${SPHINX_SOURCE_DIR}/*.rst"
    "${SPHINX_SOURCE_DIR}/*.py"
    "${SPHINX_SOURCE_DIR}/*.md"
)

# Gather all images to force a rebuild on change
file(GLOB_RECURSE IMAGES
    "${SPHINX_SOURCE_DIR}/*.svg"
)

add_custom_command(
    OUTPUT "${SPHINX_BUILD_DIR}/html/index.html"
    # COMMAND "${BREATHE_APIDOC_EXECUTABLE}" -f -o "${SPHINX_SOURCE_DIR}/api" "${BREATHE_XML_DIR}"
    COMMAND "${SPHINX_EXECUTABLE}" -b html "${SPHINX_SOURCE_DIR}" "${SPHINX_BUILD_DIR}/html"
    DEPENDS "${SPHINX_CONFIG_FILE}" ${SPHINX_SOURCE_FILES} ${IMAGES} doxygen_generate
    COMMENT "Generating Sphinx HTML documentation"
    VERBATIM
)

# Only regenerate Sphinx when:
# - Doxygen has rerun
# - Our doc files have been updated
# - The Sphinx config has been updated
# add_custom_command(OUTPUT ${SPHINX_INDEX_FILE}
#     COMMAND 
#     ${SPHINX_EXECUTABLE} -b html
#     # Tell Breathe where to find the Doxygen output
#     -Dbreathe_projects.SanicDNS=${DOXYGEN_OUTPUT_DIR}/xml
#     ${SPHINX_SOURCE_DIR} ${SPHINX_BUILD_DIR}
#     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
#     DEPENDS
#     ${SPHINX_SOURCES}
#     ${DOXYGEN_INDEX_FILE}
#     MAIN_DEPENDENCY ${SPHINX_SOURCE_DIR}/conf.py
#     COMMENT "Generating documentation with Sphinx")

# Nice named target so we can run the job easily
add_custom_target(Sphinx ALL DEPENDS ${SPHINX_INDEX_FILE})
