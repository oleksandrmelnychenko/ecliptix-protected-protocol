# Protobuf code generation for Ecliptix Protocol

# Prefer static protobuf for distribution builds to avoid runtime dependency issues
if(ECLIPTIX_BUILD_SHARED)
    set(Protobuf_USE_STATIC_LIBS ON)
endif()

# Find protobuf compiler
find_package(Protobuf REQUIRED)
find_package(absl QUIET)

# Proto source files (absolute paths)
set(PROTO_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/protocol/handshake.proto
    ${CMAKE_CURRENT_SOURCE_DIR}/protocol/envelope.proto
    ${CMAKE_CURRENT_SOURCE_DIR}/protocol/error.proto
    ${CMAKE_CURRENT_SOURCE_DIR}/protocol/state.proto
)

# Generate C++ code from proto files
# Use custom command for better control over protoc invocation
foreach(PROTO_FILE ${PROTO_FILES})
    get_filename_component(PROTO_NAME ${PROTO_FILE} NAME_WE)
    get_filename_component(PROTO_DIR ${PROTO_FILE} DIRECTORY)
    get_filename_component(PROTO_SUBDIR ${PROTO_DIR} NAME)

    set(PROTO_SRC "${CMAKE_CURRENT_BINARY_DIR}/${PROTO_SUBDIR}/${PROTO_NAME}.pb.cc")
    set(PROTO_HDR "${CMAKE_CURRENT_BINARY_DIR}/${PROTO_SUBDIR}/${PROTO_NAME}.pb.h")

    list(APPEND PROTO_SRCS ${PROTO_SRC})
    list(APPEND PROTO_HDRS ${PROTO_HDR})

    add_custom_command(
        OUTPUT ${PROTO_SRC} ${PROTO_HDR}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_SUBDIR}
        COMMAND ${Protobuf_PROTOC_EXECUTABLE}
            --proto_path=${CMAKE_CURRENT_SOURCE_DIR}
            --cpp_out=${CMAKE_CURRENT_BINARY_DIR}
            ${PROTO_FILE}
        DEPENDS ${PROTO_FILE}
        COMMENT "Generating C++ code from ${PROTO_NAME}.proto"
        VERBATIM
    )
endforeach()

# Create a library with generated code
add_library(ecliptix_proto ${PROTO_SRCS} ${PROTO_HDRS})

target_link_libraries(ecliptix_proto
    PUBLIC
        protobuf::libprotobuf
        $<$<BOOL:${absl_FOUND}>:absl::log_internal_check_op>
        $<$<BOOL:${absl_FOUND}>:absl::log_internal_message>
)

target_include_directories(ecliptix_proto
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>  # For generated headers
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>  # For proto files
        $<INSTALL_INTERFACE:include>
)

# Set C++20 for generated code
target_compile_features(ecliptix_proto PUBLIC cxx_std_20)

# Disable strict warnings for generated protobuf code
if(MSVC)
    target_compile_options(ecliptix_proto PRIVATE
        /w  # Suppress all warnings for generated protobuf code
    )
else()
    target_compile_options(ecliptix_proto PRIVATE
        -w  # Suppress all warnings for generated protobuf code
    )
endif()

# Alias for consistent usage
add_library(Ecliptix::Proto ALIAS ecliptix_proto)

# Mark for export
set_target_properties(ecliptix_proto PROPERTIES
    EXPORT_NAME Proto
)
