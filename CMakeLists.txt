cmake_minimum_required(VERSION 3.20)
project(Ecliptix_Protocol_System VERSION 1.0.0 LANGUAGES CXX)

# ============================================================================
# Project Configuration
# ============================================================================
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile commands for IDEs
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ============================================================================
# Build Options
# ============================================================================
option(ECLIPTIX_BUILD_TESTS "Build tests" ON)
option(ECLIPTIX_BUILD_EXAMPLES "Build examples" ON)
option(ECLIPTIX_BUILD_SHARED "Build shared library" OFF)
option(ECLIPTIX_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ECLIPTIX_ENABLE_TSAN "Enable ThreadSanitizer" OFF)
option(ECLIPTIX_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)

# ============================================================================
# Compiler Warnings and Security Hardening
# ============================================================================
if(MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(
        -Wall -Wextra -Wpedantic -Werror
        -Wno-unused-parameter
        -Wno-missing-field-initializers
        -Wno-gnu-statement-expression-from-macro-expansion
    )

    # Security hardening flags
    add_compile_options(
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=2
        -Wformat
        -Wformat-security
        -Werror=format-security
    )

    # Position-independent code for Release builds
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(-fPIE)
        add_link_options(-pie)
    endif()
endif()

# ============================================================================
# Sanitizers
# ============================================================================
if(ECLIPTIX_ENABLE_ASAN)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
endif()

if(ECLIPTIX_ENABLE_TSAN)
    add_compile_options(-fsanitize=thread)
    add_link_options(-fsanitize=thread)
endif()

if(ECLIPTIX_ENABLE_UBSAN)
    add_compile_options(-fsanitize=undefined)
    add_link_options(-fsanitize=undefined)
endif()

# ============================================================================
# Dependencies
# ============================================================================
find_package(PkgConfig REQUIRED)

# libsodium - Core cryptographic library
pkg_check_modules(LIBSODIUM REQUIRED libsodium)

# OpenSSL - For HKDF implementation
find_package(OpenSSL REQUIRED)

# Protobuf - Message serialization
find_package(Protobuf REQUIRED)

# Optional: spdlog for logging
find_package(spdlog QUIET)

# ============================================================================
# Project Sources
# ============================================================================
set(ECLIPTIX_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(ECLIPTIX_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Core headers (public API)
set(ECLIPTIX_PUBLIC_HEADERS
    ${ECLIPTIX_INCLUDE_DIR}/ecliptix/core/constants.hpp
    ${ECLIPTIX_INCLUDE_DIR}/ecliptix/core/result.hpp
    ${ECLIPTIX_INCLUDE_DIR}/ecliptix/core/option.hpp
    ${ECLIPTIX_INCLUDE_DIR}/ecliptix/core/failures.hpp
)

# Source files (will be populated as we port)
set(ECLIPTIX_SOURCES
    ${ECLIPTIX_SOURCE_DIR}/core/failures.cpp

    # Crypto layer - Phase 2 & 3
    ${ECLIPTIX_SOURCE_DIR}/crypto/sodium_interop.cpp
    ${ECLIPTIX_SOURCE_DIR}/crypto/sodium_secure_memory_handle.cpp
    ${ECLIPTIX_SOURCE_DIR}/crypto/hkdf.cpp
    ${ECLIPTIX_SOURCE_DIR}/crypto/master_key_derivation.cpp
    ${ECLIPTIX_SOURCE_DIR}/crypto/aes_gcm.cpp

    # Models - Phase 3
    ${ECLIPTIX_SOURCE_DIR}/models/key_materials/ed25519_key_material.cpp
    ${ECLIPTIX_SOURCE_DIR}/models/key_materials/x25519_key_material.cpp
    ${ECLIPTIX_SOURCE_DIR}/models/key_materials/signed_pre_key_material.cpp
    ${ECLIPTIX_SOURCE_DIR}/models/keys/one_time_pre_key_local.cpp
    ${ECLIPTIX_SOURCE_DIR}/models/keys/one_time_pre_key_record.cpp
    ${ECLIPTIX_SOURCE_DIR}/models/bundles/local_public_key_bundle.cpp

    # Identity - Phase 3
    ${ECLIPTIX_SOURCE_DIR}/identity/ecliptix_system_identity_keys.cpp

    # Protocol - Phase 4
    ${ECLIPTIX_SOURCE_DIR}/protocol/chain_step/ecliptix_protocol_chain_step.cpp

    # Connection - Phase 5
    ${ECLIPTIX_SOURCE_DIR}/protocol/connection/ecliptix_protocol_connection.cpp

    # Protocol System - Phase 6
    ${ECLIPTIX_SOURCE_DIR}/protocol/ecliptix_protocol_system.cpp

    # Security - Phase 5
    ${ECLIPTIX_SOURCE_DIR}/security/validation/dh_validator.cpp
    ${ECLIPTIX_SOURCE_DIR}/security/ratcheting/replay_protection.cpp
    ${ECLIPTIX_SOURCE_DIR}/security/ratcheting/ratchet_recovery.cpp

    # Utilities
    ${ECLIPTIX_SOURCE_DIR}/utilities/envelope_builder.cpp

    # Group Messaging - Phase 5
    ${ECLIPTIX_SOURCE_DIR}/protocol/group/group_member.cpp
    ${ECLIPTIX_SOURCE_DIR}/protocol/group/group_metadata.cpp

    # C API - Phase 1 (C# Interop)
    ${ECLIPTIX_SOURCE_DIR}/c_api/ecliptix_c_api.cpp
)

# ============================================================================
# Library Target
# ============================================================================
if(ECLIPTIX_BUILD_SHARED)
    add_library(${PROJECT_NAME} SHARED ${ECLIPTIX_SOURCES})
    target_compile_definitions(${PROJECT_NAME} PRIVATE ECLIPTIX_EXPORTS)
else()
    add_library(${PROJECT_NAME} STATIC ${ECLIPTIX_SOURCES})
endif()

# Library alias for consistent usage
add_library(Ecliptix::Protocol ALIAS ${PROJECT_NAME})

# ============================================================================
# Target Properties
# ============================================================================
target_include_directories(${PROJECT_NAME}
    PUBLIC
        $<BUILD_INTERFACE:${ECLIPTIX_INCLUDE_DIR}>
        $<INSTALL_INTERFACE:include>
        ${LIBSODIUM_INCLUDE_DIRS}
    PRIVATE
        ${ECLIPTIX_SOURCE_DIR}
)

target_link_directories(${PROJECT_NAME}
    PUBLIC
        ${LIBSODIUM_LIBRARY_DIRS}
)

target_link_libraries(${PROJECT_NAME}
    PUBLIC
        ${LIBSODIUM_LIBRARIES}
        OpenSSL::Crypto
        Ecliptix::Proto
    PRIVATE
        $<$<BOOL:${spdlog_FOUND}>:spdlog::spdlog>
)

target_compile_definitions(${PROJECT_NAME}
    PRIVATE
        $<$<BOOL:${spdlog_FOUND}>:ECLIPTIX_HAS_SPDLOG>
        $<$<BOOL:${ECLIPTIX_BUILD_TESTS}>:ECLIPTIX_TEST_BUILD=1>
)

# Set library properties
set_target_properties(${PROJECT_NAME} PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    OUTPUT_NAME "ecliptix_protocol"
    POSITION_INDEPENDENT_CODE ON
)

# ============================================================================
# Protobuf Code Generation
# ============================================================================
add_subdirectory(proto)

# ============================================================================
# Tests
# ============================================================================
if(ECLIPTIX_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ============================================================================
# Examples
# ============================================================================
if(ECLIPTIX_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# ============================================================================
# Installation
# ============================================================================
include(GNUInstallDirs)

# Install library
install(TARGETS ${PROJECT_NAME} ecliptix_proto
    EXPORT EcliptixProtocolTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install headers
install(DIRECTORY ${ECLIPTIX_INCLUDE_DIR}/ecliptix
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.hpp"
)

# Install CMake config
install(EXPORT EcliptixProtocolTargets
    FILE EcliptixProtocolTargets.cmake
    NAMESPACE Ecliptix::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/EcliptixProtocol
)

# Generate config file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/EcliptixProtocolConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/EcliptixProtocolConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/EcliptixProtocolConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/EcliptixProtocol
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/EcliptixProtocolConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/EcliptixProtocolConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/EcliptixProtocol
)

# ============================================================================
# Summary
# ============================================================================
message(STATUS "")
message(STATUS "Ecliptix Protocol System Configuration:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  C++ Standard: C++${CMAKE_CXX_STANDARD}")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Build Tests: ${ECLIPTIX_BUILD_TESTS}")
message(STATUS "  Build Examples: ${ECLIPTIX_BUILD_EXAMPLES}")
message(STATUS "  Build Shared: ${ECLIPTIX_BUILD_SHARED}")
message(STATUS "  libsodium: ${LIBSODIUM_VERSION}")
message(STATUS "  Protobuf: ${Protobuf_VERSION}")
if(spdlog_FOUND)
    message(STATUS "  spdlog: ${spdlog_VERSION}")
endif()
message(STATUS "")
