cmake_minimum_required(VERSION 3.20)
project(Ecliptix_Protected_Protocol VERSION 1.0.0 LANGUAGES CXX)

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
option(ECLIPTIX_BUILD_TESTS "Build tests" OFF)
option(ECLIPTIX_BUILD_EXAMPLES "Build examples" ON)
option(ECLIPTIX_BUILD_SHARED "Build shared library" OFF)
option(ECLIPTIX_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ECLIPTIX_ENABLE_TSAN "Enable ThreadSanitizer" OFF)
option(ECLIPTIX_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(ECLIPTIX_BUILD_CLIENT_TARGET "Build client (desktop/mobile) target with C API" ON)
option(ECLIPTIX_BUILD_SERVER_TARGET "Build server target (core only)" ON)

# ============================================================================
# Position Independent Code (required for shared libraries)
# ============================================================================
if(ECLIPTIX_BUILD_SHARED)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

# ============================================================================
# Windows DLL Symbol Export
# ============================================================================
# Export all symbols from DLLs on Windows (required for C API)
if(WIN32 AND ECLIPTIX_BUILD_SHARED)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

# ============================================================================
# Compiler Warnings and Security Hardening
# ============================================================================
if(MSVC)
    add_compile_options(/W4 /WX)
    # Suppress CRT secure warnings for getenv, etc.
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    # Common warnings for GCC/Clang
    add_compile_options(
        -Wall -Wextra -Werror
        -Wno-unused-parameter
        -Wno-missing-field-initializers
    )

    # Clang-specific: enable -Wpedantic with GNU extension exception
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        add_compile_options(
            -Wpedantic
            -Wno-gnu-statement-expression-from-macro-expansion
        )
    endif()
    # GCC: skip -Wpedantic as it rejects GNU statement expressions used by TRY macro

    # MinGW/GCC 15: suppress false positive with vector comparison
    if(MINGW)
        add_compile_options(-Wno-stringop-overread)
    endif()

    # Security hardening flags (GCC/Clang)
    add_compile_options(
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=2
        -Wformat
        -Wformat-security
        -Werror=format-security
    )

    # Position-independent code
    if(ECLIPTIX_BUILD_SHARED)
        # Shared libraries require -fPIC on all object files
        add_compile_options(-fPIC)
    elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
        # Executables use -fPIE for ASLR
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

# liboqs - Post-quantum cryptography (Kyber)
pkg_check_modules(LIBOQS REQUIRED liboqs)

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

# Source files
set(ECLIPTIX_CORE_SOURCES
    ${ECLIPTIX_SOURCE_DIR}/core/failures.cpp

    # Crypto layer - Phase 2 & 3
    ${ECLIPTIX_SOURCE_DIR}/crypto/sodium_interop.cpp
    ${ECLIPTIX_SOURCE_DIR}/crypto/sodium_secure_memory_handle.cpp
    ${ECLIPTIX_SOURCE_DIR}/crypto/hkdf.cpp
    ${ECLIPTIX_SOURCE_DIR}/crypto/master_key_derivation.cpp
    ${ECLIPTIX_SOURCE_DIR}/crypto/aes_gcm.cpp
    ${ECLIPTIX_SOURCE_DIR}/crypto/kyber_interop.cpp

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
)

set(ECLIPTIX_CLIENT_SOURCES
    ${ECLIPTIX_CORE_SOURCES}
    ${ECLIPTIX_SOURCE_DIR}/c_api/ecliptix_c_api.cpp
)

# Server sources include core + server-specific C API
set(ECLIPTIX_SERVER_SOURCES
    ${ECLIPTIX_CORE_SOURCES}
    ${ECLIPTIX_SOURCE_DIR}/c_api/ecliptix_server_c_api.cpp
)

function(configure_protocol_target target_name output_name)
    if(ECLIPTIX_BUILD_SHARED)
        add_library(${target_name} SHARED ${ARGN})
        target_compile_definitions(${target_name} PRIVATE ECLIPTIX_EXPORTS)
    else()
        add_library(${target_name} STATIC ${ARGN})
    endif()

    target_include_directories(${target_name}
        PUBLIC
            $<BUILD_INTERFACE:${ECLIPTIX_INCLUDE_DIR}>
            $<INSTALL_INTERFACE:include>
            ${LIBSODIUM_INCLUDE_DIRS}
            ${LIBOQS_INCLUDE_DIRS}
        PRIVATE
            ${ECLIPTIX_SOURCE_DIR}
    )

    target_link_directories(${target_name}
        PUBLIC
            ${LIBSODIUM_LIBRARY_DIRS}
            ${LIBOQS_LIBRARY_DIRS}
    )

    target_link_libraries(${target_name}
        PUBLIC
            ${LIBSODIUM_LIBRARIES}
            ${LIBOQS_LIBRARIES}
            OpenSSL::Crypto
            Ecliptix::Proto
        PRIVATE
            $<$<BOOL:${spdlog_FOUND}>:spdlog::spdlog>
    )

    target_compile_definitions(${target_name}
        PRIVATE
            $<$<BOOL:${spdlog_FOUND}>:ECLIPTIX_HAS_SPDLOG>
            $<$<BOOL:${ECLIPTIX_BUILD_TESTS}>:ECLIPTIX_TEST_BUILD>
    )

    set_target_properties(${target_name} PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        OUTPUT_NAME ${output_name}
        POSITION_INDEPENDENT_CODE ON
    )
endfunction()

# ============================================================================
# Library Target
# ============================================================================
if(ECLIPTIX_BUILD_CLIENT_TARGET)
    configure_protocol_target(${PROJECT_NAME} "epp_agent" ${ECLIPTIX_CLIENT_SOURCES})
    add_library(Ecliptix::Protocol ALIAS ${PROJECT_NAME})
endif()

if(ECLIPTIX_BUILD_SERVER_TARGET)
    configure_protocol_target(Ecliptix_Protocol_Server "epp_relay" ${ECLIPTIX_SERVER_SOURCES})
    add_library(Ecliptix::ProtocolServer ALIAS Ecliptix_Protocol_Server)
endif()

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
# Examples removed - functionality moved to tests
# if(ECLIPTIX_BUILD_EXAMPLES)
#     add_subdirectory(examples)
# endif()

# ============================================================================
# Installation
# ============================================================================
include(GNUInstallDirs)

# Install library
set(ECLIPTIX_INSTALL_TARGETS ecliptix_proto)
if(ECLIPTIX_BUILD_CLIENT_TARGET)
    list(APPEND ECLIPTIX_INSTALL_TARGETS ${PROJECT_NAME})
endif()
if(ECLIPTIX_BUILD_SERVER_TARGET)
    list(APPEND ECLIPTIX_INSTALL_TARGETS Ecliptix_Protocol_Server)
endif()

install(TARGETS ${ECLIPTIX_INSTALL_TARGETS}
    EXPORT EcliptixProtocolTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install headers
install(DIRECTORY ${ECLIPTIX_INCLUDE_DIR}/ecliptix
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.hpp" PATTERN "*.h"
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
message(STATUS "Ecliptix Protected Protocol Configuration:")
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
