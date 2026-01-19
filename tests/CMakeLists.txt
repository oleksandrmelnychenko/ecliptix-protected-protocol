# Test configuration for Ecliptix Protection Protocol

# Find Catch2
find_package(Catch2 3 QUIET)

if(NOT Catch2_FOUND)
    message(STATUS "Catch2 not found, using FetchContent")
    include(FetchContent)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG        v3.7.1  # Updated for C++20 compatibility
    )
    FetchContent_MakeAvailable(Catch2)
endif()

# =============================================================================
# Test Sources - Currently Compilable
# =============================================================================
# These tests compile with the current codebase (Phase 2 complete)

set(TEST_SOURCES
    # Unit tests - Core functionality
    unit/test_result.cpp
    unit/test_sodium_interop.cpp
    unit/test_secure_memory_handle.cpp
    unit/test_aes_gcm.cpp
    unit/test_dh_validator.cpp
    unit/test_kyber_interop_comprehensive.cpp
    unit/test_session_replay_protection.cpp
    unit/test_session_state_mac.cpp
    unit/test_session_chain_length.cpp
    unit/test_secret_sharing.cpp
    unit/test_state_import_invariants.cpp

    # Security tests
    security/test_aes_gcm_attacks.cpp
    security/test_hkdf_security.cpp

    # Signal Protocol interoperability tests
    interop/test_x3dh_vectors.cpp
    interop/test_double_ratchet_vectors.cpp

    # Benchmarks
    benchmarks/bench_crypto_performance.cpp
)

# =============================================================================
# Test Sources - Pending Implementation (Phase 3+)
# =============================================================================
# These tests exist but require headers not yet implemented:
#
# PHASE 3 - Key Management (requires: ratchet_recovery.hpp, replay_protection.hpp)
#   unit/test_ratchet_recovery.cpp
#   unit/test_replay_protection.cpp
#   attacks/test_replay_attacks.cpp
#
# PHASE 4 - Protocol Core (requires: protocol_connection.hpp, chain_step.hpp, etc.)
#   unit/test_chain_step.cpp
#   unit/test_connection.cpp
#   unit/test_envelope_builder.cpp
#   unit/test_metadata_key_agreement.cpp
#   unit/test_protocol_config.cpp
#   attacks/test_envelope_attacks.cpp
#   boundaries/test_state_transitions.cpp
#   concurrency/test_concurrent_envelopes.cpp
#   performance/test_envelope_performance.cpp
#   security/test_metadata_key_rotation.cpp
#   security/test_persistence_pq.cpp
#   security/test_rate_limiting.cpp
#   security/test_session_lifecycle.cpp
#   integration/test_end_to_end_workflow.cpp
#   integration/test_protocol_system_workflow.cpp
#   fuzzing/test_envelope_fuzzing.cpp
#
# C API Tests (requires: server API functions)
#   c_api/test_c_api_boundary.cpp
#   c_api/test_c_api_break_in_recovery.cpp
#   c_api/test_c_api_forward_secrecy.cpp
#   c_api/test_c_api_handshake_e2e.cpp
#   c_api/test_c_api_hybrid_pq.cpp
#   c_api/test_c_api_integration.cpp
#   c_api/test_c_api_pre_handshake.cpp
#   c_api/test_c_api_role_validation.cpp
#   c_api/test_c_api_state_persistence.cpp
#   c_api/test_server_c_api_secret_sharing.cpp
# =============================================================================

# Server-specific C API tests (separate binary to avoid symbol collisions)
set(SERVER_TEST_SOURCES
    test_main.cpp
)

# Test executable
add_executable(ecliptix_tests ${TEST_SOURCES})

target_link_libraries(ecliptix_tests
    PRIVATE
        Ecliptix::Protocol
        Catch2::Catch2WithMain
)

target_include_directories(ecliptix_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(ecliptix_tests
    PRIVATE
        ECLIPTIX_TEST_BUILD=1
)

# Suppress GCC 13 false positive with std::optional<std::vector<>> move semantics
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(ecliptix_tests PRIVATE -Wno-maybe-uninitialized)
endif()

# Server test executable
if(TARGET Ecliptix::ProtocolServer)
    add_executable(ecliptix_server_tests ${SERVER_TEST_SOURCES})

    # Link both client and server libraries
    # Note: Both libraries have some duplicate shared functions (identity_keys, etc.)
    # We use -force_load for the client library to ensure all its symbols take precedence
    if(APPLE)
        target_link_libraries(ecliptix_server_tests
            PRIVATE
                "-Wl,-force_load,$<TARGET_FILE:Ecliptix::Protocol>"
                Ecliptix::ProtocolServer
                Catch2::Catch2WithMain
        )
    else()
        target_link_libraries(ecliptix_server_tests
            PRIVATE
                -Wl,--whole-archive
                Ecliptix::Protocol
                -Wl,--no-whole-archive
                Ecliptix::ProtocolServer
                Catch2::Catch2WithMain
        )
    endif()

    target_include_directories(ecliptix_server_tests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}
    )

    target_compile_definitions(ecliptix_server_tests
        PRIVATE
            ECLIPTIX_TEST_BUILD=1
    )

    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(ecliptix_server_tests PRIVATE -Wno-maybe-uninitialized)
    endif()
endif()

# Register tests with CTest for CLion test runner
include(CTest)
list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
include(Catch)
catch_discover_tests(ecliptix_tests)
if(TARGET ecliptix_server_tests)
    catch_discover_tests(ecliptix_server_tests)
endif()
