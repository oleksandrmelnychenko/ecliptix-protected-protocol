# Test configuration for Ecliptix Protocol System

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

# Test sources
set(TEST_SOURCES
    unit/test_result.cpp
    unit/test_sodium_interop.cpp
    unit/test_secure_memory_handle.cpp
    unit/test_aes_gcm.cpp
    unit/test_envelope_builder.cpp
    unit/test_chain_step.cpp
    unit/test_dh_validator.cpp
    unit/test_replay_protection.cpp
    unit/test_ratchet_recovery.cpp
    unit/test_connection.cpp
    unit/test_kyber_interop_comprehensive.cpp
    unit/test_protocol_config.cpp
    unit/test_metadata_key_agreement.cpp

    # Phase 1: Cryptographic Security Tests
    security/test_aes_gcm_attacks.cpp
    security/test_hkdf_security.cpp
    security/test_metadata_key_rotation.cpp
    security/test_persistence_pq.cpp
    security/test_rate_limiting.cpp
    security/test_session_lifecycle.cpp

    # Phase 2: Protocol Attack Tests
    attacks/test_replay_attacks.cpp

    # Phase 3: Boundary and State Validation Tests
    boundaries/test_state_transitions.cpp

    # Phase 4: C API Boundary Tests (C# Integration)
    c_api/test_c_api_boundary.cpp

    # Phase 5: Signal Protocol Interoperability Tests
    interop/test_x3dh_vectors.cpp
    interop/test_double_ratchet_vectors.cpp

    # Sprint 1.5B: Aggressive Testing Suite
    integration/test_end_to_end_workflow.cpp
    attacks/test_envelope_attacks.cpp
    concurrency/test_concurrent_envelopes.cpp
    performance/test_envelope_performance.cpp
    fuzzing/test_envelope_fuzzing.cpp
    benchmarks/bench_crypto_performance.cpp

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

# Register tests with CTest for CLion test runner
include(CTest)
list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
include(Catch)
catch_discover_tests(ecliptix_tests)
