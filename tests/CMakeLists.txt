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
    unit/test_session_state_hmac.cpp
    unit/test_session_chain_length.cpp
    unit/test_secret_sharing.cpp

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
# Additional test suites are added alongside new features as they land.
# =============================================================================

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
