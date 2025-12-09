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

    # Phase 1: Cryptographic Security Tests
    security/test_aes_gcm_attacks.cpp
    security/test_hkdf_security.cpp

    # Phase 2: Protocol Attack Tests
    attacks/test_replay_attacks.cpp

    # Phase 3: Boundary and State Validation Tests
    boundaries/test_state_transitions.cpp

    # Phase 4: C API Boundary Tests (C# Integration)
    c_api/test_c_api_boundary.cpp

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

# Register tests with CTest for CLion test runner
include(CTest)
list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
include(Catch)
catch_discover_tests(ecliptix_tests)
