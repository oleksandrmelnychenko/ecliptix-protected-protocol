# Test configuration for Ecliptix Protocol System

# Find Catch2
find_package(Catch2 3 QUIET)

if(NOT Catch2_FOUND)
    message(STATUS "Catch2 not found, using FetchContent")
    include(FetchContent)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG        v3.5.0
    )
    FetchContent_MakeAvailable(Catch2)
endif()

# Test sources
set(TEST_SOURCES
    unit/test_result.cpp
    unit/test_sodium_interop.cpp
    unit/test_secure_memory_handle.cpp
    unit/test_chain_step.cpp
    unit/test_dh_validator.cpp
    unit/test_replay_protection.cpp
    unit/test_ratchet_recovery.cpp
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

# Register tests with CTest
include(Catch)
catch_discover_tests(ecliptix_tests)
