# Examples for Ecliptix Protocol System

# Basic crypto example
add_executable(basic_crypto_example
    basic_crypto_example.cpp
)

target_link_libraries(basic_crypto_example
    PRIVATE
        Ecliptix::Protocol
)

# Set output directory
set_target_properties(basic_crypto_example
    PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/examples"
)
