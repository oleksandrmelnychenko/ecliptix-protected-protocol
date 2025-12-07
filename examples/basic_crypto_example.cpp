/**
 * @file basic_crypto_example.cpp
 * @brief Basic example demonstrating secure memory and key generation
 */

#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include "ecliptix/core/result.hpp"

#include <iostream>
#include <iomanip>

using namespace ecliptix::protocol;
using namespace ecliptix::protocol::crypto;

void print_hex(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << label << ": ";
    for (auto byte : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(byte);
    }
    std::cout << std::dec << std::endl;
}

int main() {
    std::cout << "=== Ecliptix Protocol System - Basic Crypto Example ===" << std::endl;
    std::cout << std::endl;

    // Initialize libsodium
    std::cout << "1. Initializing libsodium..." << std::endl;
    auto init_result = SodiumInterop::Initialize();
    if (init_result.IsErr()) {
        std::cerr << "Failed to initialize: "
                  << init_result.UnwrapErr().message << std::endl;
        return 1;
    }
    std::cout << "   ✓ Initialized successfully" << std::endl;
    std::cout << std::endl;

    // Generate X25519 key pair
    std::cout << "2. Generating X25519 (Curve25519) key pair..." << std::endl;
    auto x25519_result = SodiumInterop::GenerateX25519KeyPair("example");
    if (x25519_result.IsErr()) {
        std::cerr << "Failed to generate X25519 key pair" << std::endl;
        return 1;
    }

    auto [sk_handle, pk_bytes] = std::move(x25519_result).Unwrap();
    std::cout << "   ✓ Generated X25519 key pair" << std::endl;
    print_hex("   Public key", pk_bytes);
    std::cout << "   Secret key: [SECURE - stored in protected memory]" << std::endl;
    std::cout << std::endl;

    // Generate Ed25519 key pair
    std::cout << "3. Generating Ed25519 (EdDSA) key pair..." << std::endl;
    auto ed25519_result = SodiumInterop::GenerateEd25519KeyPair();
    if (ed25519_result.IsErr()) {
        std::cerr << "Failed to generate Ed25519 key pair" << std::endl;
        return 1;
    }

    auto [ed_sk, ed_pk] = std::move(ed25519_result).Unwrap();
    std::cout << "   ✓ Generated Ed25519 key pair" << std::endl;
    print_hex("   Public key", ed_pk);
    std::cout << "   Secret key size: " << ed_sk.size() << " bytes" << std::endl;
    std::cout << std::endl;

    // Secure memory operations
    std::cout << "4. Demonstrating secure memory operations..." << std::endl;

    auto handle_result = SecureMemoryHandle::Allocate(32);
    if (handle_result.IsErr()) {
        std::cerr << "Failed to allocate secure memory" << std::endl;
        return 1;
    }

    auto handle = std::move(handle_result).Unwrap();
    std::cout << "   ✓ Allocated " << handle.Size() << " bytes of secure memory" << std::endl;

    // Write data
    std::vector<uint8_t> secret_data = {0x01, 0x02, 0x03, 0x04, 0x05};
    auto write_result = handle.Write(secret_data);
    if (write_result.IsErr()) {
        std::cerr << "Failed to write to secure memory" << std::endl;
        return 1;
    }
    std::cout << "   ✓ Wrote data to secure memory" << std::endl;

    // Read data back using WithReadAccess
    auto read_result = handle.WithReadAccess([](std::span<const uint8_t> data) {
        std::cout << "   ✓ Read " << data.size() << " bytes from secure memory" << std::endl;
        return true;
    });

    if (read_result.IsErr()) {
        std::cerr << "Failed to read from secure memory" << std::endl;
        return 1;
    }
    std::cout << std::endl;

    // Constant-time comparison
    std::cout << "5. Demonstrating constant-time comparison..." << std::endl;
    std::vector<uint8_t> data1 = {1, 2, 3, 4, 5};
    std::vector<uint8_t> data2 = {1, 2, 3, 4, 5};
    std::vector<uint8_t> data3 = {1, 2, 3, 4, 6};

    auto cmp1 = SodiumInterop::ConstantTimeEquals(data1, data2);
    auto cmp2 = SodiumInterop::ConstantTimeEquals(data1, data3);

    std::cout << "   data1 == data2: " << (cmp1.Unwrap() ? "true" : "false") << std::endl;
    std::cout << "   data1 == data3: " << (cmp2.Unwrap() ? "true" : "false") << std::endl;
    std::cout << std::endl;

    // Secure wiping
    std::cout << "6. Securely wiping sensitive data..." << std::endl;
    auto wipe_result = SodiumInterop::SecureWipe(std::span<uint8_t>(ed_sk));
    if (wipe_result.IsOk()) {
        std::cout << "   ✓ Ed25519 secret key securely wiped" << std::endl;
    }
    std::cout << std::endl;

    std::cout << "=== Example completed successfully ===" << std::endl;
    std::cout << std::endl;
    std::cout << "Note: All secure memory is automatically freed when handles" << std::endl;
    std::cout << "      go out of scope (RAII)." << std::endl;

    return 0;
}
