#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"

#include <algorithm>
#include <stdexcept>
#include <cstring>

namespace ecliptix::protocol::crypto {

// ============================================================================
// Initialization
// ============================================================================

Result<Unit, SodiumFailure> SodiumInterop::Initialize() {
    std::call_once(init_flag_, []() {
        if (sodium_init() < 0) {
            // Initialization failed - library may not be available
            initialized_.store(false, std::memory_order_release);
        } else {
            initialized_.store(true, std::memory_order_release);
        }
    });

    if (!initialized_.load(std::memory_order_acquire)) {
        return Result<Unit, SodiumFailure>::Err(
            SodiumFailure::InitializationFailed(
                std::string(ErrorMessages::SODIUM_INIT_FAILED)));
    }

    return Result<Unit, SodiumFailure>::Ok(unit);
}

bool SodiumInterop::IsInitialized() noexcept {
    return initialized_.load(std::memory_order_acquire);
}

// ============================================================================
// Secure Memory Operations
// ============================================================================

Result<Unit, SodiumFailure> SodiumInterop::SecureWipe(std::span<uint8_t> buffer) {
    if (!IsInitialized()) {
        return Result<Unit, SodiumFailure>::Err(
            SodiumFailure::InitializationFailed(
                std::string(ErrorMessages::NOT_INITIALIZED)));
    }

    if (buffer.empty()) {
        return Result<Unit, SodiumFailure>::Ok(unit);
    }

    if (buffer.size() > MAX_BUFFER_SIZE) {
        return Result<Unit, SodiumFailure>::Err(
            SodiumFailure::BufferTooLarge(
                "Buffer size " + std::to_string(buffer.size()) +
                " exceeds maximum " + std::to_string(MAX_BUFFER_SIZE)));
    }

    // Use different strategies based on buffer size
    if (buffer.size() <= Constants::SMALL_BUFFER_THRESHOLD) {
        return WipeSmallBuffer(buffer);
    } else {
        return WipeLargeBuffer(buffer);
    }
}

Result<Unit, SodiumFailure> SodiumInterop::SecureWipe(std::span<const uint8_t> buffer) {
    // const_cast is safe here because we're wiping the memory
    // The const is just to allow temporary const spans
    return SecureWipe(std::span<uint8_t>(
        const_cast<uint8_t*>(buffer.data()),
        buffer.size()));
}

Result<Unit, SodiumFailure> SodiumInterop::WipeSmallBuffer(std::span<uint8_t> buffer) {
    try {
        // For small buffers, use volatile to prevent optimization
        volatile uint8_t* vbuf = buffer.data();
        for (size_t i = 0; i < buffer.size(); ++i) {
            vbuf[i] = 0;
        }
        return Result<Unit, SodiumFailure>::Ok(unit);
    } catch (const std::exception& ex) {
        return Result<Unit, SodiumFailure>::Err(
            SodiumFailure::SecureWipeFailed(
                "Failed to wipe small buffer: " + std::string(ex.what())));
    }
}

Result<Unit, SodiumFailure> SodiumInterop::WipeLargeBuffer(std::span<uint8_t> buffer) {
    try {
        // For large buffers, use sodium_memzero (guaranteed not optimized away)
        sodium_memzero(buffer.data(), buffer.size());
        return Result<Unit, SodiumFailure>::Ok(unit);
    } catch (const std::exception& ex) {
        return Result<Unit, SodiumFailure>::Err(
            SodiumFailure::SecureWipeFailed(
                "Failed to wipe large buffer: " + std::string(ex.what())));
    }
}

Result<bool, SodiumFailure> SodiumInterop::ConstantTimeEquals(
    std::span<const uint8_t> a,
    std::span<const uint8_t> b) {

    // Different sizes are never equal
    if (a.size() != b.size()) {
        return Result<bool, SodiumFailure>::Ok(false);
    }

    // Empty buffers are equal
    if (a.empty()) {
        return Result<bool, SodiumFailure>::Ok(true);
    }

    try {
        // Use sodium_memcmp for constant-time comparison
        int result = sodium_memcmp(a.data(), b.data(), a.size());
        return Result<bool, SodiumFailure>::Ok(result == 0);
    } catch (const std::exception& ex) {
        return Result<bool, SodiumFailure>::Err(
            SodiumFailure::ComparisonFailed(
                std::string(ErrorMessages::CONSTANT_TIME_COMPARISON_FAILED) +
                ": " + ex.what()));
    }
}

// ============================================================================
// Key Generation
// ============================================================================

Result<std::pair<SecureMemoryHandle, std::vector<uint8_t>>, EcliptixProtocolFailure>
SodiumInterop::GenerateX25519KeyPair(std::string_view key_purpose) {
    try {
        // Allocate secure memory for secret key
        auto sk_handle_result = SecureMemoryHandle::Allocate(
            Constants::X_25519_PRIVATE_KEY_SIZE);
        if (sk_handle_result.IsErr()) {
            return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t>>,
                         EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(
                    sk_handle_result.UnwrapErr()));
        }

        SecureMemoryHandle sk_handle = std::move(sk_handle_result).Unwrap();

        // Generate random secret key
        std::vector<uint8_t> sk_bytes = GetRandomBytes(Constants::X_25519_PRIVATE_KEY_SIZE);

        // Write to secure handle
        auto write_result = sk_handle.Write(std::span<const uint8_t>(sk_bytes));
        SecureWipe(std::span<uint8_t>(sk_bytes));  // Immediately wipe the temporary

        if (write_result.IsErr()) {
            return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t>>,
                         EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(
                    write_result.UnwrapErr()));
        }

        // Derive public key from secret key
        std::vector<uint8_t> temp_sk(Constants::X_25519_PRIVATE_KEY_SIZE);
        auto read_result = sk_handle.Read(std::span<uint8_t>(temp_sk));
        if (read_result.IsErr()) {
            SecureWipe(std::span<uint8_t>(temp_sk));
            return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t>>,
                         EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(
                    read_result.UnwrapErr()));
        }

        std::vector<uint8_t> pk_bytes(Constants::X_25519_PUBLIC_KEY_SIZE);
        if (crypto_scalarmult_base(pk_bytes.data(), temp_sk.data()) != 0) {
            SecureWipe(std::span<uint8_t>(temp_sk));
            return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t>>,
                         EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::DeriveKey(
                    "Failed to derive " + std::string(key_purpose) + " public key"));
        }

        SecureWipe(std::span<uint8_t>(temp_sk));

        // Validate public key size
        if (pk_bytes.size() != Constants::X_25519_PUBLIC_KEY_SIZE) {
            return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t>>,
                         EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::DeriveKey(
                    "Derived " + std::string(key_purpose) + " public key has incorrect size"));
        }

        return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t>>,
                     EcliptixProtocolFailure>::Ok(
            std::make_pair(std::move(sk_handle), std::move(pk_bytes)));

    } catch (const std::exception& ex) {
        return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t>>,
                     EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::KeyGeneration(
                "Unexpected error generating " + std::string(key_purpose) +
                " key pair: " + ex.what()));
    }
}

Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, EcliptixProtocolFailure>
SodiumInterop::GenerateEd25519KeyPair() {
    try {
        std::vector<uint8_t> pk(Constants::ED_25519_PUBLIC_KEY_SIZE);
        std::vector<uint8_t> sk(Constants::ED_25519_SECRET_KEY_SIZE);

        if (crypto_sign_keypair(pk.data(), sk.data()) != 0) {
            SecureWipe(std::span<uint8_t>(sk));
            return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>,
                         EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::KeyGeneration(
                    "Failed to generate Ed25519 key pair"));
        }

        return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>,
                     EcliptixProtocolFailure>::Ok(
            std::make_pair(std::move(sk), std::move(pk)));

    } catch (const std::exception& ex) {
        return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>,
                     EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::KeyGeneration(
                "Unexpected error generating Ed25519 key pair: " +
                std::string(ex.what())));
    }
}

// ============================================================================
// Random Number Generation
// ============================================================================

std::vector<uint8_t> SodiumInterop::GetRandomBytes(size_t size) {
    std::vector<uint8_t> buffer(size);
    randombytes_buf(buffer.data(), size);
    return buffer;
}

uint32_t SodiumInterop::GenerateRandomUInt32(bool ensure_non_zero) {
    uint32_t value;
    do {
        value = randombytes_uniform(UINT32_MAX);
    } while (ensure_non_zero && value == 0);

    return value;
}

// ============================================================================
// Memory Allocation
// ============================================================================

void* SodiumInterop::AllocateSecure(size_t size) noexcept {
    if (!IsInitialized()) {
        return nullptr;
    }
    return sodium_malloc(size);
}

void SodiumInterop::FreeSecure(void* ptr) noexcept {
    if (ptr != nullptr) {
        sodium_free(ptr);
    }
}

} // namespace ecliptix::protocol::crypto
