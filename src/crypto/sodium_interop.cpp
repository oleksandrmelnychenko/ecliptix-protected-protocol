#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"

namespace ecliptix::protocol::crypto {
    Result<Unit, SodiumFailure> SodiumInterop::Initialize() {
        std::call_once(init_flag_, [] {
            if (sodium_init() < 0) {
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

    Result<Unit, SodiumFailure> SodiumInterop::SecureWipe(const std::span<uint8_t> buffer) {
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
        if (buffer.size() <= Constants::SMALL_BUFFER_THRESHOLD) {
            return WipeSmallBuffer(buffer);
        }

        return WipeLargeBuffer(buffer);
    }

    Result<Unit, SodiumFailure> SodiumInterop::SecureWipe(std::span<const uint8_t> buffer) {
        return SecureWipe(std::span(
            const_cast<uint8_t *>(buffer.data()),
            buffer.size()));
    }

    Result<Unit, SodiumFailure> SodiumInterop::WipeSmallBuffer(std::span<uint8_t> buffer) {
        try {
            sodium_memzero(buffer.data(), buffer.size());
            return Result<Unit, SodiumFailure>::Ok(unit);
        } catch (const std::exception &ex) {
            return Result<Unit, SodiumFailure>::Err(
                SodiumFailure::SecureWipeFailed(
                    "Failed to wipe small buffer: " + std::string(ex.what())));
        }
    }

    Result<Unit, SodiumFailure> SodiumInterop::WipeLargeBuffer(std::span<uint8_t> buffer) {
        try {
            sodium_memzero(buffer.data(), buffer.size());
            return Result<Unit, SodiumFailure>::Ok(unit);
        } catch (const std::exception &ex) {
            return Result<Unit, SodiumFailure>::Err(
                SodiumFailure::SecureWipeFailed(
                    "Failed to wipe large buffer: " + std::string(ex.what())));
        }
    }

    Result<bool, SodiumFailure> SodiumInterop::ConstantTimeEquals(
        const std::span<const uint8_t> a,
        const std::span<const uint8_t> b) {
        if (a.size() != b.size()) {
            return Result<bool, SodiumFailure>::Ok(false);
        }
        if (a.empty()) {
            return Result<bool, SodiumFailure>::Ok(true);
        }
        try {
            const int result = sodium_memcmp(a.data(), b.data(), a.size());
            return Result<bool, SodiumFailure>::Ok(result == ComparisonConstants::EQUAL);
        } catch (const std::exception &ex) {
            return Result<bool, SodiumFailure>::Err(
                SodiumFailure::ComparisonFailed(
                    std::string(ErrorMessages::CONSTANT_TIME_COMPARISON_FAILED) +
                    ": " + ex.what()));
        }
    }

    Result<std::pair<SecureMemoryHandle, std::vector<uint8_t> >, ProtocolFailure>
    SodiumInterop::GenerateX25519KeyPair(std::string_view key_purpose) {
        try {
            auto sk_handle_result = SecureMemoryHandle::Allocate(
                kX25519PrivateKeyBytes);
            if (sk_handle_result.IsErr()) {
                return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t> >,
                    ProtocolFailure>::Err(
                    ProtocolFailure::FromSodiumFailure(
                        sk_handle_result.UnwrapErr()));
            }
            SecureMemoryHandle sk_handle = std::move(sk_handle_result).Unwrap();
            std::vector<uint8_t> sk_bytes = GetRandomBytes(kX25519PrivateKeyBytes);
            auto write_result = sk_handle.Write(std::span<const uint8_t>(sk_bytes));
            SecureWipe(std::span(sk_bytes));
            if (write_result.IsErr()) {
                return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t> >,
                    ProtocolFailure>::Err(
                    ProtocolFailure::FromSodiumFailure(
                        write_result.UnwrapErr()));
            }
            std::vector<uint8_t> temp_sk(kX25519PrivateKeyBytes);
            if (auto read_result = sk_handle.Read(std::span(temp_sk)); read_result.IsErr()) {
                SecureWipe(std::span(temp_sk));
                return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t> >,
                    ProtocolFailure>::Err(
                    ProtocolFailure::FromSodiumFailure(
                        read_result.UnwrapErr()));
            }
            std::vector<uint8_t> pk_bytes(kX25519PublicKeyBytes);
            if (crypto_scalarmult_base(pk_bytes.data(), temp_sk.data()) != SodiumConstants::SUCCESS) {
                SecureWipe(std::span(temp_sk));
                return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t> >,
                    ProtocolFailure>::Err(
                    ProtocolFailure::DeriveKey(
                        "Failed to derive " + std::string(key_purpose) + " public key"));
            }
            SecureWipe(std::span(temp_sk));
            if (pk_bytes.size() != kX25519PublicKeyBytes) {
                return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t> >,
                    ProtocolFailure>::Err(
                    ProtocolFailure::DeriveKey(
                        "Derived " + std::string(key_purpose) + " public key has incorrect size"));
            }
            return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t> >,
                ProtocolFailure>::Ok(
                std::make_pair(std::move(sk_handle), std::move(pk_bytes)));
        } catch (const std::exception &ex) {
            return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t> >,
                ProtocolFailure>::Err(
                ProtocolFailure::KeyGeneration(
                    "Unexpected error generating " + std::string(key_purpose) +
                    " key pair: " + ex.what()));
        }
    }

    Result<std::pair<SecureMemoryHandle, std::vector<uint8_t>>, ProtocolFailure>
    SodiumInterop::GenerateEd25519KeyPair() {
        try {
            auto sk_handle_result = SecureMemoryHandle::Allocate(kEd25519SecretKeyBytes);
            if (sk_handle_result.IsErr()) {
                return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t>>,
                    ProtocolFailure>::Err(
                    ProtocolFailure::FromSodiumFailure(sk_handle_result.UnwrapErr()));
            }
            SecureMemoryHandle sk_handle = std::move(sk_handle_result).Unwrap();
            std::vector<uint8_t> pk(kEd25519PublicKeyBytes);
            std::vector<uint8_t> temp_sk(kEd25519SecretKeyBytes);
            if (crypto_sign_keypair(pk.data(), temp_sk.data()) != SodiumConstants::SUCCESS) {
                SecureWipe(std::span(temp_sk));
                return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t>>,
                    ProtocolFailure>::Err(
                    ProtocolFailure::KeyGeneration("Failed to generate Ed25519 key pair"));
            }
            auto write_result = sk_handle.Write(std::span<const uint8_t>(temp_sk));
            SecureWipe(std::span(temp_sk));
            if (write_result.IsErr()) {
                return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t>>,
                    ProtocolFailure>::Err(
                    ProtocolFailure::FromSodiumFailure(write_result.UnwrapErr()));
            }
            return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t>>,
                ProtocolFailure>::Ok(
                std::make_pair(std::move(sk_handle), std::move(pk)));
        } catch (const std::exception &ex) {
            return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t>>,
                ProtocolFailure>::Err(
                ProtocolFailure::KeyGeneration(
                    "Unexpected error generating Ed25519 key pair: " +
                    std::string(ex.what())));
        }
    }

    std::vector<uint8_t> SodiumInterop::GetRandomBytes(const size_t size) {
        std::vector<uint8_t> buffer(size);
        randombytes_buf(buffer.data(), size);
        return buffer;
    }

    uint32_t SodiumInterop::GenerateRandomUInt32(const bool ensure_non_zero) {
        uint32_t value;
        do {
            value = randombytes_uniform(UINT32_MAX);
        } while (ensure_non_zero && value == 0);
        return value;
    }

    void *SodiumInterop::AllocateSecure(const size_t size) noexcept {
        if (!IsInitialized()) {
            return nullptr;
        }
        return sodium_malloc(size);
    }

    void SodiumInterop::FreeSecure(void *ptr) noexcept {
        if (ptr != nullptr) {
            sodium_free(ptr);
        }
    }
}
