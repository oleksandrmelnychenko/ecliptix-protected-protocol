#ifndef ECLIPTIX_CRYPTO_KYBER_INTEROP_HPP
#define ECLIPTIX_CRYPTO_KYBER_INTEROP_HPP

#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include <span>
#include <vector>
#include <string_view>
#include <utility>

namespace ecliptix::protocol::crypto {

class KyberInterop {
public:
    static constexpr size_t KYBER_768_PUBLIC_KEY_SIZE = 1184;
    static constexpr size_t KYBER_768_SECRET_KEY_SIZE = 2400;
    static constexpr size_t KYBER_768_CIPHERTEXT_SIZE = 1088;
    static constexpr size_t KYBER_768_SHARED_SECRET_SIZE = 32;

    static Result<std::pair<SecureMemoryHandle, std::vector<uint8_t>>, SodiumFailure>
    GenerateKyber768KeyPair(std::string_view purpose);

    static Result<std::pair<SecureMemoryHandle, std::vector<uint8_t>>, SodiumFailure>
    GenerateKyber768KeyPairFromSeed(std::span<const uint8_t> seed, std::string_view purpose);

    static Result<std::pair<std::vector<uint8_t>, SecureMemoryHandle>, SodiumFailure>
    Encapsulate(std::span<const uint8_t> public_key);

    static Result<SecureMemoryHandle, SodiumFailure>
    Decapsulate(
        std::span<const uint8_t> ciphertext,
        const SecureMemoryHandle& secret_key_handle
    );

    static Result<SecureMemoryHandle, EcliptixProtocolFailure>
    CombineHybridSecrets(
        std::span<const uint8_t> x25519_shared_secret,
        std::span<const uint8_t> kyber_shared_secret,
        std::string_view context
    );

    static Result<Unit, SodiumFailure>
    ValidatePublicKey(std::span<const uint8_t> public_key);

    static Result<Unit, SodiumFailure>
    ValidateCiphertext(std::span<const uint8_t> ciphertext);

    static Result<Unit, SodiumFailure>
    ValidateSecretKey(const SecureMemoryHandle& secret_key_handle);

    static Result<Unit, SodiumFailure>
    SelfTestKeyPair(std::span<const uint8_t> public_key, const SecureMemoryHandle& secret_key_handle);

    static Result<Unit, SodiumFailure> Initialize();

private:
    struct OqsKemDeleter;
    static Result<void*, SodiumFailure> CreateKyber768Instance();
    static void FreeKyber768Instance(void* kem);
};

}

#endif
