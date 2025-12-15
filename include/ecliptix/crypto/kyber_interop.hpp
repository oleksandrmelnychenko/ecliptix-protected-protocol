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

/// KyberInterop - RAII wrapper around liboqs Kyber-768 operations
///
/// This class provides a safe, memory-secure interface to CRYSTALS-Kyber
/// (ML-KEM FIPS 203) post-quantum key encapsulation mechanism.
///
/// All secret keys are managed via SecureMemoryHandle (mlock, auto-wipe).
/// All operations use constant-time implementations from liboqs.
///
/// **Key Sizes (Kyber-768)**:
/// - Public Key:    1184 bytes
/// - Secret Key:    2400 bytes
/// - Ciphertext:    1088 bytes
/// - Shared Secret:   32 bytes
///
/// **Security Level**: NIST Level 3 (~192-bit classical, ~164-bit quantum)
///
/// @see docs/PQ_INTEGRATION_PLAN.md for detailed specification
class KyberInterop {
public:
    // Kyber-768 constants (FIPS 203)
    static constexpr size_t KYBER_768_PUBLIC_KEY_SIZE = 1184;
    static constexpr size_t KYBER_768_SECRET_KEY_SIZE = 2400;
    static constexpr size_t KYBER_768_CIPHERTEXT_SIZE = 1088;
    static constexpr size_t KYBER_768_SHARED_SECRET_SIZE = 32;

    // =======================================================================
    // Key Generation
    // =======================================================================

    /// Generates a Kyber-768 key pair
    ///
    /// The secret key is allocated in secure memory (mlock, guard pages)
    /// and will be automatically wiped on destruction (RAII).
    ///
    /// @param purpose Description for debugging/logging (e.g., "pq-identity")
    /// @return Pair of (SecureMemoryHandle for secret key, public key bytes)
    ///         or error if key generation fails
    ///
    /// @example
    /// ```cpp
    /// auto result = KyberInterop::GenerateKyber768KeyPair("pq-identity");
    /// if (result.IsOk()) {
    ///     auto [sk_handle, pk_bytes] = std::move(result).Unwrap();
    ///     // Use keys...
    /// } // sk_handle automatically wiped on scope exit
    /// ```
    static Result<std::pair<SecureMemoryHandle, std::vector<uint8_t>>, SodiumFailure>
    GenerateKyber768KeyPair(std::string_view purpose);

    // =======================================================================
    // Encapsulation (Sender Side)
    // =======================================================================

    /// Performs Kyber-768 encapsulation to a recipient's public key
    ///
    /// Generates a random shared secret and encrypts it using the recipient's
    /// public key. The shared secret is allocated in secure memory.
    ///
    /// @param public_key Recipient's Kyber-768 public key (1184 bytes)
    /// @return Pair of (ciphertext bytes, SecureMemoryHandle for shared secret)
    ///         or error if encapsulation fails
    ///
    /// @throws Error if public_key size != 1184 bytes
    ///
    /// @example
    /// ```cpp
    /// auto [ct, ss_sender] = KyberInterop::Encapsulate(bob_pk).Unwrap();
    /// // Send ct to Bob, use ss_sender for encryption
    /// ```
    static Result<std::pair<std::vector<uint8_t>, SecureMemoryHandle>, SodiumFailure>
    Encapsulate(std::span<const uint8_t> public_key);

    // =======================================================================
    // Decapsulation (Receiver Side)
    // =======================================================================

    /// Performs Kyber-768 decapsulation using receiver's secret key
    ///
    /// Decrypts the ciphertext using the receiver's secret key to recover
    /// the shared secret. Uses implicit rejection (FO transform) for IND-CCA2.
    ///
    /// @param ciphertext Kyber-768 ciphertext (1088 bytes)
    /// @param secret_key_handle Receiver's Kyber-768 secret key (2400 bytes)
    /// @return SecureMemoryHandle for shared secret (32 bytes)
    ///         or error if decapsulation fails
    ///
    /// @throws Error if ciphertext size != 1088 bytes
    ///
    /// @example
    /// ```cpp
    /// auto ss_receiver = KyberInterop::Decapsulate(ct, my_sk).Unwrap();
    /// // ss_receiver should match ss_sender from Encapsulate
    /// ```
    static Result<SecureMemoryHandle, SodiumFailure>
    Decapsulate(
        std::span<const uint8_t> ciphertext,
        const SecureMemoryHandle& secret_key_handle
    );

    // =======================================================================
    // Hybrid Key Derivation
    // =======================================================================

    /// Combines X25519 and Kyber-768 shared secrets using HKDF
    ///
    /// Implements hybrid construction for post-quantum security:
    ///   IKM = x25519_ss || kyber_ss  (64 bytes)
    ///   Salt = "Ecliptix-PQ-Hybrid-v1" || context
    ///   MasterSecret = HKDF-Extract(Salt, IKM)
    ///
    /// **Security**: Secure if X25519 OR Kyber remains secure (OR assumption)
    ///
    /// @param x25519_shared_secret X25519 DH result (32 bytes)
    /// @param kyber_shared_secret Kyber encaps/decaps result (32 bytes)
    /// @param context Domain separation string (e.g., "X3DH-Handshake")
    /// @return SecureMemoryHandle for combined master secret (32 bytes)
    ///
    /// @example
    /// ```cpp
    /// auto dh_ss = PerformX25519DH(...);
    /// auto kyber_ss = KyberInterop::Encapsulate(...).Unwrap().second;
    /// auto hybrid_secret = KyberInterop::CombineHybridSecrets(
    ///     dh_ss, kyber_ss, "X3DH-Handshake"
    /// ).Unwrap();
    /// ```
    static Result<SecureMemoryHandle, EcliptixProtocolFailure>
    CombineHybridSecrets(
        std::span<const uint8_t> x25519_shared_secret,
        std::span<const uint8_t> kyber_shared_secret,
        std::string_view context
    );

    // =======================================================================
    // Validation
    // =======================================================================

    /// Validates Kyber-768 public key format
    ///
    /// Checks:
    /// - Size is exactly 1184 bytes
    /// - Key is not all zeros (basic sanity check)
    ///
    /// @param public_key Public key to validate
    /// @return Ok if valid, error otherwise
    static Result<Unit, SodiumFailure>
    ValidatePublicKey(std::span<const uint8_t> public_key);

    /// Validates Kyber-768 ciphertext format
    ///
    /// Checks:
    /// - Size is exactly 1088 bytes
    /// - Ciphertext is not all zeros (basic sanity check)
    ///
    /// @param ciphertext Ciphertext to validate
    /// @return Ok if valid, error otherwise
    static Result<Unit, SodiumFailure>
    ValidateCiphertext(std::span<const uint8_t> ciphertext);

    /// Validates Kyber-768 secret key format
    ///
    /// Checks:
    /// - Handle contains exactly 2400 bytes
    ///
    /// @param secret_key_handle Secret key to validate
    /// @return Ok if valid, error otherwise
    static Result<Unit, SodiumFailure>
    ValidateSecretKey(const SecureMemoryHandle& secret_key_handle);

    /// Validates a Kyber key pair by performing an encapsulate/decapsulate self-test.
    /// Useful for imported/deserialized key material.
    static Result<Unit, SodiumFailure>
    SelfTestKeyPair(std::span<const uint8_t> public_key, const SecureMemoryHandle& secret_key_handle);

    // =======================================================================
    // Initialization Helpers
    // =======================================================================

    /// Initializes KyberInterop global state (binds liboqs RNG to libsodium).
    /// Safe to call multiple times; no-op after first success.
    static Result<Unit, SodiumFailure> Initialize();

private:
    // Internal helper: Creates and initializes a Kyber-768 KEM instance from liboqs
    // Returns OQS_KEM* wrapped in unique_ptr with custom deleter
    struct OqsKemDeleter;
    static Result<void*, SodiumFailure> CreateKyber768Instance();

    // Internal helper: Frees OQS_KEM instance
    static void FreeKyber768Instance(void* kem);
};

} // namespace ecliptix::protocol::crypto

#endif // ECLIPTIX_CRYPTO_KYBER_INTEROP_HPP
