#include "ecliptix/crypto/kyber_interop.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/hkdf.hpp"
#include <sodium.h>
#include <oqs/oqs.h>
#include <oqs/rand.h>
#include <cstring>
#include <algorithm>
#include <mutex>

namespace ecliptix::protocol::crypto {
    // =============================================================================
    // Internal Helpers
    // =============================================================================

    Result<void *, SodiumFailure> KyberInterop::CreateKyber768Instance() {
        // Ensure RNG binding occurred
        auto init_result = Initialize();
        if (init_result.IsErr()) {
            return Result<void *, SodiumFailure>::Err(init_result.UnwrapErr());
        }

        OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
        if (kem == nullptr) {
            return Result<void *, SodiumFailure>::Err(
                SodiumFailure::InitializationFailed("Failed to create Kyber-768 KEM instance (liboqs)")
            );
        }

        // Verify sizes match FIPS 203 specification
        if (kem->length_public_key != KYBER_768_PUBLIC_KEY_SIZE ||
            kem->length_secret_key != KYBER_768_SECRET_KEY_SIZE ||
            kem->length_ciphertext != KYBER_768_CIPHERTEXT_SIZE ||
            kem->length_shared_secret != KYBER_768_SHARED_SECRET_SIZE) {
            OQS_KEM_free(kem);
            return Result<void *, SodiumFailure>::Err(
                SodiumFailure::InitializationFailed("Kyber-768 size mismatch with FIPS 203 spec")
            );
        }

        return Result<void *, SodiumFailure>::Ok(kem);
    }

    void KyberInterop::FreeKyber768Instance(void *kem) {
        if (kem != nullptr) {
            OQS_KEM_free(static_cast<OQS_KEM *>(kem));
        }
    }

    // =============================================================================
    // Key Generation
    // =============================================================================

    Result<std::pair<SecureMemoryHandle, std::vector<uint8_t> >, SodiumFailure>
    KyberInterop::GenerateKyber768KeyPair(std::string_view purpose) {
        (void) purpose; // purpose currently unused; retained for logging hooks

        auto init_result = Initialize();
        if (init_result.IsErr()) {
            return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t> >, SodiumFailure>::Err(
                init_result.UnwrapErr());
        }

        // Create Kyber-768 KEM instance
        auto kem_result = CreateKyber768Instance();
        if (kem_result.IsErr()) {
            return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t> >, SodiumFailure>::Err(
                kem_result.UnwrapErr()
            );
        }
        auto *kem = static_cast<OQS_KEM *>(kem_result.Unwrap());

        // Allocate secure memory for secret key
        auto sk_handle_result = SecureMemoryHandle::Allocate(KYBER_768_SECRET_KEY_SIZE);
        if (sk_handle_result.IsErr()) {
            FreeKyber768Instance(kem);
            return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t> >, SodiumFailure>::Err(
                sk_handle_result.UnwrapErr()
            );
        }
        auto sk_handle = std::move(sk_handle_result).Unwrap();

        // Allocate public key buffer (not sensitive, regular memory OK)
        std::vector<uint8_t> pk(KYBER_768_PUBLIC_KEY_SIZE);

        // Generate key pair (liboqs handles randomness via RAND_bytes)
        OQS_STATUS status = OQS_ERROR;
        auto write_result = sk_handle.WithWriteAccess([&](std::span<uint8_t> sk_span) -> Unit {
            status = OQS_KEM_keypair(kem, pk.data(), sk_span.data());
            return Unit{};
        });

        // Cleanup KEM instance
        FreeKyber768Instance(kem);

        if (write_result.IsErr()) {
            return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t> >, SodiumFailure>::Err(
                write_result.UnwrapErr()
            );
        }

        if (status != OQS_SUCCESS) {
            return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t> >, SodiumFailure>::Err(
                SodiumFailure::InitializationFailed("Kyber-768 key generation failed")
            );
        }

        // Self-test: encapsulate to our public key and decapsulate with the new secret key
        auto enc_result = Encapsulate(pk);
        if (enc_result.IsErr()) {
            return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t> >, SodiumFailure>::Err(
                enc_result.UnwrapErr());
        }
        auto [ct_self, ss_sender] = std::move(enc_result).Unwrap();
        auto self_test = SelfTestKeyPair(pk, sk_handle);
        if (self_test.IsErr()) {
            return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t> >, SodiumFailure>::Err(
                self_test.UnwrapErr());
        }

        return Result<std::pair<SecureMemoryHandle, std::vector<uint8_t> >, SodiumFailure>::Ok(
            std::make_pair(std::move(sk_handle), std::move(pk))
        );
    }

    // =============================================================================
    // Encapsulation
    // =============================================================================

    Result<std::pair<std::vector<uint8_t>, SecureMemoryHandle>, SodiumFailure>
    KyberInterop::Encapsulate(std::span<const uint8_t> public_key) {
        // Validate input
        auto validation_result = ValidatePublicKey(public_key);
        if (validation_result.IsErr()) {
            return Result<std::pair<std::vector<uint8_t>, SecureMemoryHandle>, SodiumFailure>::Err(
                validation_result.UnwrapErr()
            );
        }

        // Create Kyber-768 KEM instance
        auto kem_result = CreateKyber768Instance();
        if (kem_result.IsErr()) {
            return Result<std::pair<std::vector<uint8_t>, SecureMemoryHandle>, SodiumFailure>::Err(
                kem_result.UnwrapErr()
            );
        }
        auto *kem = static_cast<OQS_KEM *>(kem_result.Unwrap());

        // Allocate ciphertext buffer
        std::vector<uint8_t> ciphertext(KYBER_768_CIPHERTEXT_SIZE);

        // Allocate secure memory for shared secret
        auto ss_handle_result = SecureMemoryHandle::Allocate(KYBER_768_SHARED_SECRET_SIZE);
        if (ss_handle_result.IsErr()) {
            FreeKyber768Instance(kem);
            return Result<std::pair<std::vector<uint8_t>, SecureMemoryHandle>, SodiumFailure>::Err(
                ss_handle_result.UnwrapErr()
            );
        }
        auto ss_handle = std::move(ss_handle_result).Unwrap();

        // Perform encapsulation
        OQS_STATUS status = OQS_ERROR;
        auto write_result = ss_handle.WithWriteAccess([&](std::span<uint8_t> ss_span) -> Unit {
            status = OQS_KEM_encaps(
                kem,
                ciphertext.data(),
                ss_span.data(),
                public_key.data()
            );
            return Unit{};
        });

        // Cleanup KEM instance
        FreeKyber768Instance(kem);

        if (write_result.IsErr()) {
            return Result<std::pair<std::vector<uint8_t>, SecureMemoryHandle>, SodiumFailure>::Err(
                write_result.UnwrapErr()
            );
        }

        if (status != OQS_SUCCESS) {
            return Result<std::pair<std::vector<uint8_t>, SecureMemoryHandle>, SodiumFailure>::Err(
                SodiumFailure::InvalidOperation("Kyber-768 encapsulation failed")
            );
        }

        return Result<std::pair<std::vector<uint8_t>, SecureMemoryHandle>, SodiumFailure>::Ok(
            std::make_pair(std::move(ciphertext), std::move(ss_handle))
        );
    }

    // =============================================================================
    // Decapsulation
    // =============================================================================

    Result<SecureMemoryHandle, SodiumFailure>
    KyberInterop::Decapsulate(
        std::span<const uint8_t> ciphertext,
        const SecureMemoryHandle &secret_key_handle
    ) {
        // Validate inputs
        auto ct_validation = ValidateCiphertext(ciphertext);
        if (ct_validation.IsErr()) {
            return Result<SecureMemoryHandle, SodiumFailure>::Err(ct_validation.UnwrapErr());
        }

        auto sk_validation = ValidateSecretKey(secret_key_handle);
        if (sk_validation.IsErr()) {
            return Result<SecureMemoryHandle, SodiumFailure>::Err(sk_validation.UnwrapErr());
        }

        // Create Kyber-768 KEM instance
        auto kem_result = CreateKyber768Instance();
        if (kem_result.IsErr()) {
            return Result<SecureMemoryHandle, SodiumFailure>::Err(kem_result.UnwrapErr());
        }
        auto *kem = static_cast<OQS_KEM *>(kem_result.Unwrap());

        // Allocate secure memory for shared secret
        auto ss_handle_result = SecureMemoryHandle::Allocate(KYBER_768_SHARED_SECRET_SIZE);
        if (ss_handle_result.IsErr()) {
            FreeKyber768Instance(kem);
            return Result<SecureMemoryHandle, SodiumFailure>::Err(ss_handle_result.UnwrapErr());
        }
        auto ss_handle = std::move(ss_handle_result).Unwrap();

        // Perform decapsulation (requires both sk and ss to be in secure memory)
        OQS_STATUS status = OQS_ERROR;
        auto access_result = secret_key_handle.WithReadAccess([&](std::span<const uint8_t> sk_span) -> Unit {
            auto write_result = ss_handle.WithWriteAccess([&](std::span<uint8_t> ss_span) -> Unit {
                status = OQS_KEM_decaps(
                    kem,
                    ss_span.data(),
                    ciphertext.data(),
                    sk_span.data()
                );
                return Unit{};
            });
            // Propagate errors from inner WithWriteAccess
            if (write_result.IsErr()) {
                // Can't return error from here, will check status after
            }
            return Unit{};
        });

        // Cleanup KEM instance
        FreeKyber768Instance(kem);

        if (access_result.IsErr()) {
            return Result<SecureMemoryHandle, SodiumFailure>::Err(access_result.UnwrapErr());
        }

        if (status != OQS_SUCCESS) {
            return Result<SecureMemoryHandle, SodiumFailure>::Err(
                SodiumFailure::InvalidOperation("Kyber-768 decapsulation failed")
            );
        }

        return Result<SecureMemoryHandle, SodiumFailure>::Ok(std::move(ss_handle));
    }

    // =============================================================================
    // Hybrid Key Derivation
    // =============================================================================

    Result<SecureMemoryHandle, EcliptixProtocolFailure>
    KyberInterop::CombineHybridSecrets(
        std::span<const uint8_t> x25519_shared_secret,
        std::span<const uint8_t> kyber_shared_secret,
        std::string_view context
    ) {
        // Validate input sizes
        if (x25519_shared_secret.size() != 32) {
            return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput(
                    "X25519 shared secret must be 32 bytes"
                )
            );
        }

        if (kyber_shared_secret.size() != 32) {
            return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput(
                    "Kyber shared secret must be 32 bytes"
                )
            );
        }

        // Concatenate IKM: x25519_ss || kyber_ss (64 bytes)
        std::vector<uint8_t> ikm(64);
        std::copy_n(x25519_shared_secret.begin(), 32, ikm.begin());
        std::copy_n(kyber_shared_secret.begin(), 32, ikm.begin() + 32);

        // Construct salt: "Ecliptix-PQ-Hybrid-v1::" || context
        std::string salt_str = "Ecliptix-PQ-Hybrid-v1::";
        salt_str += context;
        std::vector<uint8_t> salt(salt_str.begin(), salt_str.end());

        // HKDF-Extract
        auto prk_result = Hkdf::Extract(salt, ikm);

        // Secure wipe temporary buffers
        auto wipe_result = SodiumInterop::SecureWipe(std::span<uint8_t>(ikm));
        (void) wipe_result;

        if (prk_result.IsErr()) {
            return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    "HKDF-Extract failed in hybrid key combination"
                )
            );
        }

        // HKDF-Expand with context as info to derive 32-byte hybrid secret
        std::vector<uint8_t> hybrid_vec(32);
        std::vector<uint8_t> context_info(context.begin(), context.end());
        auto expand_result = Hkdf::Expand(
            prk_result.Unwrap(),
            std::span<uint8_t>(hybrid_vec),
            context_info);

        if (expand_result.IsErr()) {
            return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("HKDF-Expand failed in hybrid key combination"));
        }
        auto handle_result = SecureMemoryHandle::Allocate(hybrid_vec.size());
        if (handle_result.IsErr()) {
            SodiumInterop::SecureWipe(std::span<uint8_t>(hybrid_vec));
            return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Failed to allocate secure memory for hybrid master secret"));
        }

        auto handle = std::move(handle_result).Unwrap();
        auto write_result = handle.Write(hybrid_vec);
        SodiumInterop::SecureWipe(std::span<uint8_t>(hybrid_vec));

        if (write_result.IsErr()) {
            return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    "Failed to write hybrid master secret to secure memory"
                )
            );
        }

        return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Ok(std::move(handle));
    }

    // =============================================================================
    // Validation
    // =============================================================================

    Result<Unit, SodiumFailure>
    KyberInterop::ValidatePublicKey(std::span<const uint8_t> public_key) {
        if (public_key.size() != KYBER_768_PUBLIC_KEY_SIZE) {
            return Result<Unit, SodiumFailure>::Err(
                SodiumFailure::BufferTooSmall(
                    "Invalid Kyber-768 public key size (expected 1184 bytes)"
                )
            );
        }

        // Basic sanity check: key should not be all zeros
        if (std::all_of(public_key.begin(), public_key.end(), [](uint8_t b) { return b == 0; })) {
            return Result<Unit, SodiumFailure>::Err(
                SodiumFailure::InvalidOperation(
                    "Invalid Kyber-768 public key (all zeros)"
                )
            );
        }

        return Result<Unit, SodiumFailure>::Ok(Unit{});
    }

    Result<Unit, SodiumFailure>
    KyberInterop::ValidateCiphertext(std::span<const uint8_t> ciphertext) {
        if (ciphertext.size() != KYBER_768_CIPHERTEXT_SIZE) {
            return Result<Unit, SodiumFailure>::Err(
                SodiumFailure::BufferTooSmall(
                    "Invalid Kyber-768 ciphertext size (expected 1088 bytes)"
                )
            );
        }

        // Basic sanity check: ciphertext should not be all zeros
        if (std::all_of(ciphertext.begin(), ciphertext.end(), [](uint8_t b) { return b == 0; })) {
            return Result<Unit, SodiumFailure>::Err(
                SodiumFailure::InvalidOperation(
                    "Invalid Kyber-768 ciphertext (all zeros)"
                )
            );
        }

        return Result<Unit, SodiumFailure>::Ok(Unit{});
    }

    Result<Unit, SodiumFailure>
    KyberInterop::ValidateSecretKey(const SecureMemoryHandle &secret_key_handle) {
        if (secret_key_handle.Size() != KYBER_768_SECRET_KEY_SIZE) {
            return Result<Unit, SodiumFailure>::Err(
                SodiumFailure::BufferTooSmall(
                    "Invalid Kyber-768 secret key size (expected 2400 bytes)"
                )
            );
        }

        // Basic sanity: secret key should not be all zeros
        auto read_result = secret_key_handle.ReadBytes(KYBER_768_SECRET_KEY_SIZE);
        if (read_result.IsErr()) {
            return Result<Unit, SodiumFailure>::Err(read_result.UnwrapErr());
        }
        auto sk_bytes = read_result.Unwrap();
        if (std::all_of(sk_bytes.begin(), sk_bytes.end(), [](uint8_t b) { return b == 0; })) {
            SodiumInterop::SecureWipe(std::span(sk_bytes));
            return Result<Unit, SodiumFailure>::Err(
                SodiumFailure::InvalidOperation("Invalid Kyber-768 secret key (all zeros)"));
        }
        SodiumInterop::SecureWipe(std::span(sk_bytes));

        return Result<Unit, SodiumFailure>::Ok(Unit{});
    }

    Result<Unit, SodiumFailure>
    KyberInterop::SelfTestKeyPair(std::span<const uint8_t> public_key, const SecureMemoryHandle &secret_key_handle) {
        auto pk_validate = ValidatePublicKey(public_key);
        if (pk_validate.IsErr()) {
            return pk_validate;
        }
        auto sk_validate = ValidateSecretKey(secret_key_handle);
        if (sk_validate.IsErr()) {
            return sk_validate;
        }

        auto enc_result = Encapsulate(public_key);
        if (enc_result.IsErr()) {
            return Result<Unit, SodiumFailure>::Err(enc_result.UnwrapErr());
        }
        auto [ct, ss_sender] = std::move(enc_result).Unwrap();
        auto dec_result = Decapsulate(ct, secret_key_handle);
        if (dec_result.IsErr()) {
            return Result<Unit, SodiumFailure>::Err(dec_result.UnwrapErr());
        }
        auto ss_receiver = std::move(dec_result).Unwrap();
        auto send_bytes = ss_sender.ReadBytes(KYBER_768_SHARED_SECRET_SIZE);
        auto recv_bytes = ss_receiver.ReadBytes(KYBER_768_SHARED_SECRET_SIZE);
        if (send_bytes.IsErr() || recv_bytes.IsErr()) {
            return Result<Unit, SodiumFailure>::Err(
                SodiumFailure::InvalidOperation("Failed to read Kyber self-test shared secrets"));
        }
        auto cmp_result = SodiumInterop::ConstantTimeEquals(send_bytes.Unwrap(), recv_bytes.Unwrap());
        SodiumInterop::SecureWipe(std::span(send_bytes.Unwrap()));
        SodiumInterop::SecureWipe(std::span(recv_bytes.Unwrap()));
        if (cmp_result.IsErr() || !cmp_result.Unwrap()) {
            return Result<Unit, SodiumFailure>::Err(
                SodiumFailure::InvalidOperation("Kyber self-test failed (encap/decap mismatch)"));
        }
        return Result<Unit, SodiumFailure>::Ok(Unit{});
    }

    Result<Unit, SodiumFailure> KyberInterop::Initialize() {
        static std::once_flag rng_init_flag;
        static std::atomic<bool> initialized{false};
        std::exception_ptr init_exception = nullptr;
        std::call_once(rng_init_flag, [&]() {
            try {
                auto sodium_init = SodiumInterop::Initialize();
                if (sodium_init.IsErr()) {
                    throw sodium_init.UnwrapErr();
                }
                OQS_randombytes_custom_algorithm(
                    [](uint8_t *buf, size_t len) { randombytes_buf(buf, len); });
                initialized.store(true, std::memory_order_release);
            } catch (...) {
                init_exception = std::current_exception();
            }
        });
        if (init_exception) {
            try {
                std::rethrow_exception(init_exception);
            } catch (const SodiumFailure &err) {
                return Result<Unit, SodiumFailure>::Err(err);
            } catch (const std::exception &ex) {
                return Result<Unit, SodiumFailure>::Err(
                    SodiumFailure::InitializationFailed(ex.what()));
            }
        }
        if (!initialized.load(std::memory_order_acquire)) {
            return Result<Unit, SodiumFailure>::Err(
                SodiumFailure::InitializationFailed("KyberInterop initialization failed"));
        }
        return Result<Unit, SodiumFailure>::Ok(Unit{});
    }
} // namespace ecliptix::protocol::crypto
