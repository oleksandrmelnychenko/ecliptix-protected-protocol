#pragma once

#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include "ecliptix/models/bundles/local_public_key_bundle.hpp"
#include "ecliptix/models/identity_keys_material.hpp"

#include <vector>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace ecliptix::protocol::identity {

using protocol::Result;
using protocol::Unit;
using protocol::EcliptixProtocolFailure;
using crypto::SecureMemoryHandle;
using models::LocalPublicKeyBundle;
using models::IdentityKeysMaterial;
using models::Ed25519KeyMaterial;
using models::X25519KeyMaterial;
using models::OneTimePreKeyLocal;

/**
 * @brief Complete identity keys for the Ecliptix Protocol System
 *
 * Manages all cryptographic identity material for a protocol participant:
 * - Ed25519 identity keypair (for signatures)
 * - X25519 identity keypair (for key agreement)
 * - Signed pre-key (for X3DH)
 * - One-time pre-keys (for forward secrecy)
 * - Optional ephemeral key (for initiator role in X3DH)
 *
 * **Security Features**:
 * - All secret keys in secure memory (locked, guarded)
 * - Move-only semantics prevent accidental copies
 * - RAII cleanup on destruction
 * - Automatic zeroing of sensitive data
 *
 * **X3DH Protocol**:
 * This class implements the X3DH key agreement protocol for initial
 * session establishment. The protocol performs 4 Diffie-Hellman operations
 * to derive a shared secret with strong forward secrecy and deniability.
 *
 * **Usage Example**:
 * ```cpp
 * // Generate fresh identity
 * auto result = EcliptixSystemIdentityKeys::Create(100); // 100 OPKs
 * if (result.IsOk()) {
 *     auto identity_keys = std::move(result).Unwrap();
 *
 *     // Create public bundle to send to peer
 *     auto bundle = identity_keys.CreatePublicBundle();
 *
 *     // Perform X3DH as initiator
 *     identity_keys.GenerateEphemeralKeyPair();
 *     auto shared_secret = identity_keys.X3dhDeriveSharedSecret(
 *         remote_bundle, Constants::X3DH_INFO);
 * }
 * ```
 */
class EcliptixSystemIdentityKeys {
public:
    // ========================================================================
    // Factory Methods
    // ========================================================================

    /**
     * @brief Generate a fresh identity with random keys
     *
     * Creates a new identity with randomly generated Ed25519 and X25519
     * keypairs, a signed pre-key, and the specified number of one-time
     * pre-keys.
     *
     * @param one_time_key_count Number of one-time pre-keys to generate
     * @return Result containing the identity keys or an error
     *
     * @note All secret keys are automatically protected in secure memory
     * @note The signed pre-key is signed with the Ed25519 identity key
     */
    [[nodiscard]] static Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> Create(
        uint32_t one_time_key_count);

    /**
     * @brief Create identity deterministically from a master key
     *
     * Derives all identity keys deterministically from a master key and
     * membership ID using BLAKE2b keyed hashing. This allows for
     * reproducible key generation from a single seed.
     *
     * @param master_key Master seed (32 bytes recommended)
     * @param membership_id Unique identifier for this membership
     * @param one_time_key_count Number of one-time pre-keys to generate
     * @return Result containing the identity keys or an error
     *
     * @note Master key should be at least 32 bytes of cryptographic randomness
     * @note One-time pre-keys are still generated randomly (not derived)
     */
    [[nodiscard]] static Result<EcliptixSystemIdentityKeys, EcliptixProtocolFailure> CreateFromMasterKey(
        std::span<const uint8_t> master_key,
        std::string_view membership_id,
        uint32_t one_time_key_count);

    // ========================================================================
    // Public Key Access
    // ========================================================================

    /**
     * @brief Get a copy of the X25519 identity public key
     *
     * @return 32-byte X25519 public key
     */
    [[nodiscard]] std::vector<uint8_t> GetIdentityX25519PublicKeyCopy() const;

    // ========================================================================
    // Bundle Operations
    // ========================================================================

    /**
     * @brief Create a public key bundle for distribution to peers
     *
     * Bundles all public keys needed for a peer to initiate an X3DH
     * key agreement. This bundle should be published to a key server
     * or sent directly to peers.
     *
     * @return Result containing the public key bundle or an error
     *
     * @note Includes ephemeral key if GenerateEphemeralKeyPair() was called
     */
    [[nodiscard]] Result<LocalPublicKeyBundle, EcliptixProtocolFailure> CreatePublicBundle() const;

    /**
     * @brief Generate an ephemeral key pair for X3DH initiator role
     *
     * Generates a fresh ephemeral X25519 keypair. This must be called
     * before initiating an X3DH key agreement (as the initiator).
     *
     * Replaces any existing ephemeral key.
     *
     * @note This is required before calling X3dhDeriveSharedSecret()
     */
    void GenerateEphemeralKeyPair();

    // ========================================================================
    // X3DH Key Agreement
    // ========================================================================

    /**
     * @brief Derive shared secret using X3DH protocol
     *
     * Performs the X3DH key agreement protocol to establish a shared secret
     * with a remote peer. This involves:
     * 1. DH1 = DH(IK_local, SPK_remote)
     * 2. DH2 = DH(EK_local, IK_remote)
     * 3. DH3 = DH(EK_local, SPK_remote)
     * 4. DH4 = DH(EK_local, OPK_remote) [if available]
     * 5. Derive shared secret using HKDF-SHA256
     *
     * @param remote_bundle Public key bundle from remote peer
     * @param info Context string for HKDF (e.g., "Ecliptix-X3DH-v1")
     * @return Result containing shared secret handle or error
     *
     * @pre GenerateEphemeralKeyPair() must be called first
     * @post Ephemeral key is consumed and must be regenerated for next use
     *
     * @note The ephemeral key is automatically cleared after use
     * @note Verifies remote signed pre-key signature before proceeding
     */
    [[nodiscard]] Result<SecureMemoryHandle, EcliptixProtocolFailure> X3dhDeriveSharedSecret(
        const LocalPublicKeyBundle& remote_bundle,
        std::span<const uint8_t> info);

    // ========================================================================
    // Signature Verification
    // ========================================================================

    /**
     * @brief Verify a remote peer's signed pre-key signature
     *
     * Verifies that the signed pre-key was actually signed by the claimed
     * Ed25519 identity key. This prevents MITM attacks where an attacker
     * substitutes their own pre-key.
     *
     * @param remote_identity_ed25519 Remote Ed25519 public key (32 bytes)
     * @param remote_spk_public Remote signed pre-key public key (32 bytes)
     * @param remote_spk_signature Remote signed pre-key signature (64 bytes)
     * @return Result containing true if valid, or error if invalid
     *
     * @note This should be called before accepting a remote bundle
     */
    [[nodiscard]] static Result<bool, EcliptixProtocolFailure> VerifyRemoteSpkSignature(
        std::span<const uint8_t> remote_identity_ed25519,
        std::span<const uint8_t> remote_spk_public,
        std::span<const uint8_t> remote_spk_signature);

    // ========================================================================
    // Move/Copy Semantics
    // ========================================================================

    // Move-only (contains secure memory handles)
    EcliptixSystemIdentityKeys(EcliptixSystemIdentityKeys&&) noexcept = default;
    EcliptixSystemIdentityKeys& operator=(EcliptixSystemIdentityKeys&&) noexcept = default;
    EcliptixSystemIdentityKeys(const EcliptixSystemIdentityKeys&) = delete;
    EcliptixSystemIdentityKeys& operator=(const EcliptixSystemIdentityKeys&) = delete;

    ~EcliptixSystemIdentityKeys() = default;

private:
    // ========================================================================
    // Private Constructor
    // ========================================================================

    /**
     * @brief Private constructor - use factory methods
     */
    explicit EcliptixSystemIdentityKeys(IdentityKeysMaterial material);

    // ========================================================================
    // Key Generation Helpers
    // ========================================================================

    [[nodiscard]] static Result<Ed25519KeyMaterial, EcliptixProtocolFailure> GenerateEd25519Keys();

    [[nodiscard]] static Result<X25519KeyMaterial, EcliptixProtocolFailure> GenerateX25519IdentityKeys();

    [[nodiscard]] static Result<X25519KeyMaterial, EcliptixProtocolFailure> GenerateX25519SignedPreKey(
        uint32_t id);

    [[nodiscard]] static Result<std::vector<uint8_t>, EcliptixProtocolFailure> SignSignedPreKey(
        const SecureMemoryHandle& ed_secret_key_handle,
        std::span<const uint8_t> spk_public);

    [[nodiscard]] static Result<std::vector<OneTimePreKeyLocal>, EcliptixProtocolFailure> GenerateOneTimePreKeys(
        uint32_t count);

    // ========================================================================
    // X3DH Helpers
    // ========================================================================

    [[nodiscard]] Result<Unit, EcliptixProtocolFailure> ValidateX3dhPrerequisites(
        const LocalPublicKeyBundle& remote_bundle,
        std::span<const uint8_t> info) const;

    [[nodiscard]] static Result<Unit, EcliptixProtocolFailure> ValidateHkdfInfo(
        std::span<const uint8_t> info);

    [[nodiscard]] static Result<Unit, EcliptixProtocolFailure> ValidateRemoteBundle(
        const LocalPublicKeyBundle& remote_bundle);

    [[nodiscard]] Result<Unit, EcliptixProtocolFailure> EnsureLocalKeysValid() const;

    [[nodiscard]] static Result<size_t, EcliptixProtocolFailure> PerformX3dhDiffieHellman(
        std::span<const uint8_t> ephemeral_secret,
        std::span<const uint8_t> identity_secret,
        const LocalPublicKeyBundle& remote_bundle,
        bool use_opk,
        std::span<uint8_t> dh_results_output);

    // ========================================================================
    // Member Variables
    // ========================================================================

    // Ed25519 identity key (for signatures)
    SecureMemoryHandle ed25519_secret_key_handle_;
    std::vector<uint8_t> ed25519_public_key_;

    // X25519 identity key (for key agreement)
    SecureMemoryHandle identity_x25519_secret_key_handle_;
    std::vector<uint8_t> identity_x25519_public_key_;

    // Signed pre-key
    uint32_t signed_pre_key_id_;
    SecureMemoryHandle signed_pre_key_secret_key_handle_;
    std::vector<uint8_t> signed_pre_key_public_;
    std::vector<uint8_t> signed_pre_key_signature_;

    // One-time pre-keys
    std::vector<OneTimePreKeyLocal> one_time_pre_keys_;

    // Optional ephemeral key (for initiator)
    std::optional<SecureMemoryHandle> ephemeral_secret_key_handle_;
    std::optional<std::vector<uint8_t>> ephemeral_x25519_public_key_;
};

} // namespace ecliptix::protocol::identity
