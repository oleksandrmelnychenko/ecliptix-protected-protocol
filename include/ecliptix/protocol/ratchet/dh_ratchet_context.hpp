#pragma once

#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"

#include <vector>
#include <cstdint>
#include <optional>
#include <span>

namespace ecliptix::protocol::ratchet {

using crypto::SecureMemoryHandle;
using crypto::SodiumInterop;

/**
 * @brief RAII context for DH ratchet temporary state with automatic secure cleanup
 *
 * During a DH ratchet operation, we compute and temporarily hold sensitive
 * cryptographic material:
 * - DH shared secret (from scalar multiplication)
 * - New root key (from HKDF)
 * - New chain key (from HKDF)
 * - New ephemeral key pair (sender only)
 *
 * **Problem**: If an error occurs mid-ratchet, we need to ensure ALL temporary
 * buffers are securely wiped to prevent key material leakage.
 *
 * **Solution**: This RAII context automatically wipes all buffers in its
 * destructor, ensuring cleanup happens on both normal and exceptional returns.
 *
 * **Usage Pattern**:
 * ```cpp
 * Result<Unit, EcliptixProtocolFailure> PerformDhRatchet(bool is_sender) {
 *     DhRatchetContext ctx;  // Automatic cleanup on scope exit
 *
 *     // Step 1: Compute DH secret
 *     TRY_UNIT(ComputeDhSecret(is_sender, ctx));
 *     // ctx.dh_secret is now populated
 *
 *     // Step 2: Derive new keys
 *     TRY_UNIT(DeriveRatchetKeys(ctx));
 *     // ctx.new_root_key and ctx.new_chain_key are now populated
 *
 *     // Step 3: Update chain state
 *     TRY_UNIT(UpdateChainStep(ctx));
 *
 *     return Ok(Unit{});
 *     // Destructor automatically wipes ALL temporary buffers
 * }
 * ```
 *
 * **Memory Safety**:
 * - All std::vector<uint8_t> buffers wiped with sodium_memzero
 * - SecureMemoryHandle uses libsodium's secure allocator (automatic wipe on free)
 * - Move-only semantics prevent accidental copies
 */
class DhRatchetContext {
public:
    /**
     * @brief Default constructor - all fields start empty/null
     */
    DhRatchetContext() = default;

    /**
     * @brief Destructor - securely wipes all temporary buffers
     *
     * Wipes in this order:
     * 1. DH shared secret
     * 2. New root key
     * 3. New chain key
     * 4. Ephemeral public key (if present)
     * 5. Local private key bytes (if present)
     * 6. New DH private key bytes (if present)
     * 7. SecureMemoryHandle (automatic via destructor)
     */
    ~DhRatchetContext() {
        // Wipe sensitive byte arrays
        if (!dh_secret.empty()) {
            SodiumInterop::SecureWipe(std::span<uint8_t>(dh_secret));
        }
        if (!new_root_key.empty()) {
            SodiumInterop::SecureWipe(std::span<uint8_t>(new_root_key));
        }
        if (!new_chain_key.empty()) {
            SodiumInterop::SecureWipe(std::span<uint8_t>(new_chain_key));
        }
        if (new_ephemeral_public_key.has_value()) {
            SodiumInterop::SecureWipe(std::span<uint8_t>(*new_ephemeral_public_key));
        }
        if (local_private_key_bytes.has_value()) {
            SodiumInterop::SecureWipe(std::span<uint8_t>(*local_private_key_bytes));
        }
        if (new_dh_private_key_bytes.has_value()) {
            SodiumInterop::SecureWipe(std::span<uint8_t>(*new_dh_private_key_bytes));
        }

        // SecureMemoryHandle destructor automatically wipes
        // (no explicit action needed)
    }

    // Move-only semantics (prevent accidental copies of sensitive data)
    DhRatchetContext(DhRatchetContext&&) noexcept = default;
    DhRatchetContext& operator=(DhRatchetContext&&) noexcept = default;
    DhRatchetContext(const DhRatchetContext&) = delete;
    DhRatchetContext& operator=(const DhRatchetContext&) = delete;

    // ========================================================================
    // Temporary State Members (automatically wiped on destruction)
    // ========================================================================

    /**
     * @brief DH shared secret from scalar multiplication
     *
     * Computed as:
     * - Sender: DH(new_ephemeral_sk, peer_dh_public_key)
     * - Receiver: DH(current_sending_dh_sk, received_dh_public_key)
     *
     * Size: 32 bytes (X25519 output)
     */
    std::vector<uint8_t> dh_secret;

    /**
     * @brief New root key derived from HKDF
     *
     * Computed as:
     * HKDF-SHA256(dh_secret, salt=current_root_key, info="Ecliptix-DH-Ratchet")
     * → first 32 bytes
     *
     * Size: 32 bytes
     */
    std::vector<uint8_t> new_root_key;

    /**
     * @brief New chain key derived from HKDF
     *
     * Computed as:
     * HKDF-SHA256(dh_secret, salt=current_root_key, info="Ecliptix-DH-Ratchet")
     * → second 32 bytes
     *
     * Size: 32 bytes
     */
    std::vector<uint8_t> new_chain_key;

    /**
     * @brief New ephemeral public key (sender only)
     *
     * Generated during sender-side DH ratchet. This public key is sent
     * to the peer in the next message.
     *
     * Size: 32 bytes (X25519 public key)
     */
    std::optional<std::vector<uint8_t>> new_ephemeral_public_key;

    /**
     * @brief Local private key bytes (temporary copy for DH computation)
     *
     * Temporarily holds a copy of the private key for scalar multiplication.
     * Must be wiped after use.
     *
     * Size: 32 bytes (X25519 private key)
     */
    std::optional<std::vector<uint8_t>> local_private_key_bytes;

    /**
     * @brief New DH private key bytes (sender only, for ChainStep update)
     *
     * Temporarily holds the new ephemeral private key for updating the
     * sending chain step. Must be wiped after the update completes.
     *
     * Size: 32 bytes (X25519 private key)
     */
    std::optional<std::vector<uint8_t>> new_dh_private_key_bytes;

    /**
     * @brief New ephemeral secret key handle (sender only)
     *
     * Secure memory handle for the new ephemeral private key. This is
     * moved to the Connection's current_sending_dh_private_key_handle
     * upon successful ratchet.
     *
     * Automatically wiped on destruction (libsodium secure allocator).
     */
    std::optional<SecureMemoryHandle> new_ephemeral_sk_handle;
};

} // namespace ecliptix::protocol::ratchet
