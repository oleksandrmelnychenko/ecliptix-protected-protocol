#pragma once

/**
 * @file key_logger.hpp
 * @brief Debug logging utilities for cryptographic keys and protocol state.
 *
 * SECURITY WARNING: This module logs cryptographic keys to stdout.
 * Only enable ECLIPTIX_DEBUG_KEYS for development/debugging to verify
 * algorithm correctness between C++ and C# implementations.
 * NEVER enable in production builds.
 *
 * Enable via CMake: -DECLIPTIX_DEBUG_KEYS=ON
 */

#include <cstdint>
#include <cstdio>
#include <span>
#include <string_view>
#include <vector>
#include <optional>

namespace ecliptix::debug {

// ============================================================================
// Side identifiers - always defined so types are available
// ============================================================================

enum class Side {
    Client,
    Server,
    Unknown
};

#ifdef ECLIPTIX_DEBUG_KEYS

/**
 * @brief Converts bytes to lowercase hex string.
 */
inline std::string ToHex(std::span<const uint8_t> data) {
    static constexpr char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(data.size() * 2);
    for (const auto byte : data) {
        result.push_back(hex_chars[(byte >> 4) & 0x0F]);
        result.push_back(hex_chars[byte & 0x0F]);
    }
    return result;
}

/**
 * @brief Converts bytes to hex string, truncated for large keys.
 */
inline std::string ToHexTruncated(std::span<const uint8_t> data, size_t max_bytes = 64) {
    if (data.size() <= max_bytes) {
        return ToHex(data);
    }
    auto truncated = ToHex(data.subspan(0, max_bytes));
    truncated += "...(" + std::to_string(data.size()) + " bytes)";
    return truncated;
}

inline const char* SideToString(Side side) {
    switch (side) {
        case Side::Client: return "CLIENT";
        case Side::Server: return "SERVER";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// Core logging macros
// ============================================================================

#define EPP_LOG_KEY(side, operation, key_name, data) \
    do { \
        fprintf(stdout, "[EPP-DEBUG] %s %s %s: %s\n", \
            ::ecliptix::debug::SideToString(side), \
            operation, \
            key_name, \
            ::ecliptix::debug::ToHexTruncated(data).c_str()); \
        fflush(stdout); \
    } while(0)

#define EPP_LOG_KEY_IDX(side, operation, key_name, index, data) \
    do { \
        fprintf(stdout, "[EPP-DEBUG] %s %s %s[%u]: %s\n", \
            ::ecliptix::debug::SideToString(side), \
            operation, \
            key_name, \
            static_cast<uint32_t>(index), \
            ::ecliptix::debug::ToHexTruncated(data).c_str()); \
        fflush(stdout); \
    } while(0)

#define EPP_LOG_VALUE(side, operation, name, value) \
    do { \
        fprintf(stdout, "[EPP-DEBUG] %s %s %s: %s\n", \
            ::ecliptix::debug::SideToString(side), \
            operation, \
            name, \
            std::to_string(value).c_str()); \
        fflush(stdout); \
    } while(0)

#define EPP_LOG_MSG(side, operation, message) \
    do { \
        fprintf(stdout, "[EPP-DEBUG] %s %s %s\n", \
            ::ecliptix::debug::SideToString(side), \
            operation, \
            message); \
        fflush(stdout); \
    } while(0)

#define EPP_LOG_SECTION(side, section_name) \
    do { \
        fprintf(stdout, "[EPP-DEBUG] %s ========== %s ==========\n", \
            ::ecliptix::debug::SideToString(side), \
            section_name); \
        fflush(stdout); \
    } while(0)

// ============================================================================
// Identity Keys Logging
// ============================================================================

inline void LogIdentityKeysCreated(
    Side side,
    std::span<const uint8_t> ed25519_public,
    std::span<const uint8_t> ed25519_private,
    std::span<const uint8_t> x25519_identity_public,
    std::span<const uint8_t> x25519_identity_private,
    uint32_t signed_pre_key_id,
    std::span<const uint8_t> signed_pre_key_public,
    std::span<const uint8_t> signed_pre_key_private,
    std::span<const uint8_t> signed_pre_key_signature,
    std::span<const uint8_t> kyber_public,
    std::span<const uint8_t> kyber_private) {

    EPP_LOG_SECTION(side, "IDENTITY KEYS CREATED");
    EPP_LOG_KEY(side, "IDENTITY", "ed25519_public", ed25519_public);
    EPP_LOG_KEY(side, "IDENTITY", "ed25519_private", ed25519_private);
    EPP_LOG_KEY(side, "IDENTITY", "x25519_identity_public", x25519_identity_public);
    EPP_LOG_KEY(side, "IDENTITY", "x25519_identity_private", x25519_identity_private);
    EPP_LOG_VALUE(side, "IDENTITY", "signed_pre_key_id", signed_pre_key_id);
    EPP_LOG_KEY(side, "IDENTITY", "signed_pre_key_public", signed_pre_key_public);
    EPP_LOG_KEY(side, "IDENTITY", "signed_pre_key_private", signed_pre_key_private);
    EPP_LOG_KEY(side, "IDENTITY", "signed_pre_key_signature", signed_pre_key_signature);
    EPP_LOG_KEY(side, "IDENTITY", "kyber_public", kyber_public);
    EPP_LOG_KEY(side, "IDENTITY", "kyber_private", kyber_private);
}

inline void LogOneTimePreKey(
    Side side,
    uint32_t opk_id,
    std::span<const uint8_t> public_key,
    std::span<const uint8_t> private_key) {

    EPP_LOG_KEY_IDX(side, "IDENTITY", "opk_public", opk_id, public_key);
    EPP_LOG_KEY_IDX(side, "IDENTITY", "opk_private", opk_id, private_key);
}

inline void LogEphemeralKeyGenerated(
    Side side,
    std::span<const uint8_t> public_key,
    std::span<const uint8_t> private_key) {

    EPP_LOG_KEY(side, "EPHEMERAL", "ephemeral_public", public_key);
    EPP_LOG_KEY(side, "EPHEMERAL", "ephemeral_private", private_key);
}

// ============================================================================
// X3DH Logging
// ============================================================================

inline void LogX3DHStart(Side side, bool is_initiator) {
    EPP_LOG_SECTION(side, is_initiator ? "X3DH INITIATOR" : "X3DH RESPONDER");
}

inline void LogX3DHPeerBundle(
    Side side,
    std::span<const uint8_t> peer_identity_x25519,
    std::span<const uint8_t> peer_signed_pre_key,
    std::optional<std::span<const uint8_t>> peer_ephemeral,
    std::optional<std::span<const uint8_t>> peer_kyber_public,
    std::optional<uint32_t> used_opk_id) {

    EPP_LOG_KEY(side, "X3DH", "peer_identity_x25519", peer_identity_x25519);
    EPP_LOG_KEY(side, "X3DH", "peer_signed_pre_key", peer_signed_pre_key);
    if (peer_ephemeral.has_value()) {
        EPP_LOG_KEY(side, "X3DH", "peer_ephemeral", *peer_ephemeral);
    }
    if (peer_kyber_public.has_value()) {
        EPP_LOG_KEY(side, "X3DH", "peer_kyber_public", *peer_kyber_public);
    }
    if (used_opk_id.has_value()) {
        EPP_LOG_VALUE(side, "X3DH", "used_opk_id", *used_opk_id);
    }
}

inline void LogX3DHDH(
    Side side,
    int dh_number,
    const char* description,
    std::span<const uint8_t> result) {

    char key_name[32];
    snprintf(key_name, sizeof(key_name), "dh%d (%s)", dh_number, description);
    EPP_LOG_KEY(side, "X3DH", key_name, result);
}

inline void LogX3DHConcatenated(
    Side side,
    std::span<const uint8_t> concatenated,
    size_t num_dhs) {

    char msg[64];
    snprintf(msg, sizeof(msg), "dh_concatenated (%zu DHs)", num_dhs);
    EPP_LOG_KEY(side, "X3DH", msg, concatenated);
}

inline void LogX3DHRootKey(
    Side side,
    std::span<const uint8_t> root_key) {

    EPP_LOG_KEY(side, "X3DH", "root_key (HKDF output)", root_key);
}

inline void LogKyberEncapsulation(
    Side side,
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> shared_secret) {

    EPP_LOG_KEY(side, "KYBER", "ciphertext", ciphertext);
    EPP_LOG_KEY(side, "KYBER", "shared_secret", shared_secret);
}

inline void LogKyberDecapsulation(
    Side side,
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> shared_secret) {

    EPP_LOG_KEY(side, "KYBER", "decap_ciphertext", ciphertext);
    EPP_LOG_KEY(side, "KYBER", "decap_shared_secret", shared_secret);
}

inline void LogHybridCombination(
    Side side,
    std::span<const uint8_t> classical_shared,
    std::span<const uint8_t> kyber_shared,
    std::span<const uint8_t> hybrid_result) {

    EPP_LOG_KEY(side, "HYBRID", "classical_shared", classical_shared);
    EPP_LOG_KEY(side, "HYBRID", "kyber_shared", kyber_shared);
    EPP_LOG_KEY(side, "HYBRID", "hybrid_result", hybrid_result);
}

// ============================================================================
// Double Ratchet Logging
// ============================================================================

inline void LogChainKeyDerivation(
    Side side,
    const char* chain_type,
    uint32_t index,
    std::span<const uint8_t> chain_key,
    std::span<const uint8_t> message_key) {

    char ck_name[64];
    snprintf(ck_name, sizeof(ck_name), "%s_chain_key", chain_type);
    EPP_LOG_KEY_IDX(side, "CHAIN", ck_name, index, chain_key);

    char mk_name[64];
    snprintf(mk_name, sizeof(mk_name), "%s_message_key", chain_type);
    EPP_LOG_KEY_IDX(side, "CHAIN", mk_name, index, message_key);
}

inline void LogDHRatchet(
    Side side,
    bool is_sending,
    std::span<const uint8_t> root_key_before,
    std::span<const uint8_t> root_key_after,
    std::span<const uint8_t> new_chain_key,
    std::span<const uint8_t> dh_public,
    std::span<const uint8_t> peer_dh_public,
    uint64_t ratchet_epoch) {

    const char* dir = is_sending ? "SEND" : "RECV";
    EPP_LOG_SECTION(side, is_sending ? "DH RATCHET (SENDING)" : "DH RATCHET (RECEIVING)");
    EPP_LOG_KEY(side, dir, "root_key_before", root_key_before);
    EPP_LOG_KEY(side, dir, "root_key_after", root_key_after);
    EPP_LOG_KEY(side, dir, "new_chain_key", new_chain_key);
    EPP_LOG_KEY(side, dir, "dh_public", dh_public);
    EPP_LOG_KEY(side, dir, "peer_dh_public", peer_dh_public);
    EPP_LOG_VALUE(side, dir, "ratchet_epoch", ratchet_epoch);
}

inline void LogKyberRatchet(
    Side side,
    std::span<const uint8_t> kyber_ciphertext,
    std::span<const uint8_t> kyber_shared_secret) {

    EPP_LOG_KEY(side, "KYBER_RATCHET", "ciphertext", kyber_ciphertext);
    EPP_LOG_KEY(side, "KYBER_RATCHET", "shared_secret", kyber_shared_secret);
}

// ============================================================================
// Encryption/Decryption Logging
// ============================================================================

inline void LogEncryption(
    Side side,
    uint32_t message_index,
    std::span<const uint8_t> message_key,
    std::span<const uint8_t> nonce,
    std::span<const uint8_t> metadata_key,
    std::span<const uint8_t> dh_public,
    uint64_t ratchet_epoch) {

    EPP_LOG_SECTION(side, "ENCRYPT");
    EPP_LOG_KEY_IDX(side, "ENCRYPT", "message_key", message_index, message_key);
    EPP_LOG_KEY(side, "ENCRYPT", "nonce", nonce);
    EPP_LOG_KEY(side, "ENCRYPT", "metadata_key", metadata_key);
    EPP_LOG_KEY(side, "ENCRYPT", "dh_public_in_envelope", dh_public);
    EPP_LOG_VALUE(side, "ENCRYPT", "ratchet_epoch", ratchet_epoch);
}

inline void LogDecryption(
    Side side,
    uint32_t message_index,
    std::span<const uint8_t> message_key,
    std::span<const uint8_t> nonce,
    std::span<const uint8_t> metadata_key,
    std::span<const uint8_t> received_dh_public,
    uint64_t received_ratchet_epoch,
    bool triggered_ratchet) {

    EPP_LOG_SECTION(side, "DECRYPT");
    EPP_LOG_KEY_IDX(side, "DECRYPT", "message_key", message_index, message_key);
    EPP_LOG_KEY(side, "DECRYPT", "nonce", nonce);
    EPP_LOG_KEY(side, "DECRYPT", "metadata_key", metadata_key);
    EPP_LOG_KEY(side, "DECRYPT", "received_dh_public", received_dh_public);
    EPP_LOG_VALUE(side, "DECRYPT", "received_ratchet_epoch", received_ratchet_epoch);
    EPP_LOG_MSG(side, "DECRYPT", triggered_ratchet ? "triggered_ratchet: YES" : "triggered_ratchet: NO");
}

// ============================================================================
// Nonce Logging
// ============================================================================

inline void LogNonce(
    Side side,
    const char* operation,
    std::span<const uint8_t> prefix,
    uint32_t counter,
    uint32_t index,
    std::span<const uint8_t> final_nonce) {

    EPP_LOG_KEY(side, operation, "nonce_prefix", prefix);
    EPP_LOG_VALUE(side, operation, "nonce_counter", counter);
    EPP_LOG_VALUE(side, operation, "nonce_index", index);
    EPP_LOG_KEY(side, operation, "final_nonce", final_nonce);
}

// ============================================================================
// Connection State Logging
// ============================================================================

inline void LogConnectionCreated(
    Side side,
    uint32_t connection_id,
    bool is_initiator,
    std::span<const uint8_t> session_id,
    std::span<const uint8_t> root_key,
    std::span<const uint8_t> initial_dh_public) {

    EPP_LOG_SECTION(side, "CONNECTION CREATED");
    EPP_LOG_VALUE(side, "CONN", "connection_id", connection_id);
    EPP_LOG_MSG(side, "CONN", is_initiator ? "is_initiator: YES" : "is_initiator: NO");
    EPP_LOG_KEY(side, "CONN", "session_id", session_id);
    EPP_LOG_KEY(side, "CONN", "root_key", root_key);
    EPP_LOG_KEY(side, "CONN", "initial_dh_public", initial_dh_public);
}

#else // !ECLIPTIX_DEBUG_KEYS

// No-op implementations when ECLIPTIX_DEBUG_KEYS is not defined
#define EPP_LOG_KEY(side, operation, key_name, data) ((void)0)
#define EPP_LOG_KEY_IDX(side, operation, key_name, index, data) ((void)0)
#define EPP_LOG_VALUE(side, operation, name, value) ((void)0)
#define EPP_LOG_MSG(side, operation, message) ((void)0)
#define EPP_LOG_SECTION(side, section_name) ((void)0)

inline void LogIdentityKeysCreated(Side, std::span<const uint8_t>, std::span<const uint8_t>,
    std::span<const uint8_t>, std::span<const uint8_t>, uint32_t, std::span<const uint8_t>,
    std::span<const uint8_t>, std::span<const uint8_t>, std::span<const uint8_t>,
    std::span<const uint8_t>) {}

inline void LogOneTimePreKey(Side, uint32_t, std::span<const uint8_t>, std::span<const uint8_t>) {}
inline void LogEphemeralKeyGenerated(Side, std::span<const uint8_t>, std::span<const uint8_t>) {}
inline void LogX3DHStart(Side, bool) {}
inline void LogX3DHPeerBundle(Side, std::span<const uint8_t>, std::span<const uint8_t>,
    std::optional<std::span<const uint8_t>>, std::optional<std::span<const uint8_t>>,
    std::optional<uint32_t>) {}
inline void LogX3DHDH(Side, int, const char*, std::span<const uint8_t>) {}
inline void LogX3DHConcatenated(Side, std::span<const uint8_t>, size_t) {}
inline void LogX3DHRootKey(Side, std::span<const uint8_t>) {}
inline void LogKyberEncapsulation(Side, std::span<const uint8_t>, std::span<const uint8_t>) {}
inline void LogKyberDecapsulation(Side, std::span<const uint8_t>, std::span<const uint8_t>) {}
inline void LogHybridCombination(Side, std::span<const uint8_t>, std::span<const uint8_t>,
    std::span<const uint8_t>) {}
inline void LogChainKeyDerivation(Side, const char*, uint32_t, std::span<const uint8_t>,
    std::span<const uint8_t>) {}
inline void LogDHRatchet(Side, bool, std::span<const uint8_t>, std::span<const uint8_t>,
    std::span<const uint8_t>, std::span<const uint8_t>, std::span<const uint8_t>, uint64_t) {}
inline void LogKyberRatchet(Side, std::span<const uint8_t>, std::span<const uint8_t>) {}
inline void LogEncryption(Side, uint32_t, std::span<const uint8_t>, std::span<const uint8_t>,
    std::span<const uint8_t>, std::span<const uint8_t>, uint64_t) {}
inline void LogDecryption(Side, uint32_t, std::span<const uint8_t>, std::span<const uint8_t>,
    std::span<const uint8_t>, std::span<const uint8_t>, uint64_t, bool) {}
inline void LogNonce(Side, const char*, std::span<const uint8_t>, uint32_t, uint32_t,
    std::span<const uint8_t>) {}
inline void LogConnectionCreated(Side, uint32_t, bool, std::span<const uint8_t>,
    std::span<const uint8_t>, std::span<const uint8_t>) {}

#endif // ECLIPTIX_DEBUG_KEYS

} // namespace ecliptix::debug
