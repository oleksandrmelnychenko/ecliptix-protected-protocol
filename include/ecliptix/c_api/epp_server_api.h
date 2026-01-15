#pragma once

/**
 * Server-side C API for Ecliptix Protocol System
 *
 * This header provides the C-compatible interface for .NET interop on the server side.
 * It wraps the core C++ protocol functionality with a stable ABI.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define EPP_SERVER_API_VERSION_MAJOR 1
#define EPP_SERVER_API_VERSION_MINOR 0
#define EPP_SERVER_API_VERSION_PATCH 0

// ============================================================================
// Error Codes
// ============================================================================
typedef enum {
    EPP_SUCCESS = 0,
    EPP_ERROR_GENERIC = 1,
    EPP_ERROR_INVALID_INPUT = 2,
    EPP_ERROR_KEY_GENERATION = 3,
    EPP_ERROR_DERIVE_KEY = 4,
    EPP_ERROR_HANDSHAKE = 5,
    EPP_ERROR_ENCRYPTION = 6,
    EPP_ERROR_DECRYPTION = 7,
    EPP_ERROR_DECODE = 8,
    EPP_ERROR_ENCODE = 9,
    EPP_ERROR_BUFFER_TOO_SMALL = 10,
    EPP_ERROR_OBJECT_DISPOSED = 11,
    EPP_ERROR_PREPARE_LOCAL = 12,
    EPP_ERROR_OUT_OF_MEMORY = 13,
    EPP_ERROR_SODIUM_FAILURE = 14,
    EPP_ERROR_NULL_POINTER = 15,
    EPP_ERROR_INVALID_STATE = 16,
    EPP_ERROR_REPLAY_ATTACK = 17,
    EPP_ERROR_SESSION_EXPIRED = 18,
    EPP_ERROR_PQ_MISSING = 19
} EppErrorCode;

// ============================================================================
// Opaque Handle Types
// ============================================================================
typedef struct ProtocolSystemHandle ProtocolSystemHandle;
typedef struct EppIdentityHandle EppIdentityHandle;

// ============================================================================
// Data Structures
// ============================================================================
typedef struct EppBuffer {
    uint8_t* data;
    size_t length;
} EppBuffer;

typedef struct EppError {
    EppErrorCode code;
    char* message;
} EppError;

typedef void (*EppEventCallback)(uint32_t connection_id, void* user_data);

typedef struct EppCallbacks {
    EppEventCallback on_protocol_state_changed;
    void* user_data;
} EppCallbacks;

// ============================================================================
// Version & Initialization
// ============================================================================

/** Get the library version string */
const char* epp_version(void);

/** Initialize the library (must be called before any other functions) */
EppErrorCode epp_init(void);

/** Shutdown the library */
void epp_shutdown(void);

// ============================================================================
// Identity Keys Management
// ============================================================================

/** Create new random identity keys */
EppErrorCode epp_identity_create(
    EppIdentityHandle** out_handle,
    EppError* out_error);

/** Create identity keys from a seed */
EppErrorCode epp_identity_create_from_seed(
    const uint8_t* seed,
    size_t seed_length,
    EppIdentityHandle** out_handle,
    EppError* out_error);

/** Create identity keys from a seed with membership context */
EppErrorCode epp_identity_create_with_context(
    const uint8_t* seed,
    size_t seed_length,
    const char* membership_id,
    size_t membership_id_length,
    EppIdentityHandle** out_handle,
    EppError* out_error);

/** Get the X25519 public key (32 bytes) */
EppErrorCode epp_identity_get_x25519_public(
    const EppIdentityHandle* handle,
    uint8_t* out_key,
    size_t out_key_length,
    EppError* out_error);

/** Get the Ed25519 public key (32 bytes) */
EppErrorCode epp_identity_get_ed25519_public(
    const EppIdentityHandle* handle,
    uint8_t* out_key,
    size_t out_key_length,
    EppError* out_error);

/** Get the Kyber (ML-KEM-768) public key (1184 bytes) */
EppErrorCode epp_identity_get_kyber_public(
    const EppIdentityHandle* handle,
    uint8_t* out_key,
    size_t out_key_length,
    EppError* out_error);

/** Destroy identity keys and securely wipe memory */
void epp_identity_destroy(EppIdentityHandle* handle);

// ============================================================================
// Protocol Server System
// ============================================================================

/** Create a new protocol server system */
EppErrorCode epp_server_create(
    EppIdentityHandle* identity_keys,
    ProtocolSystemHandle** out_handle,
    EppError* out_error);

/** Create protocol system from pre-shared root key (e.g., OPAQUE) and peer bundle */
EppErrorCode epp_server_create_from_root(
    EppIdentityHandle* identity_keys,
    const uint8_t* root_key,
    size_t root_key_length,
    const uint8_t* peer_bundle,
    size_t peer_bundle_length,
    bool is_initiator,
    ProtocolSystemHandle** out_handle,
    EppError* out_error);

/** Import protocol system from serialized state */
EppErrorCode epp_server_deserialize(
    EppIdentityHandle* identity_keys,
    const uint8_t* state_bytes,
    size_t state_bytes_length,
    ProtocolSystemHandle** out_handle,
    EppError* out_error);

/** Set event callbacks for protocol state changes */
EppErrorCode epp_server_set_callbacks(
    ProtocolSystemHandle* handle,
    const EppCallbacks* callbacks,
    EppError* out_error);

/** Begin a handshake with peer's Kyber public key (mandatory for PQ security) */
EppErrorCode epp_server_begin_handshake(
    ProtocolSystemHandle* handle,
    uint32_t connection_id,
    uint8_t exchange_type,
    const uint8_t* peer_kyber_public_key,
    size_t peer_kyber_public_key_length,
    EppBuffer* out_handshake_message,
    EppError* out_error);

/** Complete handshake with explicit root key */
EppErrorCode epp_server_complete_handshake(
    ProtocolSystemHandle* handle,
    const uint8_t* peer_handshake_message,
    size_t peer_handshake_message_length,
    const uint8_t* root_key,
    size_t root_key_length,
    EppError* out_error);

/** Complete handshake by auto-deriving root key from peer handshake */
EppErrorCode epp_server_complete_handshake_auto(
    ProtocolSystemHandle* handle,
    const uint8_t* peer_handshake_message,
    size_t peer_handshake_message_length,
    EppError* out_error);

/** Encrypt a message using the Double Ratchet */
EppErrorCode epp_server_encrypt(
    const ProtocolSystemHandle* handle,
    const uint8_t* plaintext,
    size_t plaintext_length,
    EppBuffer* out_encrypted_envelope,
    EppError* out_error);

/** Decrypt a message using the Double Ratchet */
EppErrorCode epp_server_decrypt(
    const ProtocolSystemHandle* handle,
    const uint8_t* encrypted_envelope,
    size_t encrypted_envelope_length,
    EppBuffer* out_plaintext,
    EppError* out_error);

/** Check if the system has an active connection */
EppErrorCode epp_server_is_established(
    const ProtocolSystemHandle* handle,
    bool* out_has_connection,
    EppError* out_error);

/** Get the current connection ID */
EppErrorCode epp_server_get_id(
    const ProtocolSystemHandle* handle,
    uint32_t* out_connection_id,
    EppError* out_error);

/** Get current chain indices */
EppErrorCode epp_server_get_chain_indices(
    const ProtocolSystemHandle* handle,
    uint32_t* out_sending_index,
    uint32_t* out_receiving_index,
    EppError* out_error);

/** Get the selected OPK ID during X3DH handshake */
EppErrorCode epp_server_get_used_prekey_id(
    const ProtocolSystemHandle* handle,
    bool* out_has_opk_id,
    uint32_t* out_opk_id,
    EppError* out_error);

/** Export the full protocol state for persistence */
EppErrorCode epp_server_serialize(
    const ProtocolSystemHandle* handle,
    EppBuffer* out_state,
    EppError* out_error);

/** Set Kyber hybrid handshake secrets for manual PQ setup */
EppErrorCode epp_server_set_kyber_secrets(
    const ProtocolSystemHandle* handle,
    const uint8_t* kyber_ciphertext,
    size_t kyber_ciphertext_length,
    const uint8_t* kyber_shared_secret,
    size_t kyber_shared_secret_length,
    EppError* out_error);

/** Destroy the protocol server system */
void epp_server_destroy(const ProtocolSystemHandle* handle);

// ============================================================================
// Utilities
// ============================================================================

// Secret sharing (Shamir, GF(256), v1 share format)
EppErrorCode epp_shamir_split(
    const uint8_t* secret,
    size_t secret_length,
    uint8_t threshold,
    uint8_t share_count,
    const uint8_t* auth_key,
    size_t auth_key_length,
    EppBuffer* out_shares,
    size_t* out_share_length,
    EppError* out_error);

EppErrorCode epp_shamir_reconstruct(
    const uint8_t* shares,
    size_t shares_length,
    size_t share_length,
    size_t share_count,
    const uint8_t* auth_key,
    size_t auth_key_length,
    EppBuffer* out_secret,
    EppError* out_error);

/** Get session age in seconds since creation */
EppErrorCode epp_session_age_seconds(
    const ProtocolSystemHandle* handle,
    uint64_t* out_age_seconds,
    EppError* out_error);

/** Validate that an envelope meets hybrid (PQ) requirements */
EppErrorCode epp_envelope_validate(
    const uint8_t* encrypted_envelope,
    size_t encrypted_envelope_length,
    EppError* out_error);

/** Derive a root key from OPAQUE session key */
EppErrorCode epp_derive_root_key(
    const uint8_t* opaque_session_key,
    size_t opaque_session_key_length,
    const uint8_t* user_context,
    size_t user_context_length,
    uint8_t* out_root_key,
    size_t out_root_key_length,
    EppError* out_error);

// ============================================================================
// Memory Management
// ============================================================================

/** Allocate a buffer */
EppBuffer* epp_buffer_alloc(size_t capacity);

/** Free an allocated buffer */
void epp_buffer_free(EppBuffer* buffer);

/** Free an error structure */
void epp_error_free(EppError* error);

/** Convert error code to string */
const char* epp_error_string(EppErrorCode code);

#ifdef __cplusplus
}
#endif
