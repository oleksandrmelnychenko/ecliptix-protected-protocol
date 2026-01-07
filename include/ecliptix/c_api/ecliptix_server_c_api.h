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

#define ECLIPTIX_SERVER_API_VERSION_MAJOR 1
#define ECLIPTIX_SERVER_API_VERSION_MINOR 0
#define ECLIPTIX_SERVER_API_VERSION_PATCH 0

// ============================================================================
// Error Codes
// ============================================================================
typedef enum {
    ECLIPTIX_SUCCESS = 0,
    ECLIPTIX_ERROR_GENERIC = 1,
    ECLIPTIX_ERROR_INVALID_INPUT = 2,
    ECLIPTIX_ERROR_KEY_GENERATION = 3,
    ECLIPTIX_ERROR_DERIVE_KEY = 4,
    ECLIPTIX_ERROR_HANDSHAKE = 5,
    ECLIPTIX_ERROR_ENCRYPTION = 6,
    ECLIPTIX_ERROR_DECRYPTION = 7,
    ECLIPTIX_ERROR_DECODE = 8,
    ECLIPTIX_ERROR_ENCODE = 9,
    ECLIPTIX_ERROR_BUFFER_TOO_SMALL = 10,
    ECLIPTIX_ERROR_OBJECT_DISPOSED = 11,
    ECLIPTIX_ERROR_PREPARE_LOCAL = 12,
    ECLIPTIX_ERROR_OUT_OF_MEMORY = 13,
    ECLIPTIX_ERROR_SODIUM_FAILURE = 14,
    ECLIPTIX_ERROR_NULL_POINTER = 15,
    ECLIPTIX_ERROR_INVALID_STATE = 16,
    ECLIPTIX_ERROR_REPLAY_ATTACK = 17,
    ECLIPTIX_ERROR_SESSION_EXPIRED = 18,
    ECLIPTIX_ERROR_PQ_MISSING = 19
} EcliptixErrorCode;

// ============================================================================
// Opaque Handle Types
// ============================================================================
typedef struct EcliptixProtocolSystemHandle EcliptixProtocolSystemHandle;
typedef struct EcliptixIdentityKeysHandle EcliptixIdentityKeysHandle;

// ============================================================================
// Data Structures
// ============================================================================
typedef struct EcliptixBuffer {
    uint8_t* data;
    size_t length;
} EcliptixBuffer;

typedef struct EcliptixError {
    EcliptixErrorCode code;
    char* message;
} EcliptixError;

typedef void (*EcliptixProtocolEventCallback)(uint32_t connection_id, void* user_data);

typedef struct EcliptixCallbacks {
    EcliptixProtocolEventCallback on_protocol_state_changed;
    void* user_data;
} EcliptixCallbacks;

// ============================================================================
// Version & Initialization
// ============================================================================

/** Get the library version string */
const char* ecliptix_get_version(void);

/** Initialize the library (must be called before any other functions) */
EcliptixErrorCode ecliptix_initialize(void);

/** Shutdown the library */
void ecliptix_shutdown(void);

// ============================================================================
// Identity Keys Management
// ============================================================================

/** Create new random identity keys */
EcliptixErrorCode ecliptix_identity_keys_create(
    EcliptixIdentityKeysHandle** out_handle,
    EcliptixError* out_error);

/** Create identity keys from a seed */
EcliptixErrorCode ecliptix_identity_keys_create_from_seed(
    const uint8_t* seed,
    size_t seed_length,
    EcliptixIdentityKeysHandle** out_handle,
    EcliptixError* out_error);

/** Create identity keys from a seed with membership context */
EcliptixErrorCode ecliptix_identity_keys_create_from_seed_with_context(
    const uint8_t* seed,
    size_t seed_length,
    const char* membership_id,
    size_t membership_id_length,
    EcliptixIdentityKeysHandle** out_handle,
    EcliptixError* out_error);

/** Get the X25519 public key (32 bytes) */
EcliptixErrorCode ecliptix_identity_keys_get_public_x25519(
    const EcliptixIdentityKeysHandle* handle,
    uint8_t* out_key,
    size_t out_key_length,
    EcliptixError* out_error);

/** Get the Ed25519 public key (32 bytes) */
EcliptixErrorCode ecliptix_identity_keys_get_public_ed25519(
    const EcliptixIdentityKeysHandle* handle,
    uint8_t* out_key,
    size_t out_key_length,
    EcliptixError* out_error);

/** Get the Kyber (ML-KEM-768) public key (1184 bytes) */
EcliptixErrorCode ecliptix_identity_keys_get_public_kyber(
    const EcliptixIdentityKeysHandle* handle,
    uint8_t* out_key,
    size_t out_key_length,
    EcliptixError* out_error);

/** Destroy identity keys and securely wipe memory */
void ecliptix_identity_keys_destroy(EcliptixIdentityKeysHandle* handle);

// ============================================================================
// Protocol Server System
// ============================================================================

/** Create a new protocol server system */
EcliptixErrorCode ecliptix_protocol_server_system_create(
    EcliptixIdentityKeysHandle* identity_keys,
    EcliptixProtocolSystemHandle** out_handle,
    EcliptixError* out_error);

/** Create protocol system from pre-shared root key (e.g., OPAQUE) and peer bundle */
EcliptixErrorCode ecliptix_protocol_server_system_create_from_root(
    EcliptixIdentityKeysHandle* identity_keys,
    const uint8_t* root_key,
    size_t root_key_length,
    const uint8_t* peer_bundle,
    size_t peer_bundle_length,
    bool is_initiator,
    EcliptixProtocolSystemHandle** out_handle,
    EcliptixError* out_error);

/** Import protocol system from serialized state */
EcliptixErrorCode ecliptix_protocol_server_system_import_state(
    EcliptixIdentityKeysHandle* identity_keys,
    const uint8_t* state_bytes,
    size_t state_bytes_length,
    EcliptixProtocolSystemHandle** out_handle,
    EcliptixError* out_error);

/** Set event callbacks for protocol state changes */
EcliptixErrorCode ecliptix_protocol_server_system_set_callbacks(
    EcliptixProtocolSystemHandle* handle,
    const EcliptixCallbacks* callbacks,
    EcliptixError* out_error);

/** Begin a handshake with the specified exchange type */
EcliptixErrorCode ecliptix_protocol_server_system_begin_handshake(
    EcliptixProtocolSystemHandle* handle,
    uint32_t connection_id,
    uint8_t exchange_type,
    EcliptixBuffer* out_handshake_message,
    EcliptixError* out_error);

/** Begin a handshake with peer's Kyber public key for post-quantum security */
EcliptixErrorCode ecliptix_protocol_server_system_begin_handshake_with_peer_kyber(
    EcliptixProtocolSystemHandle* handle,
    uint32_t connection_id,
    uint8_t exchange_type,
    const uint8_t* peer_kyber_public_key,
    size_t peer_kyber_public_key_length,
    EcliptixBuffer* out_handshake_message,
    EcliptixError* out_error);

/** Complete handshake with explicit root key */
EcliptixErrorCode ecliptix_protocol_server_system_complete_handshake(
    EcliptixProtocolSystemHandle* handle,
    const uint8_t* peer_handshake_message,
    size_t peer_handshake_message_length,
    const uint8_t* root_key,
    size_t root_key_length,
    EcliptixError* out_error);

/** Complete handshake by auto-deriving root key from peer handshake */
EcliptixErrorCode ecliptix_protocol_server_system_complete_handshake_auto(
    EcliptixProtocolSystemHandle* handle,
    const uint8_t* peer_handshake_message,
    size_t peer_handshake_message_length,
    EcliptixError* out_error);

/** Encrypt a message using the Double Ratchet */
EcliptixErrorCode ecliptix_protocol_server_system_send_message(
    EcliptixProtocolSystemHandle* handle,
    const uint8_t* plaintext,
    size_t plaintext_length,
    EcliptixBuffer* out_encrypted_envelope,
    EcliptixError* out_error);

/** Decrypt a message using the Double Ratchet */
EcliptixErrorCode ecliptix_protocol_server_system_receive_message(
    EcliptixProtocolSystemHandle* handle,
    const uint8_t* encrypted_envelope,
    size_t encrypted_envelope_length,
    EcliptixBuffer* out_plaintext,
    EcliptixError* out_error);

/** Check if the system has an active connection */
EcliptixErrorCode ecliptix_protocol_server_system_has_connection(
    const EcliptixProtocolSystemHandle* handle,
    bool* out_has_connection,
    EcliptixError* out_error);

/** Get the current connection ID */
EcliptixErrorCode ecliptix_protocol_server_system_get_connection_id(
    const EcliptixProtocolSystemHandle* handle,
    uint32_t* out_connection_id,
    EcliptixError* out_error);

/** Get current chain indices */
EcliptixErrorCode ecliptix_protocol_server_system_get_chain_indices(
    const EcliptixProtocolSystemHandle* handle,
    uint32_t* out_sending_index,
    uint32_t* out_receiving_index,
    EcliptixError* out_error);

/** Get the selected OPK ID during X3DH handshake */
EcliptixErrorCode ecliptix_protocol_server_system_get_selected_opk_id(
    const EcliptixProtocolSystemHandle* handle,
    bool* out_has_opk_id,
    uint32_t* out_opk_id,
    EcliptixError* out_error);

/** Export the full protocol state for persistence */
EcliptixErrorCode ecliptix_protocol_server_system_export_state(
    EcliptixProtocolSystemHandle* handle,
    EcliptixBuffer* out_state,
    EcliptixError* out_error);

/** Set Kyber hybrid handshake secrets for manual PQ setup */
EcliptixErrorCode ecliptix_protocol_server_system_set_kyber_secrets(
    EcliptixProtocolSystemHandle* handle,
    const uint8_t* kyber_ciphertext,
    size_t kyber_ciphertext_length,
    const uint8_t* kyber_shared_secret,
    size_t kyber_shared_secret_length,
    EcliptixError* out_error);

/** Destroy the protocol server system */
void ecliptix_protocol_server_system_destroy(EcliptixProtocolSystemHandle* handle);

// ============================================================================
// Utilities
// ============================================================================

/** Get session age in seconds since creation */
EcliptixErrorCode ecliptix_connection_get_session_age_seconds(
    const EcliptixProtocolSystemHandle* handle,
    uint64_t* out_age_seconds,
    EcliptixError* out_error);

/** Validate that an envelope meets hybrid (PQ) requirements */
EcliptixErrorCode ecliptix_envelope_validate_hybrid_requirements(
    const uint8_t* encrypted_envelope,
    size_t encrypted_envelope_length,
    EcliptixError* out_error);

/** Derive a root key from OPAQUE session key */
EcliptixErrorCode ecliptix_derive_root_from_opaque_session_key(
    const uint8_t* opaque_session_key,
    size_t opaque_session_key_length,
    const uint8_t* user_context,
    size_t user_context_length,
    uint8_t* out_root_key,
    size_t out_root_key_length,
    EcliptixError* out_error);

// ============================================================================
// Memory Management
// ============================================================================

/** Allocate a buffer */
EcliptixBuffer* ecliptix_buffer_allocate(size_t capacity);

/** Free an allocated buffer */
void ecliptix_buffer_free(EcliptixBuffer* buffer);

/** Free an error structure */
void ecliptix_error_free(EcliptixError* error);

/** Convert error code to string */
const char* ecliptix_error_code_to_string(EcliptixErrorCode code);

#ifdef __cplusplus
}
#endif
