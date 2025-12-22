#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define ECLIPTIX_C_API_VERSION_MAJOR 1
#define ECLIPTIX_C_API_VERSION_MINOR 0
#define ECLIPTIX_C_API_VERSION_PATCH 0

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

typedef struct EcliptixProtocolSystemHandle EcliptixProtocolSystemHandle;
typedef struct EcliptixProtocolConnectionHandle EcliptixProtocolConnectionHandle;
typedef struct EcliptixIdentityKeysHandle EcliptixIdentityKeysHandle;
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

const char* ecliptix_get_version(void);

EcliptixErrorCode ecliptix_initialize(void);

void ecliptix_shutdown(void);

EcliptixErrorCode ecliptix_identity_keys_create(
    EcliptixIdentityKeysHandle** out_handle,
    EcliptixError* out_error);

EcliptixErrorCode ecliptix_identity_keys_create_from_seed(
    const uint8_t* seed,
    size_t seed_length,
    EcliptixIdentityKeysHandle** out_handle,
    EcliptixError* out_error);

EcliptixErrorCode ecliptix_identity_keys_create_from_seed_with_context(
    const uint8_t* seed,
    size_t seed_length,
    const char* membership_id,
    size_t membership_id_length,
    EcliptixIdentityKeysHandle** out_handle,
    EcliptixError* out_error);

EcliptixErrorCode ecliptix_identity_keys_get_public_x25519(
    const EcliptixIdentityKeysHandle* handle,
    uint8_t* out_key,
    size_t out_key_length,
    EcliptixError* out_error);

EcliptixErrorCode ecliptix_identity_keys_get_public_ed25519(
    const EcliptixIdentityKeysHandle* handle,
    uint8_t* out_key,
    size_t out_key_length,
    EcliptixError* out_error);

void ecliptix_identity_keys_destroy(EcliptixIdentityKeysHandle* handle);

EcliptixErrorCode ecliptix_protocol_system_create(
    EcliptixIdentityKeysHandle* identity_keys,
    EcliptixProtocolSystemHandle** out_handle,
    EcliptixError* out_error);

EcliptixErrorCode ecliptix_protocol_system_set_callbacks(
    EcliptixProtocolSystemHandle* handle,
    const EcliptixCallbacks* callbacks,
    EcliptixError* out_error);

EcliptixErrorCode ecliptix_protocol_system_begin_handshake(
    EcliptixProtocolSystemHandle* handle,
    uint32_t connection_id,
    uint8_t exchange_type,
    EcliptixBuffer* out_handshake_message,
    EcliptixError* out_error);

// Begin a handshake with encapsulation to peer's Kyber public key.
// Use this when you know the peer's Kyber key (e.g., after receiving their bundle).
// The resulting bundle will include kyber_ciphertext for the peer to decapsulate.
EcliptixErrorCode ecliptix_protocol_system_begin_handshake_with_peer_kyber(
    EcliptixProtocolSystemHandle* handle,
    uint32_t connection_id,
    uint8_t exchange_type,
    const uint8_t* peer_kyber_public_key,
    size_t peer_kyber_public_key_length,
    EcliptixBuffer* out_handshake_message,
    EcliptixError* out_error);

EcliptixErrorCode ecliptix_protocol_system_complete_handshake(
    EcliptixProtocolSystemHandle* handle,
    const uint8_t* peer_handshake_message,
    size_t peer_handshake_message_length,
    const uint8_t* root_key,
    size_t root_key_length,
    EcliptixError* out_error);

// Complete a handshake by deriving the root key (hybrid X3DH/PQ) from the peer handshake payload
// using the local identity keys. This avoids root-key derivation on the caller side.
EcliptixErrorCode ecliptix_protocol_system_complete_handshake_auto(
    EcliptixProtocolSystemHandle* handle,
    const uint8_t* peer_handshake_message,
    size_t peer_handshake_message_length,
    EcliptixError* out_error);

EcliptixErrorCode ecliptix_protocol_system_send_message(
    EcliptixProtocolSystemHandle* handle,
    const uint8_t* plaintext,
    size_t plaintext_length,
    EcliptixBuffer* out_encrypted_envelope,
    EcliptixError* out_error);

EcliptixErrorCode ecliptix_protocol_system_receive_message(
    EcliptixProtocolSystemHandle* handle,
    const uint8_t* encrypted_envelope,
    size_t encrypted_envelope_length,
    EcliptixBuffer* out_plaintext,
    EcliptixError* out_error);

// Create a protocol system from a pre-shared root key (e.g., OPAQUE) and peer bundle (serialized PublicKeyBundle).
EcliptixErrorCode ecliptix_protocol_system_create_from_root(
    EcliptixIdentityKeysHandle* identity_keys,
    const uint8_t* root_key,
    size_t root_key_length,
    const uint8_t* peer_bundle,
    size_t peer_bundle_length,
    bool is_initiator,
    EcliptixProtocolSystemHandle** out_handle,
    EcliptixError* out_error);

// Export/import full protocol state (serialized ProtocolState protobuf).
EcliptixErrorCode ecliptix_protocol_system_export_state(
    EcliptixProtocolSystemHandle* handle,
    EcliptixBuffer* out_state,
    EcliptixError* out_error);

EcliptixErrorCode ecliptix_protocol_system_import_state(
    EcliptixIdentityKeysHandle* identity_keys,
    const uint8_t* state_bytes,
    size_t state_bytes_length,
    EcliptixProtocolSystemHandle** out_handle,
    EcliptixError* out_error);

EcliptixErrorCode ecliptix_envelope_validate_hybrid_requirements(
    const uint8_t* encrypted_envelope,
    size_t encrypted_envelope_length,
    EcliptixError* out_error);

EcliptixErrorCode ecliptix_derive_root_from_opaque_session_key(
    const uint8_t* opaque_session_key,
    size_t opaque_session_key_length,
    const uint8_t* user_context,
    size_t user_context_length,
    uint8_t* out_root_key,
    size_t out_root_key_length,
    EcliptixError* out_error);

EcliptixErrorCode ecliptix_protocol_system_has_connection(
    const EcliptixProtocolSystemHandle* handle,
    bool* out_has_connection,
    EcliptixError* out_error);

EcliptixErrorCode ecliptix_protocol_system_get_connection_id(
    const EcliptixProtocolSystemHandle* handle,
    uint32_t* out_connection_id,
    EcliptixError* out_error);

EcliptixErrorCode ecliptix_protocol_system_get_chain_indices(
    const EcliptixProtocolSystemHandle* handle,
    uint32_t* out_sending_index,
    uint32_t* out_receiving_index,
    EcliptixError* out_error);

// Get the OPK ID selected during X3DH handshake (for communicating to peer).
// Returns the ID via out_opk_id and sets out_has_opk_id to true if an OPK was used.
// If no OPK was used (no OPKs available from peer), out_has_opk_id will be false.
EcliptixErrorCode ecliptix_protocol_system_get_selected_opk_id(
    const EcliptixProtocolSystemHandle* handle,
    bool* out_has_opk_id,
    uint32_t* out_opk_id,
    EcliptixError* out_error);

void ecliptix_protocol_system_destroy(EcliptixProtocolSystemHandle* handle);

EcliptixErrorCode ecliptix_protocol_connection_create(
    uint32_t connection_id,
    bool is_initiator,
    EcliptixProtocolConnectionHandle** out_handle,
    EcliptixError* out_error);

EcliptixErrorCode ecliptix_protocol_connection_set_peer_bundle(
    EcliptixProtocolConnectionHandle* handle,
    const uint8_t* peer_bundle,
    size_t peer_bundle_length,
    EcliptixError* out_error);

EcliptixErrorCode ecliptix_protocol_connection_finalize_keys(
    EcliptixProtocolConnectionHandle* handle,
    const uint8_t* initial_root_key,
    size_t initial_root_key_length,
    const uint8_t* peer_dh_public_key,
    size_t peer_dh_public_key_length,
    EcliptixError* out_error);

EcliptixErrorCode ecliptix_protocol_connection_serialize(
    const EcliptixProtocolConnectionHandle* handle,
    EcliptixBuffer* out_serialized_state,
    EcliptixError* out_error);

EcliptixErrorCode ecliptix_protocol_connection_deserialize(
    const uint8_t* serialized_state,
    size_t serialized_state_length,
    uint32_t connection_id,
    EcliptixProtocolConnectionHandle** out_handle,
    EcliptixError* out_error);

void ecliptix_protocol_connection_destroy(EcliptixProtocolConnectionHandle* handle);

EcliptixBuffer* ecliptix_buffer_allocate(size_t capacity);

void ecliptix_buffer_free(EcliptixBuffer* buffer);

void ecliptix_error_free(EcliptixError* error);

const char* ecliptix_error_code_to_string(EcliptixErrorCode code);

EcliptixErrorCode ecliptix_secure_wipe(
    uint8_t* data,
    size_t length);

#ifdef __cplusplus
}
#endif
