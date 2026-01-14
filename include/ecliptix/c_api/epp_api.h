#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define EPP_API_VERSION_MAJOR 1
#define EPP_API_VERSION_MINOR 0
#define EPP_API_VERSION_PATCH 0

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

typedef struct ProtocolSystemHandle ProtocolSystemHandle;
typedef struct ProtocolConnectionHandle ProtocolConnectionHandle;
typedef struct EppIdentityHandle EppIdentityHandle;
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

const char* epp_version(void);

EppErrorCode epp_init(void);

void epp_shutdown(void);

EppErrorCode epp_identity_create(
    EppIdentityHandle** out_handle,
    EppError* out_error);

EppErrorCode epp_identity_create_from_seed(
    const uint8_t* seed,
    size_t seed_length,
    EppIdentityHandle** out_handle,
    EppError* out_error);

EppErrorCode epp_identity_create_with_context(
    const uint8_t* seed,
    size_t seed_length,
    const char* membership_id,
    size_t membership_id_length,
    EppIdentityHandle** out_handle,
    EppError* out_error);

EppErrorCode epp_identity_get_x25519_public(
    const EppIdentityHandle* handle,
    uint8_t* out_key,
    size_t out_key_length,
    EppError* out_error);

EppErrorCode epp_identity_get_ed25519_public(
    const EppIdentityHandle* handle,
    uint8_t* out_key,
    size_t out_key_length,
    EppError* out_error);

// Get the identity Kyber (ML-KEM-768) public key (1184 bytes).
EppErrorCode epp_identity_get_kyber_public(
    const EppIdentityHandle* handle,
    uint8_t* out_key,
    size_t out_key_length,
    EppError* out_error);

void epp_identity_destroy(const EppIdentityHandle* handle);

EppErrorCode epp_session_create(
    EppIdentityHandle* identity_keys,
    ProtocolSystemHandle** out_handle,
    EppError* out_error);

EppErrorCode epp_session_set_callbacks(
    ProtocolSystemHandle* handle,
    const EppCallbacks* callbacks,
    EppError* out_error);

// Begin a handshake with encapsulation to peer's Kyber public key (MANDATORY - Kyber is required).
// Use this when you know the peer's Kyber key (e.g., after receiving their bundle).
// The resulting bundle will include kyber_ciphertext for the peer to decapsulate.
EppErrorCode epp_session_begin_handshake(
    ProtocolSystemHandle* handle,
    uint32_t connection_id,
    uint8_t exchange_type,
    const uint8_t* peer_kyber_public_key,
    size_t peer_kyber_public_key_length,
    EppBuffer* out_handshake_message,
    EppError* out_error);

EppErrorCode epp_session_complete_handshake(
    ProtocolSystemHandle* handle,
    const uint8_t* peer_handshake_message,
    size_t peer_handshake_message_length,
    const uint8_t* root_key,
    size_t root_key_length,
    EppError* out_error);

// Complete a handshake by deriving the root key (hybrid X3DH/PQ) from the peer handshake payload
// using the local identity keys. This avoids root-key derivation on the caller side.
EppErrorCode epp_session_complete_handshake_auto(
    ProtocolSystemHandle* handle,
    const uint8_t* peer_handshake_message,
    size_t peer_handshake_message_length,
    EppError* out_error);

EppErrorCode epp_session_encrypt(
    const ProtocolSystemHandle* handle,
    const uint8_t* plaintext,
    size_t plaintext_length,
    EppBuffer* out_encrypted_envelope,
    EppError* out_error);

EppErrorCode epp_session_decrypt(
    const ProtocolSystemHandle* handle,
    const uint8_t* encrypted_envelope,
    size_t encrypted_envelope_length,
    EppBuffer* out_plaintext,
    EppError* out_error);

// Create a protocol system from a pre-shared root key (e.g., OPAQUE) and peer bundle (serialized PublicKeyBundle).
EppErrorCode epp_session_create_from_root(
    EppIdentityHandle* identity_keys,
    const uint8_t* root_key,
    size_t root_key_length,
    const uint8_t* peer_bundle,
    size_t peer_bundle_length,
    bool is_initiator,
    ProtocolSystemHandle** out_handle,
    EppError* out_error);

// Export/import full protocol state (serialized ProtocolState protobuf).
EppErrorCode epp_session_serialize(
    const ProtocolSystemHandle* handle,
    EppBuffer* out_state,
    EppError* out_error);

EppErrorCode epp_session_deserialize(
    EppIdentityHandle* identity_keys,
    const uint8_t* state_bytes,
    size_t state_bytes_length,
    ProtocolSystemHandle** out_handle,
    EppError* out_error);

EppErrorCode epp_envelope_validate(
    const uint8_t* encrypted_envelope,
    size_t encrypted_envelope_length,
    EppError* out_error);

EppErrorCode epp_derive_root_key(
    const uint8_t* opaque_session_key,
    size_t opaque_session_key_length,
    const uint8_t* user_context,
    size_t user_context_length,
    uint8_t* out_root_key,
    size_t out_root_key_length,
    EppError* out_error);

EppErrorCode epp_session_is_established(
    const ProtocolSystemHandle* handle,
    bool* out_has_connection,
    EppError* out_error);

EppErrorCode epp_session_get_id(
    const ProtocolSystemHandle* handle,
    uint32_t* out_connection_id,
    EppError* out_error);

EppErrorCode epp_session_get_chain_indices(
    const ProtocolSystemHandle* handle,
    uint32_t* out_sending_index,
    uint32_t* out_receiving_index,
    EppError* out_error);

// Get the OPK ID selected during X3DH handshake (for communicating to peer).
// Returns the ID via out_opk_id and sets out_has_opk_id to true if an OPK was used.
// If no OPK was used (no OPKs available from peer), out_has_opk_id will be false.
EppErrorCode epp_session_get_used_prekey_id(
    const ProtocolSystemHandle* handle,
    bool* out_has_opk_id,
    uint32_t* out_opk_id,
    EppError* out_error);

// Get session age in seconds since creation.
// Application layer can use this to decide when to refresh/rehandshake.
// Session timeout is no longer enforced by the library - it's the application's responsibility.
EppErrorCode epp_session_age_seconds(
    const ProtocolSystemHandle* handle,
    uint64_t* out_age_seconds,
    EppError* out_error);

// Set Kyber hybrid handshake secrets on the active connection.
// Call this BEFORE finalizing the connection when using manual Kyber secret setup.
// This is useful when the Kyber shared secret is derived externally (e.g., from OPAQUE).
EppErrorCode epp_session_set_kyber_secrets(
    const ProtocolSystemHandle* handle,
    const uint8_t* kyber_ciphertext,
    size_t kyber_ciphertext_length,
    const uint8_t* kyber_shared_secret,
    size_t kyber_shared_secret_length,
    EppError* out_error);

void epp_session_destroy(const ProtocolSystemHandle* handle);

EppErrorCode epp_connection_create(
    uint32_t connection_id,
    bool is_initiator,
    ProtocolConnectionHandle** out_handle,
    EppError* out_error);

EppErrorCode epp_connection_set_peer_bundle(
    ProtocolConnectionHandle* handle,
    const uint8_t* peer_bundle,
    size_t peer_bundle_length,
    EppError* out_error);

EppErrorCode epp_connection_finalize_keys(
    ProtocolConnectionHandle* handle,
    const uint8_t* initial_root_key,
    size_t initial_root_key_length,
    const uint8_t* peer_dh_public_key,
    size_t peer_dh_public_key_length,
    EppError* out_error);

EppErrorCode epp_connection_serialize(
    const ProtocolConnectionHandle* handle,
    EppBuffer* out_serialized_state,
    EppError* out_error);

EppErrorCode epp_connection_deserialize(
    const uint8_t* serialized_state,
    size_t serialized_state_length,
    uint32_t connection_id,
    ProtocolConnectionHandle** out_handle,
    EppError* out_error);

void epp_connection_destroy(ProtocolConnectionHandle* handle);

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

EppBuffer* epp_buffer_alloc(size_t capacity);

void epp_buffer_free(const EppBuffer* buffer);

void epp_error_free(EppError* error);

const char* epp_error_string(EppErrorCode code);

EppErrorCode epp_secure_wipe(
    uint8_t* data,
    size_t length);

#ifdef __cplusplus
}
#endif
