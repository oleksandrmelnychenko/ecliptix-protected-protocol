#pragma once
#include "epp_export.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define EPP_API_VERSION_MAJOR 1
#define EPP_API_VERSION_MINOR 0
#define EPP_API_VERSION_PATCH 0

#define EPP_DEFAULT_ONE_TIME_KEY_COUNT 100
#define EPP_LIBRARY_VERSION "1.0.0"

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

typedef struct EppIdentityHandle EppIdentityHandle;
typedef struct EppSessionHandle EppSessionHandle;
#ifndef EPP_SERVER_BUILD
typedef struct EppHandshakeInitiatorHandle EppHandshakeInitiatorHandle;
#endif
typedef struct EppHandshakeResponderHandle EppHandshakeResponderHandle;

typedef struct EppBuffer {
    uint8_t* data;
    size_t length;
} EppBuffer;

typedef enum {
    EPP_ENVELOPE_REQUEST = 0,
    EPP_ENVELOPE_RESPONSE = 1,
    EPP_ENVELOPE_NOTIFICATION = 2,
    EPP_ENVELOPE_HEARTBEAT = 3,
    EPP_ENVELOPE_ERROR_RESPONSE = 4
} EppEnvelopeType;

typedef struct EppError {
    EppErrorCode code;
    char* message;
} EppError;

typedef struct EppSessionConfig {
    uint32_t max_messages_per_chain;
} EppSessionConfig;

EPP_API const char* epp_version(void);
EPP_API EppErrorCode epp_init(void);
EPP_API void epp_shutdown(void);

EPP_API EppErrorCode epp_identity_create(
    EppIdentityHandle** out_handle,
    EppError* out_error);

EPP_API EppErrorCode epp_identity_create_from_seed(
    const uint8_t* seed,
    size_t seed_length,
    EppIdentityHandle** out_handle,
    EppError* out_error);

EPP_API EppErrorCode epp_identity_create_with_context(
    const uint8_t* seed,
    size_t seed_length,
    const char* membership_id,
    size_t membership_id_length,
    EppIdentityHandle** out_handle,
    EppError* out_error);

EPP_API EppErrorCode epp_identity_get_x25519_public(
    const EppIdentityHandle* handle,
    uint8_t* out_key,
    size_t out_key_length,
    EppError* out_error);

EPP_API EppErrorCode epp_identity_get_ed25519_public(
    const EppIdentityHandle* handle,
    uint8_t* out_key,
    size_t out_key_length,
    EppError* out_error);

EPP_API EppErrorCode epp_identity_get_kyber_public(
    const EppIdentityHandle* handle,
    uint8_t* out_key,
    size_t out_key_length,
    EppError* out_error);

EPP_API void epp_identity_destroy(EppIdentityHandle* handle);

EPP_API EppErrorCode epp_prekey_bundle_create(
    const EppIdentityHandle* identity_keys,
    EppBuffer* out_bundle,
    EppError* out_error);

#ifndef EPP_SERVER_BUILD
EPP_API EppErrorCode epp_handshake_initiator_start(
    EppIdentityHandle* identity_keys,
    const uint8_t* peer_prekey_bundle,
    size_t peer_prekey_bundle_length,
    const EppSessionConfig* config,
    EppHandshakeInitiatorHandle** out_handle,
    EppBuffer* out_handshake_init,
    EppError* out_error);

EPP_API EppErrorCode epp_handshake_initiator_finish(
    EppHandshakeInitiatorHandle* handle,
    const uint8_t* handshake_ack,
    size_t handshake_ack_length,
    EppSessionHandle** out_session,
    EppError* out_error);

EPP_API void epp_handshake_initiator_destroy(EppHandshakeInitiatorHandle* handle);
#endif

EPP_API EppErrorCode epp_handshake_responder_start(
    EppIdentityHandle* identity_keys,
    const uint8_t* local_prekey_bundle,
    size_t local_prekey_bundle_length,
    const uint8_t* handshake_init,
    size_t handshake_init_length,
    const EppSessionConfig* config,
    EppHandshakeResponderHandle** out_handle,
    EppBuffer* out_handshake_ack,
    EppError* out_error);

EPP_API EppErrorCode epp_handshake_responder_finish(
    EppHandshakeResponderHandle* handle,
    EppSessionHandle** out_session,
    EppError* out_error);

EPP_API void epp_handshake_responder_destroy(EppHandshakeResponderHandle* handle);

EPP_API EppErrorCode epp_session_encrypt(
    EppSessionHandle* handle,
    const uint8_t* plaintext,
    size_t plaintext_length,
    EppEnvelopeType envelope_type,
    uint32_t envelope_id,
    const char* correlation_id,
    size_t correlation_id_length,
    EppBuffer* out_encrypted_envelope,
    EppError* out_error);

EPP_API EppErrorCode epp_session_decrypt(
    EppSessionHandle* handle,
    const uint8_t* encrypted_envelope,
    size_t encrypted_envelope_length,
    EppBuffer* out_plaintext,
    EppBuffer* out_metadata,
    EppError* out_error);

EPP_API EppErrorCode epp_session_serialize(
    EppSessionHandle* handle,
    EppBuffer* out_state,
    EppError* out_error);

EPP_API EppErrorCode epp_session_deserialize(
    const uint8_t* state_bytes,
    size_t state_bytes_length,
    EppSessionHandle** out_handle,
    EppError* out_error);

EPP_API void epp_session_destroy(EppSessionHandle* handle);

EPP_API EppErrorCode epp_envelope_validate(
    const uint8_t* encrypted_envelope,
    size_t encrypted_envelope_length,
    EppError* out_error);

EPP_API EppErrorCode epp_derive_root_key(
    const uint8_t* opaque_session_key,
    size_t opaque_session_key_length,
    const uint8_t* user_context,
    size_t user_context_length,
    uint8_t* out_root_key,
    size_t out_root_key_length,
    EppError* out_error);

EPP_API EppErrorCode epp_shamir_split(
    const uint8_t* secret,
    size_t secret_length,
    uint8_t threshold,
    uint8_t share_count,
    const uint8_t* auth_key,
    size_t auth_key_length,
    EppBuffer* out_shares,
    size_t* out_share_length,
    EppError* out_error);

EPP_API EppErrorCode epp_shamir_reconstruct(
    const uint8_t* shares,
    size_t shares_length,
    size_t share_length,
    size_t share_count,
    const uint8_t* auth_key,
    size_t auth_key_length,
    EppBuffer* out_secret,
    EppError* out_error);

EPP_API void epp_buffer_release(EppBuffer* buffer);

EPP_API EppBuffer* epp_buffer_alloc(size_t capacity);

EPP_API void epp_buffer_free(EppBuffer* buffer);
EPP_API void epp_error_free(EppError* error);
EPP_API const char* epp_error_string(EppErrorCode code);

EPP_API EppErrorCode epp_secure_wipe(
    uint8_t* data,
    size_t length);

#ifdef __cplusplus
}
#endif
