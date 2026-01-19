# EPP C API Reference

C-compatible API for the Ecliptix Protection Protocol library. This API provides a stable ABI for FFI bindings (Swift, Kotlin, C#, etc.).

## Table of Contents

- [Initialization](#initialization)
- [Identity Keys](#identity-keys)
- [Handshake + Session](#handshake--session)
- [Utilities](#utilities)
- [Memory Management](#memory-management)
- [Error Codes](#error-codes)

---

## Initialization

### `epp_version`
```c
const char* epp_version(void);
```
Returns the library version string.

### `epp_init`
```c
EppErrorCode epp_init(void);
```
Initialize the library. Must be called before any other functions.

### `epp_shutdown`
```c
void epp_shutdown(void);
```
Shutdown the library and release global resources.

---

## Identity Keys

Identity keys contain Ed25519 (signing), X25519 (key exchange), and Kyber-768 (post-quantum) key pairs.

### `epp_identity_create`
```c
EppErrorCode epp_identity_create(
    EppIdentityHandle** out_handle,
    EppError* out_error);
```
Create new random identity keys.

### `epp_identity_create_from_seed`
```c
EppErrorCode epp_identity_create_from_seed(
    const uint8_t* seed,
    size_t seed_length,
    EppIdentityHandle** out_handle,
    EppError* out_error);
```
Create identity keys deterministically from a seed.

### `epp_identity_create_with_context`
```c
EppErrorCode epp_identity_create_with_context(
    const uint8_t* seed,
    size_t seed_length,
    const char* membership_id,
    size_t membership_id_length,
    EppIdentityHandle** out_handle,
    EppError* out_error);
```
Create identity keys with membership context for domain separation.

### `epp_identity_get_x25519_public`
```c
EppErrorCode epp_identity_get_x25519_public(
    const EppIdentityHandle* handle,
    uint8_t* out_key,
    size_t out_key_length,  // Must be 32
    EppError* out_error);
```
Get the X25519 public key (32 bytes).

### `epp_identity_get_ed25519_public`
```c
EppErrorCode epp_identity_get_ed25519_public(
    const EppIdentityHandle* handle,
    uint8_t* out_key,
    size_t out_key_length,  // Must be 32
    EppError* out_error);
```
Get the Ed25519 public key (32 bytes).

### `epp_identity_get_kyber_public`
```c
EppErrorCode epp_identity_get_kyber_public(
    const EppIdentityHandle* handle,
    uint8_t* out_key,
    size_t out_key_length,  // Must be 1184
    EppError* out_error);
```
Get the Kyber-768 (ML-KEM-768) public key (1184 bytes). Kyber is mandatory.

### `epp_identity_destroy`
```c
void epp_identity_destroy(EppIdentityHandle* handle);
```
Destroy identity keys and securely wipe memory.

---

## Handshake + Session

Handshake uses serialized `PreKeyBundle` and `HandshakeInit`/`HandshakeAck` protobufs. Sessions encrypt and decrypt `SecureEnvelope` protobufs.

### `EppSessionConfig`
```c
typedef struct EppSessionConfig {
    uint32_t max_messages_per_chain;
} EppSessionConfig;
```
Per-session configuration. `max_messages_per_chain` must be greater than zero and not exceed 10000.
Both initiator and responder must use the same value or the handshake will fail.

### `epp_prekey_bundle_create`
```c
EppErrorCode epp_prekey_bundle_create(
    const EppIdentityHandle* identity_keys,
    EppBuffer* out_bundle,
    EppError* out_error);
```
Create a serialized `PreKeyBundle` for publishing.

### `epp_handshake_initiator_start`
```c
EppErrorCode epp_handshake_initiator_start(
    EppIdentityHandle* identity_keys,
    const uint8_t* peer_prekey_bundle,
    size_t peer_prekey_bundle_length,
    const EppSessionConfig* config,
    EppHandshakeInitiatorHandle** out_handle,
    EppBuffer* out_handshake_init,
    EppError* out_error);
```
Start the initiator handshake and return `HandshakeInit` bytes.

### `epp_handshake_initiator_finish`
```c
EppErrorCode epp_handshake_initiator_finish(
    EppHandshakeInitiatorHandle* handle,
    const uint8_t* handshake_ack,
    size_t handshake_ack_length,
    EppSessionHandle** out_session,
    EppError* out_error);
```
Finish the initiator handshake using `HandshakeAck` bytes.

### `epp_handshake_initiator_destroy`
```c
void epp_handshake_initiator_destroy(EppHandshakeInitiatorHandle* handle);
```
Destroy the initiator handshake handle.

### `epp_handshake_responder_start`
```c
EppErrorCode epp_handshake_responder_start(
    EppIdentityHandle* identity_keys,
    const uint8_t* local_prekey_bundle,
    size_t local_prekey_bundle_length,
    const uint8_t* handshake_init,
    size_t handshake_init_length,
    const EppSessionConfig* config,
    EppHandshakeResponderHandle** out_handle,
    EppBuffer* out_handshake_ack,
    EppError* out_error);
```
Process `HandshakeInit` and return `HandshakeAck` bytes.

### `epp_handshake_responder_finish`
```c
EppErrorCode epp_handshake_responder_finish(
    EppHandshakeResponderHandle* handle,
    EppSessionHandle** out_session,
    EppError* out_error);
```
Finish the responder handshake after the ack is sent.

### `epp_handshake_responder_destroy`
```c
void epp_handshake_responder_destroy(EppHandshakeResponderHandle* handle);
```
Destroy the responder handshake handle.

### `epp_session_encrypt`
```c
EppErrorCode epp_session_encrypt(
    EppSessionHandle* handle,
    const uint8_t* plaintext,
    size_t plaintext_length,
    EppEnvelopeType envelope_type,
    uint32_t envelope_id,
    const char* correlation_id,
    size_t correlation_id_length,
    EppBuffer* out_encrypted_envelope,
    EppError* out_error);
```
Encrypt a message into `SecureEnvelope` bytes.

### `epp_session_decrypt`
```c
EppErrorCode epp_session_decrypt(
    EppSessionHandle* handle,
    const uint8_t* encrypted_envelope,
    size_t encrypted_envelope_length,
    EppBuffer* out_plaintext,
    EppBuffer* out_metadata,
    EppError* out_error);
```
Decrypt a `SecureEnvelope` and return plaintext plus metadata bytes.

### `epp_session_serialize`
```c
EppErrorCode epp_session_serialize(
    EppSessionHandle* handle,
    EppBuffer* out_state,
    EppError* out_error);
```
Serialize session state as `ProtocolState` protobuf bytes. Export increments
`state_counter` and embeds a `state_hmac` (HMAC-SHA256) for integrity;
deserialize rejects missing or invalid MACs.

### `epp_session_deserialize`
```c
EppErrorCode epp_session_deserialize(
    const uint8_t* state_bytes,
    size_t state_bytes_length,
    EppSessionHandle** out_handle,
    EppError* out_error);
```
Restore a session from serialized `ProtocolState` bytes.

### `epp_session_destroy`
```c
void epp_session_destroy(EppSessionHandle* handle);
```
Destroy a session and securely wipe memory.

---

## Utilities

### `epp_envelope_validate`
```c
EppErrorCode epp_envelope_validate(
    const uint8_t* encrypted_envelope,
    size_t encrypted_envelope_length,
    EppError* out_error);
```
Validate a `SecureEnvelope` (version checks, nonce and ciphertext sizes, hybrid ratchet
consistency, DH/Kyber validation, and non-zero ratchet epochs for headers).

### `epp_derive_root_key`
```c
EppErrorCode epp_derive_root_key(
    const uint8_t* opaque_session_key,
    size_t opaque_session_key_length,
    const uint8_t* user_context,
    size_t user_context_length,
    uint8_t* out_root_key,
    size_t out_root_key_length,
    EppError* out_error);
```
Derive a root key from an opaque session key + user context.

### `epp_shamir_split`
```c
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
```
Split a secret into Shamir shares.

### `epp_shamir_reconstruct`
```c
EppErrorCode epp_shamir_reconstruct(
    const uint8_t* shares,
    size_t shares_length,
    size_t share_length,
    size_t share_count,
    const uint8_t* auth_key,
    size_t auth_key_length,
    EppBuffer* out_secret,
    EppError* out_error);
```
Reconstruct a secret from Shamir shares.

### `epp_secure_wipe`
```c
EppErrorCode epp_secure_wipe(
    uint8_t* data,
    size_t length);
```
Securely wipe a buffer in place.

---

## Memory Management

### `epp_buffer_release`
```c
void epp_buffer_release(EppBuffer* buffer);
```
Release data for caller-provided buffers (e.g., outputs from API calls).

### `epp_buffer_alloc`
```c
EppBuffer* epp_buffer_alloc(size_t capacity);
```
Allocate a heap-owned buffer structure plus capacity.

### `epp_buffer_free`
```c
void epp_buffer_free(EppBuffer* buffer);
```
Free a buffer allocated by `epp_buffer_alloc`.

### `epp_error_free`
```c
void epp_error_free(EppError* error);
```
Free the error message buffer returned by the API.

### `epp_error_string`
```c
const char* epp_error_string(EppErrorCode code);
```
Return a static string for an error code.

---

## Error Codes

```c
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
```
