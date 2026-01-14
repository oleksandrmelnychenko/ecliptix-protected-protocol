# EPP C API Reference

C-compatible API for the Ecliptix Protection Protocol library. This API provides stable ABI for FFI bindings (.NET, Swift, Kotlin, etc.).

## Table of Contents

- [Initialization](#initialization)
- [Identity Keys](#identity-keys)
- [Session Management (Client)](#session-management-client)
- [Server Management](#server-management)
- [Shamir Secret Sharing](#shamir-secret-sharing)
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
Get the Kyber-768 (ML-KEM-768) public key (1184 bytes).

### `epp_identity_destroy`
```c
void epp_identity_destroy(EppIdentityHandle* handle);
```
Destroy identity keys and securely wipe memory.

---

## Session Management (Client)

Client-side protocol session for initiating connections.

### `epp_session_create`
```c
EppErrorCode epp_session_create(
    EppIdentityHandle* identity_keys,
    ProtocolSystemHandle** out_handle,
    EppError* out_error);
```
Create a new client session.

### `epp_session_begin_handshake`
```c
EppErrorCode epp_session_begin_handshake(
    ProtocolSystemHandle* handle,
    uint32_t connection_id,
    uint8_t exchange_type,
    const uint8_t* peer_kyber_public_key,  // Required, 1184 bytes
    size_t peer_kyber_public_key_length,
    EppBuffer* out_handshake_message,
    EppError* out_error);
```
Begin a handshake with the peer's Kyber public key. **Kyber is mandatory** for post-quantum security.

### `epp_session_complete_handshake`
```c
EppErrorCode epp_session_complete_handshake(
    ProtocolSystemHandle* handle,
    const uint8_t* peer_handshake_message,
    size_t peer_handshake_message_length,
    const uint8_t* root_key,
    size_t root_key_length,
    EppError* out_error);
```
Complete handshake with an explicit root key.

### `epp_session_complete_handshake_auto`
```c
EppErrorCode epp_session_complete_handshake_auto(
    ProtocolSystemHandle* handle,
    const uint8_t* peer_handshake_message,
    size_t peer_handshake_message_length,
    EppError* out_error);
```
Complete handshake by auto-deriving the root key from the peer's handshake message (hybrid X3DH/PQ).

### `epp_session_encrypt`
```c
EppErrorCode epp_session_encrypt(
    const ProtocolSystemHandle* handle,
    const uint8_t* plaintext,
    size_t plaintext_length,
    EppBuffer* out_encrypted_envelope,
    EppError* out_error);
```
Encrypt a message using the Double Ratchet.

### `epp_session_decrypt`
```c
EppErrorCode epp_session_decrypt(
    const ProtocolSystemHandle* handle,
    const uint8_t* encrypted_envelope,
    size_t encrypted_envelope_length,
    EppBuffer* out_plaintext,
    EppError* out_error);
```
Decrypt a message using the Double Ratchet.

### `epp_session_serialize` / `epp_session_deserialize`
Export/import session state for persistence.

### `epp_session_destroy`
```c
void epp_session_destroy(const ProtocolSystemHandle* handle);
```
Destroy the session and securely wipe memory.

---

## Server Management

Server-side protocol session for responding to connections.

### `epp_server_create`
```c
EppErrorCode epp_server_create(
    EppIdentityHandle* identity_keys,
    ProtocolSystemHandle** out_handle,
    EppError* out_error);
```
Create a new server session.

### `epp_server_begin_handshake`
```c
EppErrorCode epp_server_begin_handshake(
    ProtocolSystemHandle* handle,
    uint32_t connection_id,
    uint8_t exchange_type,
    const uint8_t* peer_kyber_public_key,  // Required, 1184 bytes
    size_t peer_kyber_public_key_length,
    EppBuffer* out_handshake_message,
    EppError* out_error);
```
Begin a server handshake with the client's Kyber public key. **Kyber is mandatory**.

### `epp_server_encrypt` / `epp_server_decrypt`
Same as client-side encryption/decryption.

### `epp_server_serialize` / `epp_server_deserialize`
Export/import server state for persistence.

### `epp_server_destroy`
```c
void epp_server_destroy(const ProtocolSystemHandle* handle);
```
Destroy the server session.

---

## Shamir Secret Sharing

Split secrets into multiple shares where a threshold number is required to reconstruct. Uses GF(256) field arithmetic with v1 share format.

### `epp_shamir_split`

Split a secret into shares.

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

| Parameter | Type | Description |
|-----------|------|-------------|
| `secret` | `const uint8_t*` | Secret to split |
| `secret_length` | `size_t` | Length of secret (1 to 1MB) |
| `threshold` | `uint8_t` | Minimum shares to reconstruct (2-255) |
| `share_count` | `uint8_t` | Total shares to generate (threshold to 255) |
| `auth_key` | `const uint8_t*` | **Optional** 32-byte HMAC key for tamper detection, or `NULL` |
| `auth_key_length` | `size_t` | Length of auth_key (0 or 32) |
| `out_shares` | `EppBuffer*` | Output: concatenated shares |
| `out_share_length` | `size_t*` | Output: length of each share |
| `out_error` | `EppError*` | Output: error details |

### `epp_shamir_reconstruct`

Reconstruct a secret from shares.

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

| Parameter | Type | Description |
|-----------|------|-------------|
| `shares` | `const uint8_t*` | Concatenated shares |
| `shares_length` | `size_t` | Total length of shares buffer |
| `share_length` | `size_t` | Length of each individual share |
| `share_count` | `size_t` | Number of shares provided (must be >= threshold) |
| `auth_key` | `const uint8_t*` | **Optional** 32-byte HMAC key (must match split), or `NULL` |
| `auth_key_length` | `size_t` | Length of auth_key (0 or 32) |
| `out_secret` | `EppBuffer*` | Output: reconstructed secret |
| `out_error` | `EppError*` | Output: error details |

### The `auth_key` Parameter

The `auth_key` is an **optional 32-byte HMAC-SHA256 key** for tamper detection:

- **Purpose**: Detect if shares have been corrupted or maliciously modified
- **When splitting**: Each share gets an HMAC authentication tag appended (32 bytes)
- **When reconstructing**: Tags are verified before reconstruction; fails if any share is invalid
- **Size**: Exactly 32 bytes if provided, or `NULL` to skip authentication
- **Recommendation**: Always use `auth_key` for sensitive secrets

#### Example: With Authentication

```c
// Generate a 32-byte authentication key
uint8_t auth_key[32];
randombytes_buf(auth_key, 32);

uint8_t secret[] = "my sensitive data";
EppBuffer shares;
size_t share_length;
EppError error;

// Split into 5 shares, requiring 3 to reconstruct
EppErrorCode result = epp_shamir_split(
    secret, sizeof(secret) - 1,
    3,              // threshold
    5,              // share_count
    auth_key, 32,   // authentication key
    &shares,
    &share_length,
    &error);

if (result == EPP_SUCCESS) {
    // Distribute shares[0..share_length], shares[share_length..2*share_length], etc.

    // Later: reconstruct from any 3+ shares
    EppBuffer recovered;
    result = epp_shamir_reconstruct(
        shares.data, shares.length,
        share_length,
        5,              // share_count
        auth_key, 32,   // same auth key
        &recovered,
        &error);

    if (result == EPP_SUCCESS) {
        // recovered.data contains the original secret
    }

    epp_buffer_free(&recovered);
}

epp_buffer_free(&shares);
```

#### Example: Without Authentication

```c
// Split without authentication (not recommended for sensitive data)
EppErrorCode result = epp_shamir_split(
    secret, secret_len,
    3, 5,
    NULL, 0,        // no authentication
    &shares, &share_length, &error);

// Reconstruct
result = epp_shamir_reconstruct(
    shares.data, shares.length,
    share_length, 5,
    NULL, 0,        // no authentication
    &recovered, &error);
```

### Share Format (v1)

Each share has the following structure:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic bytes: `ESS1` |
| 4 | 1 | Share index (1-255) |
| 5 | 1 | Threshold |
| 6 | 1 | Share count |
| 7 | 1 | Flags (0x01 = has auth) |
| 8 | 4 | Secret length (little-endian) |
| 12 | N | Share data (same length as secret) |
| 12+N | 32 | Auth tag (if FLAG_HAS_AUTH) |

---

## Utilities

### `epp_envelope_validate`
```c
EppErrorCode epp_envelope_validate(
    const uint8_t* encrypted_envelope,
    size_t encrypted_envelope_length,
    EppError* out_error);
```
Validate that an envelope meets hybrid (PQ) requirements.

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
Derive a root key from an OPAQUE session key.

### `epp_session_age_seconds`
```c
EppErrorCode epp_session_age_seconds(
    const ProtocolSystemHandle* handle,
    uint64_t* out_age_seconds,
    EppError* out_error);
```
Get session age in seconds since creation.

---

## Memory Management

### `epp_buffer_alloc`
```c
EppBuffer* epp_buffer_alloc(size_t capacity);
```
Allocate a buffer with the specified capacity.

### `epp_buffer_free`
```c
void epp_buffer_free(EppBuffer* buffer);
```
Free an allocated buffer.

### `epp_error_free`
```c
void epp_error_free(EppError* error);
```
Free an error structure.

### `epp_error_string`
```c
const char* epp_error_string(EppErrorCode code);
```
Convert an error code to a human-readable string.

---

## Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | `EPP_SUCCESS` | Operation succeeded |
| 1 | `EPP_ERROR_GENERIC` | Generic error |
| 2 | `EPP_ERROR_INVALID_INPUT` | Invalid input parameter |
| 3 | `EPP_ERROR_KEY_GENERATION` | Key generation failed |
| 4 | `EPP_ERROR_DERIVE_KEY` | Key derivation failed |
| 5 | `EPP_ERROR_HANDSHAKE` | Handshake failed |
| 6 | `EPP_ERROR_ENCRYPTION` | Encryption failed |
| 7 | `EPP_ERROR_DECRYPTION` | Decryption failed |
| 8 | `EPP_ERROR_DECODE` | Decoding failed |
| 9 | `EPP_ERROR_ENCODE` | Encoding failed |
| 10 | `EPP_ERROR_BUFFER_TOO_SMALL` | Buffer too small |
| 11 | `EPP_ERROR_OBJECT_DISPOSED` | Object already disposed |
| 12 | `EPP_ERROR_PREPARE_LOCAL` | Local preparation failed |
| 13 | `EPP_ERROR_OUT_OF_MEMORY` | Out of memory |
| 14 | `EPP_ERROR_SODIUM_FAILURE` | libsodium operation failed |
| 15 | `EPP_ERROR_NULL_POINTER` | Null pointer passed |
| 16 | `EPP_ERROR_INVALID_STATE` | Invalid state |
| 17 | `EPP_ERROR_REPLAY_ATTACK` | Replay attack detected |
| 18 | `EPP_ERROR_SESSION_EXPIRED` | Session expired |
| 19 | `EPP_ERROR_PQ_MISSING` | Post-quantum material missing |
