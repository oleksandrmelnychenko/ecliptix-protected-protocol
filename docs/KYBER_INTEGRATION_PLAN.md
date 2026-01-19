# Kyber-768 Integration Plan

## Overview

Kyber is mandatory in the current Session-based protocol. Hybrid secrets are derived from
X25519 + Kyber during the handshake and every DH ratchet rotation.

## Current Session Architecture

- Handshake: `include/ecliptix/protocol/handshake.hpp`, `src/protocol/handshake.cpp`,
  `proto/protocol/handshake.proto`
- Session: `include/ecliptix/protocol/session.hpp`, `src/protocol/session.cpp`
- State: `proto/protocol/state.proto`
- Envelope: `proto/protocol/envelope.proto`

## Integration Points (Session-based)

1. Handshake (implemented)
   - `PreKeyBundle` requires `kyber_public`.
   - `HandshakeInit` carries `kyber_ciphertext` and `initiator_kyber_public`.
   - The handshake derives a hybrid shared secret from X25519 + Kyber.

2. Session initialization (implemented)
   - `Session::FromHandshakeState` receives the hybrid material.
   - `Session::InitializeFromHandshake` derives root and chain keys from the hybrid secret.

3. Ratchet rotation (implemented)
   - When a DH ratchet occurs, `SecureEnvelope` includes `dh_public_key` and
     `kyber_ciphertext` together.
   - The receiver decapsulates the ciphertext to derive the same hybrid secret.

4. State persistence (implemented)
   - `ProtocolState` stores `kyber_local` and `kyber_remote_public`.
   - `state_hmac` authenticates all state bytes, including Kyber fields.

5. Validation (implemented)
   - Missing or wrong-sized Kyber material is rejected during handshake and
     envelope processing.

## Tests

- `tests/unit/test_kyber_interop_comprehensive.cpp`
- `tests/unit/test_session_state_hmac.cpp`
- `tests/unit/test_session_chain_length.cpp`

## Open Items

- None. Kyber is required for all sessions.
