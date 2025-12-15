# Kyber-768 Integration Plan

## Overview

This document details how Kyber-768 post-quantum cryptography will be integrated into the existing Ecliptix Protocol System without breaking backward compatibility.

## Current Architecture (Classical)

### Key Components

1. **EcliptixProtocolConnection** (line 50-52 in ecliptix_protocol_connection.hpp):
   - `FinalizeChainAndDhKeys()` - Establishes initial session keys
   - Uses X25519 DH for root key derivation

2. **EcliptixProtocolChainStep** (line 47-50 in ecliptix_protocol_chain_step.hpp):
   - `UpdateKeysAfterDhRatchet()` - Performs DH ratchet steps
   - Uses X25519 DH for chain key updates

3. **DH Key Material**:
   - `dh_private_key_handle_` - X25519 secret key (32 bytes, SecureMemoryHandle)
   - `dh_public_key_` - X25519 public key (32 bytes, std::vector)

### Current DH Ratchet Flow

```
1. Sender generates X25519 keypair
2. Sender computes: x25519_ss = DH(sender_sk, receiver_pk)
3. Sender derives: (new_root_key, new_chain_key) = HKDF(x25519_ss || current_root_key)
4. Sender sends message with new X25519 public key
5. Receiver performs same computation
```

## Post-Quantum Hybrid Architecture

### Integration Points

#### 1. Add PQ Key Material to Chain Step

**File**: `include/ecliptix/protocol/chain_step/ecliptix_protocol_chain_step.hpp`

Add optional Kyber-768 keys alongside existing X25519 keys:

```cpp
class EcliptixProtocolChainStep {
private:
    // EXISTING (Classical)
    std::optional<SecureMemoryHandle> dh_private_key_handle_;      // X25519 SK (32B)
    std::optional<std::vector<uint8_t>> dh_public_key_;            // X25519 PK (32B)

    // NEW (Post-Quantum)
    std::optional<SecureMemoryHandle> pq_dh_private_key_handle_;   // Kyber-768 SK (2400B)
    std::optional<std::vector<uint8_t>> pq_dh_public_key_;         // Kyber-768 PK (1184B)
};
```

#### 2. Add PQ Key Material to Connection

**File**: `include/ecliptix/protocol/connection/ecliptix_protocol_connection.hpp`

Add optional Kyber-768 peer keys:

```cpp
class EcliptixProtocolConnection {
private:
    // EXISTING (Classical)
    std::optional<std::vector<uint8_t>> peer_dh_public_key_;       // Peer X25519 PK

    // NEW (Post-Quantum)
    std::optional<std::vector<uint8_t>> peer_pq_dh_public_key_;    // Peer Kyber-768 PK
};
```

#### 3. Extend FinalizeChainAndDhKeys() for Hybrid Setup

**File**: `src/protocol/connection/ecliptix_protocol_connection.cpp`

```cpp
Result<Unit, EcliptixProtocolFailure> EcliptixProtocolConnection::FinalizeChainAndDhKeys(
    std::span<const uint8_t> initial_root_key,
    std::span<const uint8_t> initial_peer_dh_public_key,
    std::optional<std::span<const uint8_t>> initial_peer_pq_dh_public_key  // NEW
) {
    // Validate inputs
    TRY(ValidateInitialKeys(initial_root_key, initial_peer_dh_public_key));

    // Classical X25519 DH
    auto x25519_ss = SodiumInterop::ComputeX25519SharedSecret(
        initial_sending_dh_private_handle_,
        initial_peer_dh_public_key
    ).Unwrap();

    // Post-Quantum Kyber-768 KEM (if provided)
    std::vector<uint8_t> kyber_ss;
    if (initial_peer_pq_dh_public_key.has_value() &&
        ratchet_config_.enable_pq_ratchet) {

        auto encaps_result = KyberInterop::Encapsulate(
            initial_peer_pq_dh_public_key.value()
        );
        if (encaps_result.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(encaps_result.UnwrapErr());
        }

        auto [ct, ss] = std::move(encaps_result).Unwrap();
        kyber_ss = ss;

        // Store ciphertext to send back to peer (peer will decapsulate)
        pq_kem_ciphertext_ = std::move(ct);
    }

    // Hybrid KDF: Combine X25519 ⊕ Kyber-768 via HKDF
    auto hybrid_ss = KyberInterop::CombineHybridSecrets(
        x25519_ss,
        kyber_ss,  // Empty if PQ disabled
        "ECLIPTIX_INITIAL_HANDSHAKE_V1"
    ).Unwrap();

    // Derive session keys from hybrid shared secret
    auto derived_keys = DeriveRatchetKeys(
        hybrid_ss,
        initial_root_key,
        new_root_key,
        new_chain_key
    ).Unwrap();

    // ... rest of initialization
}
```

#### 4. Extend PerformDhRatchet() for Hybrid Ratcheting

**File**: `src/protocol/connection/ecliptix_protocol_connection.cpp`

```cpp
Result<Unit, EcliptixProtocolFailure> EcliptixProtocolConnection::PerformDhRatchet(
    bool is_sender,
    std::span<const uint8_t> received_dh_public_key,
    std::optional<std::span<const uint8_t>> received_pq_dh_public_key  // NEW
) {
    // Generate new X25519 keypair
    auto x25519_kp = SodiumInterop::GenerateX25519KeyPair("ratchet").Unwrap();
    auto [x25519_sk, x25519_pk] = std::move(x25519_kp);

    // Generate new Kyber-768 keypair (if PQ enabled)
    std::optional<SecureMemoryHandle> kyber_sk;
    std::optional<std::vector<uint8_t>> kyber_pk;
    std::vector<uint8_t> kyber_ss;

    if (ratchet_config_.enable_pq_ratchet) {
        auto kyber_kp = KyberInterop::GenerateKyber768KeyPair("ratchet").Unwrap();
        kyber_sk = std::move(kyber_kp.first);
        kyber_pk = kyber_kp.second;

        // If we received peer's PQ key, encapsulate to it
        if (received_pq_dh_public_key.has_value()) {
            auto [ct, ss] = KyberInterop::Encapsulate(
                received_pq_dh_public_key.value()
            ).Unwrap();
            kyber_ss = ss;
        }
    }

    // Classical X25519 DH
    std::vector<uint8_t> peer_x25519_pk;
    if (is_sender) {
        peer_x25519_pk = peer_dh_public_key_.value();
    } else {
        peer_x25519_pk.assign(
            received_dh_public_key.begin(),
            received_dh_public_key.end()
        );
    }

    auto x25519_ss = SodiumInterop::ComputeX25519SharedSecret(
        x25519_sk,
        peer_x25519_pk
    ).Unwrap();

    // Hybrid KDF: X25519 ⊕ Kyber-768
    auto hybrid_ss = KyberInterop::CombineHybridSecrets(
        x25519_ss,
        kyber_ss,
        "ECLIPTIX_DH_RATCHET_V1"
    ).Unwrap();

    // Derive new root key and chain key
    std::vector<uint8_t> new_root_key(32);
    std::vector<uint8_t> new_chain_key(32);

    TRY(DeriveRatchetKeys(
        hybrid_ss,
        root_key_handle_.value(),
        new_root_key,
        new_chain_key
    ));

    // Update chain step with new keys (both classical and PQ)
    if (is_sender) {
        sending_step_.UpdateKeysAfterDhRatchet(
            new_chain_key,
            std::span(x25519_sk.ReadBytes().Unwrap()),
            std::span(x25519_pk),
            kyber_sk,   // NEW: optional Kyber SK
            kyber_pk    // NEW: optional Kyber PK
        );
    } else {
        receiving_step_ = EcliptixProtocolChainStep::Create(
            ChainStepType::RECEIVER,
            new_chain_key,
            std::nullopt,  // Receiver doesn't store X25519 private key
            std::span(peer_x25519_pk),
            std::nullopt,  // Receiver doesn't store Kyber private key
            received_pq_dh_public_key  // Store peer's Kyber PK
        ).Unwrap();
    }

    // Update root key
    root_key_handle_->Write(new_root_key);
    SodiumInterop::SecureWipe(new_root_key);

    return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
}
```

#### 5. Update UpdateKeysAfterDhRatchet() Signature

**File**: `include/ecliptix/protocol/chain_step/ecliptix_protocol_chain_step.hpp`

```cpp
[[nodiscard]] Result<Unit, EcliptixProtocolFailure> UpdateKeysAfterDhRatchet(
    std::span<const uint8_t> new_chain_key,
    std::optional<std::span<const uint8_t>> new_dh_private_key = std::nullopt,
    std::optional<std::span<const uint8_t>> new_dh_public_key = std::nullopt,
    std::optional<SecureMemoryHandle> new_pq_dh_private_key = std::nullopt,  // NEW
    std::optional<std::span<const uint8_t>> new_pq_dh_public_key = std::nullopt  // NEW
);
```

## Wire Format Integration

### Protobuf Changes (ALREADY DONE ✅)

The protobuf schemas already have optional PQ fields:

#### SecureEnvelope (secure_envelope.proto)
```protobuf
message SecureEnvelope {
  // ... existing fields ...
  optional bytes pq_ratchet_ciphertext = 20;   // Kyber-768 KEM ciphertext (1088 bytes)
  optional bytes pq_ratchet_public_key = 21;   // Sender's new Kyber-768 PK (1184 bytes)
}
```

#### ChainStepState (protocol_state.proto)
```protobuf
message ChainStepState {
  // ... existing fields ...
  bytes pq_dh_private_key = 20;  // Kyber-768 ephemeral SK (2400 bytes)
  bytes pq_dh_public_key = 21;   // Kyber-768 ephemeral PK (1184 bytes)
}
```

### Serialization/Deserialization

**ToProtoState()** - Serialize Kyber keys to protobuf:
```cpp
Result<proto::protocol::ChainStepState>
EcliptixProtocolChainStep::ToProtoState() const {
    auto proto = proto::protocol::ChainStepState();

    // ... existing X25519 serialization ...

    // Serialize Kyber-768 keys (if present)
    if (pq_dh_private_key_handle_.has_value()) {
        auto pq_sk_bytes = pq_dh_private_key_handle_->ReadBytes().Unwrap();
        proto.set_pq_dh_private_key(pq_sk_bytes.data(), pq_sk_bytes.size());
        SodiumInterop::SecureWipe(pq_sk_bytes);
    }

    if (pq_dh_public_key_.has_value()) {
        proto.set_pq_dh_public_key(
            pq_dh_public_key_->data(),
            pq_dh_public_key_->size()
        );
    }

    return Result<...>::Ok(proto);
}
```

**FromProtoState()** - Deserialize Kyber keys from protobuf:
```cpp
Result<EcliptixProtocolChainStep>
EcliptixProtocolChainStep::FromProtoState(
    ChainStepType step_type,
    const proto::protocol::ChainStepState& proto
) {
    // ... existing X25519 deserialization ...

    // Deserialize Kyber-768 keys (if present)
    std::optional<SecureMemoryHandle> pq_sk_handle;
    std::optional<std::vector<uint8_t>> pq_pk;

    if (proto.has_pq_dh_private_key() && !proto.pq_dh_private_key().empty()) {
        auto pq_sk_data = proto.pq_dh_private_key();
        TRY(KyberInterop::ValidateSecretKey(
            std::span(
                reinterpret_cast<const uint8_t*>(pq_sk_data.data()),
                pq_sk_data.size()
            )
        ));

        pq_sk_handle = SecureMemoryHandle::Allocate(pq_sk_data.size()).Unwrap();
        pq_sk_handle->Write(
            std::span(
                reinterpret_cast<const uint8_t*>(pq_sk_data.data()),
                pq_sk_data.size()
            )
        );
    }

    if (proto.has_pq_dh_public_key() && !proto.pq_dh_public_key().empty()) {
        auto pq_pk_data = proto.pq_dh_public_key();
        TRY(KyberInterop::ValidatePublicKey(
            std::span(
                reinterpret_cast<const uint8_t*>(pq_pk_data.data()),
                pq_pk_data.size()
            )
        ));

        pq_pk = std::vector<uint8_t>(
            pq_pk_data.begin(),
            pq_pk_data.end()
        );
    }

    return EcliptixProtocolChainStep::Create(
        step_type,
        chain_key,
        dh_sk,
        dh_pk,
        std::move(pq_sk_handle),  // NEW
        pq_pk                      // NEW
    );
}
```

## Configuration Control

### RatchetConfig Extension

**File**: `include/ecliptix/configuration/ratchet_config.hpp`

```cpp
struct RatchetConfig {
    // ... existing fields ...

    // Post-quantum ratchet controls
    bool enable_pq_ratchet = true;                       // Enable Kyber-768 in ratchet
    uint32_t pq_ratchet_every_n_messages = 100;          // Frequency of PQ ratchet
    std::chrono::milliseconds pq_max_chain_age{3600000}; // 1 hour max without PQ ratchet
};
```

### Policy Examples

```cpp
// High Security (recommended)
RatchetConfig high_security;
high_security.enable_pq_ratchet = true;
high_security.pq_ratchet_every_n_messages = 1;  // Every message direction change

// Balanced (default)
RatchetConfig balanced;
balanced.enable_pq_ratchet = true;
balanced.pq_ratchet_every_n_messages = 100;  // Every 100 messages or 1 hour

// Bandwidth-Constrained
RatchetConfig low_bandwidth;
low_bandwidth.enable_pq_ratchet = true;
low_bandwidth.pq_ratchet_every_n_messages = 500;  // Every 500 messages

// Classical Only (backward compatibility)
RatchetConfig classical_only;
classical_only.enable_pq_ratchet = false;
```

## Backward Compatibility Strategy

### Wire Protocol Compatibility

1. **Optional PQ fields** - All PQ fields in protobuf are `optional`
   - Classical clients ignore PQ fields
   - Hybrid clients fall back to classical if peer doesn't support PQ

2. **Capability Negotiation**
   ```cpp
   // Detect if peer supports PQ
   bool peer_supports_pq = peer_bundle_.pq_identity_public_key.has_value();

   // Only use PQ if both sides support it
   bool use_pq_ratchet = ratchet_config_.enable_pq_ratchet && peer_supports_pq;
   ```

3. **Graceful Degradation**
   - If PQ operations fail, log warning and continue with classical
   - Never fail message delivery due to PQ errors

### State Persistence Compatibility

- Old sessions (without PQ keys) deserialize successfully
- PQ fields are `std::optional`, so missing data = classical mode
- Sessions can upgrade from classical → hybrid on next ratchet

## Testing Strategy

### Unit Tests

1. **Kyber Integration Tests** (DONE ✅)
   - 30 tests covering all Kyber-768 operations
   - Validation, encaps/decaps, hybrid KDF

2. **Hybrid Ratchet Tests** (TODO)
   - Test classical-only ratchet (existing behavior)
   - Test hybrid ratchet (X25519 ⊕ Kyber-768)
   - Test fallback from hybrid → classical

3. **Serialization Tests** (TODO)
   - Serialize/deserialize chain step with PQ keys
   - Serialize/deserialize connection state with PQ keys
   - Backward compatibility (deserialize old states)

### Integration Tests

1. **Hybrid X3DH Handshake**
   - Alice (hybrid) ↔ Bob (hybrid): Full PQ handshake
   - Alice (hybrid) ↔ Bob (classical): Fallback to X25519
   - Alice (classical) ↔ Bob (hybrid): Fallback to X25519

2. **Hybrid Ratchet E2E**
   - 1000 messages with PQ ratchet every 100 messages
   - Measure bandwidth overhead
   - Verify forward secrecy at PQ boundaries

3. **State Rehydration**
   - Save session with PQ keys → Load → Continue messaging
   - Save classical session → Load → Upgrade to hybrid

## Performance Considerations

### Bandwidth Overhead

| Operation | Classical | Hybrid PQ | Overhead |
|-----------|-----------|-----------|----------|
| Initial Handshake | ~100 bytes | ~2.4 KB | +2.3 KB |
| DH Ratchet (per) | 32 bytes | 2,304 bytes | +2.27 KB |
| Message (no ratchet) | ~50 bytes | ~50 bytes | 0 |

**With `pq_ratchet_every_n_messages = 100`:**
- Amortized overhead per message: ~23 bytes
- Acceptable for most use cases

### Computational Overhead

| Operation | Time (M1 Pro) |
|-----------|---------------|
| Kyber-768 KeyGen | ~0.05 ms |
| Kyber-768 Encaps | ~0.06 ms |
| Kyber-768 Decaps | ~0.08 ms |
| X25519 DH | ~0.03 ms |
| HKDF (hybrid) | ~0.01 ms |
| **Total per ratchet** | **~0.2 ms** |

**Impact**: Negligible (<1% CPU for typical messaging patterns)

## Implementation Phases

### Phase 1: Core Integration (THIS SPRINT)
- [x] Install liboqs v0.15.0
- [x] Implement KyberInterop wrapper
- [x] Write 30+ unit tests for Kyber
- [x] Extend protobuf with optional PQ fields
- [ ] Add PQ key material to ChainStep
- [ ] Add PQ key material to Connection
- [ ] Extend FinalizeChainAndDhKeys() for hybrid setup
- [ ] Extend PerformDhRatchet() for hybrid ratcheting
- [ ] Write hybrid ratchet tests

### Phase 2: Wire Format & Persistence (NEXT SPRINT)
- [ ] Implement ToProtoState() with PQ serialization
- [ ] Implement FromProtoState() with PQ deserialization
- [ ] Write state persistence tests
- [ ] Test backward compatibility with old states

### Phase 3: Optimization & Adaptive Policies (FUTURE)
- [ ] Implement adaptive PQ ratchet frequency
- [ ] Add bandwidth monitoring
- [ ] Performance profiling and optimization
- [ ] Production deployment

## Security Guarantees

### Quantum Resistance
- **Initial Handshake**: Protected by Kyber-768 (NIST Level 3)
- **DH Ratchet**: Each ratchet provides fresh quantum-resistant key material
- **Forward Secrecy**: Quantum adversary cannot decrypt past messages after ratchet

### Hybrid Security (OR Assumption)
- System remains secure if **either** X25519 **or** Kyber-768 is unbroken
- No single point of cryptographic failure

### Break-in Recovery
- Compromised state + quantum computer = system heals after next PQ ratchet
- Maintains Signal Protocol's break-in recovery property against quantum adversaries

## References

- NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
- Signal Protocol Specification: https://signal.org/docs/
- NIST SP 800-56C Rev. 2: Hybrid Key Derivation
- liboqs Documentation: https://github.com/open-quantum-safe/liboqs

---

**Status**: Phase 1 in progress (60% complete)
**Last Updated**: 2025-12-11
