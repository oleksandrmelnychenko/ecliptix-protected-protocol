# Hybrid Post-Quantum DH Ratchet Implementation

## Overview

This document specifies the exact cryptographic construction for integrating Kyber-768 into the existing X25519-based DH ratchet to create a hybrid post-quantum ratchet.

## Cryptographic Construction

### Classical DH Ratchet (Current)

```
Input:  dh_secret (32 bytes from X25519), root_key (32 bytes)
Output: new_root_key (32 bytes), new_chain_key (32 bytes)

hkdf_output ← HKDF-SHA256(
    ikm = dh_secret,
    salt = root_key,
    info = "ECLIPTIX_DH_RATCHET",
    length = 64
)

new_root_key  ← hkdf_output[0:32]
new_chain_key ← hkdf_output[32:64]
```

### Hybrid PQ DH Ratchet (New)

```
Input:  x25519_secret (32 bytes), kyber_secret (32 bytes), root_key (32 bytes)
Output: new_root_key (32 bytes), new_chain_key (32 bytes)

// Step 1: Concatenate both shared secrets
hybrid_secret ← x25519_secret || kyber_secret  // 64 bytes total

// Step 2: Derive keys using combined secret as IKM
hkdf_output ← HKDF-SHA256(
    ikm = hybrid_secret,
    salt = root_key,
    info = "ECLIPTIX_HYBRID_DH_RATCHET",  // Different info string for domain separation
    length = 64
)

new_root_key  ← hkdf_output[0:32]
new_chain_key ← hkdf_output[32:64]

// Secure wipe hybrid_secret immediately after use
```

**Security Property**: This construction provides the OR assumption - the ratchet remains secure if **either** X25519 or Kyber-768 is unbroken. If quantum computers break X25519, Kyber-768 keeps it secure. If Kyber-768 has a classical weakness, X25519 keeps it secure.

## Implementation Changes

### 1. PerformDhRatchet() Function Modifications

#### Current Signature
```cpp
Result<Unit, EcliptixProtocolFailure>
PerformDhRatchet(bool is_sender, std::span<const uint8_t> received_dh_public_key);
```

#### Implementation Strategy

**No signature change needed** - The function already has access to PQ keys via class members:
- `peer_pq_dh_public_key_` (stored in `PerformReceivingRatchet()` and `FinalizeChainAndDhKeys()`)
- `sending_step_` and `receiving_step_` have PQ key handles via `GetPqDhPrivateKeyHandle()`

**Hybrid Mode Detection**:
```cpp
bool is_hybrid_mode = (peer_pq_dh_public_key_.has_value() &&
                        !peer_pq_dh_public_key_->empty());
```

### 2. Sender Ratchet Flow (is_sender == true)

#### Classical-Only Mode (Existing)
1. Generate new X25519 keypair
2. Compute X25519 DH: `dh_secret = X25519(new_sk, peer_pk)`
3. Derive: `HKDF(dh_secret, root_key, "ECLIPTIX_DH_RATCHET")`
4. Update sending step with new X25519 keys

#### Hybrid Mode (New)
1. Generate new X25519 keypair
2. Generate new Kyber-768 keypair
3. Encapsulate: `(ct, kyber_ss) = Kyber768.Encap(peer_pq_pk)`
4. Compute X25519 DH: `x25519_ss = X25519(new_x25519_sk, peer_x25519_pk)`
5. Combine: `hybrid_secret = x25519_ss || kyber_ss` (64 bytes)
6. Derive: `HKDF(hybrid_secret, root_key, "ECLIPTIX_HYBRID_DH_RATCHET")`
7. Update sending step with both X25519 and Kyber-768 keys
8. **Store `ct` (Kyber ciphertext, 1088 bytes) to send with next message**

**Note**: The Kyber ciphertext must be transmitted to the peer so they can decapsulate and derive the same shared secret.

### 3. Receiver Ratchet Flow (is_sender == false)

#### Classical-Only Mode (Existing)
1. Use existing receiving X25519 private key
2. Compute X25519 DH: `dh_secret = X25519(our_sk, received_pk)`
3. Derive: `HKDF(dh_secret, root_key, "ECLIPTIX_DH_RATCHET")`
4. Update peer DH public key

#### Hybrid Mode (New)
1. Use existing receiving X25519 private key
2. Use existing receiving Kyber-768 private key
3. Compute X25519 DH: `x25519_ss = X25519(our_x25519_sk, received_x25519_pk)`
4. Decapsulate: `kyber_ss = Kyber768.Decap(received_ct, our_kyber_sk)`
5. Combine: `hybrid_secret = x25519_ss || kyber_ss` (64 bytes)
6. Derive: `HKDF(hybrid_secret, root_key, "ECLIPTIX_HYBRID_DH_RATCHET")`
7. Update peer X25519 and Kyber-768 public keys
8. Generate new Kyber-768 keypair for next receiving ratchet

**Note**: The receiver needs the Kyber ciphertext from the message header to decapsulate.

### Wire Format and Validation

- `SecureEnvelope` now carries `kyber_ciphertext` (1088 bytes). Any envelope that includes a DH public key **must** include this ciphertext; missing CTs are rejected as `ECLIPTIX_ERROR_PQ_MISSING` at the C API boundary and as decode errors in the core receive path.
- Sender path publishes the current Kyber CT whenever a DH ratchet is included. Receiver path decapsulates before deriving the hybrid secret.
- C API prefilter `ecliptix_envelope_validate_hybrid_requirements` performs early validation (parsing + Kyber size check) for untrusted queues.
- Persisted state stores Kyber SK sealed with AES-GCM and MACs all Kyber artifacts; tampering or absent PQ material causes deserialization failure.

### 4. Code Structure

```cpp
Result<Unit, EcliptixProtocolFailure>
EcliptixProtocolConnection::PerformDhRatchet(
    bool is_sender,
    std::span<const uint8_t> received_dh_public_key) {

    // Detect hybrid mode
    bool is_hybrid_mode = (peer_pq_dh_public_key_.has_value() &&
                            !peer_pq_dh_public_key_->empty());

    if (is_hybrid_mode) {
        // HYBRID MODE PATH
        std::vector<uint8_t> x25519_secret;
        std::vector<uint8_t> kyber_secret;
        std::vector<uint8_t> kyber_ciphertext;  // For sender only
        std::vector<uint8_t> new_kyber_public;
        std::vector<uint8_t> new_kyber_private;

        if (is_sender) {
            // 1. Generate X25519 keypair (existing code)
            // 2. Compute X25519 DH (existing code)
            // 3. Generate Kyber-768 keypair
            // 4. Encapsulate with peer's Kyber PK
            // 5. Combine secrets
        } else {
            // 1. Use existing X25519 SK (existing code)
            // 2. Compute X25519 DH (existing code)
            // 3. Get Kyber ciphertext from somewhere (TBD - message header)
            // 4. Decapsulate with our Kyber SK
            // 5. Combine secrets
            // 6. Generate new Kyber keypair for next ratchet
        }

        // Combine both secrets
        std::vector<uint8_t> hybrid_secret;
        hybrid_secret.reserve(64);
        hybrid_secret.insert(hybrid_secret.end(), x25519_secret.begin(), x25519_secret.end());
        hybrid_secret.insert(hybrid_secret.end(), kyber_secret.begin(), kyber_secret.end());

        // Derive with hybrid info string
        auto hkdf_result = Hkdf::DeriveKeyBytes(
            hybrid_secret,
            64,  // output length
            root_bytes,
            std::vector<uint8_t>(ProtocolConstants::HYBRID_DH_RATCHET_INFO.begin(),
                                 ProtocolConstants::HYBRID_DH_RATCHET_INFO.end()));

        // Wipe hybrid_secret immediately
        SodiumInterop::SecureWipe(std::span(hybrid_secret));

        // Rest of key derivation logic (existing)

        // Update chain step with BOTH X25519 and Kyber keys
        if (is_sender) {
            sending_step_.UpdateKeysAfterDhRatchet(
                new_chain_key,
                new_dh_private,
                new_dh_public,
                new_kyber_private,  // NEW
                new_kyber_public);  // NEW
        } else {
            receiving_step_->UpdateKeysAfterDhRatchet(
                new_chain_key,
                std::nullopt,  // No new X25519 keys for receiver
                std::nullopt,
                new_kyber_private,  // NEW
                new_kyber_public);  // NEW
        }

    } else {
        // CLASSICAL MODE PATH (existing code unchanged)
    }
}
```

### 5. Missing Piece: Kyber Ciphertext Transmission

**Problem**: The receiver needs the Kyber ciphertext to decapsulate, but it's not currently included in the message envelope or protocol.

**Solution Options**:

**Option A: Store in class member (temporary)**
```cpp
// Add to EcliptixProtocolConnection:
std::optional<std::vector<uint8_t>> pending_kyber_ciphertext_;

// After encapsulation in sender ratchet:
pending_kyber_ciphertext_ = kyber_ciphertext;

// In PrepareNextSendMessage(), include it in RatchetChainKey or return it separately
```

**Option B: Extend RatchetChainKey model**
```cpp
// In include/ecliptix/models/keys/ratchet_chain_key.hpp
struct RatchetChainKey {
    // ... existing fields ...
    std::optional<std::vector<uint8_t>> kyber_ciphertext;  // NEW: 1088 bytes
};
```

**Option C: Extend message envelope protobuf** (proper solution, requires protobuf changes)
```protobuf
message MessageEnvelope {
    // ... existing fields ...
    optional bytes kyber_ciphertext = 10;  // 1088 bytes for Kyber-768
}
```

**Recommendation**: Start with **Option A** (class member) as it requires minimal changes and allows testing the hybrid ratchet logic. Later migrate to **Option C** for production.

### 6. Required Constants

Add to `include/ecliptix/core/protocol_constants.hpp`:

```cpp
// Post-quantum ratchet info string for HKDF domain separation
inline constexpr std::string_view HYBRID_DH_RATCHET_INFO = "ECLIPTIX_HYBRID_DH_RATCHET";
```

## Testing Strategy

### Unit Tests
1. **Hybrid encapsulation/decapsulation**: Verify Kyber-768 shared secrets match
2. **Hybrid secret combination**: Test X25519 || Kyber concatenation
3. **HKDF derivation**: Verify hybrid HKDF matches expected output
4. **Sender ratchet**: Generate keys, encapsulate, derive
5. **Receiver ratchet**: Decapsulate, derive, verify match
6. **Bidirectional**: Full Alice→Bob→Alice hybrid ratchet sequence

### Integration Tests
1. **Classical-only mode**: Verify existing tests still pass (no PQ keys)
2. **Hybrid mode**: Full message flow with PQ keys
3. **Mixed mode**: One peer sends PQ, other doesn't (graceful degradation)
4. **Performance**: Measure overhead of Kyber operations

## Implementation Phases

### Phase 1: Core Hybrid Logic (This Sprint)
- [ ] Add `HYBRID_DH_RATCHET_INFO` constant
- [ ] Add `pending_kyber_ciphertext_` member to Connection
- [ ] Implement hybrid secret combination in `PerformDhRatchet()`
- [ ] Add Kyber encap/decap calls
- [ ] Update chain step with PQ keys
- [ ] Write unit tests for hybrid ratchet

### Phase 2: Message Transmission (Next Sprint)
- [ ] Extend RatchetChainKey to include Kyber ciphertext
- [ ] Update PrepareNextSendMessage() to return ciphertext
- [ ] Update ProcessReceivedMessage() to accept ciphertext
- [ ] Extend protobuf MessageEnvelope with optional Kyber CT field

### Phase 3: End-to-End Integration (Future)
- [ ] Update C# interop layer
- [ ] Update desktop client
- [ ] Performance profiling and optimization
- [ ] Security audit

## Security Considerations

1. **Domain Separation**: Use different HKDF info strings ("ECLIPTIX_DH_RATCHET" vs "ECLIPTIX_HYBRID_DH_RATCHET") to prevent cross-protocol attacks

2. **Secure Wiping**: Wipe `hybrid_secret` (64 bytes) immediately after HKDF derivation

3. **Ciphertext Validation**: Validate Kyber ciphertext is exactly 1088 bytes before decapsulation

4. **Fallback Security**: If Kyber operations fail, the protocol should NOT fall back to classical-only mode silently - this would downgrade security

5. **Forward Secrecy**: Each Kyber keypair is ephemeral (one per ratchet) for PQ forward secrecy

6. **Break-in Recovery**: After a compromise, both X25519 and Kyber-768 ratchet to fresh keys, providing quantum break-in recovery

## References

- NIST FIPS 203 (ML-KEM / Kyber specification)
- Signal Protocol Double Ratchet specification
- "Hybrid Post-Quantum Key Exchange" (IETF draft-ietf-tls-hybrid-design)
- liboqs v0.15.0 API documentation

---

**Document Version**: 1.0
**Last Updated**: 2025-12-11
**Author**: Claude Code + Oleksandr Melnychenko
