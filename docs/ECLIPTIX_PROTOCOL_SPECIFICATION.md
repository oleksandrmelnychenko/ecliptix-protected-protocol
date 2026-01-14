# Ecliptix Hybrid Post-Quantum Double Ratchet Protocol Specification

**Version**: 1.0
**Date**: January 2026
**Status**: Implementation Complete, Security Review Pending

---

## Part I: Introduction

### 1. Abstract

The Ecliptix Protocol is a hybrid post-quantum end-to-end encryption protocol designed for secure messaging applications. It combines the Signal Protocol's proven Double Ratchet Algorithm with NIST-standardized post-quantum cryptography (ML-KEM-768/Kyber) to provide security against both classical and quantum adversaries.

**Key Features:**
- **Hybrid Key Exchange**: X3DH extended with Kyber-768 encapsulation
- **Hybrid Ratcheting**: X25519 DH combined with Kyber-768 per ratchet epoch
- **Forward Secrecy**: Compromise of current keys cannot decrypt past messages
- **Break-in Recovery**: Fresh keys are established within N messages after compromise
- **Post-Quantum Resistance**: Security under the "OR assumption" - remains secure if either X25519 or Kyber-768 is unbroken

### 2. Introduction

#### 2.1 Motivation

Classical Diffie-Hellman based protocols, including the Signal Protocol, are vulnerable to quantum computers running Shor's algorithm. While large-scale quantum computers are not yet available, the "harvest now, decrypt later" threat motivates immediate deployment of post-quantum cryptography for long-term confidential communications.

#### 2.2 Design Goals

1. **Quantum Resistance**: Protect against future quantum adversaries
2. **Classical Security**: Maintain at least Signal Protocol security level
3. **Backward Compatibility**: Interoperate with classical-only clients during transition
4. **Performance**: Minimize additional latency and bandwidth overhead
5. **Implementation Simplicity**: Avoid complex protocol state machines

#### 2.3 Related Work

- **Signal Protocol** [Marlinspike & Perrin, 2016]: Foundation for our classical ratchet design
- **NIST FIPS 203** [2024]: ML-KEM (Kyber) standardization
- **PQXDH** [Signal, 2023]: Post-quantum X3DH variant (different construction)
- **Hybrid Key Exchange** [IETF draft]: TLS 1.3 hybrid design principles

### 3. Notation and Definitions

#### 3.1 Symbols

| Symbol | Description |
|--------|-------------|
| ‖ | Byte string concatenation |
| ← | Assignment |
| ⊕ | XOR operation |
| \|x\| | Byte length of x |
| x[i:j] | Bytes i through j-1 of x (0-indexed) |
| (a, b) ← F() | Function F returns tuple (a, b) |

#### 3.2 Cryptographic Functions

| Function | Description |
|----------|-------------|
| X25519(sk, pk) | Curve25519 scalar multiplication |
| Ed25519.Sign(sk, m) | EdDSA signature generation |
| Ed25519.Verify(pk, m, σ) | EdDSA signature verification |
| Kyber768.KeyGen() | Generate (sk, pk) keypair |
| Kyber768.Encap(pk) | Generate (ct, ss) ciphertext and shared secret |
| Kyber768.Decap(ct, sk) | Recover shared secret ss |
| HKDF(ikm, salt, info, len) | HKDF-SHA256 key derivation |
| AES-GCM-256.Enc(k, n, ad, pt) | Authenticated encryption |
| AES-GCM-256.Dec(k, n, ad, ct) | Authenticated decryption |

#### 3.3 Byte Ordering

All multi-byte integers are encoded in **little-endian** format unless otherwise specified. Public keys and cryptographic outputs use their native encoding:
- X25519/Ed25519: 32 bytes, RFC 7748/8032 encoding
- Kyber-768 public key: 1184 bytes
- Kyber-768 ciphertext: 1088 bytes
- Kyber-768 shared secret: 32 bytes

---

## Part II: Cryptographic Foundation

### 4. Cryptographic Primitives

#### 4.1 X25519 (Curve25519 ECDH)

**Reference**: RFC 7748

X25519 provides 128-bit classical security for key agreement. Given Alice's private key `a` and Bob's public key `B`:

```
shared_secret = X25519(a, B) = [a]B
```

**Properties**:
- Output: 32 bytes
- Cofactor-safe: No small subgroup attacks
- Constant-time implementation required

#### 4.2 Ed25519 (EdDSA Signatures)

**Reference**: RFC 8032

Ed25519 provides 128-bit classical security for digital signatures.

```
(sk, pk) ← Ed25519.KeyGen()
σ ← Ed25519.Sign(sk, message)
valid ← Ed25519.Verify(pk, message, σ)
```

**Properties**:
- Signature: 64 bytes
- Public key: 32 bytes
- Deterministic: Same message always produces same signature

#### 4.3 ML-KEM-768 (Kyber-768)

**Reference**: NIST FIPS 203

ML-KEM-768 is a lattice-based key encapsulation mechanism providing NIST Security Level 3 (roughly equivalent to AES-192).

```
(sk, pk) ← Kyber768.KeyGen()
(ct, ss) ← Kyber768.Encap(pk)    // Sender encapsulates
ss' ← Kyber768.Decap(ct, sk)     // Receiver decapsulates
// ss == ss' (32 bytes shared secret)
```

**Sizes**:
- Public key: 1184 bytes
- Secret key: 2400 bytes
- Ciphertext: 1088 bytes
- Shared secret: 32 bytes

#### 4.4 HKDF-SHA256

**Reference**: RFC 5869

HKDF extracts and expands keying material:

```
prk ← HKDF-Extract(salt, ikm)           // Extract
okm ← HKDF-Expand(prk, info, length)    // Expand
```

Combined single-call interface:

```
okm ← HKDF(ikm, salt, info, length)
```

#### 4.5 AES-256-GCM

**Reference**: NIST SP 800-38D

Authenticated Encryption with Associated Data (AEAD):

```
(ciphertext, tag) ← AES-GCM-256.Enc(key, nonce, ad, plaintext)
plaintext | ⊥ ← AES-GCM-256.Dec(key, nonce, ad, ciphertext, tag)
```

**Parameters**:
- Key: 32 bytes
- Nonce: 12 bytes (MUST be unique per key)
- Tag: 16 bytes

### 5. Key Classification

The protocol uses multiple key types with different lifecycles and security properties.

#### 5.1 Static Keys (Identity)

| Key | Type | Size | Lifetime | Purpose |
|-----|------|------|----------|---------|
| IK | Ed25519 | 32B | Years | Identity signing, authentication |
| IK_DH | X25519 | 32B | Years | X3DH identity component |

Static keys are generated once and stored long-term. Compromise reveals identity but not past messages (due to forward secrecy).

#### 5.2 Semi-Static Keys (Signed Pre-Keys)

| Key | Type | Size | Lifetime | Purpose |
|-----|------|------|----------|---------|
| SPK | X25519 | 32B | ~30 days | X3DH pre-key agreement |
| SPK_sig | Ed25519 sig | 64B | ~30 days | SPK authenticity |
| OPK | X25519 | 32B | Single-use | One-time forward secrecy |

Semi-static keys provide a balance between availability and forward secrecy. SPK rotation limits the window of compromise.

#### 5.3 Ephemeral Keys (Per-Session/Ratchet)

| Key | Type | Size | Lifetime | Purpose |
|-----|------|------|----------|---------|
| EK | X25519 | 32B | Single handshake | X3DH initiator ephemeral |
| DH_ratchet | X25519 | 32B | Per ratchet epoch | Asymmetric ratchet |
| KPK | Kyber768 | 1184B | Per ratchet epoch | PQ encapsulation |

Ephemeral keys are generated fresh and destroyed after use, providing forward secrecy.

#### 5.4 Immutable Session Keys

| Key | Symbol | Size | Lifetime | Purpose |
|-----|--------|------|----------|---------|
| Initial Sender DH | IPK_self | 32B | Session lifetime | Metadata key derivation |
| Initial Peer DH | IPK_peer | 32B | Session lifetime | Metadata key derivation |
| Metadata Key | MDK | 32B | Session lifetime | Envelope metadata encryption |

**Critical Property**: These keys are captured during the initial handshake and NEVER updated during subsequent DH ratchets. This ensures metadata key stability across the entire session.

#### 5.5 Mutable Session Keys

| Key | Symbol | Size | Lifetime | Purpose |
|-----|--------|------|----------|---------|
| Root Key | RK | 32B | Per DH ratchet | Key derivation chain anchor |
| Chain Key | CK | 32B | Per message | Message key derivation |
| Current Peer DH | CPK | 32B | Per DH ratchet | DH computation |

Mutable keys are updated during protocol operation to provide forward secrecy and break-in recovery.

---

## Part III: Protocol Specification

### 6. X3DH Key Agreement

#### 6.1 Pre-Key Bundle Publication

Bob (responder) publishes to the server:

```
PublicKeyBundle {
    identity_public_key: IK_B           // Ed25519, 32 bytes
    identity_x25519_public_key: IK_DH_B // X25519, 32 bytes
    signed_pre_key_id: uint32
    signed_pre_key_public: SPK_B        // X25519, 32 bytes
    signed_pre_key_signature: σ_SPK     // Ed25519 signature of SPK_B
    one_time_pre_keys: [OPK_B_1, ...]   // X25519 keys, optional
    kyber_public_key: KPK_B             // Kyber768, 1184 bytes
}
```

#### 6.2 Initiator Computation (Alice)

Alice fetches Bob's bundle and computes:

```
Algorithm: X3DH_Initiator
Input:
  - Alice's identity keys: (IK_A, IK_DH_A)
  - Bob's bundle: (IK_B, IK_DH_B, SPK_B, OPK_B, KPK_B)
Output:
  - Shared secret: SS (32 bytes)
  - Kyber ciphertext: CT (1088 bytes)
  - Kyber shared secret: KSS (32 bytes)

Procedure:
  1. (EK_sk, EK_pk) ← X25519.KeyGen()          // Generate ephemeral
  2. DH1 ← X25519(IK_DH_A_sk, SPK_B)           // IK_A × SPK_B
  3. DH2 ← X25519(EK_sk, IK_DH_B)              // EK_A × IK_B
  4. DH3 ← X25519(EK_sk, SPK_B)                // EK_A × SPK_B
  5. if OPK_B available:
       DH4 ← X25519(EK_sk, OPK_B)              // EK_A × OPK_B
     else:
       DH4 ← empty
  6. dh_concat ← DH1 ‖ DH2 ‖ DH3 ‖ DH4         // 96 or 128 bytes
  7. SS ← HKDF(dh_concat, null, "Ecliptix-X3DH-v1", 32)
  8. (CT, KSS) ← Kyber768.Encap(KPK_B)         // PQ encapsulation
  9. Wipe: EK_sk, DH1, DH2, DH3, DH4, dh_concat
  10. Return (SS, CT, KSS, EK_pk)
```

#### 6.3 Responder Computation (Bob)

Bob receives Alice's handshake message:

```
Algorithm: X3DH_Responder
Input:
  - Bob's identity keys: (IK_B, IK_DH_B, SPK_B_sk, OPK_B_sk)
  - Alice's message: (IK_A, IK_DH_A, EK_A, CT, used_OPK_id)
Output:
  - Shared secret: SS (32 bytes)
  - Kyber shared secret: KSS (32 bytes)

Procedure:
  1. DH1 ← X25519(SPK_B_sk, IK_DH_A)           // SPK_B × IK_A
  2. DH2 ← X25519(IK_DH_B_sk, EK_A)            // IK_B × EK_A
  3. DH3 ← X25519(SPK_B_sk, EK_A)              // SPK_B × EK_A
  4. if used_OPK_id present:
       DH4 ← X25519(OPK_B_sk[used_OPK_id], EK_A)
       Delete OPK_B_sk[used_OPK_id]            // One-time use
     else:
       DH4 ← empty
  5. dh_concat ← DH1 ‖ DH2 ‖ DH3 ‖ DH4
  6. SS ← HKDF(dh_concat, null, "Ecliptix-X3DH-v1", 32)
  7. KSS ← Kyber768.Decap(CT, KSK_B)           // PQ decapsulation
  8. Wipe: DH1, DH2, DH3, DH4, dh_concat
  9. Return (SS, KSS)
```

#### 6.4 Kyber Integration

The Kyber shared secret (KSS) is combined with the X3DH output to form the hybrid initial root key:

```
Algorithm: DeriveHybridRootKey
Input:
  - SS: X3DH shared secret (32 bytes)
  - KSS: Kyber shared secret (32 bytes)
Output:
  - RK_0: Initial root key (32 bytes)

Procedure:
  1. hybrid_secret ← SS ‖ KSS                  // 64 bytes
  2. RK_0 ← HKDF(hybrid_secret, null, "Ecliptix-Hybrid-Init", 32)
  3. Wipe: hybrid_secret
  4. Return RK_0
```

### 7. Double Ratchet

#### 7.1 Session Initialization

After X3DH, both parties initialize the ratchet state:

```
Algorithm: InitializeSession
Input:
  - RK_0: Initial root key (32 bytes)
  - is_initiator: boolean
  - peer_initial_dh: Peer's initial DH public key (32 bytes)
  - KSS: Kyber shared secret (32 bytes)
Output:
  - Session state initialized

Procedure (Initiator - Alice):
  1. (SK_send, PK_send) ← X25519.KeyGen()      // Initial sending DH
  2. DH_secret ← X25519(SK_send, peer_initial_dh)
  3. (RK_1, temp) ← HKDF(DH_secret, RK_0, "Ecliptix-DH-Ratchet", 64)
  4. (CK_send, CK_recv) ← HKDF(RK_1, null, "Ecliptix-Initial-Sender", 32),
                           HKDF(RK_1, null, "Ecliptix-Initial-Receiver", 32)
  5. Store immutable: IPK_self ← PK_send, IPK_peer ← peer_initial_dh
  6. Store mutable: CPK_peer ← peer_initial_dh, RK ← RK_1

Procedure (Responder - Bob):
  1. Use existing SPK as initial sending DH
  2. Same DH computation
  3. SWAP: CK_send ← Receiver material, CK_recv ← Sender material
  4. Store immutable: IPK_self ← SPK_B, IPK_peer ← EK_A
  5. Store mutable: CPK_peer ← EK_A, RK ← RK_1
```

**Critical**: The `IPK_self` and `IPK_peer` values are stored ONCE and never modified, even when `CPK_peer` is updated during DH ratchets.

#### 7.2 Symmetric Ratchet (Per-Message)

```
Algorithm: SymmetricRatchet
Input:
  - CK_n: Current chain key (32 bytes)
  - n: Message index
Output:
  - MK_n: Message key (32 bytes)
  - CK_{n+1}: Next chain key (32 bytes)

Procedure:
  1. MK_n ← HKDF(CK_n, null, "Ecliptix-Msg", 32)
  2. CK_{n+1} ← HKDF(CK_n, null, "Ecliptix-Chain", 32)
  3. Wipe: CK_n (after updating state)
  4. Return (MK_n, CK_{n+1})
```

#### 7.3 Asymmetric Ratchet (DH + Kyber Hybrid)

Triggered every N messages (default: 100) or when receiving a new DH public key:

```
Algorithm: HybridDHRatchet_Sender
Input:
  - RK: Current root key
  - CPK_peer: Current peer DH public (mutable)
  - KPK_peer: Peer Kyber public key
Output:
  - RK': New root key
  - CK': New sending chain key
  - PK_new: New sender DH public to transmit
  - CT: Kyber ciphertext to transmit

Procedure:
  1. (SK_new, PK_new) ← X25519.KeyGen()
  2. (KSK_new, KPK_new) ← Kyber768.KeyGen()
  3. DH_secret ← X25519(SK_new, CPK_peer)
  4. (CT, KSS) ← Kyber768.Encap(KPK_peer)
  5. hybrid_secret ← DH_secret ‖ KSS            // 64 bytes
  6. output ← HKDF(hybrid_secret, RK, "ECLIPTIX_HYBRID_DH_RATCHET", 64)
  7. RK' ← output[0:32]
  8. CK' ← output[32:64]
  9. Update: SK_send ← SK_new, PK_send ← PK_new
  10. Update: KSK_self ← KSK_new, KPK_self ← KPK_new
  11. Reset: sending_index ← 0
  12. Increment: sending_ratchet_epoch += 1
  13. Wipe: SK_old, hybrid_secret, DH_secret, KSS
  14. Return (RK', CK', PK_new, CT)
```

```
Algorithm: HybridDHRatchet_Receiver
Input:
  - RK: Current root key
  - PK_received: Received DH public key
  - CT_received: Received Kyber ciphertext
  - SK_self: Own DH private key
  - KSK_self: Own Kyber private key
Output:
  - RK': New root key
  - CK': New receiving chain key

Procedure:
  1. DH_secret ← X25519(SK_self, PK_received)
  2. KSS ← Kyber768.Decap(CT_received, KSK_self)
  3. hybrid_secret ← DH_secret ‖ KSS
  4. output ← HKDF(hybrid_secret, RK, "ECLIPTIX_HYBRID_DH_RATCHET", 64)
  5. RK' ← output[0:32]
  6. CK' ← output[32:64]
  7. Update: CPK_peer ← PK_received             // NOTE: IPK_peer unchanged!
  8. (KSK_new, KPK_new) ← Kyber768.KeyGen()    // For next ratchet
  9. Update: KSK_self ← KSK_new, KPK_self ← KPK_new
  10. Reset: receiving_index ← 0
  11. Increment: receiving_ratchet_epoch += 1
  12. Wipe: hybrid_secret, DH_secret, KSS, KSK_old
  13. Return (RK', CK')
```

#### 7.4 Out-of-Order Message Handling

When receiving message with index N but current receiving index is M (M < N):

```
Algorithm: SkipMessageKeys
Input:
  - CK_M: Current chain key at index M
  - N: Target message index
  - max_skip: Maximum allowed skip (default: 1000)
Output:
  - cached_keys: Map of index → message key
  - CK_N: Chain key at index N

Procedure:
  1. if (N - M) > max_skip:
       Return Error("Skip limit exceeded")
  2. cached_keys ← {}
  3. CK ← CK_M
  4. for i in [M+1, N):
       MK_i ← HKDF(CK, null, "Ecliptix-Msg", 32)
       CK ← HKDF(CK, null, "Ecliptix-Chain", 32)
       cached_keys[i] ← SecureStore(MK_i)
       Wipe: MK_i (after secure storage)
  5. Return (cached_keys, CK)
```

Cached message keys are single-use: retrieved once, then deleted.

### 8. Metadata Protection

#### 8.1 Metadata Key Derivation

The metadata encryption key is derived using **immutable** initial DH keys:

```
Algorithm: DeriveMetadataKey
Input:
  - RK: Root key (32 bytes)
  - IPK_self: Initial sender DH public (32 bytes) [IMMUTABLE]
  - IPK_peer: Initial peer DH public (32 bytes) [IMMUTABLE]
  - KSS: Kyber shared secret from handshake (32 bytes)
Output:
  - MDK: Metadata encryption key (32 bytes)

Procedure:
  1. // Canonical sort ensures both parties use same order
  2. if IPK_self < IPK_peer (lexicographic):
       sorted_dh ← IPK_self ‖ IPK_peer
     else:
       sorted_dh ← IPK_peer ‖ IPK_self
  3. salt ← sorted_dh ‖ KSS                     // 96 bytes
  4. MDK ← HKDF(RK, salt, "ecliptix-metadata-v1", 32)
  5. Return MDK
```

**Critical Invariant**: `IPK_self` and `IPK_peer` are captured once during handshake and NEVER updated during DH ratchets. This ensures MDK remains stable for the entire session, allowing envelope metadata decryption even after multiple ratchets.

#### 8.2 Envelope Encryption

Message envelopes contain:
- Encrypted metadata (sender info, timestamps)
- Encrypted payload (actual message)
- DH ratchet material (when applicable)

```
SecureEnvelope {
    encrypted_metadata: bytes       // AES-GCM(MDK, metadata)
    encrypted_payload: bytes        // AES-GCM(MK_n, plaintext)
    sender_dh_public: bytes         // Current sender DH (if ratchet)
    kyber_ciphertext: bytes         // Kyber CT (if ratchet)
    message_index: uint32
    ratchet_epoch: uint64
    nonce: bytes[12]
}
```

#### 8.3 Replay Protection

```
Algorithm: CheckReplay
Input:
  - nonce: Received nonce (12 bytes)
  - message_index: Received index
  - received_epoch: Ratchet epoch from envelope
Output:
  - valid: boolean

Procedure:
  1. if received_epoch < current_receiving_epoch:
       Return Error("Stale ratchet epoch - possible replay")
  2. if nonce in seen_nonces:
       Return Error("Duplicate nonce - replay detected")
  3. Add nonce to seen_nonces (with TTL)
  4. Prune old entries from seen_nonces
  5. Return valid
```

---

## Part IV: Security Analysis

### 9. Threat Model

#### 9.1 Adversary Capabilities

| Adversary Type | Capabilities |
|----------------|--------------|
| **Passive (Classical)** | Observe all network traffic, no message modification |
| **Active (Classical)** | Modify, delay, replay messages; compromise endpoints |
| **Quantum (Future)** | Run Shor's algorithm on captured ciphertexts |
| **Harvest Now, Decrypt Later** | Store encrypted traffic for future quantum attack |

#### 9.2 Trust Assumptions

1. **Cryptographic Primitives**: X25519, Ed25519, Kyber-768, AES-256-GCM, HKDF-SHA256 are secure
2. **Random Number Generation**: CSPRNG provides unpredictable output
3. **Secure Memory**: Key material is protected in memory (guard pages, mlock)
4. **Server Honesty**: Key distribution server is honest-but-curious (does not forge keys)
5. **Endpoint Security**: Endpoint devices are not permanently compromised

### 10. Security Properties

#### 10.1 Forward Secrecy

**Definition**: Compromise of long-term keys does not reveal past session keys.

**Mechanism**: Each DH ratchet generates fresh ephemeral keys. After wiping:
- Past DH private keys are unrecoverable
- Past Kyber private keys are unrecoverable
- Past messages cannot be decrypted even with identity key compromise

**Formal Statement**: For any message m encrypted at time t, given identity keys IK compromised at time t' > t:

```
Pr[Decrypt(m) | IK compromised at t'] = negl(λ)
```

#### 10.2 Break-in Recovery (Post-Compromise Security)

**Definition**: After temporary key compromise, security is restored within N messages.

**Mechanism**: The DH ratchet (every 100 messages by default) generates fresh keys:
1. New X25519 keypair from CSPRNG
2. New Kyber keypair from CSPRNG
3. Both combined via HKDF with current root key

**Recovery Window**: At most `DEFAULT_MESSAGE_COUNT_BEFORE_RATCHET` (100) messages after compromise.

#### 10.3 Post-Quantum Resistance (Hybrid OR Assumption)

**Definition**: Protocol remains secure if **either** X25519 **or** Kyber-768 is unbroken.

**Mechanism**: Hybrid secret construction:
```
hybrid_secret = X25519_shared_secret ‖ Kyber_shared_secret
```

**Security Argument**:
- If quantum computer breaks X25519: Kyber provides 128-bit PQ security
- If classical attack breaks Kyber: X25519 provides 128-bit classical security
- Both must be broken simultaneously to compromise the protocol

#### 10.4 Key Compromise Impersonation Resistance

**Definition**: Compromise of Alice's identity key does not allow impersonating Bob to Alice.

**Mechanism**: X3DH requires knowledge of:
- Alice's identity key (compromised) ✓
- Bob's signed pre-key private (not compromised) ✗

Bob's SPK is required for DH1/DH3, preventing impersonation.

#### 10.5 Replay Attack Resistance

**Definition**: Previously valid messages cannot be replayed.

**Mechanisms**:
1. **Unique nonces**: 12-byte nonces include random prefix + counter
2. **Ratchet epochs**: Old epoch messages rejected
3. **Nonce tracking**: Seen nonces cached and checked (with TTL)
4. **Single-use message keys**: Retrieved from cache once, then deleted

### 11. Security Proofs (Informal)

#### 11.1 Forward Secrecy Argument

Let SK_t be the sending DH private key at time t. After DH ratchet at time t+1:
1. SK_t is securely wiped from memory
2. SK_{t+1} is generated from fresh CSPRNG output
3. No computational path from SK_{t+1} to SK_t exists

Similarly for Kyber keys. Therefore, past shared secrets are computationally unrecoverable.

#### 11.2 Break-in Recovery Argument

Assume adversary learns all session keys at time t. At time t + N (where N ≤ 100):
1. DH ratchet generates (SK_new, PK_new) from CSPRNG
2. Adversary cannot predict CSPRNG output
3. DH_secret = X25519(SK_new, peer_pk) is unknown to adversary
4. Similarly, Kyber encapsulation produces unknown KSS
5. New root key RK' is computationally independent of compromised keys

#### 11.3 PQ Hybrid Security Argument

The hybrid construction:
```
HKDF(X25519_ss ‖ Kyber_ss, salt, info, len)
```

Provides security under the OR assumption because:
1. HKDF is a secure key derivation function (RFC 5869 security analysis)
2. If X25519_ss has full entropy (X25519 secure): Output indistinguishable from random
3. If Kyber_ss has full entropy (Kyber secure): Output indistinguishable from random
4. Both inputs are independent, concatenation preserves entropy

---

## Part V: Implementation

### 12. Wire Format

#### 12.1 Protobuf Message Definitions

```protobuf
// Key Exchange Bundle
message PublicKeyBundle {
    bytes identity_public_key = 1;           // Ed25519, 32 bytes
    bytes identity_x25519_public_key = 2;    // X25519, 32 bytes
    uint32 signed_pre_key_id = 3;
    bytes signed_pre_key_public_key = 4;     // X25519, 32 bytes
    bytes signed_pre_key_signature = 5;      // Ed25519 sig, 64 bytes
    repeated OneTimePreKey one_time_pre_keys = 6;
    bytes ephemeral_x25519_public_key = 7;   // X25519, 32 bytes (initiator only)
    bytes kyber_public_key = 8;              // Kyber768, 1184 bytes
    bytes kyber_ciphertext = 9;              // Kyber768 CT, 1088 bytes
    optional uint32 used_one_time_pre_key_id = 10;
}

// Encrypted Message Envelope
message SecureEnvelope {
    bytes encrypted_metadata = 1;
    bytes nonce = 2;                         // 12 bytes
    bytes encrypted_payload = 3;
    bytes sender_dh_public_key = 4;          // X25519, 32 bytes (if ratchet)
    bytes kyber_ciphertext = 5;              // Kyber768 CT, 1088 bytes (if ratchet)
    uint32 message_index = 6;
    uint64 sending_ratchet_epoch = 7;
    uint64 receiving_ratchet_epoch = 8;
}

// Session State (for persistence)
message RatchetState {
    bool is_initiator = 1;
    bytes session_id = 7;
    uint32 connection_id = 8;
    bytes root_key = 10;
    ChainStepState sending_step = 11;
    ChainStepState receiving_step = 12;
    bytes peer_dh_public_key = 5;            // MUTABLE: updated on ratchet
    bytes initial_peer_dh_public = 24;       // IMMUTABLE: never changes
    bytes kyber_public_key = 20;
    bytes kyber_secret_key = 19;
    bytes kyber_ciphertext = 17;
    bytes kyber_shared_secret = 18;
    uint64 receiving_ratchet_epoch = 22;
    uint64 sending_ratchet_epoch = 23;
}
```

#### 12.2 Byte Encoding Conventions

| Field | Encoding | Size |
|-------|----------|------|
| uint32 | Little-endian | 4 bytes |
| uint64 | Little-endian | 8 bytes |
| X25519 public key | Raw bytes | 32 bytes |
| Ed25519 public key | Raw bytes | 32 bytes |
| Ed25519 signature | Raw bytes | 64 bytes |
| Kyber768 public key | Raw bytes | 1184 bytes |
| Kyber768 ciphertext | Raw bytes | 1088 bytes |
| AES-GCM nonce | Raw bytes | 12 bytes |
| AES-GCM tag | Appended to ciphertext | 16 bytes |

### 13. Test Vectors

#### 13.1 X3DH Test Vector

```
// Alice (Initiator)
alice_ik_private: 0x... (32 bytes)
alice_ik_public: 0x... (32 bytes)
alice_ek_private: 0x... (32 bytes)
alice_ek_public: 0x... (32 bytes)

// Bob (Responder)
bob_ik_private: 0x... (32 bytes)
bob_ik_public: 0x... (32 bytes)
bob_spk_private: 0x... (32 bytes)
bob_spk_public: 0x... (32 bytes)

// Expected outputs
DH1 = X25519(alice_ik_private, bob_spk_public) = 0x...
DH2 = X25519(alice_ek_private, bob_ik_public) = 0x...
DH3 = X25519(alice_ek_private, bob_spk_public) = 0x...
shared_secret = HKDF(DH1‖DH2‖DH3, null, "Ecliptix-X3DH-v1", 32) = 0x...
```

#### 13.2 Symmetric Ratchet Test Vector

```
chain_key_0: 0x0102030405060708091011121314151617181920212223242526272829303132
message_key_0 = HKDF(chain_key_0, null, "Ecliptix-Msg", 32) = 0x...
chain_key_1 = HKDF(chain_key_0, null, "Ecliptix-Chain", 32) = 0x...
```

#### 13.3 Metadata Key Derivation Test Vector

```
root_key: 0x... (32 bytes)
ipk_self: 0x... (32 bytes, initiator's initial DH)
ipk_peer: 0x... (32 bytes, responder's initial DH)
kyber_ss: 0x... (32 bytes)

sorted_dh = min(ipk_self, ipk_peer) ‖ max(ipk_self, ipk_peer)
salt = sorted_dh ‖ kyber_ss
metadata_key = HKDF(root_key, salt, "ecliptix-metadata-v1", 32) = 0x...
```

---

## Part VI: References

1. **Signal Protocol Specification**
   Marlinspike, M. & Perrin, T. (2016). "The Double Ratchet Algorithm"
   https://signal.org/docs/specifications/doubleratchet/

2. **NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard**
   National Institute of Standards and Technology (2024)
   https://csrc.nist.gov/publications/detail/fips/203/final

3. **RFC 7748: Elliptic Curves for Security**
   Langley, A., Hamburg, M., & Turner, S. (2016)
   https://datatracker.ietf.org/doc/html/rfc7748

4. **RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)**
   Josefsson, S. & Liusvaara, I. (2017)
   https://datatracker.ietf.org/doc/html/rfc8032

5. **RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)**
   Krawczyk, H. & Eronen, P. (2010)
   https://datatracker.ietf.org/doc/html/rfc5869

6. **NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: GCM**
   Dworkin, M. (2007)
   https://csrc.nist.gov/publications/detail/sp/800-38d/final

7. **PQXDH: Post-Quantum Extended Diffie-Hellman**
   Signal Foundation (2023)
   https://signal.org/docs/specifications/pqxdh/

---

**Document Version**: 1.0
**Last Updated**: January 2026
**Authors**: Ecliptix Protocol Team
**Implementation**: `github.com/ecliptix/Ecliptix.Protection.Protocol`
