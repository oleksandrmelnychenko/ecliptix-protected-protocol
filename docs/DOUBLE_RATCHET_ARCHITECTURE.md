# Double Ratchet Protocol Architecture

> **Note**: For the complete formal protocol specification including security proofs and test vectors, see [ECLIPTIX_PROTOCOL_SPECIFICATION.md](./ECLIPTIX_PROTOCOL_SPECIFICATION.md).

## Overview

This document captures the critical architectural patterns and algorithmic details from the C# reference implementation, serving as the blueprint for the C++ port.

## 1. Protocol Flow

### 1.1 Initial Handshake (X3DH - Already Implemented in Phase 3)

```
Alice                                                    Bob
-----                                                    ---
  ├─ Generate ephemeral key pair (EK_A)
  ├─ Perform 4 DH operations with Bob's bundle:
  │    DH1 = DH(IK_A, SPK_B)
  │    DH2 = DH(EK_A, IK_B)
  │    DH3 = DH(EK_A, SPK_B)
  │    DH4 = DH(EK_A, OPK_B)  [if available]
  │
  └─ HKDF-SHA256(DH1 || DH2 || DH3 || DH4, info="Ecliptix-X3DH")
       └─> Initial Shared Secret (32 bytes) = "Initial Root Key"
```

**Result**: Alice and Bob both have the same 32-byte `Initial Root Key`.

### 1.2 Connection Initialization (FinalizeChainAndDhKeys)

After X3DH, both parties need to establish symmetric sending/receiving chains:

```
Input: Initial Root Key (from X3DH), Peer's Initial DH Public Key

Step 1: First DH Ratchet
  DH_Secret = DH(Local_Initial_Ephemeral_SK, Peer_Initial_DH_PK)

Step 2: Derive New Root Key
  HKDF-SHA256(
    IKM = DH_Secret,
    salt = Initial_Root_Key,
    info = "Ecliptix-DH-Ratchet",
    output_length = 64 bytes
  ) → [New_Root_Key(32) || Temp_Buffer(32)]

Step 3: Derive Both Chain Keys from New Root Key
  HKDF-SHA256(
    IKM = New_Root_Key,
    salt = null,
    info = "Ecliptix-Initial-Sender",
    output_length = 32 bytes
  ) → Sender_Chain_Key_Material

  HKDF-SHA256(
    IKM = New_Root_Key,
    salt = null,
    info = "Ecliptix-Initial-Receiver",
    output_length = 32 bytes
  ) → Receiver_Chain_Key_Material

Step 4: Assign Based on Role
  if (is_initiator):
    Sending_Chain_Key = Sender_Chain_Key_Material
    Receiving_Chain_Key = Receiver_Chain_Key_Material
  else:
    Sending_Chain_Key = Receiver_Chain_Key_Material  ← SWAPPED
    Receiving_Chain_Key = Sender_Chain_Key_Material  ← SWAPPED
```

**Critical Insight**: The initiator and responder use the **same HKDF derivations** but **swap the assignments**. This ensures:
- Alice's sending chain = Bob's receiving chain
- Alice's receiving chain = Bob's sending chain

### 1.2b OPAQUE-Derived Initialization (Desktop Login)

When the application authenticates via OPAQUE, reuse the session key only as input to a fresh messaging root:

```
Input: opaque_session_key (32 bytes), user_context (non-empty, e.g., user id hash)
Root = HKDF-SHA256(
    IKM  = opaque_session_key,
    salt = user_context,
    info = "Ecliptix-OPAQUE-Root",
    output_length = 32 bytes
)
```

Guidelines:
- Require the 32-byte session key; reject other sizes.
- Always supply a non-empty, user-bound context to prevent cross-user reuse on shared devices.
- Use `epp_derive_root_key()` (C API) or HKDF with `Ecliptix-OPAQUE-Root` info to derive the root, then initialize the session with the new handshake/state flow.
- Wipe the OPAQUE session key and derived root after seeding the ratchet; do not persist the session key or reuse a previous messaging root across logins/resumptions.

### 1.3 Symmetric Ratchet (Per-Message Key Derivation)

Every time a message is sent or received, the chain key advances:

```cpp
// Current state: ChainKey[N], CurrentIndex = N

// Derive message key for encryption
HKDF-SHA256(
  IKM = ChainKey[N],
  salt = null,
  info = "Ecliptix-Msg",
  output_length = 32 bytes
) → MessageKey[N]

// Derive next chain key for ratcheting
HKDF-SHA256(
  IKM = ChainKey[N],
  salt = null,
  info = "Ecliptix-Chain",
  output_length = 32 bytes
) → ChainKey[N+1]

// Update state: ChainKey[N+1], CurrentIndex = N+1
```

**Critical Insights**:
1. **Two HKDF calls** per message, both using the same input but different `info` strings (domain separation)
2. Message key is used for AES-256-GCM encryption
3. Chain key is immediately replaced and never reused
4. Old message keys can be cached for out-of-order delivery
5. Each DH ratchet increments a monotonic `ratchet_epoch`; envelopes carry this epoch so receivers can reject stale state (e.g., after restoring an old snapshot) and trigger re-establish.

### 1.4 Asymmetric Ratchet (Periodic DH Key Rotation)

Periodically (e.g., every 100 messages or when receiving a new DH key from peer), perform a DH ratchet:

```
Trigger Conditions:
  - Sent MessageCountBeforeRatchet messages (e.g., 100)
  - OR received a new DH public key from peer

Sender Side (Alice):
  Step 1: Generate new ephemeral key pair
    (New_Ephemeral_SK, New_Ephemeral_PK) = GenerateX25519KeyPair()

  Step 2: Compute DH with peer's current DH public key
    DH_Secret = DH(New_Ephemeral_SK, Peer_DH_PK)

  Step 3: Derive new root key and chain key
    HKDF-SHA256(
      IKM = DH_Secret,
      salt = Current_Root_Key,
      info = "Ecliptix-DH-Ratchet",
      output_length = 64 bytes
    ) → [New_Root_Key(32) || New_Chain_Key(32)]

  Step 4: Update sending chain
    Sending_Chain.UpdateKeysAfterDhRatchet(
      new_chain_key = New_Chain_Key,
      new_dh_private_key = New_Ephemeral_SK,
      new_dh_public_key = New_Ephemeral_PK
    )
    Root_Key = New_Root_Key
    Current_Index = 0  ← RESET

  Step 5: Include new DH public key in next message
    Next message contains New_Ephemeral_PK

Receiver Side (Bob):
  Step 1: Receive new DH public key from peer (New_Peer_DH_PK)

  Step 2: Compute DH with current sending DH private key
    DH_Secret = DH(Current_Sending_DH_SK, New_Peer_DH_PK)

  Step 3: Same HKDF as sender
    → [New_Root_Key(32) || New_Chain_Key(32)]

  Step 4: Update receiving chain
    Receiving_Chain.UpdateKeysAfterDhRatchet(
      new_chain_key = New_Chain_Key
    )
    Peer_DH_Public_Key = New_Peer_DH_PK
    Root_Key = New_Root_Key
```

**Critical Insights**:
1. **HKDF uses current root key as salt** (key chaining)
2. **Output is split**: First 32 bytes = new root key, second 32 bytes = new chain key
3. **Sending side** generates new ephemeral key and updates its sending chain
4. **Receiving side** uses existing DH key and updates its receiving chain
5. **Chain index resets to 0** after DH ratchet
6. **Forward secrecy**: Old ephemeral keys are wiped, making past messages unrecoverable

## 2. Out-of-Order Message Handling

### 2.1 SkipKeysUntil Pattern

When receiving message with index N but current index is M (where M < N):

```cpp
// Example: Current index = 5, received index = 10
// Need to derive and cache keys for indices 6, 7, 8, 9

for (uint32_t i = current_index + 1; i < received_index; i++) {
    // Derive message key for index i
    MessageKey[i] = HKDF(ChainKey[i-1], "Ecliptix-Msg")
    ChainKey[i] = HKDF(ChainKey[i-1], "Ecliptix-Chain")

    // Cache in secure memory
    skipped_message_keys[i] = SecureMemoryHandle::Create(MessageKey[i])

    // Securely wipe temporary buffers
    SecureWipe(MessageKey[i])
}

// Now derive for the received index
MessageKey[received_index] = HKDF(ChainKey[received_index-1], "Ecliptix-Msg")
```

### 2.2 Message Key Cache Management

```cpp
// Data structure
std::map<uint32_t, SecureMemoryHandle> skipped_message_keys_;

// Cache window parameters
constexpr uint32_t MAX_SKIP_MESSAGE_KEYS = 1000;
constexpr uint32_t MESSAGE_KEY_CACHE_WINDOW = 2000;

// Pruning old keys
void PruneOldKeys() {
    if (skipped_message_keys_.size() > MESSAGE_KEY_CACHE_WINDOW) {
        // Remove keys older than (current_index - CACHE_WINDOW)
        auto cutoff_index = current_index_ > MESSAGE_KEY_CACHE_WINDOW
            ? current_index_ - MESSAGE_KEY_CACHE_WINDOW
            : 0;

        auto it = skipped_message_keys_.begin();
        while (it != skipped_message_keys_.end() && it->first < cutoff_index) {
            it = skipped_message_keys_.erase(it);  // Destructor wipes secure memory
        }
    }
}

// Retrieving cached key
std::optional<SecureMemoryHandle> GetCachedMessageKey(uint32_t index) {
    auto it = skipped_message_keys_.find(index);
    if (it != skipped_message_keys_.end()) {
        // Move out of cache (single-use)
        SecureMemoryHandle handle = std::move(it->second);
        skipped_message_keys_.erase(it);
        return handle;
    }
    return std::nullopt;
}
```

**Critical Insights**:
1. **Cached keys are single-use**: Once retrieved, they're removed from cache
2. **Pruning prevents unbounded growth**: Old keys beyond window are wiped
3. **Max skip limit** prevents DoS attacks (can't skip more than 1000 messages)

## 3. IKeyProvider Pattern

### 3.1 Design Rationale

Instead of exposing raw key material, ChainStep implements IKeyProvider to control access:

```cpp
class IKeyProvider {
public:
    virtual Result<Unit, EcliptixProtocolFailure> ExecuteWithKey(
        uint32_t index,
        std::function<Result<Unit, EcliptixProtocolFailure>(std::span<const uint8_t>)> operation
    ) = 0;
};

// ChainStep implements this interface
class EcliptixProtocolChainStep : public IKeyProvider {
    Result<Unit, EcliptixProtocolFailure> ExecuteWithKey(
        uint32_t index,
        std::function<Result<Unit, EcliptixProtocolFailure>(std::span<const uint8_t>)> operation
    ) override {
        // Derive or retrieve key for index
        std::vector<uint8_t> key_material;
        if (index == current_index_) {
            key_material = DeriveCurrentMessageKey();
        } else if (auto cached = GetCachedMessageKey(index)) {
            key_material = cached->ReadBytes();
        } else {
            return Error("Key not available");
        }

        // Execute operation with key
        auto result = operation(key_material);

        // Securely wipe before returning
        SodiumInterop::SecureWipe(std::span<uint8_t>(key_material));

        return result;
    }
};
```

### 3.2 RatchetChainKey and MessageKey

Lightweight wrappers that defer to the provider:

```cpp
class RatchetChainKey {
    IKeyProvider* provider_;  // Non-owning pointer
    uint32_t index_;

public:
    RatchetChainKey(IKeyProvider* provider, uint32_t index)
        : provider_(provider), index_(index) {}

    // Encrypt data using the message key at this index
    Result<std::vector<uint8_t>, EcliptixProtocolFailure> Encrypt(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> ad
    ) const {
        return provider_->ExecuteWithKeyTyped<std::vector<uint8_t>>(
            index_,
            [&](std::span<const uint8_t> key) -> Result<std::vector<uint8_t>, EcliptixProtocolFailure> {
                // Use AES-256-GCM with this key
                return AesGcmEncrypt(key, plaintext, ad);
            }
        );
    }

    uint32_t Index() const { return index_; }
};
```

**Critical Insights**:
1. **Keys never escape**: They only exist within the callback scope
2. **Provider lifetime must exceed user lifetime**: Use references carefully
3. **Thread-safe if provider is thread-safe**: Lock inside ExecuteWithKey

## 4. Nonce Generation

### 4.1 AES-GCM Nonce Structure

```
Nonce (12 bytes total):
  ┌──────────────┬──────────────┬──────────────┐
  │ Prefix (4B)  │ Counter (4B) │ Index (4B)   │
  └──────────────┴──────────────┴──────────────┘
   Bytes 0-3      Bytes 4-7      Bytes 8-11

Counter/index encoding: Little-endian uint32
```

### 4.2 Generation Algorithm

```cpp
std::atomic<uint64_t> nonce_counter_{0};
constexpr uint64_t MAX_NONCE_COUNTER = std::numeric_limits<uint32_t>::max();
constexpr size_t PREFIX_SIZE = 4;
constexpr size_t COUNTER_SIZE = 4;
constexpr size_t INDEX_SIZE = 4;
std::array<uint8_t, PREFIX_SIZE> nonce_prefix_ = GenerateNoncePrefix();

Result<std::vector<uint8_t>, EcliptixProtocolFailure> GenerateNextNonce() {
    // Check counter overflow (pre-increment guard)
    uint64_t current = nonce_counter_.load();
    if (current > MAX_NONCE_COUNTER) {
        return Error("Nonce counter overflow - session must be rekeyed");
    }
    nonce_counter_.store(current + 1);

    // Generate 12-byte nonce
    std::vector<uint8_t> nonce(kAesGcmNonceBytes);

    // First 4 bytes: per-session random prefix
    std::copy(nonce_prefix_.begin(), nonce_prefix_.end(), nonce.begin());

    // Next 4 bytes: monotonic counter (little-endian)
    uint32_t counter_value = static_cast<uint32_t>(current);

    // Write as little-endian
    nonce[4] = (counter_value >>  0) & 0xFF;
    nonce[5] = (counter_value >>  8) & 0xFF;
    nonce[6] = (counter_value >> 16) & 0xFF;
    nonce[7] = (counter_value >> 24) & 0xFF;

    // Last 4 bytes: message index binding (little-endian)
    const uint32_t index = ResolveMessageIndex();
    nonce[8]  = (index >>  0) & 0xFF;
    nonce[9]  = (index >>  8) & 0xFF;
    nonce[10] = (index >> 16) & 0xFF;
    nonce[11] = (index >> 24) & 0xFF;

    return Result::Ok(std::move(nonce));
}
```

**Critical Insights**:
1. **Nonce reuse is catastrophic** for AES-GCM
2. **Random prefix** ensures uniqueness across sessions
3. **Counter suffix** ensures uniqueness within session
4. **Atomic counter** provides thread-safety
5. **Session expiry** when counter exhausted (prevents wraparound)

## 5. Thread Safety

### 5.1 Locking Strategy

```cpp
class EcliptixProtocolConnection {
    mutable std::mutex lock_;  // Protects all mutable state

public:
    Result<RatchetChainKey, EcliptixProtocolFailure> PrepareNextSendMessage() {
        std::lock_guard<std::mutex> guard(lock_);  // RAII lock

        // All ratchet operations are serialized
        // ...
    }

    Result<RatchetChainKey, EcliptixProtocolFailure> ProcessReceivedMessage(uint32_t index) {
        std::lock_guard<std::mutex> guard(lock_);

        // Receiving operations also serialized
        // ...
    }
};
```

### 5.2 Nonce Counter (Atomic)

```cpp
// Atomic counter for nonce generation
std::atomic<uint64_t> nonce_counter_{0};

// Nonce generation uses the connection lock to coordinate rate limiting
Result<std::vector<uint8_t>, EcliptixProtocolFailure> GenerateNextNonce() {
    std::lock_guard<std::mutex> guard(lock_);
    // ...
}
```

**Critical Insights**:
1. **Coarse-grained locking** for ratchet state (simplicity over performance)
2. **Atomic nonce counters** paired with serialized generation for rate limiting
3. **No lock ordering issues** (only one lock per connection)

## 6. Memory Safety

### 6.1 RAII for Cleanup

```cpp
// DhRatchetContext: Automatically wipes temporary keys
class DhRatchetContext {
    std::vector<uint8_t> dh_secret_;
    std::vector<uint8_t> new_root_key_;
    std::vector<uint8_t> new_chain_key_;
    std::optional<std::vector<uint8_t>> new_ephemeral_public_key_;
    std::optional<SecureMemoryHandle> new_ephemeral_sk_handle_;

public:
    ~DhRatchetContext() {
        // Automatic secure wiping on scope exit
        SodiumInterop::SecureWipe(std::span<uint8_t>(dh_secret_));
        SodiumInterop::SecureWipe(std::span<uint8_t>(new_root_key_));
        SodiumInterop::SecureWipe(std::span<uint8_t>(new_chain_key_));
        if (new_ephemeral_public_key_) {
            SodiumInterop::SecureWipe(std::span<uint8_t>(*new_ephemeral_public_key_));
        }
        // SecureMemoryHandle destructor automatically wipes
    }

    // Move-only
    DhRatchetContext(DhRatchetContext&&) noexcept = default;
    DhRatchetContext(const DhRatchetContext&) = delete;
};

// Usage
Result<Unit, EcliptixProtocolFailure> PerformDhRatchet(bool is_sender) {
    DhRatchetContext ctx;  // Automatic cleanup on scope exit (success or error)

    TRY_UNIT(ComputeDhSecret(is_sender, ctx));
    TRY_UNIT(DeriveRatchetKeys(ctx));
    TRY_UNIT(UpdateChainSteps(ctx));

    return Ok(Unit{});
    // ctx destructor wipes all temporary buffers
}
```

### 6.2 SecureMemoryHandle Lifecycle

```cpp
// Allocation
auto handle_result = SecureMemoryHandle::Allocate(32);
TRY(handle, handle_result);  // Move out of Result

// Reading (creates temporary copy)
auto bytes_result = handle.ReadBytes(32);
TRY(bytes, bytes_result);
// ... use bytes ...
SodiumInterop::SecureWipe(std::span<uint8_t>(bytes));  // Must wipe!

// Writing (overwrites existing content)
handle.Write(new_data);  // Old data automatically wiped

// Destruction
// ~SecureMemoryHandle() automatically calls sodium_free() → wipes memory
```

## 7. Constants Reference

```cpp
namespace ecliptix::protocol {

inline constexpr std::string_view kX3dhInfo = "Ecliptix-X3DH";
inline constexpr std::string_view kMessageInfo = "Ecliptix-Msg";
inline constexpr std::string_view kChainInfo = "Ecliptix-Chain";
inline constexpr std::string_view kDhRatchetInfo = "Ecliptix-DH-Ratchet";
inline constexpr std::string_view kInitialSenderChainInfo = "Ecliptix-Initial-Sender";
inline constexpr std::string_view kInitialReceiverChainInfo = "Ecliptix-Initial-Receiver";
inline constexpr std::string_view kMetadataKeyInfo = "Ecliptix-MetadataKey";

inline constexpr uint64_t kDefaultMessagesPerChain = 1000; // default per-session limit
inline constexpr size_t kMaxSkippedMessageKeys = 1000;
inline constexpr size_t kMaxMessagesPerChain = 10000;

inline constexpr size_t kNoncePrefixBytes = 4;
inline constexpr size_t kNonceCounterBytes = 4;
inline constexpr size_t kNonceIndexBytes = 4;
inline constexpr uint64_t kMaxNonceCounter = 0xFFFFFFFFull;

} // namespace ecliptix::protocol
```

Note: The active per-session ratchet limit is carried in `ProtocolState.max_messages_per_chain`
and negotiated during handshake. `kDefaultMessagesPerChain` is the default value used by APIs.

## 8. Error Handling Strategy

### 8.1 Result<T, E> Monad Pattern

```cpp
// Already established in codebase
Result<SecureMemoryHandle, EcliptixProtocolFailure> DeriveMessageKey(uint32_t index) {
    TRY(chain_key_bytes, chain_key_handle_.ReadBytes(kChainKeyBytes));

    std::vector<uint8_t> message_key(kMessageKeyBytes);
    std::vector<uint8_t> message_info(kMessageInfo.begin(), kMessageInfo.end());
    TRY_UNIT(Hkdf::DeriveKey(
        chain_key_bytes,
        std::span<uint8_t>(message_key),
        std::nullopt,  // No salt
        message_info
    ));

    TRY(handle, SecureMemoryHandle::Allocate(kMessageKeyBytes));
    TRY_UNIT(handle.Write(message_key));

    SodiumInterop::SecureWipe(std::span<uint8_t>(message_key));
    SodiumInterop::SecureWipe(std::span<uint8_t>(chain_key_bytes));

    return Result::Ok(std::move(handle));
}
```

### 8.2 Common Error Types

```cpp
// Key derivation failure
EcliptixProtocolFailure::DeriveKey("Failed to derive message key", exception);

// Invalid input
EcliptixProtocolFailure::InvalidInput("Received index too large");

// State violation
EcliptixProtocolFailure::Generic("Receiving chain not initialized");

// Resource exhaustion
EcliptixProtocolFailure::Generic("Nonce counter overflow");

// Cryptographic failure
EcliptixProtocolFailure::CryptoFailure("AES-GCM decryption failed");
```

## 9. Testing Strategy

### 9.1 Unit Test Coverage

**ChainStep Tests**:
- [x] Key derivation produces correct HKDF outputs
- [x] Message key caching and retrieval
- [x] SkipKeysUntil with various gap sizes
- [x] Cache pruning behavior
- [x] UpdateKeysAfterDhRatchet resets state correctly

**Connection Tests**:
- [ ] Initial handshake completion
- [ ] Sending messages (symmetric ratchet advancement)
- [ ] Receiving messages (symmetric ratchet verification)
- [ ] DH ratchet triggers (message count threshold)
- [ ] DH ratchet triggers (received new DH key)
- [ ] Out-of-order message handling
- [ ] Nonce generation uniqueness

**Integration Tests**:
- [ ] Alice → Bob single message
- [ ] Bob → Alice response
- [ ] Bidirectional conversation
- [ ] DH ratchet rotation during conversation
- [ ] Out-of-order delivery simulation
- [ ] State persistence and recovery
- [ ] Session timeout handling

### 9.2 Security Test Vectors

Generate test vectors from C# implementation:
1. Known X3DH inputs → Expected shared secret
2. Known chain key → Expected message key and next chain key
3. Known DH secret + root key → Expected new root key and chain key
4. Known plaintext + message key → Expected ciphertext

## 10. Implementation Checklist

### Phase 4A: Foundational Types
- [x] IKeyProvider interface
- [ ] RatchetChainKey struct
- [ ] MessageKey struct
- [ ] ChainStepType enum
- [ ] Protocol constants update
- [ ] DhRatchetContext RAII struct

### Phase 4B: Symmetric Ratchet
- [ ] EcliptixProtocolChainStep class skeleton
- [ ] DeriveNextChainKeys algorithm
- [ ] Message key caching (std::map)
- [ ] SkipKeysUntil implementation
- [ ] PruneOldKeys implementation
- [ ] GetOrDeriveKeyFor method
- [ ] UpdateKeysAfterDhRatchet

### Phase 4C: Connection Layer
- [ ] RatchetConfig class
- [ ] EcliptixProtocolConnection class skeleton
- [ ] FinalizeChainAndDhKeys
- [ ] PrepareNextSendMessage
- [ ] ProcessReceivedMessage
- [ ] PerformDhRatchet (sender side)
- [ ] PerformDhRatchet (receiver side)
- [ ] Nonce generation
- [ ] Metadata encryption key derivation

### Phase 4D: Security Components
- [ ] ReplayProtection implementation
- [ ] RatchetRecovery implementation
- [ ] DhValidator for public key validation

### Phase 4E: Main API
- [ ] HandshakeInitiator/HandshakeResponder API
- [ ] Session API (Encrypt/Decrypt)
- [ ] Session serialization (ToProtoState)
- [ ] Session deserialization (FromProtoState)
- [ ] PreKey bundle creation/validation

### Phase 4F: Testing
- [ ] ChainStep unit tests
- [ ] Connection unit tests
- [ ] Integration tests
- [ ] Performance benchmarks
- [ ] Memory leak testing (Valgrind)

---

**Document Version**: 1.0
**Last Updated**: 2025-12-07
**Author**: Claude (from C# reference implementation analysis)
