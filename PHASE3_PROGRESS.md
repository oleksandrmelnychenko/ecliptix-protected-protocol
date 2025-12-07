# Phase 3 Progress: Key Management & Derivation

**Status**: Partially Complete (~60%)
**Date**: December 5, 2025

---

## ✅ Completed Components

### 1. **HKDF (HMAC-based Key Derivation Function)**

**Files**:
- `include/ecliptix/crypto/hkdf.hpp`
- `src/crypto/hkdf.cpp`

**Features**:
- RFC 5869 compliant HKDF implementation using SHA-256
- OpenSSL backend for cryptographic operations
- Extract and Expand phases
- `DeriveKey()` - Combined extract+expand operation
- `DeriveKeyBytes()` - Convenience method with allocation
- `Extract()` - Standalone extract phase
- `Expand()` - Standalone expand phase
- Input validation (max output length: 255 * 32 bytes)
- Proper error handling with `Result<T, E>`

**Usage**:
```cpp
// Derive 32 bytes from shared secret
auto result = Hkdf::DeriveKeyBytes(
    shared_secret,  // ikm
    32,             // output_size
    salt,           // optional salt
    info            // optional context info
);

if (result.IsOk()) {
    auto derived_key = std::move(result).Unwrap();
    // Use derived_key...
}
```

---

### 2. **Master Key Derivation**

**Files**:
- `include/ecliptix/crypto/master_key_derivation.hpp`
- `src/crypto/master_key_derivation.cpp`

**Features**:
- Deterministic key derivation from master seed + membership ID
- BLAKE2b (via libsodium `crypto_generichash`) for keyed hashing
- Versioned derivation (allows future algorithm upgrades)
- Domain separation via context strings
- Three derivation functions:
  - `DeriveEd25519Seed()` - For signing keys
  - `DeriveX25519Seed()` - For key exchange keys
  - `DeriveSignedPreKeySeed()` - For pre-keys

**Context Strings** (Domain Separation):
- `ecliptix-ed25519-v1` - Ed25519 signing keys
- `ecliptix-x25519-v1` - X25519 key exchange keys
- `ecliptix-spk-v1` - Signed pre-keys

**Derivation Format**:
```
[version (4 bytes)] [context string] [membership ID]
  ↓
BLAKE2b (keyed with master_key)
  ↓
32-byte derived seed
```

**Usage**:
```cpp
// Derive Ed25519 seed for user
auto ed_seed = MasterKeyDerivation::DeriveEd25519Seed(
    master_key,
    "user_membership_id"
);

// Use seed to generate deterministic keypair
auto keypair = PublicKeyAuth::GenerateKeyPair(ed_seed);
```

---

### 3. **Key Material Models**

#### **Ed25519KeyMaterial**

**Files**:
- `include/ecliptix/models/key_materials/ed25519_key_material.hpp`
- `src/models/key_materials/ed25519_key_material.cpp`

**Purpose**: Holds Ed25519 (EdDSA) signing key pair

**Properties**:
- Secret key: 64 bytes (in `SecureMemoryHandle`)
- Public key: 32 bytes (plain `std::vector`)
- Move-only semantics
- RAII cleanup

**Methods**:
- `GetSecretKeyHandle()` - Access secure handle
- `GetPublicKey()` / `GetPublicKeyCopy()` - Access public key

---

#### **X25519KeyMaterial**

**Files**:
- `include/ecliptix/models/key_materials/x25519_key_material.hpp`
- `src/models/key_materials/x25519_key_material.cpp`

**Purpose**: Holds X25519 (Curve25519) DH key pair

**Properties**:
- Secret key: 32 bytes (in `SecureMemoryHandle`)
- Public key: 32 bytes (plain `std::vector`)
- Move-only semantics
- RAII cleanup

**Methods**:
- `GetSecretKeyHandle()` - Access secure handle
- `GetPublicKey()` / `GetPublicKeyCopy()` - Access public key

**Use Cases**:
- Identity key
- Ephemeral keys
- Signed pre-keys

---

#### **SignedPreKeyMaterial**

**Files**:
- `include/ecliptix/models/key_materials/signed_pre_key_material.hpp`
- `src/models/key_materials/signed_pre_key_material.cpp`

**Purpose**: Holds signed X25519 pre-key for X3DH

**Properties**:
- Key ID: `uint32_t` identifier
- Secret key: 32 bytes (in `SecureMemoryHandle`)
- Public key: 32 bytes
- Signature: 64 bytes (Ed25519 signature of public key)
- Move-only semantics
- RAII cleanup

**Methods**:
- `GetId()` - Get pre-key ID
- `GetSecretKeyHandle()` - Access secure handle
- `GetPublicKey()` / `GetPublicKeyCopy()` - Access public key
- `GetSignature()` / `GetSignatureCopy()` - Access signature

**Purpose**: Proves pre-key ownership via identity key signature

---

## 📊 Statistics

| Component | Lines (Header) | Lines (Impl) | Total |
|-----------|----------------|--------------|-------|
| HKDF | ~100 | ~150 | ~250 |
| MasterKeyDerivation | ~70 | ~80 | ~150 |
| Ed25519KeyMaterial | ~60 | ~15 | ~75 |
| X25519KeyMaterial | ~60 | ~15 | ~75 |
| SignedPreKeyMaterial | ~90 | ~15 | ~105 |
| **Total** | **~380** | **~275** | **~655** |

---

## 🔄 Remaining Work (Phase 3)

### **High Priority**

1. **Identity Keys Material Wrapper** (~50 lines)
   - Aggregate model holding all key materials
   - Constructor combining Ed25519, X25519, SignedPreKey, and OPKs

2. **One-Time Pre-Key Models** (~100 lines)
   - `OneTimePreKeyLocal` - Local OPK with secret key
   - `OneTimePreKeyRecord` - Public OPK record

3. **Key Bundle Models** (~80 lines)
   - `LocalPublicKeyBundle` - Bundle of all public keys
   - Used for X3DH key exchange

4. **EcliptixSystemIdentityKeys** (~1020 lines) - **MAJOR COMPONENT**
   - Factory methods:
     - `Create()` - Generate fresh identity
     - `CreateFromMasterKey()` - Deterministic generation
     - `FromProtoState()` - Deserialize from storage
   - Key generation:
     - Ed25519 signing key pair
     - X25519 identity key pair
     - Signed pre-key with signature
     - Batch one-time pre-key generation
   - X3DH operations:
     - `X3dhDeriveSharedSecret()` - Perform X3DH handshake
     - `CreatePublicBundle()` - Export public keys
   - State management:
     - `ToProtoState()` - Serialize for storage
     - Ephemeral key generation
   - Validation:
     - `VerifyRemoteSpkSignature()` - Verify peer's signed pre-key

---

## 🎯 Next Steps

### **Immediate** (Complete Phase 3)

1. **Port `OneTimePreKeyLocal`** (C#: lines 15-96 of `OneTimePreKeyLocal.cs`)
   - Factory method: `Generate(uint32_t id)`
   - Factory method: `CreateFromParts(...)`
   - Secure memory handle for private key
   - Public key storage
   - RAII cleanup

2. **Port Key Bundle Models**
   - `LocalPublicKeyBundle` - Aggregate of public keys
   - Serialization helpers for protobuf (Phase 5)

3. **Begin `EcliptixSystemIdentityKeys`** (Main component)
   - Start with basic structure
   - Port key generation methods
   - Port X3DH derivation

### **Testing** (Parallel with Implementation)

1. Write unit tests for:
   - HKDF derivation
   - Master key derivation
   - Key material models
   - Identity keys operations

2. Integration tests:
   - Full X3DH handshake
   - Key bundle exchange
   - Deterministic key generation

---

## 🔧 Build System Updates

**CMakeLists.txt Changes**:
- Added OpenSSL dependency for HKDF
- Included new source files:
  - `crypto/hkdf.cpp`
  - `crypto/master_key_derivation.cpp`
  - `models/key_materials/ed25519_key_material.cpp`
  - `models/key_materials/x25519_key_material.cpp`
  - `models/key_materials/signed_pre_key_material.cpp`

**Dependencies**:
- ✅ libsodium (Phase 2)
- ✅ OpenSSL (Phase 3 - for HKDF)
- ✅ Protobuf (Phase 5)

---

## 📝 Notes

### **Design Decisions**

1. **HKDF Implementation Choice**:
   - Using OpenSSL's EVP_KDF API (OpenSSL 3.0+)
   - Pros: Well-tested, hardware acceleration, standard compliance
   - Cons: Adds OpenSSL dependency (acceptable for production crypto)

2. **Master Key Derivation**:
   - BLAKE2b via libsodium (already a dependency)
   - Keyed hashing provides strong domain separation
   - Version field allows future algorithm upgrades

3. **Key Material Ownership**:
   - Move-only semantics prevent accidental copies
   - `SecureMemoryHandle` ensures secure cleanup
   - Public keys stored in plain `std::vector` (not secret)

4. **Naming Conventions**:
   - `GetPublicKeyCopy()` - Returns copy (explicit allocation)
   - `GetPublicKey()` - Returns const reference (zero-copy)
   - Matching C# port conventions where possible

### **Security Considerations**

1. **Secure Memory**:
   - All secret keys in `SecureMemoryHandle`
   - Automatic zeroing on destruction
   - Guard pages detect buffer overflows

2. **Domain Separation**:
   - Different context strings for different key types
   - Prevents key misuse across contexts

3. **Versioning**:
   - Master key derivation includes version field
   - Allows future algorithm upgrades without breaking existing keys

---

## 🎓 C# to C++ Port Mapping

| C# Class | C++ Class | Status |
|----------|-----------|--------|
| `MasterKeyDerivation` | `MasterKeyDerivation` | ✅ Complete |
| `Ed25519KeyMaterial` | `Ed25519KeyMaterial` | ✅ Complete |
| `X25519KeyMaterial` | `X25519KeyMaterial` | ✅ Complete |
| `SignedPreKeyMaterial` | `SignedPreKeyMaterial` | ✅ Complete |
| `IdentityKeysMaterial` | `IdentityKeysMaterial` | ⏳ Pending |
| `OneTimePreKeyLocal` | `OneTimePreKeyLocal` | ⏳ Pending |
| `OneTimePreKeyRecord` | `OneTimePreKeyRecord` | ⏳ Pending |
| `LocalPublicKeyBundle` | `LocalPublicKeyBundle` | ⏳ Pending |
| `EcliptixSystemIdentityKeys` | `EcliptixSystemIdentityKeys` | ⏳ Pending |

---

## ⏱️ Time Estimate

- **Completed so far**: ~2 hours
- **Remaining for Phase 3**: ~4-5 hours
  - OneTimePreKey models: ~1 hour
  - Key bundles: ~1 hour
  - EcliptixSystemIdentityKeys: ~2-3 hours
- **Total Phase 3**: ~6-7 hours

---

**Overall Project Progress**: ~35% Complete (was 30%)

**Next Session**: Complete OneTimePreKey models and start EcliptixSystemIdentityKeys
