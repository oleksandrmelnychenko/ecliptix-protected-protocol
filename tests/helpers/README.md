# Test Helpers

## MockKeyProvider

`MockKeyProvider` is a test helper that implements `IKeyProvider` interface for isolated testing of `ChainKey` and encryption logic without requiring full Session chain-state infrastructure.

### Usage Example

```cpp
#include "helpers/mock_key_provider.hpp"
#include "ecliptix/models/keys/chain_key.hpp"
#include "ecliptix/crypto/aes_gcm.hpp"

using namespace ecliptix::protocol::test_helpers;
using namespace ecliptix::protocol::models;
using namespace ecliptix::protocol::crypto;

TEST_CASE("Test encryption with mock key") {
    MockKeyProvider mock;

    std::vector<uint8_t> test_key(32, 0xAB);
    mock.SetKey(0, test_key);

    ChainKey key(&mock, 0);

    auto result = key.WithKeyMaterial<std::vector<uint8_t>>([&](auto key_span) {
        std::vector<uint8_t> nonce(12, 0x00);
        std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03};
        std::vector<uint8_t> aad = {0xAA, 0xBB};

        return AesGcm::Encrypt(key_span, nonce, plaintext, aad);
    });

    REQUIRE(result.IsOk());
}
```

### API Methods

#### `void SetKey(uint32_t index, std::span<const uint8_t> key_material)`
Stores key material at the specified index in a `SecureMemoryHandle`.

#### `Result<Unit, Failure> ExecuteWithKey(uint32_t index, auto operation)`
Executes callback with key material at index. Returns error if index not found.

#### `void Clear()`
Removes all stored keys. Use between test cases to ensure isolation.

#### `size_t KeyCount() const`
Returns number of keys currently stored.

#### `bool HasKey(uint32_t index) const`
Checks if key exists at index.

#### `void PruneKeysBelow(uint32_t min_index)`
Removes all keys with index < min_index. Prevents memory growth in long-running tests.

### ⚠️ CRITICAL: Lifetime Contract

**`ChainKey` DOES NOT OWN the `MockKeyProvider`**

The provider must outlive any `ChainKey` instances that reference it:

```cpp
// ❌ WRONG - Dangling pointer:
ChainKey DangerousFunction() {
    MockKeyProvider mock;  // Destroyed when function returns
    mock.SetKey(0, key);
    return ChainKey(&mock, 0);  // Returns dangling pointer!
}

// ✅ CORRECT - Provider outlives key:
TEST_CASE("Safe usage") {
    MockKeyProvider mock;  // Lives for entire test
    mock.SetKey(0, key);

    {
        ChainKey key(&mock, 0);
        key.WithKeyMaterial(...);
    }  // key destroyed, mock still valid
}
```

### Security Properties

`MockKeyProvider` maintains the same security properties as production Session chain key handling:

1. **Keys stored in `SecureMemoryHandle`** - Memory is locked and wiped on destruction
2. **Keys only accessible via callback** - `WithKeyMaterial()` is the ONLY way to access key bytes
3. **No key copying to application memory** - Keys exist only in callback scope

```cpp
// ❌ This is impossible (good!):
std::vector<uint8_t> leaked = key.GetRawBytes();  // Doesn't exist

// ✅ This is the only way:
key.WithKeyMaterial([](auto key_span) {
    // key_span only valid in this scope
    return DoSomething(key_span);
});  // key_span invalid after callback returns
```

### Thread Safety

`MockKeyProvider` is **NOT thread-safe**. Use separate instances per thread or add external synchronization if testing concurrent scenarios.

Production Session key handling uses internal mutexes and is thread-safe.

### Memory Management

Unlike production Session chain state, `MockKeyProvider` does NOT automatically prune old keys. For tests simulating many messages:

```cpp
MockKeyProvider mock;

for (uint32_t i = 0; i < 10000; ++i) {
    mock.SetKey(i, GenerateKey(i));

    // Prevent unbounded growth - keep only last 1000 keys:
    if (i > 1000) {
        mock.PruneKeysBelow(i - 1000);
    }
}
```

### When to Use

**Use `MockKeyProvider` when**:
- Testing encryption/decryption logic in isolation
- Testing key derivation algorithms
- Testing skip-key scenarios (receiving message N without 0..N-1)
- Writing unit tests for cryptographic correctness

**Use production Session chain handling when**:
- Integration testing full protocol flow
- Testing DH ratchet stepping
- Testing chain key advancement logic
- Performance benchmarking

### Example: Testing Skip Keys

```cpp
TEST_CASE("Receive message 1000 without receiving 0-999") {
    MockKeyProvider mock;

    // Pre-populate with expected keys:
    for (uint32_t i = 0; i <= 1000; ++i) {
        auto key = DeriveChainKey(initial_key, i);
        mock.SetKey(i, key);
    }

    // Skip directly to message 1000:
    ChainKey key1000(&mock, 1000);

    auto result = key1000.WithKeyMaterial<std::vector<uint8_t>>([&](auto k) {
        return AesGcm::Decrypt(k, nonce, ciphertext, aad);
    });

    REQUIRE(result.IsOk());
    REQUIRE(result.Unwrap() == expected_plaintext);
}
```
