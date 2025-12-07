# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Ecliptix.Protocol.System** is a production-ready C++20 cryptographic protocol library implementing a Signal Protocol-like double ratchet with X3DH key agreement. This is a port from C# (.NET 10) to C++ with enhanced security features.

**Status**: Phase 2 Complete (~30% overall)

## Project Architecture

This is an **end-to-end encrypted messaging protocol** library with:
- **X3DH (Extended Triple Diffie-Hellman)** for initial key agreement
- **Double Ratchet Algorithm** for forward secrecy and break-in recovery
- **AES-256-GCM** for message encryption
- **Ed25519** for signatures, **X25519** for key exchange
- **HKDF-SHA256** for key derivation
- **Protobuf** for state serialization (Phase 5)

### Core Components (Current Status)

**✅ Phase 1 - Foundation (Complete)**
- Modern CMake build system with C++20
- Result<T, E> monadic error handling (Rust-style)
- Option<T> wrapper for std::optional
- Failure types (SodiumFailure, EcliptixProtocolFailure)
- All cryptographic constants

**✅ Phase 2 - Crypto & Secure Memory (Complete)**
- `SodiumInterop` - libsodium wrapper with RAII
  - Secure memory allocation/deallocation
  - Constant-time comparison
  - Secure wiping (small/large buffers)
  - X25519 and Ed25519 key generation
  - Random number generation
- `SecureMemoryHandle` - RAII secure memory
  - Move-only semantics (non-copyable)
  - Automatic zeroing on free
  - Guard pages, locked in RAM
  - Template accessors (`WithReadAccess`, `WithWriteAccess`)
- Comprehensive unit tests (Catch2)

**🚧 Phase 3 - Key Management (Next)**
- Identity keys management
- Key derivation (HKDF, master key)
- Key material models

**⏳ Phase 4 - Protocol Core (Pending)**
- Chain step ratcheting
- DH ratchet implementation
- Message encryption/decryption

**⏳ Phase 5 - Serialization (Pending)**
- Protobuf definitions
- State persistence

## Build System

### Dependencies
- **libsodium** - Core cryptography (REQUIRED)
- **protobuf** - Message serialization (REQUIRED)
- **Catch2** - Testing framework (auto-fetched if not found)
- **spdlog** - Logging (optional)

### Install Dependencies (macOS)
```bash
brew install libsodium protobuf pkg-config

# Optional
brew install spdlog
```

### Building the Project

```bash
# Configure
cmake -B build -S . \
  -DCMAKE_BUILD_TYPE=Release \
  -DECLIPTIX_BUILD_TESTS=ON \
  -DECLIPTIX_BUILD_EXAMPLES=ON

# Build
cmake --build build -j$(nproc)

# Run tests
cd build && ctest --output-on-failure

# Run example
./build/examples/basic_crypto_example
```

### Build Options
- `ECLIPTIX_BUILD_TESTS=ON/OFF` - Build tests (default: ON)
- `ECLIPTIX_BUILD_EXAMPLES=ON/OFF` - Build examples (default: ON)
- `ECLIPTIX_BUILD_SHARED=ON/OFF` - Build shared library (default: OFF)
- `ECLIPTIX_ENABLE_ASAN=ON/OFF` - Enable AddressSanitizer (default: OFF)
- `ECLIPTIX_ENABLE_TSAN=ON/OFF` - Enable ThreadSanitizer (default: OFF)
- `ECLIPTIX_ENABLE_UBSAN=ON/OFF` - Enable UndefinedBehaviorSanitizer (default: OFF)

### Development Build with Sanitizers
```bash
cmake -B build-debug -S . \
  -DCMAKE_BUILD_TYPE=Debug \
  -DECLIPTIX_ENABLE_ASAN=ON \
  -DECLIPTIX_ENABLE_UBSAN=ON

cmake --build build-debug
cd build-debug && ctest
```

## Project Structure

```
include/ecliptix/          # Public API headers
  core/                    # Core types (Result, Option, Failures, Constants)
  crypto/                  # Crypto layer (SodiumInterop, SecureMemoryHandle)
  protocol/                # Protocol API (Phase 4+)
  models/                  # Data models (Phase 3+)

src/                       # Implementation files
  core/                    # Core implementations
  crypto/                  # Crypto implementations
  protocol/                # Protocol implementations (Phase 4+)
  models/                  # Model implementations (Phase 3+)

tests/                     # Test suite
  unit/                    # Unit tests (Catch2)
  integration/             # Integration tests (Phase 6)
  security/                # Security tests (Phase 6)

examples/                  # Usage examples
proto/                     # Protobuf definitions (Phase 5)
```

## Error Handling Philosophy

This library uses **Result<T, E>** for all fallible operations:

```cpp
// Example: Key generation
auto result = SodiumInterop::GenerateX25519KeyPair("test");
if (result.IsOk()) {
    auto [sk_handle, pk_bytes] = std::move(result).Unwrap();
    // Use keys...
} else {
    auto error = result.UnwrapErr();
    // Handle error...
}

// Monadic chaining
auto final_result = GenerateKey()
    .Map([](auto key) { return DeriveFrom(key); })
    .Bind([](auto derived) { return UseKey(derived); });

// Early return with TRY macro
auto value = TRY(some_fallible_operation());
```

**Never throw exceptions** in hot paths or destructors.

## Memory Management

### Secure Memory
ALL cryptographic keys MUST use `SecureMemoryHandle`:

```cpp
// Allocate secure memory (guard pages, locked in RAM)
auto handle = SecureMemoryHandle::Allocate(32).Unwrap();

// Write data
std::vector<uint8_t> key = GetKey();
handle.Write(key);
SodiumInterop::SecureWipe(key);  // Immediately wipe temporary

// Access without copying
handle.WithReadAccess([](std::span<const uint8_t> data) {
    // Use data directly
    return DoSomething(data);
});

// Automatic cleanup on scope exit (RAII)
```

### General Memory
- **RAII everywhere** - No manual `delete` or `free`
- **`std::unique_ptr`** for single ownership
- **`std::shared_ptr`** only when truly needed
- **Move semantics** for secure handles (non-copyable)

## Coding Standards

### C# to C++ Mappings
| C# | C++ |
|-----|-----|
| `Result<T, E>` | `Result<T, E>` (custom) |
| `Option<T>` | `std::optional<T>` (aliased) |
| `Span<T>` | `std::span<T>` (C++20) |
| `ReadOnlySpan<T>` | `std::span<const T>` |
| `Lock` | `std::mutex` + `std::lock_guard` |
| `IDisposable` | RAII destructors |
| `sealed class` | `final class` |
| `internal` | `namespace internal` + unnamed namespace |

### Naming Conventions
- **Classes**: `PascalCase` (e.g., `SecureMemoryHandle`)
- **Functions**: `PascalCase` (matches C# port)
- **Variables**: `snake_case` (e.g., `sk_handle`)
- **Constants**: `SCREAMING_SNAKE_CASE` (e.g., `MAX_BUFFER_SIZE`)
- **Namespaces**: `lowercase` (e.g., `ecliptix::protocol::crypto`)

### Thread Safety
- **Immutable by default**: Prefer `const` where possible
- **Explicit synchronization**: Use `std::mutex` when needed
- **Document guarantees**: Clearly state thread-safety in comments

## Testing

### Running Tests
```bash
cd build
ctest --output-on-failure

# Run specific test
./ecliptix_tests "[sodium]"

# Verbose output
./ecliptix_tests --success
```

### Writing Tests
Use Catch2 with descriptive test names:

```cpp
TEST_CASE("SodiumInterop - X25519 Key Generation", "[sodium][crypto][keygen]") {
    SECTION("Generate valid key pair") {
        auto result = SodiumInterop::GenerateX25519KeyPair("test");
        REQUIRE(result.IsOk());
        // ...
    }
}
```

## Development Workflow

### Adding New Features
1. Read the C# source for context (`/Users/oleksandrmelnychenko/RiderProjects/ecliptix-desktop/Ecliptix.Protocol.System/`)
2. Port the component to C++ following existing patterns
3. Update `CMakeLists.txt` to include new sources
4. Write unit tests in `tests/unit/`
5. Update `PORTING_PROGRESS.md` and todo list
6. Rebuild and verify all tests pass

### Before Committing
```bash
# Build with all warnings
cmake --build build

# Run tests
cd build && ctest

# Run with sanitizers
cmake -B build-asan -DECLIPTIX_ENABLE_ASAN=ON -DECLIPTIX_ENABLE_UBSAN=ON
cmake --build build-asan && cd build-asan && ctest
```

## Critical Security Considerations

1. **Constant-Time Operations**: ALWAYS use `SodiumInterop::ConstantTimeEquals()` for cryptographic comparisons
2. **Secure Wiping**: Call `SodiumInterop::SecureWipe()` on ALL temporary key material
3. **Secure Memory**: Use `SecureMemoryHandle` for ALL keys and secrets
4. **No Logging**: NEVER log keys, secrets, or sensitive data
5. **RAII**: All resources MUST be freed via RAII (no manual cleanup)

## Next Development Phase

**Phase 3: Key Management** (Starting Next)
- Port `EcliptixSystemIdentityKeys` from C# (1020 lines)
- Implement master key derivation
- Create key material models (Ed25519, X25519, SignedPreKey)
- Port one-time pre-key generation
- Implement X3DH shared secret derivation

See `PORTING_PROGRESS.md` for detailed roadmap.

## References

- **C# Source**: `/Users/oleksandrmelnychenko/RiderProjects/ecliptix-desktop/Ecliptix.Protocol.System/`
- **Progress Tracking**: `PORTING_PROGRESS.md`
- **libsodium docs**: https://doc.libsodium.org/
- **Signal Protocol**: https://signal.org/docs/
