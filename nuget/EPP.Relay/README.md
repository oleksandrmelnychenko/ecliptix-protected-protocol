# EPP.Relay

High-performance native EPP relay/server bindings for .NET applications.

## Features

- Hybrid X3DH + Kyber handshake (mandatory PQ)
- Double ratchet session encryption
- AES-256-GCM authenticated encryption
- Secure memory via libsodium
- Cross-platform native library

## Installation

```bash
dotnet add package EPP.Relay
```

Or add to your project file:

```xml
<PackageReference Include="EPP.Relay" Version="1.0.0" />
```

## Quick Start (Interop)

```csharp
using EPP;
using EPP.Relay;

RelayNativeInterop.epp_init();

RelayNativeInterop.epp_identity_create(out var identity, out var error);
RelayNativeInterop.epp_prekey_bundle_create(identity, out var bundle, out error);
RelayNativeInterop.epp_buffer_release(ref bundle);

var config = new EppSessionConfig { MaxMessagesPerChain = 200 };
RelayNativeInterop.epp_handshake_responder_start(
    identity, localBundleBytes, (nuint)localBundleBytes.Length,
    handshakeInitBytes, (nuint)handshakeInitBytes.Length, ref config,
    out var responderHandle, out var handshakeAck, out error);
RelayNativeInterop.epp_buffer_release(ref handshakeAck);

RelayNativeInterop.epp_handshake_responder_finish(
    responderHandle, out var sessionHandle, out error);

RelayNativeInterop.epp_session_destroy(sessionHandle);
RelayNativeInterop.epp_identity_destroy(identity);
RelayNativeInterop.epp_shutdown();
```

Note: For higher-level C# wrappers, see `bindings/csharp/README.md` in the repo.

## Platform Support

| Platform | Architecture | Status |
|----------|--------------|--------|
| Windows  | x64          | Supported |
| Linux    | x64          | Supported |
| Linux    | ARM64        | Supported |
| macOS    | x64          | Supported |
| macOS    | ARM64        | Supported |

## License

MIT License - See LICENSE file for details.
