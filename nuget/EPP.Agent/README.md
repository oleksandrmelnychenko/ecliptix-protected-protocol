# EPP.Agent

High-performance native Ecliptix Protection Protocol agent bindings for .NET applications.

## Features

- Hybrid X3DH + Kyber handshake (mandatory PQ)
- Double ratchet session encryption
- AES-256-GCM authenticated encryption
- Secure memory via libsodium
- Cross-platform native library

## Installation

```bash
dotnet add package EPP.Agent
```

Or add to your project file:

```xml
<PackageReference Include="EPP.Agent" Version="1.0.0" />
```

## Quick Start (Interop)

```csharp
using EPP;
using EPP.Agent;

AgentNativeInterop.epp_init();

// Create identity keys and publish bundle
AgentNativeInterop.epp_identity_create(out var identity, out var error);
AgentNativeInterop.epp_prekey_bundle_create(identity, out var bundle, out error);
// Marshal bundle.Data (bundle.Length) -> byte[] and release buffer
AgentNativeInterop.epp_buffer_release(ref bundle);

// Handshake + session
var config = new EppSessionConfig { MaxMessagesPerChain = 200 };
AgentNativeInterop.epp_handshake_initiator_start(
    identity, peerBundleBytes, (nuint)peerBundleBytes.Length, ref config,
    out var initiatorHandle, out var handshakeInit, out error);
AgentNativeInterop.epp_buffer_release(ref handshakeInit);

AgentNativeInterop.epp_handshake_initiator_finish(
    initiatorHandle, handshakeAckBytes, (nuint)handshakeAckBytes.Length,
    out var sessionHandle, out error);

// Encrypt / decrypt
AgentNativeInterop.epp_session_encrypt(
    sessionHandle, plaintextBytes, (nuint)plaintextBytes.Length,
    EppEnvelopeType.Request, 1, null, 0,
    out var encryptedEnvelope, out error);
AgentNativeInterop.epp_buffer_release(ref encryptedEnvelope);

AgentNativeInterop.epp_session_destroy(sessionHandle);
AgentNativeInterop.epp_identity_destroy(identity);
AgentNativeInterop.epp_shutdown();
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
