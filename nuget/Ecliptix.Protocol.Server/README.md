# Ecliptix.Protocol.Server

High-performance native Signal Protocol server implementation for .NET applications.

## Features

- **X3DH Key Agreement** - Extended Triple Diffie-Hellman for secure initial key exchange
- **Double Ratchet Algorithm** - Forward secrecy and break-in recovery
- **Post-Quantum Cryptography** - Kyber hybrid mode for quantum-resistant encryption
- **AES-256-GCM Encryption** - Authenticated encryption for messages
- **Secure Memory Management** - Guard pages, memory locking via libsodium
- **Cross-Platform** - Windows, Linux, macOS (x64 and ARM64)

## Installation

```bash
dotnet add package Ecliptix.Protocol.Server
```

Or add to your project file:

```xml
<PackageReference Include="Ecliptix.Protocol.Server" Version="1.0.0" />
```

### GitHub Packages

Add the GitHub Packages source to your NuGet configuration:

```xml
<configuration>
  <packageSources>
    <add key="github" value="https://nuget.pkg.github.com/oleksandrmelnychenko/index.json" />
  </packageSources>
</configuration>
```

## Quick Start

```csharp
using Ecliptix.Protocol.Server;

// Initialize the library (once per application)
EcliptixNativeInterop.ecliptix_initialize();

// Create identity keys
var identityKeysResult = EcliptixIdentityKeysWrapper.Create();
if (identityKeysResult.IsErr)
{
    Console.WriteLine($"Failed: {identityKeysResult.UnwrapErr().Message}");
    return;
}

using var identityKeys = identityKeysResult.Unwrap();

// Get public keys for sharing
var publicX25519 = identityKeys.GetPublicX25519().Unwrap();
var publicEd25519 = identityKeys.GetPublicEd25519().Unwrap();

// Create protocol system
var systemResult = EcliptixProtocolSystemWrapper.Create(identityKeys);
using var protocolSystem = systemResult.Unwrap();

// Send encrypted message
byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("Hello, secure world!");
var sendResult = protocolSystem.SendMessage(plaintext);
if (sendResult.IsOk)
{
    byte[] encrypted = sendResult.Unwrap();
    // Send encrypted to peer...
}

// Receive and decrypt message
var receiveResult = protocolSystem.ReceiveMessage(encryptedFromPeer);
if (receiveResult.IsOk)
{
    byte[] decrypted = receiveResult.Unwrap();
    string message = System.Text.Encoding.UTF8.GetString(decrypted);
}

// Cleanup (once per application)
EcliptixNativeInterop.ecliptix_shutdown();
```

## Platform Support

| Platform | Architecture | Status |
|----------|--------------|--------|
| Windows  | x64          | Supported |
| Windows  | x86          | Supported |
| Linux    | x64          | Supported |
| Linux    | ARM64        | Supported |
| macOS    | x64 (Intel)  | Supported |
| macOS    | ARM64 (Apple Silicon) | Supported |

## Performance

| Operation | Latency |
|-----------|---------|
| X3DH Key Agreement | ~150μs |
| Message Encryption | ~12μs |
| Message Decryption | ~14μs |

## Security

- All cryptographic operations use constant-time implementations
- Sensitive memory is securely wiped after use
- Guard pages prevent buffer overflows
- Memory is locked to prevent swapping to disk

## License

MIT License - See LICENSE file for details.
