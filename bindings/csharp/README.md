# EPP.Native - C# Bindings

## Overview

This directory contains C# P/Invoke bindings for the EPP native library. The bindings expose a clean, unversioned handshake + session API that matches the protocol build (no v1/v2 split).

## Architecture

```
┌──────────────────────────────────────┐
│   C# Application Layer               │
│   (Your app logic)                   │
└──────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────┐
│   Managed Wrapper Layer              │
│   (SessionBindings.cs)               │
│   - RAII / IDisposable               │
│   - Error translation                │
│   - Buffer marshaling                │
└──────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────┐
│   P/Invoke Layer                     │
│   (NativeInterop.cs)                 │
│   - DllImport declarations           │
│   - Struct marshaling                │
└──────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────┐
│   C API Layer                        │
│   (epp_api.h / epp_common.cpp)       │
│   - C ABI compatibility              │
│   - Handle management                │
└──────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────┐
│   C++ Protocol Implementation        │
│   (EPP Protocol Core)                │
│   - libsodium cryptography           │
│   - Hybrid PQ handshake + ratchet    │
└──────────────────────────────────────┘
```

## Usage Example (1:1)

```csharp
using System.Text;
using EPP;
using EPP.Native;

// Initialize the native library (once per process)
NativeInterop.epp_init();

// Create identity keys
var aliceKeys = IdentityKeys.Create().Unwrap();
var bobKeys = IdentityKeys.Create().Unwrap();

// Publish prekey bundles (serialized protobufs)
byte[] aliceBundle = aliceKeys.CreatePreKeyBundle().Unwrap();
byte[] bobBundle = bobKeys.CreatePreKeyBundle().Unwrap();

uint maxMessagesPerChain = 200;

// Alice starts handshake using Bob's bundle
var aliceStart = HandshakeInitiator.Start(aliceKeys, bobBundle, maxMessagesPerChain).Unwrap();

// Bob processes handshake init using his local bundle
var bobStart = HandshakeResponder.Start(
    bobKeys,
    bobBundle,
    aliceStart.HandshakeInit,
    maxMessagesPerChain).Unwrap();

// Bob finalizes and returns ack
var bobSession = bobStart.Responder.Finish().Unwrap();

// Alice finalizes using Bob's ack
var aliceSession = aliceStart.Initiator.Finish(bobStart.HandshakeAck).Unwrap();

// Encrypt and decrypt
byte[] plaintext = Encoding.UTF8.GetBytes("Hello, secure world!");
byte[] encrypted = aliceSession.Encrypt(plaintext, EppEnvelopeType.Request, 1).Unwrap();
var decrypted = bobSession.Decrypt(encrypted).Unwrap();

Console.WriteLine(Encoding.UTF8.GetString(decrypted.Plaintext));

// Cleanup happens via IDisposable
aliceSession.Dispose();
bobSession.Dispose();
aliceKeys.Dispose();
bobKeys.Dispose();

// Shutdown the library (once per process)
NativeInterop.epp_shutdown();
```

## Building

### Prerequisites

1. Build the C++ library:
```bash
cd /path/to/protocol-repo
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

2. The library will be output to:
   - macOS: `build/libepp_agent.dylib`
   - Linux: `build/libepp_agent.so`
   - Windows: `build/epp_agent.dll`

### Integration into C# Project

1. Copy the native library to your C# project's output directory.

2. Add the C# binding files to your project:
   ```xml
   <ItemGroup>
     <Compile Include="bindings/csharp/EPP.Native/NativeInterop.cs" />
     <Compile Include="bindings/csharp/EPP.Native/SessionBindings.cs" />
     <Compile Include="nuget/shared/src/Result.cs" />
     <Compile Include="nuget/shared/src/Unit.cs" />
     <Compile Include="nuget/shared/src/UtilityConstants.cs" />
     <Compile Include="nuget/shared/src/ProtocolFailure.cs" />
     <Compile Include="nuget/shared/src/NativeTypes.cs" />
   </ItemGroup>
   ```

3. Ensure the native library is copied to output:
   ```xml
   <ItemGroup>
     <None Include="libepp_agent.dylib">
       <CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory>
     </None>
   </ItemGroup>
   ```

## Usage (Handshake + Session API)
```csharp
NativeInterop.epp_init();

var identityKeys = IdentityKeys.Create().Unwrap();
byte[] bundle = identityKeys.CreatePreKeyBundle().Unwrap();

uint maxMessagesPerChain = 200;
var initiatorStart = HandshakeInitiator.Start(
    identityKeys,
    peerBundle,
    maxMessagesPerChain).Unwrap();
var responderStart = HandshakeResponder.Start(
    peerKeys,
    peerBundle,
    initiatorStart.HandshakeInit,
    maxMessagesPerChain).Unwrap();

var responderSession = responderStart.Responder.Finish().Unwrap();
var initiatorSession = initiatorStart.Initiator.Finish(responderStart.HandshakeAck).Unwrap();

var encrypted = initiatorSession.Encrypt(plaintext, EppEnvelopeType.Request, 1).Unwrap();
var decrypted = responderSession.Decrypt(encrypted).Unwrap();

NativeInterop.epp_shutdown();
```

## Platform Support

| Platform | Architecture | Status |
|----------|--------------|--------|
| macOS    | x64          | ✅ Tested |
| macOS    | ARM64        | ✅ Tested |
| Linux    | x64          | ✅ Supported |
| Linux    | ARM64        | ✅ Supported |
| Windows  | x64          | ⚠️  Not yet tested |

## Troubleshooting

### Library Not Found

**Error:** `DllNotFoundException: Unable to load DLL 'epp_agent'`

**Solution:**
1. Ensure the library is in the same directory as your executable.
2. Verify the library filename matches the platform naming.
