# Build Targets (Client vs Server)

We now produce two binaries so desktop/mobile apps and server-side services can be built independently:

- **Agent target** (`Ecliptix_Protocol_System`, alias `Ecliptix::Protocol`)
  - Sources: core + C API (`src/c_api/ecliptix_c_api.cpp`) for native/mobile bindings.
  - Output name: `epp_agent` (shared if `ECLIPTIX_BUILD_SHARED=ON`, otherwise static).

- **Relay target** (`Ecliptix_Protocol_Server`, alias `Ecliptix::ProtocolServer`)
  - Sources: core only (no C API), minimal surface for headless/server deployments.
  - Output name: `epp_relay`.

Options (CMake):
```
-DECLIPTIX_BUILD_CLIENT_TARGET=ON   # default ON
-DECLIPTIX_BUILD_SERVER_TARGET=ON   # default ON
-DECLIPTIX_BUILD_SHARED=OFF         # build static by default
```

Examples:
```
# Build both client + server (default)
cmake -S . -B build
cmake --build build

# Server-only build
cmake -S . -B build -DECLIPTIX_BUILD_CLIENT_TARGET=OFF -DECLIPTIX_BUILD_SERVER_TARGET=ON
cmake --build build

# Client-only build (desktop/mobile bindings)
cmake -S . -B build -DECLIPTIX_BUILD_CLIENT_TARGET=ON -DECLIPTIX_BUILD_SERVER_TARGET=OFF
cmake --build build
```

Bindings:
- C#/PInvoke targets the agent library name (`epp_agent`) by default. If you **must** point it at a differently named artifact, define `ECLIPTIX_SERVER` in your C# build to switch the DllImport library name to `epp_relay` (note: the relay target does not expose the C API).

Both targets retain the same cryptographic guarantees (hybrid DH ratchet with mandatory Kyber, ratchet epochs on envelopes to detect stale state). Pick the target that matches your runtime: use the agent build for native/mobile apps that need the C API or managed bindings; use the relay build for stateless relays or headless services.
