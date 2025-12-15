# Build Targets (Client vs Server)

We now produce two binaries so desktop/mobile apps and server-side services can be built independently:

- **Client target** (`Ecliptix_Protocol_System`, alias `Ecliptix::Protocol`)  
  - Sources: core + C API (`src/c_api/ecliptix_c_api.cpp`) for native/mobile bindings.  
  - Output name: `ecliptix_protocol` (shared if `ECLIPTIX_BUILD_SHARED=ON`, otherwise static).

- **Server target** (`Ecliptix_Protocol_Server`, alias `Ecliptix::ProtocolServer`)  
  - Sources: core only (no C API), minimal surface for headless/server deployments.  
  - Output name: `ecliptix_protocol_server`.

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

Both targets retain the same cryptographic guarantees (hybrid DH ratchet with mandatory Kyber, ratchet epochs on envelopes to detect stale state). Pick the target that matches your runtime: use the client build for native/mobile apps that need the C API or managed bindings; use the server build for stateless relays or headless services.***
