# Repository Guidelines

## Project Structure & Module Organization
- `include/ecliptix/` exposes the public API (core, crypto, protocol, security, utilities, configuration); keep headers lean under `ecliptix::protocol`.
- `src/` mirrors headers: `crypto/` handles libsodium + liboqs (Kyber), `protocol/` implements the ratchet, `c_api/` backs bindings; `proto/` builds the `ecliptix_proto` target.
- `tests/` uses Catch2: `unit/` for fast checks, `security/` and `attacks/` for adversarial cases, `interop/` for X3DH/double-ratchet vectors, `integration/` for workflows; slow suites stay in `performance/`, `concurrency/`, `fuzzing/`, and `benchmarks/`.
- `examples/` are runnable snippets; `docs/` capture design notes and PQ/hybrid plans.

## Build, Test, and Development Commands
- Configure: `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DECLIPTIX_BUILD_TESTS=ON`; add sanitizers with `-DECLIPTIX_ENABLE_ASAN=ON`/`TSAN`/`UBSAN`.
- Pull in slow/long-running suites only when needed: `-DECLIPTIX_ENABLE_SLOW_TESTS=ON` (default OFF to keep CI fast).
- Build: `cmake --build build` (targets `Ecliptix::Protocol`, `ecliptix_tests`, examples).
- Test: `ctest --test-dir build --output-on-failure` for the default set; focus via `./build/ecliptix_tests "[connection]"` or list with `ctest -N`.
- Dependencies: libsodium, liboqs (>=0.15.0), OpenSSL, Protobuf; spdlog optional. Confirm pkg-config sees these before configuring.

## Coding Style & Naming Conventions
- C++20, 4-space indent, and `-Wall -Wextra -Wpedantic -Werror`; keep builds warning-free.
- Namespaces follow `ecliptix::protocol::<module>`. Public types and methods use `PascalCase`; internal helpers may use `snake_case`.
- Prefer `std::span`, `std::string_view`, and the internal `Result<T, E>` / `Option<T>`; avoid raw pointers except at boundaries. Keep headers minimal and honor secure-memory handling around key material.

## Testing Guidelines
- Catch2 v3 registered via CTest. Name files `test_<area>.cpp` and `TEST_CASE` strings after observable behaviors.
- Keep deterministic coverage in `tests/unit/`; adversarial/regression vectors go to `security/`, `attacks/`, or `interop/`. Put expensive or randomized cases behind `ECLIPTIX_ENABLE_SLOW_TESTS`.
- For protocol or PQ changes, add regression coverage for ratchet transitions, replay protection, and state rehydration.

## Commit & Pull Request Guidelines
- Commits use concise, imperative summaries (~72 chars), e.g., “Add Kyber hybrid ratchet guardrails”.
- PRs should note intent, security/behavioral impact, test commands run (call out if slow suites were enabled), and docs updated. Link issues/milestones and include logs or screenshots for interop/performance updates.

## Security & Configuration Tips
- `ProtocolConfig` controls hybrid PQ usage; keep peers aligned and fail fast if required PQ material is missing.
- Store private keys in secure memory handles, zeroize temporary buffers, and avoid logging secrets. Validate Protobuf inputs (sizes, formats) before using ratchet keys or ciphertexts.
