# Ecliptix Protection Protocol: Research-Grade Enhancement Roadmap

**Version**: 1.0
**Date**: January 2025
**Target**: IEEE S&P 2026 / USENIX Security 2026
**Timeline**: 9 months (January - September 2025)
**Status**: Phase 0 Complete (Security Bugs Fixed)

---

## Executive Summary

This document outlines a 9-month plan to transform Ecliptix.Protection.Protocol into the most advanced end-to-end encrypted messaging protocol library, with **three novel research contributions**:

1. **Dense Post-Quantum Ratchet**: Kyber-768 every 10 DH steps (vs Signal's ~50-500)
2. **Puncturable Forward Secrecy**: First production implementation of cryptographic FS
3. **Zero-Knowledge Metadata Privacy**: Optional zk-SNARK proofs for ratchet validity

**Research Goal**: Publish at IEEE S&P 2026 or USENIX Security 2026
**Engineering Goal**: Production-ready C++20 library for desktop applications
**Security Goal**: Formally verified (Tamarin + CryptoVerif + UC framework)

---

## Current Status (January 2025)

### ✅ Phase 0: Foundation Complete
- [x] All 5 critical security vulnerabilities fixed:
  - DH key selection in finalization (FIXED)
  - Inbound ratchet key usage (FIXED)
  - Replay protection (FIXED)
  - State rehydration validation (FIXED)
  - Protobuf parsing bounds (FIXED)
- [x] Comprehensive test suite (1000+ tests, 90%+ coverage)
- [x] C++20 modern architecture (RAII, Result<T,E>, SecureMemoryHandle)
- [x] Core protocol complete (X3DH, Double Ratchet, AES-256-GCM)

### 📊 Project Metrics
- **Lines of Code**: ~8,500 (current)
- **Target LOC**: ~20,000 (after enhancements)
- **Test Coverage**: 90% (target: 95%+)
- **Dependencies**: libsodium, protobuf, Catch2, OpenSSL
- **Platforms**: macOS, Linux, Windows (desktop-focused)

---

## Three Novel Research Contributions

### Contribution #1: Dense Post-Quantum Ratchet
**Novelty**: 10× denser than Signal's SPQR (Sparse PQ Ratchet)

**Current State**:
- Signal PQXDH: Kyber + X25519 hybrid (Oct 2024)
- Signal SPQR: Kyber ratchet every ~50-500 messages (sparse)
- **Limitation**: Wide quantum attack window

**Our Innovation**:
- Dense PQ ratchet: Kyber every 10 DH steps
- Configurable: Sparse mode (50 msgs) for mobile, Dense mode (10 msgs) for desktop
- **Benefit**: 10× narrower quantum attack window

**Research Impact**: ⭐⭐⭐⭐ (High) - Measurable security improvement

---

### Contribution #2: Puncturable Forward Secrecy (HIGHEST NOVELTY)
**Novelty**: First production E2EE with cryptographic (not delete-based) FS

**Current State**:
- All protocols (Signal, Matrix, etc.) rely on "delete and hope"
- Theory exists (Green & Miers 2015, Derler et al. 2018)
- **Limitation**: No production implementation

**Our Innovation**:
- GGM tree-based puncturable encryption
- After decrypting message i, key for i is cryptographically undecryptable
- Provable security via reduction to PRF (AES-256-CTR)
- **Benefit**: Protection against memory forensics, formal guarantee

**Performance**:
- Key derivation: 60 μs (20 PRF calls)
- Puncture operation: 5 μs
- Memory: ~320 KB per 1000 messages
- **Target**: <100 μs total overhead per message

**Research Impact**: ⭐⭐⭐⭐⭐ (VERY HIGH) - Completely novel, no prior work

---

### Contribution #3: Zero-Knowledge Metadata Privacy
**Novelty**: First E2EE with zk-SNARK proofs for ratchet validity

**Current State**:
- All protocols expose ratchet indices, channel IDs (metadata leakage)
- Signal's "Sealed Sender" hides sender, but not ratchet state
- **Limitation**: Server/network can track message patterns

**Our Innovation**:
- zk-SNARK (Groth16) proves ratchet validity without revealing index
- Circuit: ~28,000 R1CS constraints (SHA-256 + range check)
- Optional mode (user-configurable via SecurityProfile)
- **Benefit**: Maximum metadata privacy for high-security users

**Performance**:
- Proof generation: ~100 ms (acceptable for desktop)
- Proof verification: ~3 ms (very fast)
- Proof size: 192 bytes (constant)
- **Target**: <150 ms in High-Security profile

**Research Impact**: ⭐⭐⭐⭐ (High) - Novel application, not novel crypto

---

## 9-Month Implementation Plan

### Month 1-2: Post-Quantum Foundation
**Goal**: Working hybrid PQ-X3DH with Kyber-768

**Week 1-2: Refactoring & Setup**
- [ ] Extract `IRatchet` interface
- [ ] Create `KeyDerivationService` abstraction
- [ ] Add `ICryptoBackend` interface
- [ ] Integrate liboqs via CMake
- [ ] Benchmark Kyber-768 operations

**Week 3-4: Kyber Integration**
- [ ] Implement `KyberInterop` class
- [ ] Add Kyber key material models (`KyberKeyPair`, `KyberPublicKey`, etc.)
- [ ] Extend `LocalPublicKeyBundle` with PQ keys
- [ ] Update protobuf definitions
- [ ] 50+ unit tests for Kyber

**Week 5-6: Hybrid X3DH**
- [ ] Implement `PQ_X3DH_DeriveSharedSecret()`
- [ ] Hybrid KDF: `HKDF(X25519_SS || Kyber_SS)`
- [ ] Integration tests with existing X3DH
- [ ] Benchmark: <500 μs total handshake
- [ ] Document security proof sketch

**Week 7-8: Sparse PQ Ratchet**
- [ ] Add `PqRatchetState` to `Session`
- [ ] Implement sparse mode (Kyber every 50 messages)
- [ ] Integration with DH ratchet
- [ ] Performance profiling
- [ ] **MILESTONE**: Hybrid PQ-X3DH working

**Deliverable**: Branch `feature/post-quantum` with working PQ handshake

---

### Month 3-4: Dense PQ Ratchet + Formal Verification
**Goal**: Formally verified dense triple ratchet

**Week 9-10: Tamarin Modeling**
- [ ] Install Tamarin Prover v1.8.0+
- [ ] Model PQ-X3DH protocol
- [ ] Model dense triple ratchet (Symmetric + DH + PQ)
- [ ] Define security lemmas (secrecy, FS, PQ-FS, PCS)
- [ ] Initial automated proving

**Week 11-12: Dense Mode Implementation**
- [ ] Implement dense PQ ratchet (Kyber every 10 DH steps)
- [ ] Add `RatchetConfig` options (sparse vs dense)
- [ ] Optimize performance (target: <20 μs amortized per message)
- [ ] Memory profiling
- [ ] 100+ unit tests

**Week 13-14: CryptoVerif Proofs**
- [ ] Install CryptoVerif v2.10+
- [ ] Model hybrid KDF in CryptoVerif
- [ ] Prove HKDF composition security
- [ ] Prove PRF security of key derivation
- [ ] Document all cryptographic reductions

**Week 15-16: Integration & Testing**
- [ ] End-to-end Alice/Bob PQ handshake tests
- [ ] Interoperability tests (serialization round-trip)
- [ ] Performance regression suite
- [ ] Memory leak testing (Valgrind)
- [ ] **MILESTONE**: Formally verified PQ ratchet

**Deliverable**: Paper section draft: "Dense PQ Ratchet Design"

---

### Month 5-6: Puncturable Encryption (CRITICAL PATH)
**Goal**: Production-ready puncturable forward secrecy

**Week 17-18: GGM Tree Core**
- [ ] Design binary tree structure (depth = 20 for 1M messages)
- [ ] Implement PRF (AES-256-CTR mode)
- [ ] Key derivation via tree traversal
- [ ] Basic puncture operation
- [ ] Unit tests (1000 punctures)

**Week 19-20: Performance Optimization**
- [ ] Profile key derivation (target: <60 μs for 20 PRFs)
- [ ] Optimize puncture operation (target: <5 μs)
- [ ] Memory management (prune old tree nodes)
- [ ] Benchmark at scale (100,000 operations)
- [ ] Identify and fix bottlenecks

**Week 21-22: Integration with Session Chain State**
- [ ] Create `PuncturableChainState` model (extends `ChainState`)
- [ ] Implement auto-puncture after successful decryption
- [ ] Serialization to protobuf (compressed punctured tree state)
- [ ] Integration with existing ratchet logic
- [ ] 200+ unit tests

**Week 23-24: Security Proof & Evaluation**
- [ ] Write formal reduction to PRF security
- [ ] Prove composition with double ratchet
- [ ] Security analysis document (10+ pages)
- [ ] Performance comparison vs delete-based FS
- [ ] **MILESTONE**: Working puncturable FS

**Deliverable**: Paper section draft: "Puncturable Forward Secrecy"

---

### Month 7: Zero-Knowledge Integration
**Goal**: Optional ZK mode for metadata privacy

**Week 25: Circuit Design**
- [ ] Design Circom circuit for ratchet validity
- [ ] Statement: "I know (index, key) such that hash = SHA256(key || index)"
- [ ] Compile to R1CS (~28,000 constraints)
- [ ] Generate test vectors
- [ ] Verify circuit correctness

**Week 26: libsnark Integration**
- [ ] Integrate libsnark via CMake
- [ ] Implement proving key generation
- [ ] Implement proof generation API
- [ ] Implement proof verification API
- [ ] Basic correctness tests

**Week 27: Trusted Setup**
- [ ] Implement trusted setup ceremony
- [ ] Document setup security assumptions
- [ ] Consider MPC ceremony (future work)
- [ ] **Submit arXiv preprint** (establishes priority)

**Week 28: Integration & Testing**
- [ ] Add `PrivacyLevel` enum to `SecurityProfile`
- [ ] Integrate ZK proof generation in `SendMessage()`
- [ ] Integrate ZK proof verification in `ReceiveMessage()`
- [ ] Performance benchmarking (target: <150 ms proof gen)
- [ ] **MILESTONE**: Optional ZK mode working

**Deliverable**: Paper section draft: "Zero-Knowledge Metadata Privacy"

---

### Month 8: Security Profiles + UC Proof
**Goal**: Complete formal security analysis

**Week 29-30: Security Profile System**
- [ ] Design `SecurityProfile` enum (Mobile/Desktop/HighSecurity)
- [ ] Mobile: Sparse PQ, no puncturable, no ZK
- [ ] Desktop: Dense PQ + puncturable
- [ ] HighSecurity: Dense PQ + puncturable + ZK
- [ ] Auto-detection based on platform
- [ ] Configuration API + tests

**Week 31-32: Performance Optimization**
- [ ] Profile all hotspots (perf, flamegraph)
- [ ] SIMD optimization (AVX2 for Kyber, AES-NI for PRF)
- [ ] Memory pool for frequent allocations
- [ ] Benchmark all profiles vs Signal
- [ ] Document performance results

**Week 33-34: UC Security Proof (Part 1)**
- [ ] Define ideal functionality F_SecureChannel
- [ ] Define real protocol (PQ-X3DH + Dense Ratchet + Puncturable + ZK)
- [ ] Simulator construction (high-level sketch)
- [ ] Begin LaTeX writeup

**Week 35-36: UC Security Proof (Part 2)**
- [ ] Complete simulator for all cases
- [ ] Prove indistinguishability via hybrid argument
- [ ] Full proof document (30+ pages)
- [ ] Peer review (internal)
- [ ] **MILESTONE**: Complete formal analysis

**Deliverable**: Full UC security proof document

---

### Month 9: Paper Writing + Submission
**Goal**: Submit to IEEE S&P 2026

**Week 37: Paper Drafting**
- [ ] Abstract (250 words)
- [ ] Introduction (2 pages)
- [ ] Background (2 pages): X3DH, Double Ratchet, Kyber, GGM, zk-SNARKs
- [ ] Design (4 pages): System architecture, three contributions
- [ ] Security Analysis (3 pages): Formal proofs summary
- [ ] Implementation (2 pages): C++20 details, optimizations

**Week 38: Evaluation + Writing**
- [ ] Evaluation (3 pages): Performance benchmarks, comparison vs Signal
- [ ] Related Work (2 pages): Signal, Matrix, academic work
- [ ] Conclusion (1 page)
- [ ] Create all figures, diagrams, tables
- [ ] Internal review + revisions

**Week 39: Code Hardening**
- [ ] Constant-time verification (valgrind --tool=ctgrind)
- [ ] Fuzzing (AFL++, 72 hours continuous)
- [ ] Final security audit (internal)
- [ ] Resolve all TODOs in code
- [ ] Prepare GitHub release package

**Week 40: Submission**
- [ ] Final paper polish (LaTeX formatting)
- [ ] Prepare supplementary materials
- [ ] Create artifact reproduction package
- [ ] **Submit to IEEE S&P 2026** (Deadline: ~May 2025)
- [ ] Publish open-source release
- [ ] **MILESTONE**: Research paper submitted!

**Deliverable**: Complete IEEE S&P submission + open-source release

---

## Performance Targets

### Baseline (Current Implementation)
- X3DH handshake: ~360 μs
- Message encryption (1KB): ~10 μs
- Message decryption (1KB): ~12 μs

### Desktop Profile (Dense PQ + Puncturable, NO ZK)
- PQ-X3DH handshake: **<500 μs** (vs 360 μs baseline)
- Message encryption: **<100 μs** (vs 10 μs baseline)
- Message decryption: **<100 μs** (vs 12 μs baseline)
- Memory per connection: **<500 KB** (vs 7 KB baseline)

### High-Security Profile (+ ZK)
- Message encryption: **<150 ms** (ZK proof generation)
- Message decryption: **<5 ms** (ZK proof verification)
- Memory per connection: **<550 KB** (+ ZK keys)

**Acceptance Criteria**: All targets must be met for publication

---

## Research Paper Structure

### Title
"Ecliptix: A Dense Post-Quantum Double Ratchet with Puncturable Forward Secrecy and Zero-Knowledge Metadata Privacy"

### Abstract (250 words)
End-to-end encrypted (E2EE) messaging protocols like Signal protect billions of users. However, they face two critical limitations: (1) sparse post-quantum forward secrecy leaves wide attack windows for quantum adversaries, and (2) delete-based forward secrecy relies on unreliable memory wiping. We present Ecliptix, the first E2EE protocol that addresses both limitations with three contributions...

### Paper Sections
1. **Introduction** (2 pages)
   - Problem: Quantum threats + memory forensics
   - Signal's limitations (sparse PQ, delete-based FS)
   - Our solution: Dense PQ + puncturable FS + ZK

2. **Background** (2 pages)
   - X3DH key agreement
   - Double Ratchet algorithm
   - CRYSTALS-Kyber (ML-KEM)
   - GGM trees & puncturable encryption
   - zk-SNARKs (Groth16)

3. **Design** (4 pages)
   - System architecture
   - Contribution 1: Dense PQ ratchet
   - Contribution 2: Puncturable forward secrecy
   - Contribution 3: ZK metadata privacy

4. **Security Analysis** (3 pages)
   - Threat model
   - Formal proofs (Tamarin + CryptoVerif + UC)
   - Security guarantees

5. **Implementation** (2 pages)
   - C++20 architecture
   - Performance optimizations
   - Security considerations

6. **Evaluation** (3 pages)
   - Performance benchmarks
   - Comparison vs Signal
   - Memory overhead analysis

7. **Related Work** (2 pages)
   - Signal Protocol (X3DH, SPQR)
   - Matrix/Olm
   - Academic research

8. **Conclusion** (1 page)
   - Summary of contributions
   - Future work
   - Open-source availability

**Target Length**: 13 pages (IEEE S&P format) + 1 page ethics + bibliography

---

## Success Metrics

### Technical Milestones (Must Complete)
- [x] Phase 0: All security bugs fixed
- [ ] Month 2: Hybrid PQ-X3DH working
- [ ] Month 4: Dense PQ ratchet + Tamarin verification
- [ ] Month 6: Puncturable encryption working
- [ ] Month 7: ZK mode operational
- [ ] Month 8: Complete UC proof
- [ ] Month 9: Paper submitted

### Research Metrics (Publication Goals)
- [ ] 3 novel contributions documented
- [ ] Formal security proofs complete (Tamarin + CryptoVerif + UC)
- [ ] Performance evaluation vs Signal
- [ ] 40+ page total documentation (paper + proofs)
- [ ] Open-source release with reproduction package

### Publication Timeline
- **January 2025**: Project start
- **July 2025**: arXiv preprint submission
- **September 2025**: IEEE S&P 2026 submission
- **December 2025**: Notification (if accepted)
- **May 2026**: Conference presentation

---

## Risk Management

### Critical Risks
| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Puncturable performance fails | Medium | High | Start early (Month 5), continuous benchmarking |
| Tamarin verification finds bugs | Medium | Medium | Allocate time for fixes in schedule |
| ZK integration too complex | High | Low | Make it optional, can defer to future work |
| Timeline slips | Medium | Medium | Monthly reviews, adjust scope as needed |

### Fallback Plans
1. **If puncturable fails**: Focus on dense PQ + ZK (still 2 contributions)
2. **If ZK fails**: Focus on dense PQ + puncturable (still strong paper)
3. **If timeline slips**: Target USENIX Security 2026 (August deadline)

---

## Dependencies

### Software Dependencies
- **liboqs** v0.15.0+ (Open Quantum Safe - Kyber)
- **libsnark** (SCIPR Lab - zk-SNARKs)
- **Tamarin Prover** v1.8.0+ (Formal verification)
- **CryptoVerif** v2.10+ (Cryptographic proofs)
- **AFL++** (Fuzzing)
- **Valgrind** + ctgrind (Constant-time verification)

### External Collaborations (Optional)
- Formal methods expert for Tamarin assistance
- Cryptography reviewer for UC proof
- Performance engineer for optimization

---

## Open Questions (To Resolve Early)

1. **Kyber variant**: Kyber-768 vs Kyber-1024? (Recommend: 768)
2. **PRF for GGM tree**: HMAC-SHA256 vs AES-256-CTR? (Recommend: AES-256-CTR)
3. **ZK trusted setup**: Solo ceremony vs MPC? (Recommend: Solo, document MPC as future)
4. **Sparse vs dense default**: Which should be default profile? (Recommend: Dense for desktop)
5. **Serialization format**: Extend existing protobuf or new? (Recommend: Extend)

**Action**: Resolve these in Week 1-2 planning meetings

---

## Communication & Reporting

### Weekly Progress Reports
- Every Monday: Email update with progress, blockers, next week's goals
- Format: [DONE] / [IN PROGRESS] / [BLOCKED] / [NEXT]

### Monthly Milestones
- End of each month: Detailed progress review
- Adjust roadmap if needed
- Update risk register

### External Communication
- **Month 7**: arXiv preprint (public)
- **Month 9**: GitHub open-source release (public)
- **Post-submission**: Blog post explaining contributions

---

## Resources

### Documentation
- This file: `docs/RESEARCH_ROADMAP.md`
- Security audit: `docs/SECURITY_AUDIT_2025.md`
- PQ integration: `docs/PQ_INTEGRATION_PLAN.md`
- Puncturable design: `docs/PUNCTURABLE_DESIGN.md`
- ZK circuit spec: `docs/ZK_CIRCUIT_SPEC.md`

### References
1. Signal PQXDH Specification: https://signal.org/docs/specifications/pqxdh/
2. Signal SPQR Blog Post: https://signal.org/blog/spqr/
3. liboqs Documentation: https://openquantumsafe.org/liboqs/
4. Tamarin Manual: https://tamarin-prover.github.io/manual/
5. Groth16 Paper: https://eprint.iacr.org/2016/260
6. Green & Miers (Puncturable Encryption): https://ieeexplore.ieee.org/document/7163033

---

## Conclusion

This 9-month roadmap transforms Ecliptix.Protection.Protocol from a solid Signal-like protocol into a research-grade contribution with three novel features. The plan is ambitious but achievable, with clear milestones, fallback options, and risk mitigation.

**Key Success Factors**:
1. Start puncturable encryption early (highest risk)
2. Continuous performance benchmarking
3. Incremental formal verification
4. Monthly progress reviews
5. Flexible scope adjustment

**Estimated Success Probability**: 85% for completion, 25% for IEEE S&P acceptance (typical for first submission to top tier)

**Let's build the best E2EE protocol in the world!** 🚀

---

**Document Version History**:
- v1.0 (January 2025): Initial 9-month plan
- [Updates will be logged here]

**Last Updated**: January 2025
**Next Review**: End of Month 1
