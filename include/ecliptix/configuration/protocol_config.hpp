#pragma once

#include <cstdint>

namespace ecliptix::protocol::configuration {

/// Security level for the protocol configuration
///
/// Determines which cryptographic features are enabled:
/// - Classical: X25519 + Ed25519 only (baseline Signal-like protocol)
/// - PostQuantum: Classical + Kyber-768 hybrid construction
/// - Puncturable: PostQuantum + GGM tree puncturable encryption
/// - ZeroKnowledge: All features + zk-SNARK metadata privacy
enum class SecurityLevel : uint8_t {
    /// Classical cryptography only (X25519 DH + Ed25519 signatures)
    /// - Performance: Baseline (fastest)
    /// - Security: ~128-bit classical, vulnerable to quantum
    /// - Overhead: None
    Classical = 0,

    /// Hybrid post-quantum (X25519 ⊕ Kyber-768)
    /// - Performance: +40% handshake time, +20% per-message
    /// - Security: ~128-bit classical + ~164-bit quantum resistant
    /// - Overhead: +1184 bytes per handshake (Kyber public key)
    PostQuantum = 1,

    /// Post-quantum + GGM puncturable encryption
    /// - Performance: PostQuantum + 60μs key derivation
    /// - Security: Cryptographic forward secrecy (not delete-based)
    /// - Overhead: +4KB per connection (GGM tree state)
    Puncturable = 2,

    /// All features + zk-SNARK metadata privacy
    /// - Performance: Puncturable + 150ms proof generation
    /// - Security: Zero-knowledge metadata hiding
    /// - Overhead: +192 bytes per message (proof)
    ZeroKnowledge = 3
};

/// Configuration for protocol cryptographic features
///
/// This class provides a type-safe way to configure which cryptographic
/// enhancements are enabled. Design principles:
///
/// 1. **Additive Layers**: Each level builds on the previous
///    - Classical is always available (baseline)
///    - PostQuantum includes Classical
///    - Puncturable includes PostQuantum + Classical
///    - ZeroKnowledge includes all features
///
/// 2. **Zero Overhead**: Disabled features have NO runtime cost
///    - Classical mode is identical to current implementation
///    - No virtual dispatch, no dynamic allocation
///    - Compile-time branching only
///
/// 3. **Non-Breaking**: All features are optional and backward compatible
///    - Protobuf uses optional fields
///    - Handshake negotiates common features
///    - Graceful degradation to Classical if needed
///
/// @example
/// ```cpp
/// // Desktop app: Enable all features
/// auto config = ProtocolConfig::MaximumSecurity();
///
/// // Mobile app: PQ only, skip ZK proofs
/// auto config = ProtocolConfig::PostQuantumOnly();
///
/// // Legacy mode: Classical only
/// auto config = ProtocolConfig::ClassicalOnly();
///
/// // Check features
/// if (config.IsPqEnabled()) {
///     // Use Kyber-768 hybrid construction
/// }
/// ```
class ProtocolConfig {
public:
    // =========================================================================
    // Factory Methods
    // =========================================================================

    /// Classical cryptography only (baseline protocol)
    ///
    /// Identical to current implementation:
    /// - X25519 for key agreement
    /// - Ed25519 for signatures
    /// - AES-256-GCM for encryption
    /// - HKDF-SHA256 for key derivation
    ///
    /// Use when:
    /// - Maximum performance is critical
    /// - Quantum threat is not a concern (pre-2030)
    /// - Compatibility with legacy systems required
    [[nodiscard]] static constexpr ProtocolConfig ClassicalOnly() noexcept {
        return ProtocolConfig(SecurityLevel::Classical);
    }

    /// Post-quantum hybrid (X25519 ⊕ Kyber-768)
    ///
    /// Adds quantum resistance via hybrid construction:
    /// - X25519 DH (classical security)
    /// - Kyber-768 KEM (quantum resistance)
    /// - HKDF combines both (secure if either holds)
    ///
    /// Use when:
    /// - Quantum threat mitigation is priority
    /// - Can tolerate +40% handshake overhead
    /// - Desktop/server deployment (not mobile)
    [[nodiscard]] static constexpr ProtocolConfig PostQuantumOnly() noexcept {
        return ProtocolConfig(SecurityLevel::PostQuantum);
    }

    /// Post-quantum + puncturable encryption (GGM tree)
    ///
    /// Adds cryptographic forward secrecy:
    /// - All PostQuantum features
    /// - GGM binary tree (depth 20, 1M messages)
    /// - Instant puncturing (40μs, no delete required)
    ///
    /// Use when:
    /// - Forward secrecy is critical
    /// - Can tolerate +4KB per connection
    /// - Long-lived connections (ephemeral messaging)
    [[nodiscard]] static constexpr ProtocolConfig PuncturableOnly() noexcept {
        return ProtocolConfig(SecurityLevel::Puncturable);
    }

    /// Maximum security (all features enabled)
    ///
    /// Adds zero-knowledge metadata privacy:
    /// - All Puncturable features
    /// - zk-SNARK proofs (Groth16, 192 bytes)
    /// - Metadata hiding (sender, timing, ratchet state)
    ///
    /// Use when:
    /// - Metadata privacy is critical
    /// - Can tolerate +150ms proof generation
    /// - Desktop deployment only
    [[nodiscard]] static constexpr ProtocolConfig MaximumSecurity() noexcept {
        return ProtocolConfig(SecurityLevel::ZeroKnowledge);
    }

    /// Default configuration (Classical for compatibility/testing)
    ///
    /// Keeps the baseline Signal-style flow enabled by default to avoid
    /// surprising PQ requirements in environments that have not negotiated
    /// Kyber support. Post-quantum and higher tiers remain opt-in.
    [[nodiscard]] static constexpr ProtocolConfig Default() noexcept {
        return ClassicalOnly();
    }

    // =========================================================================
    // Feature Queries
    // =========================================================================

    /// Check if post-quantum cryptography is enabled
    ///
    /// When true:
    /// - Kyber-768 keys will be generated
    /// - Hybrid X3DH handshake will be used
    /// - Protobuf will include PQ fields
    [[nodiscard]] constexpr bool IsPqEnabled() const noexcept {
        return level_ >= SecurityLevel::PostQuantum;
    }

    /// Check if puncturable encryption is enabled
    ///
    /// When true:
    /// - GGM tree will be initialized (depth 20)
    /// - Message keys derived from tree nodes
    /// - Automatic puncturing after use
    [[nodiscard]] constexpr bool IsPuncturableEnabled() const noexcept {
        return level_ >= SecurityLevel::Puncturable;
    }

    /// Check if zero-knowledge proofs are enabled
    ///
    /// When true:
    /// - zk-SNARK proofs generated for messages
    /// - Metadata hidden in proofs
    /// - Verifier checks proofs on receive
    [[nodiscard]] constexpr bool IsZkEnabled() const noexcept {
        return level_ >= SecurityLevel::ZeroKnowledge;
    }

    /// Get the configured security level
    [[nodiscard]] constexpr SecurityLevel GetSecurityLevel() const noexcept {
        return level_;
    }

    // =========================================================================
    // Performance Estimates
    // =========================================================================

    /// Estimate handshake overhead in microseconds
    ///
    /// Returns approximate additional time compared to Classical:
    /// - Classical: 0μs (baseline ~360μs total)
    /// - PostQuantum: +140μs (Kyber keygen + encaps)
    /// - Puncturable: +200μs (PostQuantum + GGM init)
    /// - ZeroKnowledge: +200μs (same, ZK only for messages)
    [[nodiscard]] constexpr uint32_t EstimateHandshakeOverheadUs() const noexcept {
        switch (level_) {
            case SecurityLevel::Classical:
                return 0;
            case SecurityLevel::PostQuantum:
                return 140;
            case SecurityLevel::Puncturable:
            case SecurityLevel::ZeroKnowledge:
                return 200;
        }
        return 0; // Unreachable
    }

    /// Estimate per-message overhead in microseconds
    ///
    /// Returns approximate additional time compared to Classical:
    /// - Classical: 0μs (baseline ~50μs AES-GCM)
    /// - PostQuantum: +10μs (hybrid KDF)
    /// - Puncturable: +70μs (PostQuantum + GGM derive + puncture)
    /// - ZeroKnowledge: +150,070μs (Puncturable + proof generation)
    [[nodiscard]] constexpr uint32_t EstimateMessageOverheadUs() const noexcept {
        switch (level_) {
            case SecurityLevel::Classical:
                return 0;
            case SecurityLevel::PostQuantum:
                return 10;
            case SecurityLevel::Puncturable:
                return 70;
            case SecurityLevel::ZeroKnowledge:
                return 150'070; // 150ms proof generation
        }
        return 0; // Unreachable
    }

    /// Estimate memory overhead per connection in bytes
    ///
    /// Returns approximate additional memory compared to Classical:
    /// - Classical: 0 bytes (baseline ~2KB)
    /// - PostQuantum: +2400 bytes (Kyber secret key)
    /// - Puncturable: +6400 bytes (PostQuantum + GGM tree)
    /// - ZeroKnowledge: +10,400 bytes (Puncturable + proving key cache)
    [[nodiscard]] constexpr uint32_t EstimateMemoryOverheadBytes() const noexcept {
        switch (level_) {
            case SecurityLevel::Classical:
                return 0;
            case SecurityLevel::PostQuantum:
                return 2400; // Kyber-768 secret key
            case SecurityLevel::Puncturable:
                return 6400; // Kyber + GGM tree state
            case SecurityLevel::ZeroKnowledge:
                return 10'400; // Puncturable + ZK proving key
        }
        return 0; // Unreachable
    }

    // =========================================================================
    // Comparison Operators
    // =========================================================================

    [[nodiscard]] constexpr bool operator==(const ProtocolConfig& other) const noexcept {
        return level_ == other.level_;
    }

    [[nodiscard]] constexpr bool operator!=(const ProtocolConfig& other) const noexcept {
        return level_ != other.level_;
    }

    /// Check if this config is more secure than another
    [[nodiscard]] constexpr bool operator>(const ProtocolConfig& other) const noexcept {
        return level_ > other.level_;
    }

    [[nodiscard]] constexpr bool operator<(const ProtocolConfig& other) const noexcept {
        return level_ < other.level_;
    }

private:
    /// Private constructor - use factory methods
    explicit constexpr ProtocolConfig(const SecurityLevel level) noexcept
        : level_(level) {}

    SecurityLevel level_;
};

} // namespace ecliptix::protocol::configuration
