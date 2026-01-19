#pragma once
#include "ecliptix/core/failures.hpp"
#include "ecliptix/core/result.hpp"
#include "protocol/envelope.pb.h"
#include "protocol/state.pb.h"
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <mutex>
#include <unordered_set>

namespace ecliptix::protocol {

/// Secure messaging session implementing Double Ratchet with X3DH key agreement.
///
/// The Session class manages encrypted bidirectional communication between two parties.
/// It provides forward secrecy through the Double Ratchet Algorithm and post-compromise
/// security through periodic key rotation.
///
/// Thread Safety: All public methods are thread-safe; internal state is protected by mutex.
class Session {
public:
    /// Result of decrypting a SecureEnvelope.
    struct DecryptResult {
        std::vector<uint8_t> plaintext;
        ecliptix::proto::protocol::EnvelopeMetadata metadata;
    };

    /// State produced by handshake, used to initialize a new Session.
    struct HandshakeState {
        ecliptix::proto::protocol::ProtocolState state;
        std::vector<uint8_t> kyber_shared_secret;
    };

    /// The peer's identity key pair (public keys only).
    ///
    /// Contains the cryptographic identity of the remote party. The Ed25519 key
    /// is used for signature verification, while the X25519 key is used in the
    /// key agreement protocol. Both keys are bound into the session's identity
    /// binding hash to cryptographically tie messages to specific identities.
    struct PeerIdentity {
        std::vector<uint8_t> ed25519_public;  ///< Ed25519 signing public key (32 bytes)
        std::vector<uint8_t> x25519_public;   ///< X25519 key exchange public key (32 bytes)
    };

    /// The local party's identity key pair (public keys only).
    ///
    /// Contains the cryptographic identity of the local party. Like PeerIdentity,
    /// both keys are bound into the session's identity binding hash.
    struct LocalIdentity {
        std::vector<uint8_t> ed25519_public;  ///< Ed25519 signing public key (32 bytes)
        std::vector<uint8_t> x25519_public;   ///< X25519 key exchange public key (32 bytes)
    };

    [[nodiscard]] static Result<std::unique_ptr<Session>, ProtocolFailure> FromHandshakeState(
        HandshakeState state);

    [[nodiscard]] static Result<std::unique_ptr<Session>, ProtocolFailure> FromState(
        const ecliptix::proto::protocol::ProtocolState& state);

    [[nodiscard]] Result<ecliptix::proto::protocol::ProtocolState, ProtocolFailure> ExportState();

    [[nodiscard]] Result<ecliptix::proto::protocol::SecureEnvelope, ProtocolFailure> Encrypt(
        std::span<const uint8_t> payload,
        ecliptix::proto::protocol::EnvelopeType envelope_type,
        uint32_t envelope_id,
        std::string_view correlation_id = "");

    [[nodiscard]] Result<DecryptResult, ProtocolFailure> Decrypt(
        const ecliptix::proto::protocol::SecureEnvelope& envelope);

    [[nodiscard]] uint32_t Version() const noexcept;
    [[nodiscard]] bool IsInitiator() const noexcept;

    /// Returns the peer's identity keys (Ed25519 and X25519 public keys).
    ///
    /// The returned keys are copies; the caller owns the memory.
    /// Thread-safe: acquires internal lock.
    [[nodiscard]] PeerIdentity GetPeerIdentity() const;

    /// Returns the local party's identity keys (Ed25519 and X25519 public keys).
    ///
    /// The returned keys are copies; the caller owns the memory.
    /// Thread-safe: acquires internal lock.
    [[nodiscard]] LocalIdentity GetLocalIdentity() const;

    /// Returns the identity binding hash (32 bytes).
    ///
    /// The binding hash is computed as:
    ///   SHA-256(label || sorted(local_ed25519, peer_ed25519) || sorted(local_x25519, peer_x25519))
    ///
    /// This hash:
    /// - Is deterministic: both parties compute the same value regardless of who is "local"
    /// - Includes both Ed25519 (signature) and X25519 (key exchange) identity keys
    /// - Is included in AAD for all encrypted messages to bind messages to identities
    /// - Prevents identity misbinding attacks where an attacker substitutes identities
    ///
    /// The returned hash is a copy; the caller owns the memory.
    /// Thread-safe: acquires internal lock.
    [[nodiscard]] std::vector<uint8_t> GetIdentityBindingHash() const;

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    Session(Session&&) noexcept = delete;
    Session& operator=(Session&&) noexcept = delete;
    ~Session() = default;

private:
    explicit Session(
        ecliptix::proto::protocol::ProtocolState state,
        std::vector<uint8_t> pending_kyber_shared_secret);

    [[nodiscard]] Result<Unit, ProtocolFailure> InitializeFromHandshake();
    [[nodiscard]] Result<std::vector<uint8_t>, ProtocolFailure> NextSendMessageKey(uint64_t& message_index);
    [[nodiscard]] Result<std::vector<uint8_t>, ProtocolFailure> GetRecvMessageKey(uint64_t message_index);
    [[nodiscard]] Result<Unit, ProtocolFailure> MaybeRotateSendRatchet(
        ecliptix::proto::protocol::SecureEnvelope& envelope);
    [[nodiscard]] Result<Unit, ProtocolFailure> ApplyRecvRatchet(
        const ecliptix::proto::protocol::SecureEnvelope& envelope);
    void ResetReplayTracking(uint64_t epoch);

    bool is_initiator_ = false;
    ecliptix::proto::protocol::ProtocolState state_{};
    std::vector<uint8_t> pending_kyber_shared_secret_{};
    std::map<uint64_t, std::vector<uint8_t>> skipped_message_keys_{};
    uint64_t replay_epoch_ = 0;
    std::unordered_set<std::string> seen_payload_nonces_{};
    mutable std::mutex lock_;
};

}
