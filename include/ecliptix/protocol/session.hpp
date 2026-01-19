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

class Session {
public:
    struct DecryptResult {
        std::vector<uint8_t> plaintext;
        ecliptix::proto::protocol::EnvelopeMetadata metadata;
    };

    struct HandshakeState {
        ecliptix::proto::protocol::ProtocolState state;
        std::vector<uint8_t> kyber_shared_secret;
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
