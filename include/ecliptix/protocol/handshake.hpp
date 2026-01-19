#pragma once
#include "ecliptix/core/failures.hpp"
#include "ecliptix/core/result.hpp"
#include "ecliptix/identity/identity_keys.hpp"
#include "protocol/handshake.pb.h"
#include "protocol/state.pb.h"
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace ecliptix::protocol {

class Session;

class HandshakeInitiator {
public:
    [[nodiscard]] static Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure> Start(
        identity::IdentityKeys& identity_keys,
        const ecliptix::proto::protocol::PreKeyBundle& peer_bundle,
        uint32_t max_messages_per_chain);

    [[nodiscard]] const ecliptix::proto::protocol::HandshakeInit& Message() const;
    [[nodiscard]] const std::vector<uint8_t>& EncodedMessage() const;

    [[nodiscard]] Result<std::unique_ptr<Session>, ProtocolFailure> Finish(
        const ecliptix::proto::protocol::HandshakeAck& ack);

    HandshakeInitiator(const HandshakeInitiator&) = delete;
    HandshakeInitiator& operator=(const HandshakeInitiator&) = delete;
    HandshakeInitiator(HandshakeInitiator&&) noexcept = default;
    HandshakeInitiator& operator=(HandshakeInitiator&&) noexcept = default;
    ~HandshakeInitiator();

private:
    HandshakeInitiator() = default;

    struct State;
    std::unique_ptr<State> state_{};
    ecliptix::proto::protocol::HandshakeInit init_message_{};
    std::vector<uint8_t> init_bytes_{};
};

class HandshakeResponder {
public:
    [[nodiscard]] static Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure> Process(
        identity::IdentityKeys& identity_keys,
        const ecliptix::proto::protocol::PreKeyBundle& local_bundle,
        std::span<const uint8_t> init_message_bytes,
        uint32_t max_messages_per_chain);

    [[nodiscard]] const ecliptix::proto::protocol::HandshakeAck& Ack() const;
    [[nodiscard]] const std::vector<uint8_t>& EncodedAck() const;

    [[nodiscard]] Result<std::unique_ptr<Session>, ProtocolFailure> Finish();

    HandshakeResponder(const HandshakeResponder&) = delete;
    HandshakeResponder& operator=(const HandshakeResponder&) = delete;
    HandshakeResponder(HandshakeResponder&&) noexcept = default;
    HandshakeResponder& operator=(HandshakeResponder&&) noexcept = default;
    ~HandshakeResponder();

private:
    HandshakeResponder() = default;

    struct State;
    std::unique_ptr<State> state_{};
    ecliptix::proto::protocol::HandshakeAck ack_message_{};
    std::vector<uint8_t> ack_bytes_{};
};

}  // namespace ecliptix::protocol
