#pragma once
#include "ecliptix/protocol/connection/protocol_connection.hpp"
#include "ecliptix/identity/identity_keys.hpp"
#include "ecliptix/interfaces/i_protocol_event_handler.hpp"
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"
#include "common/secure_envelope.pb.h"
#include "protocol/protocol_state.pb.h"
#include "protocol/key_exchange.pb.h"
#include <optional>
#include <shared_mutex>

namespace ecliptix::protocol {
    using protocol::Result;
    using protocol::Unit;
    using protocol::ProtocolFailure;
    using protocol::IProtocolEventHandler;
    using connection::ProtocolConnection;
    using identity::IdentityKeys;

    class ProtocolSystem {
    public:
        [[nodiscard]] static Result<std::unique_ptr<ProtocolSystem>, ProtocolFailure>
        Create(std::unique_ptr<IdentityKeys> identity_keys);

        [[nodiscard]] static Result<std::unique_ptr<ProtocolSystem>, ProtocolFailure>
        CreateFromRootAndPeerBundle(std::unique_ptr<IdentityKeys> identity_keys,
                                    std::span<const uint8_t> root_key,
                                    const proto::protocol::PublicKeyBundle &peer_bundle,
                                    bool is_initiator);

        [[nodiscard]] static Result<std::unique_ptr<ProtocolSystem>, ProtocolFailure>
        CreateFromRootAndPeerBundle(std::unique_ptr<IdentityKeys> identity_keys,
                                    std::span<const uint8_t> root_key,
                                    const proto::protocol::PublicKeyBundle &peer_bundle,
                                    bool is_initiator,
                                    std::span<const uint8_t> kyber_ciphertext,
                                    std::span<const uint8_t> kyber_shared_secret);

        [[nodiscard]] static Result<std::unique_ptr<ProtocolSystem>, ProtocolFailure>
        FromProtoState(std::unique_ptr<IdentityKeys> identity_keys,
                       const proto::protocol::RatchetState &state);

        [[nodiscard]] Result<Unit, ProtocolFailure> FinalizeWithRootAndPeerBundle(
            std::span<const uint8_t> root_key,
            const proto::protocol::PublicKeyBundle &peer_bundle,
            bool is_initiator);

        [[nodiscard]] Result<Unit, ProtocolFailure> FinalizeWithRootAndPeerBundle(
            std::span<const uint8_t> root_key,
            const proto::protocol::PublicKeyBundle &peer_bundle,
            bool is_initiator,
            std::span<const uint8_t> kyber_ciphertext,
            std::span<const uint8_t> kyber_shared_secret);

        [[nodiscard]] Result<Unit, ProtocolFailure> FinalizeWithRootAndPeerBundle(
            std::span<const uint8_t> root_key,
            const proto::protocol::PublicKeyBundle &peer_bundle,
            bool is_initiator,
            std::span<const uint8_t> kyber_ciphertext,
            std::span<const uint8_t> kyber_shared_secret,
            std::span<const uint8_t> initial_dh_public_key,
            std::span<const uint8_t> initial_dh_private_key);

        void SetConnection(std::unique_ptr<ProtocolConnection> connection);

        [[nodiscard]] const IdentityKeys &GetIdentityKeys() const;
        [[nodiscard]] IdentityKeys &GetIdentityKeysMutable() const;

        void SetEventHandler(std::shared_ptr<IProtocolEventHandler> handler);

        [[nodiscard]] Result<proto::common::SecureEnvelope, ProtocolFailure>
        SendMessage(std::span<const uint8_t> payload) const;

        [[nodiscard]] Result<std::vector<uint8_t>, ProtocolFailure>
        ReceiveMessage(const proto::common::SecureEnvelope &envelope) const;

        [[nodiscard]] Result<proto::protocol::RatchetState, ProtocolFailure>
        ToProtoState() const;

        [[nodiscard]] bool HasConnection() const;

        void SetPendingInitiator(bool is_initiator);

        [[nodiscard]] std::optional<bool> GetPendingInitiator() const;

        [[nodiscard]] std::optional<bool> ConsumePendingInitiator();

        void SetPendingConnectionId(uint32_t connection_id);

        [[nodiscard]] std::optional<uint32_t> ConsumePendingConnectionId();

        [[nodiscard]] uint32_t GetConnectionId() const;

        [[nodiscard]] Result<std::pair<uint32_t, uint32_t>, ProtocolFailure>
        GetChainIndices() const;

        [[nodiscard]] uint64_t GetSessionAgeSeconds() const;

        [[nodiscard]] Result<Unit, ProtocolFailure> SetConnectionKyberSecrets(
            std::span<const uint8_t> kyber_ciphertext,
            std::span<const uint8_t> kyber_shared_secret) const;

        ProtocolSystem(ProtocolSystem &&) noexcept = default;

        ProtocolSystem &operator=(ProtocolSystem &&) noexcept = default;

        ProtocolSystem(const ProtocolSystem &) = delete;

        ProtocolSystem &operator=(const ProtocolSystem &) = delete;

        ~ProtocolSystem() = default;

    private:
        explicit ProtocolSystem(std::unique_ptr<IdentityKeys> identity_keys);

        [[nodiscard]] static std::vector<uint8_t> CreateAssociatedData(
            std::span<const uint8_t> local_identity,
            std::span<const uint8_t> peer_identity);

        [[nodiscard]] std::shared_ptr<ProtocolConnection> GetConnectionSafe() const;

        std::unique_ptr<IdentityKeys> identity_keys_;
        std::shared_ptr<ProtocolConnection> connection_;
        std::shared_ptr<IProtocolEventHandler> event_handler_;
        mutable std::unique_ptr<std::shared_mutex> mutex_;
        std::optional<bool> pending_initiator_flag_;
        std::optional<uint32_t> pending_connection_id_;
    };
}
