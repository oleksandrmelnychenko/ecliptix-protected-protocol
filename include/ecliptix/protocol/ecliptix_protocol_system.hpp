#pragma once
#include "ecliptix/protocol/connection/ecliptix_protocol_connection.hpp"
#include "ecliptix/identity/ecliptix_system_identity_keys.hpp"
#include "ecliptix/interfaces/i_protocol_event_handler.hpp"
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"
#include "common/secure_envelope.pb.h"
#include "protocol/protocol_state.pb.h"
#include "protocol/key_exchange.pb.h"
#include <optional>

namespace ecliptix::protocol {
    using protocol::Result;
    using protocol::Unit;
    using protocol::EcliptixProtocolFailure;
    using protocol::IProtocolEventHandler;
    using connection::EcliptixProtocolConnection;
    using identity::EcliptixSystemIdentityKeys;

    class EcliptixProtocolSystem {
    public:
        [[nodiscard]] static Result<std::unique_ptr<EcliptixProtocolSystem>, EcliptixProtocolFailure>
        Create(std::unique_ptr<EcliptixSystemIdentityKeys> identity_keys);

        [[nodiscard]] static Result<std::unique_ptr<EcliptixProtocolSystem>, EcliptixProtocolFailure>
        CreateFromRootAndPeerBundle(std::unique_ptr<EcliptixSystemIdentityKeys> identity_keys,
                                    std::span<const uint8_t> root_key,
                                    const proto::protocol::PublicKeyBundle &peer_bundle,
                                    bool is_initiator);

        [[nodiscard]] static Result<std::unique_ptr<EcliptixProtocolSystem>, EcliptixProtocolFailure>
        FromProtoState(std::unique_ptr<EcliptixSystemIdentityKeys> identity_keys,
                       const proto::protocol::RatchetState &state);

        // Finalize an in-flight system using a pre-shared root and peer bundle (OPAQUE/bootstrap).
        [[nodiscard]] Result<Unit, EcliptixProtocolFailure> FinalizeWithRootAndPeerBundle(
            std::span<const uint8_t> root_key,
            const proto::protocol::PublicKeyBundle &peer_bundle,
            bool is_initiator);

        // Finalize with Kyber artifacts for hybrid PQ mode
        [[nodiscard]] Result<Unit, EcliptixProtocolFailure> FinalizeWithRootAndPeerBundle(
            std::span<const uint8_t> root_key,
            const proto::protocol::PublicKeyBundle &peer_bundle,
            bool is_initiator,
            std::span<const uint8_t> kyber_ciphertext,
            std::span<const uint8_t> kyber_shared_secret);

        void SetConnection(std::unique_ptr<EcliptixProtocolConnection> connection);

        [[nodiscard]] const EcliptixSystemIdentityKeys &GetIdentityKeys() const noexcept;
        [[nodiscard]] EcliptixSystemIdentityKeys &GetIdentityKeysMutable() noexcept;

        void SetEventHandler(std::shared_ptr<IProtocolEventHandler> handler);

        [[nodiscard]] Result<proto::common::SecureEnvelope, EcliptixProtocolFailure>
        SendMessage(std::span<const uint8_t> payload) const;

        [[nodiscard]] Result<std::vector<uint8_t>, EcliptixProtocolFailure>
        ReceiveMessage(const proto::common::SecureEnvelope &envelope) const;

        [[nodiscard]] Result<proto::protocol::RatchetState, EcliptixProtocolFailure>
        ToProtoState() const;

        [[nodiscard]] bool HasConnection() const noexcept;

        void SetPendingInitiator(bool is_initiator) noexcept;

        [[nodiscard]] std::optional<bool> GetPendingInitiator() const noexcept;

        [[nodiscard]] uint32_t GetConnectionId() const noexcept;

        // Set Kyber handshake secrets on the active connection (for hybrid PQ mode)
        [[nodiscard]] Result<Unit, EcliptixProtocolFailure> SetConnectionKyberSecrets(
            std::span<const uint8_t> kyber_ciphertext,
            std::span<const uint8_t> kyber_shared_secret);

        EcliptixProtocolSystem(EcliptixProtocolSystem &&) noexcept = default;

        EcliptixProtocolSystem &operator=(EcliptixProtocolSystem &&) noexcept = default;

        EcliptixProtocolSystem(const EcliptixProtocolSystem &) = delete;

        EcliptixProtocolSystem &operator=(const EcliptixProtocolSystem &) = delete;

        ~EcliptixProtocolSystem() = default;

    private:
        explicit EcliptixProtocolSystem(std::unique_ptr<EcliptixSystemIdentityKeys> identity_keys);

        [[nodiscard]] static std::vector<uint8_t> CreateAssociatedData(
            std::span<const uint8_t> local_identity,
            std::span<const uint8_t> peer_identity);

        [[nodiscard]] EcliptixProtocolConnection *GetConnectionSafe() const noexcept;

        [[nodiscard]] Result<Unit, EcliptixProtocolFailure>
        HandleDhRatchetIfNeeded(const proto::common::SecureEnvelope &envelope) const;

        std::unique_ptr<EcliptixSystemIdentityKeys> identity_keys_;
        std::unique_ptr<EcliptixProtocolConnection> connection_;
        std::shared_ptr<IProtocolEventHandler> event_handler_;
        mutable std::unique_ptr<std::mutex> mutex_;
        std::optional<bool> pending_initiator_flag_;
    };
}
