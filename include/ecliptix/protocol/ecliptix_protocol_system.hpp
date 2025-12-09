#pragma once
#include "ecliptix/protocol/connection/ecliptix_protocol_connection.hpp"
#include "ecliptix/identity/ecliptix_system_identity_keys.hpp"
#include "ecliptix/interfaces/i_protocol_event_handler.hpp"
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"
#include "common/secure_envelope.pb.h"

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

        void SetConnection(std::unique_ptr<EcliptixProtocolConnection> connection);

        [[nodiscard]] const EcliptixSystemIdentityKeys &GetIdentityKeys() const noexcept;

        void SetEventHandler(std::shared_ptr<IProtocolEventHandler> handler);

        [[nodiscard]] Result<proto::common::SecureEnvelope, EcliptixProtocolFailure>
        SendMessage(std::span<const uint8_t> payload) const;

        [[nodiscard]] Result<std::vector<uint8_t>, EcliptixProtocolFailure>
        ReceiveMessage(const proto::common::SecureEnvelope &envelope) const;

        [[nodiscard]] bool HasConnection() const noexcept;

        [[nodiscard]] static uint32_t GetConnectionId() noexcept;

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
    };
}
