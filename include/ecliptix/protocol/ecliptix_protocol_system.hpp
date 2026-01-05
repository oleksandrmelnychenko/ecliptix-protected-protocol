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
#include <shared_mutex>

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

        // Create with Kyber artifacts for hybrid PQ mode
        [[nodiscard]] static Result<std::unique_ptr<EcliptixProtocolSystem>, EcliptixProtocolFailure>
        CreateFromRootAndPeerBundle(std::unique_ptr<EcliptixSystemIdentityKeys> identity_keys,
                                    std::span<const uint8_t> root_key,
                                    const proto::protocol::PublicKeyBundle &peer_bundle,
                                    bool is_initiator,
                                    std::span<const uint8_t> kyber_ciphertext,
                                    std::span<const uint8_t> kyber_shared_secret);

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

        // Finalize with Kyber artifacts AND initial DH key pair from X3DH.
        // This ensures the Double Ratchet uses the correct initial sender DH key pair:
        //   - Initiator: their ephemeral key (EK) and private key
        //   - Responder: their Signed Pre-Key (SPK) and private key
        [[nodiscard]] Result<Unit, EcliptixProtocolFailure> FinalizeWithRootAndPeerBundle(
            std::span<const uint8_t> root_key,
            const proto::protocol::PublicKeyBundle &peer_bundle,
            bool is_initiator,
            std::span<const uint8_t> kyber_ciphertext,
            std::span<const uint8_t> kyber_shared_secret,
            std::span<const uint8_t> initial_dh_public_key,
            std::span<const uint8_t> initial_dh_private_key);

        void SetConnection(std::unique_ptr<EcliptixProtocolConnection> connection);

        [[nodiscard]] const EcliptixSystemIdentityKeys &GetIdentityKeys() const;
        [[nodiscard]] EcliptixSystemIdentityKeys &GetIdentityKeysMutable() const;

        void SetEventHandler(std::shared_ptr<IProtocolEventHandler> handler);

        [[nodiscard]] Result<proto::common::SecureEnvelope, EcliptixProtocolFailure>
        SendMessage(std::span<const uint8_t> payload) const;

        [[nodiscard]] Result<std::vector<uint8_t>, EcliptixProtocolFailure>
        ReceiveMessage(const proto::common::SecureEnvelope &envelope) const;

        [[nodiscard]] Result<proto::protocol::RatchetState, EcliptixProtocolFailure>
        ToProtoState() const;

        [[nodiscard]] bool HasConnection() const;

        void SetPendingInitiator(bool is_initiator);

        [[nodiscard]] std::optional<bool> GetPendingInitiator() const;

        [[nodiscard]] uint32_t GetConnectionId() const;

        [[nodiscard]] Result<std::pair<uint32_t, uint32_t>, EcliptixProtocolFailure>
        GetChainIndices() const;

        /// Returns the session age in seconds since creation.
        /// Application layer can use this to decide when to refresh/rehandshake.
        [[nodiscard]] uint64_t GetSessionAgeSeconds() const;

        // Set Kyber handshake secrets on the active connection (for hybrid PQ mode)
        [[nodiscard]] Result<Unit, EcliptixProtocolFailure> SetConnectionKyberSecrets(
            std::span<const uint8_t> kyber_ciphertext,
            std::span<const uint8_t> kyber_shared_secret) const;

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

        [[nodiscard]] std::shared_ptr<EcliptixProtocolConnection> GetConnectionSafe() const;

        std::unique_ptr<EcliptixSystemIdentityKeys> identity_keys_;
        std::shared_ptr<EcliptixProtocolConnection> connection_;
        std::shared_ptr<IProtocolEventHandler> event_handler_;
        mutable std::unique_ptr<std::shared_mutex> mutex_;
        std::optional<bool> pending_initiator_flag_;
    };
}
