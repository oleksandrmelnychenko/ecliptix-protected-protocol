#include "ecliptix/protocol/handshake.hpp"
#include "ecliptix/protocol/constants.hpp"
#include "ecliptix/protocol/nonce.hpp"
#include "ecliptix/protocol/session.hpp"
#include "ecliptix/crypto/hkdf.hpp"
#include "ecliptix/crypto/kyber_interop.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/security/validation/dh_validator.hpp"
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <google/protobuf/message.h>
#include <sodium.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <string>

namespace ecliptix::protocol {
    using crypto::Hkdf;
    using crypto::KyberInterop;
    using crypto::SodiumInterop;
    using security::DhValidator;

    struct HandshakeInitiator::State {
        Session::HandshakeState session_state;
        std::vector<uint8_t> expected_ack_mac;
    };

    struct HandshakeResponder::State {
        Session::HandshakeState session_state;
    };

    HandshakeInitiator::~HandshakeInitiator() = default;
    HandshakeResponder::~HandshakeResponder() = default;

    namespace {
        Result<std::vector<uint8_t>, ProtocolFailure> SerializeDeterministic(
            const google::protobuf::Message& message) {
            std::string output;
            google::protobuf::io::StringOutputStream stream(&output);
            google::protobuf::io::CodedOutputStream coded_out(&stream);
            coded_out.SetSerializationDeterministic(true);
            if (!message.SerializeToCodedStream(&coded_out) || coded_out.HadError()) {
                return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                    ProtocolFailure::Encode("Failed to serialize protobuf deterministically"));
            }
            return Result<std::vector<uint8_t>, ProtocolFailure>::Ok(
                std::vector<uint8_t>(output.begin(), output.end()));
        }

        Result<std::vector<uint8_t>, ProtocolFailure> ComputeSha256(
            std::span<const uint8_t> data) {
            std::vector<uint8_t> digest(crypto_hash_sha256_BYTES);
            crypto_hash_sha256(digest.data(), data.data(), data.size());
            return Result<std::vector<uint8_t>, ProtocolFailure>::Ok(std::move(digest));
        }

        Result<std::vector<uint8_t>, ProtocolFailure> ComputeHmacSha256(
            std::span<const uint8_t> key,
            std::span<const uint8_t> data) {
            if (key.size() != kHmacBytes) {
                return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("HMAC key must be 32 bytes"));
            }
            std::vector<uint8_t> mac(crypto_auth_hmacsha256_BYTES);
            crypto_auth_hmacsha256(mac.data(), data.data(), data.size(), key.data());
            return Result<std::vector<uint8_t>, ProtocolFailure>::Ok(std::move(mac));
        }

        Result<std::vector<uint8_t>, ProtocolFailure> DeriveKeyBytes(
            std::span<const uint8_t> ikm,
            size_t out_len,
            std::span<const uint8_t> salt,
            std::string_view info) {
            std::vector<uint8_t> info_bytes(info.begin(), info.end());
            return Hkdf::DeriveKeyBytes(ikm, out_len, salt, info_bytes);
        }

        Result<std::vector<uint8_t>, ProtocolFailure> ComputeDh(
            std::span<const uint8_t> private_key,
            std::span<const uint8_t> public_key,
            std::string_view context) {
            if (private_key.size() != kX25519PrivateKeyBytes ||
                public_key.size() != kX25519PublicKeyBytes) {
                return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Invalid X25519 key size for DH"));
            }
            std::vector<uint8_t> shared(kX25519PublicKeyBytes);
            if (crypto_scalarmult(shared.data(), private_key.data(), public_key.data()) != 0) {
                return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                    ProtocolFailure::Handshake(
                        std::string("X25519 DH failed for ") + std::string(context)));
            }
            return Result<std::vector<uint8_t>, ProtocolFailure>::Ok(std::move(shared));
        }

        Result<Unit, ProtocolFailure> ValidateBundle(
            const ecliptix::proto::protocol::PreKeyBundle& bundle) {
            if (bundle.version() != kProtocolVersion) {
                return Result<Unit, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Invalid PreKeyBundle version"));
            }
            if (bundle.identity_ed25519_public().size() != kEd25519PublicKeyBytes ||
                bundle.identity_x25519_public().size() != kX25519PublicKeyBytes ||
                bundle.signed_pre_key_public().size() != kX25519PublicKeyBytes ||
                bundle.signed_pre_key_signature().size() != kEd25519SignatureBytes) {
                return Result<Unit, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Invalid PreKeyBundle key sizes"));
            }
            if (bundle.kyber_public().size() != kKyberPublicKeyBytes) {
                return Result<Unit, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Kyber public key required for handshake"));
            }
            auto verify_result = identity::IdentityKeys::VerifyRemoteSpkSignature(
                std::span(reinterpret_cast<const uint8_t*>(bundle.identity_ed25519_public().data()),
                          bundle.identity_ed25519_public().size()),
                std::span(reinterpret_cast<const uint8_t*>(bundle.signed_pre_key_public().data()),
                          bundle.signed_pre_key_public().size()),
                std::span(reinterpret_cast<const uint8_t*>(bundle.signed_pre_key_signature().data()),
                          bundle.signed_pre_key_signature().size()));
            if (verify_result.IsErr()) {
                return Result<Unit, ProtocolFailure>::Err(verify_result.UnwrapErr());
            }
            if (auto dh_check = DhValidator::ValidateX25519PublicKey(
                std::span(reinterpret_cast<const uint8_t*>(bundle.identity_x25519_public().data()),
                          bundle.identity_x25519_public().size())); dh_check.IsErr()) {
                return Result<Unit, ProtocolFailure>::Err(dh_check.UnwrapErr());
            }
            if (auto dh_check = DhValidator::ValidateX25519PublicKey(
                std::span(reinterpret_cast<const uint8_t*>(bundle.signed_pre_key_public().data()),
                          bundle.signed_pre_key_public().size())); dh_check.IsErr()) {
                return Result<Unit, ProtocolFailure>::Err(dh_check.UnwrapErr());
            }
            for (const auto& opk : bundle.one_time_pre_keys()) {
                if (opk.public_key().size() != kX25519PublicKeyBytes) {
                    return Result<Unit, ProtocolFailure>::Err(
                        ProtocolFailure::InvalidInput("Invalid OPK size in PreKeyBundle"));
                }
                if (auto dh_check = DhValidator::ValidateX25519PublicKey(
                    std::span(reinterpret_cast<const uint8_t*>(opk.public_key().data()),
                              opk.public_key().size())); dh_check.IsErr()) {
                    return Result<Unit, ProtocolFailure>::Err(dh_check.UnwrapErr());
                }
            }
            if (auto pq_check = KyberInterop::ValidatePublicKey(
                std::span(reinterpret_cast<const uint8_t*>(bundle.kyber_public().data()),
                          bundle.kyber_public().size())); pq_check.IsErr()) {
                return Result<Unit, ProtocolFailure>::Err(
                    ProtocolFailure::FromSodiumFailure(pq_check.UnwrapErr()));
            }
            return Result<Unit, ProtocolFailure>::Ok(Unit{});
        }

        Result<Unit, ProtocolFailure> ValidateMaxMessagesPerChain(uint32_t max_messages_per_chain) {
            if (max_messages_per_chain == 0) {
                return Result<Unit, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Max messages per chain must be greater than zero"));
            }
            if (max_messages_per_chain > kMaxMessagesPerChain) {
                return Result<Unit, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Max messages per chain exceeds protocol limit"));
            }
            return Result<Unit, ProtocolFailure>::Ok(Unit{});
        }

        Result<Unit, ProtocolFailure> ValidateInitMessage(
            const ecliptix::proto::protocol::HandshakeInit& init) {
            if (init.version() != kProtocolVersion) {
                return Result<Unit, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Invalid HandshakeInit version"));
            }
            if (init.initiator_identity_ed25519_public().size() != kEd25519PublicKeyBytes ||
                init.initiator_identity_x25519_public().size() != kX25519PublicKeyBytes ||
                init.initiator_ephemeral_x25519_public().size() != kX25519PublicKeyBytes) {
                return Result<Unit, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Invalid initiator key sizes"));
            }
            if (init.kyber_ciphertext().size() != kKyberCiphertextBytes) {
                return Result<Unit, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Kyber ciphertext required for handshake"));
            }
            if (init.key_confirmation_mac().size() != kHmacBytes) {
                return Result<Unit, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Invalid key confirmation MAC size"));
            }
            if (init.initiator_kyber_public().size() != kKyberPublicKeyBytes) {
                return Result<Unit, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Initiator Kyber public key required for handshake"));
            }
            if (auto dh_check = DhValidator::ValidateX25519PublicKey(
                std::span(reinterpret_cast<const uint8_t*>(init.initiator_identity_x25519_public().data()),
                          init.initiator_identity_x25519_public().size())); dh_check.IsErr()) {
                return Result<Unit, ProtocolFailure>::Err(dh_check.UnwrapErr());
            }
            if (auto dh_check = DhValidator::ValidateX25519PublicKey(
                std::span(reinterpret_cast<const uint8_t*>(init.initiator_ephemeral_x25519_public().data()),
                          init.initiator_ephemeral_x25519_public().size())); dh_check.IsErr()) {
                return Result<Unit, ProtocolFailure>::Err(dh_check.UnwrapErr());
            }
            if (auto pq_check = KyberInterop::ValidateCiphertext(
                std::span(reinterpret_cast<const uint8_t*>(init.kyber_ciphertext().data()),
                          init.kyber_ciphertext().size())); pq_check.IsErr()) {
                return Result<Unit, ProtocolFailure>::Err(
                    ProtocolFailure::FromSodiumFailure(pq_check.UnwrapErr()));
            }
            if (auto pq_check = KyberInterop::ValidatePublicKey(
                std::span(reinterpret_cast<const uint8_t*>(init.initiator_kyber_public().data()),
                          init.initiator_kyber_public().size())); pq_check.IsErr()) {
                return Result<Unit, ProtocolFailure>::Err(
                    ProtocolFailure::FromSodiumFailure(pq_check.UnwrapErr()));
            }
            if (auto chain_limit = ValidateMaxMessagesPerChain(init.max_messages_per_chain());
                chain_limit.IsErr()) {
                return Result<Unit, ProtocolFailure>::Err(chain_limit.UnwrapErr());
            }
            return Result<Unit, ProtocolFailure>::Ok(Unit{});
        }

        std::vector<uint8_t> BuildMetadataContext(
            std::span<const uint8_t> self_dh_public,
            std::span<const uint8_t> peer_dh_public,
            std::span<const uint8_t> session_id) {
            std::array<std::vector<uint8_t>, 2> keys = {
                std::vector<uint8_t>(self_dh_public.begin(), self_dh_public.end()),
                std::vector<uint8_t>(peer_dh_public.begin(), peer_dh_public.end())
            };
            if (keys[0] > keys[1]) {
                std::swap(keys[0], keys[1]);
            }
            std::vector<uint8_t> context;
            context.reserve(keys[0].size() + keys[1].size() + session_id.size());
            context.insert(context.end(), keys[0].begin(), keys[0].end());
            context.insert(context.end(), keys[1].begin(), keys[1].end());
            context.insert(context.end(), session_id.begin(), session_id.end());
            return context;
        }

        Result<std::vector<uint8_t>, ProtocolFailure> BuildTranscriptHash(
            const ecliptix::proto::protocol::PreKeyBundle& bundle,
            const ecliptix::proto::protocol::HandshakeInit& init) {
            auto bundle_bytes_result = SerializeDeterministic(bundle);
            if (bundle_bytes_result.IsErr()) {
                return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                    bundle_bytes_result.UnwrapErr());
            }
            ecliptix::proto::protocol::HandshakeInit init_copy = init;
            init_copy.clear_key_confirmation_mac();
            auto init_bytes_result = SerializeDeterministic(init_copy);
            if (init_bytes_result.IsErr()) {
                return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                    init_bytes_result.UnwrapErr());
            }
            std::vector<uint8_t> transcript;
            transcript.insert(transcript.end(), kTranscriptLabel.begin(), kTranscriptLabel.end());
            const auto& bundle_bytes = bundle_bytes_result.Unwrap();
            const auto& init_bytes = init_bytes_result.Unwrap();
            transcript.insert(transcript.end(), bundle_bytes.begin(), bundle_bytes.end());
            transcript.insert(transcript.end(), init_bytes.begin(), init_bytes.end());
            return ComputeSha256(
                std::span<const uint8_t>(transcript.data(), transcript.size()));
        }

        void SetTimestampNow(google::protobuf::Timestamp* timestamp) {
            const auto now = std::chrono::system_clock::now();
            const auto epoch = now.time_since_epoch();
            const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(epoch);
            const auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(
                epoch - seconds);
            timestamp->set_seconds(seconds.count());
            timestamp->set_nanos(static_cast<int32_t>(nanos.count()));
        }

        Result<ecliptix::proto::protocol::ProtocolState, ProtocolFailure> BuildProtocolState(
            bool is_initiator,
            std::span<const uint8_t> root_key,
            std::span<const uint8_t> session_id,
            std::span<const uint8_t> metadata_key,
            std::span<const uint8_t> dh_local_private,
            std::span<const uint8_t> dh_local_public,
            std::span<const uint8_t> dh_remote_public,
            std::span<const uint8_t> initial_self_public,
            std::span<const uint8_t> initial_peer_public,
            std::span<const uint8_t> kyber_secret,
            std::span<const uint8_t> kyber_public,
            std::span<const uint8_t> peer_kyber_public,
            uint32_t max_messages_per_chain,
            const NonceGenerator::State& nonce_generator) {
            if (root_key.size() != kRootKeyBytes ||
                session_id.size() != kSessionIdBytes ||
                metadata_key.size() != kMetadataKeyBytes) {
                return Result<ecliptix::proto::protocol::ProtocolState, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Invalid root/session/metadata key sizes"));
            }
            if (dh_local_private.size() != kX25519PrivateKeyBytes ||
                dh_local_public.size() != kX25519PublicKeyBytes ||
                dh_remote_public.size() != kX25519PublicKeyBytes ||
                initial_self_public.size() != kX25519PublicKeyBytes ||
                initial_peer_public.size() != kX25519PublicKeyBytes) {
                return Result<ecliptix::proto::protocol::ProtocolState, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Invalid DH key sizes"));
            }
            if (kyber_secret.size() != kKyberSecretKeyBytes ||
                kyber_public.size() != kKyberPublicKeyBytes ||
                peer_kyber_public.size() != kKyberPublicKeyBytes) {
                return Result<ecliptix::proto::protocol::ProtocolState, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Invalid Kyber key sizes"));
            }
            if (auto chain_limit = ValidateMaxMessagesPerChain(max_messages_per_chain);
                chain_limit.IsErr()) {
                return Result<ecliptix::proto::protocol::ProtocolState, ProtocolFailure>::Err(
                    chain_limit.UnwrapErr());
            }

            ecliptix::proto::protocol::ProtocolState state;
            state.set_version(kProtocolVersion);
            state.set_is_initiator(is_initiator);
            state.set_session_id(session_id.data(), session_id.size());
            state.set_root_key(root_key.data(), root_key.size());
            state.set_metadata_key(metadata_key.data(), metadata_key.size());
            state.set_state_counter(0);
            state.set_send_ratchet_epoch(0);
            state.set_recv_ratchet_epoch(0);
            state.set_max_messages_per_chain(max_messages_per_chain);

            SetTimestampNow(state.mutable_created_at());

            auto* dh_local = state.mutable_dh_local();
            dh_local->set_private_key(dh_local_private.data(), dh_local_private.size());
            dh_local->set_public_key(dh_local_public.data(), dh_local_public.size());
            state.set_dh_remote_public(dh_remote_public.data(), dh_remote_public.size());
            state.set_dh_local_initial_public(initial_self_public.data(), initial_self_public.size());
            state.set_dh_remote_initial_public(initial_peer_public.data(), initial_peer_public.size());

            auto* kyber_local = state.mutable_kyber_local();
            kyber_local->set_secret_key(kyber_secret.data(), kyber_secret.size());
            kyber_local->set_public_key(kyber_public.data(), kyber_public.size());
            state.set_kyber_remote_public(peer_kyber_public.data(), peer_kyber_public.size());

            auto* nonce_proto = state.mutable_nonce_generator();
            nonce_proto->set_prefix(nonce_generator.prefix.data(), nonce_generator.prefix.size());
            nonce_proto->set_counter(nonce_generator.counter);

            state.mutable_send_chain()->set_message_index(0);
            state.mutable_recv_chain()->set_message_index(0);

            return Result<ecliptix::proto::protocol::ProtocolState, ProtocolFailure>::Ok(std::move(state));
        }
    }

    Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure> HandshakeInitiator::Start(
        identity::IdentityKeys& identity_keys,
        const ecliptix::proto::protocol::PreKeyBundle& peer_bundle,
        uint32_t max_messages_per_chain) {
        if (auto validate_result = ValidateBundle(peer_bundle); validate_result.IsErr()) {
            return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Err(
                validate_result.UnwrapErr());
        }
        if (auto chain_limit = ValidateMaxMessagesPerChain(max_messages_per_chain);
            chain_limit.IsErr()) {
            return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Err(
                chain_limit.UnwrapErr());
        }

        identity_keys.GenerateEphemeralKeyPair();
        auto eph_public_opt = identity_keys.GetEphemeralX25519PublicCopy();
        if (!eph_public_opt.has_value() || eph_public_opt->size() != kX25519PublicKeyBytes) {
            return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Err(
                ProtocolFailure::PrepareLocal("Initiator ephemeral key not available"));
        }
        auto eph_private_result = identity_keys.GetEphemeralX25519PrivateKeyCopy();
        if (eph_private_result.IsErr()) {
            return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Err(
                eph_private_result.UnwrapErr());
        }
        auto identity_private_result = identity_keys.GetIdentityX25519PrivateKeyCopy();
        if (identity_private_result.IsErr()) {
            return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Err(
                identity_private_result.UnwrapErr());
        }

        const auto eph_public = eph_public_opt.value();
        auto eph_private = eph_private_result.Unwrap();
        auto identity_private = identity_private_result.Unwrap();

        std::optional<uint32_t> used_one_time_pre_key_id;
        std::vector<uint8_t> opk_public;
        if (peer_bundle.one_time_pre_keys_size() > 0) {
            const uint32_t opk_count = static_cast<uint32_t>(peer_bundle.one_time_pre_keys_size());
            const uint32_t opk_index = SodiumInterop::GenerateRandomUInt32() % opk_count;
            const auto& opk = peer_bundle.one_time_pre_keys(opk_index);
            if (opk.public_key().size() != kX25519PublicKeyBytes) {
                return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Invalid OPK public key size"));
            }
            used_one_time_pre_key_id = opk.one_time_pre_key_id();
            opk_public.assign(opk.public_key().begin(), opk.public_key().end());
            if (auto dh_check = DhValidator::ValidateX25519PublicKey(
                std::span<const uint8_t>(opk_public.data(), opk_public.size())); dh_check.IsErr()) {
                return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Err(
                    dh_check.UnwrapErr());
            }
        }

        auto dh1_result = ComputeDh(
            std::span<const uint8_t>(identity_private.data(), identity_private.size()),
            std::span(reinterpret_cast<const uint8_t*>(peer_bundle.signed_pre_key_public().data()),
                      peer_bundle.signed_pre_key_public().size()),
            "DH1");
        auto dh2_result = ComputeDh(
            std::span<const uint8_t>(eph_private.data(), eph_private.size()),
            std::span(reinterpret_cast<const uint8_t*>(peer_bundle.identity_x25519_public().data()),
                      peer_bundle.identity_x25519_public().size()),
            "DH2");
        auto dh3_result = ComputeDh(
            std::span<const uint8_t>(eph_private.data(), eph_private.size()),
            std::span(reinterpret_cast<const uint8_t*>(peer_bundle.signed_pre_key_public().data()),
                      peer_bundle.signed_pre_key_public().size()),
            "DH3");
        if (dh1_result.IsErr() || dh2_result.IsErr() || dh3_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe;
            auto _wipe_eph = SodiumInterop::SecureWipe(std::span(eph_private));
            (void) _wipe_eph;
            return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Err(
                dh1_result.IsErr() ? dh1_result.UnwrapErr() :
                (dh2_result.IsErr() ? dh2_result.UnwrapErr() : dh3_result.UnwrapErr()));
        }

        std::vector<uint8_t> dh4;
        if (used_one_time_pre_key_id.has_value()) {
            auto dh4_result = ComputeDh(
                std::span<const uint8_t>(eph_private.data(), eph_private.size()),
                std::span<const uint8_t>(opk_public.data(), opk_public.size()),
                "DH4");
            if (dh4_result.IsErr()) {
                auto _wipe = SodiumInterop::SecureWipe(std::span(identity_private));
                (void) _wipe;
                auto _wipe_eph = SodiumInterop::SecureWipe(std::span(eph_private));
                (void) _wipe_eph;
                return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Err(
                    dh4_result.UnwrapErr());
            }
            dh4 = dh4_result.Unwrap();
        }

        std::vector<uint8_t> dh1 = dh1_result.Unwrap();
        std::vector<uint8_t> dh2 = dh2_result.Unwrap();
        std::vector<uint8_t> dh3 = dh3_result.Unwrap();

        size_t dh_total = dh1.size() + dh2.size() + dh3.size() + dh4.size();
        std::vector<uint8_t> ikm(kX25519PublicKeyBytes + dh_total, 0xFF);
        size_t offset = kX25519PublicKeyBytes;
        auto append = [&](const std::vector<uint8_t>& dh) {
            std::copy(dh.begin(), dh.end(), ikm.begin() + static_cast<long>(offset));
            offset += dh.size();
        };
        append(dh1);
        append(dh2);
        append(dh3);
        if (!dh4.empty()) {
            append(dh4);
        }

        auto classical_shared_result = DeriveKeyBytes(
            std::span<const uint8_t>(ikm.data(), ikm.size()),
            kRootKeyBytes,
            {},
            kX3dhInfo);
        auto _wipe_ikm = SodiumInterop::SecureWipe(std::span(ikm));
        (void) _wipe_ikm;
        auto _wipe_dh1 = SodiumInterop::SecureWipe(std::span(dh1));
        (void) _wipe_dh1;
        auto _wipe_dh2 = SodiumInterop::SecureWipe(std::span(dh2));
        (void) _wipe_dh2;
        auto _wipe_dh3 = SodiumInterop::SecureWipe(std::span(dh3));
        (void) _wipe_dh3;
        if (!dh4.empty()) {
            auto _wipe_dh4 = SodiumInterop::SecureWipe(std::span(dh4));
            (void) _wipe_dh4;
        }

        if (classical_shared_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe;
            auto _wipe_eph = SodiumInterop::SecureWipe(std::span(eph_private));
            (void) _wipe_eph;
            return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Err(
                classical_shared_result.UnwrapErr());
        }
        auto classical_shared = classical_shared_result.Unwrap();

        auto encap_result = KyberInterop::Encapsulate(
            std::span(reinterpret_cast<const uint8_t*>(peer_bundle.kyber_public().data()),
                      peer_bundle.kyber_public().size()));
        if (encap_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe;
            auto _wipe_eph = SodiumInterop::SecureWipe(std::span(eph_private));
            (void) _wipe_eph;
            auto _wipe_classical = SodiumInterop::SecureWipe(std::span(classical_shared));
            (void) _wipe_classical;
            return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(encap_result.UnwrapErr()));
        }
        auto [kyber_ciphertext, kyber_ss_handle] = std::move(encap_result).Unwrap();
        auto kyber_ss_result = kyber_ss_handle.ReadBytes(kKyberSharedSecretBytes);
        if (kyber_ss_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe;
            auto _wipe_eph = SodiumInterop::SecureWipe(std::span(eph_private));
            (void) _wipe_eph;
            auto _wipe_classical = SodiumInterop::SecureWipe(std::span(classical_shared));
            (void) _wipe_classical;
            return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(kyber_ss_result.UnwrapErr()));
        }
        auto kyber_shared_secret = kyber_ss_result.Unwrap();

        std::vector<uint8_t> hybrid_ikm;
        hybrid_ikm.reserve(classical_shared.size() + kyber_shared_secret.size());
        hybrid_ikm.insert(hybrid_ikm.end(), classical_shared.begin(), classical_shared.end());
        hybrid_ikm.insert(hybrid_ikm.end(), kyber_shared_secret.begin(), kyber_shared_secret.end());
        auto root_key_result = DeriveKeyBytes(
            std::span<const uint8_t>(hybrid_ikm.data(), hybrid_ikm.size()),
            kRootKeyBytes,
            {},
            kHybridX3dhInfo);
        auto _wipe_hybrid = SodiumInterop::SecureWipe(std::span(hybrid_ikm));
        (void) _wipe_hybrid;
        auto _wipe_classical = SodiumInterop::SecureWipe(std::span(classical_shared));
        (void) _wipe_classical;
        if (root_key_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe;
            auto _wipe_eph = SodiumInterop::SecureWipe(std::span(eph_private));
            (void) _wipe_eph;
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Err(
                root_key_result.UnwrapErr());
        }
        auto root_key = root_key_result.Unwrap();

        auto session_id_result = DeriveKeyBytes(
            std::span<const uint8_t>(root_key.data(), root_key.size()),
            kSessionIdBytes,
            {},
            kSessionIdInfo);
        if (session_id_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe;
            auto _wipe_eph = SodiumInterop::SecureWipe(std::span(eph_private));
            (void) _wipe_eph;
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Err(
                session_id_result.UnwrapErr());
        }
        auto session_id = session_id_result.Unwrap();

        auto metadata_context = BuildMetadataContext(
            std::span(eph_public.data(), eph_public.size()),
            std::span(reinterpret_cast<const uint8_t*>(peer_bundle.signed_pre_key_public().data()),
                      peer_bundle.signed_pre_key_public().size()),
            std::span<const uint8_t>(session_id.data(), session_id.size()));
        auto metadata_key_result = DeriveKeyBytes(
            std::span<const uint8_t>(root_key.data(), root_key.size()),
            kMetadataKeyBytes,
            std::span<const uint8_t>(metadata_context.data(), metadata_context.size()),
            kMetadataKeyInfo);
        if (metadata_key_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe;
            auto _wipe_eph = SodiumInterop::SecureWipe(std::span(eph_private));
            (void) _wipe_eph;
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Err(
                metadata_key_result.UnwrapErr());
        }
        auto metadata_key = metadata_key_result.Unwrap();

        auto kc_i_result = DeriveKeyBytes(
            std::span<const uint8_t>(root_key.data(), root_key.size()),
            kHmacBytes,
            {},
            kKeyConfirmInitInfo);
        auto kc_r_result = DeriveKeyBytes(
            std::span<const uint8_t>(root_key.data(), root_key.size()),
            kHmacBytes,
            {},
            kKeyConfirmRespInfo);
        if (kc_i_result.IsErr() || kc_r_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe;
            auto _wipe_eph = SodiumInterop::SecureWipe(std::span(eph_private));
            (void) _wipe_eph;
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Err(
                kc_i_result.IsErr() ? kc_i_result.UnwrapErr() : kc_r_result.UnwrapErr());
        }
        auto kc_i = kc_i_result.Unwrap();
        auto kc_r = kc_r_result.Unwrap();

        auto kyber_public = identity_keys.GetKyberPublicCopy();
        if (kyber_public.size() != kKyberPublicKeyBytes) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe;
            auto _wipe_eph = SodiumInterop::SecureWipe(std::span(eph_private));
            (void) _wipe_eph;
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Err(
                ProtocolFailure::PrepareLocal("Invalid local Kyber public key size"));
        }
        ecliptix::proto::protocol::HandshakeInit init_message;
        init_message.set_version(kProtocolVersion);
        auto ed_public = identity_keys.GetIdentityEd25519PublicCopy();
        auto id_public = identity_keys.GetIdentityX25519PublicCopy();
        init_message.set_initiator_identity_ed25519_public(ed_public.data(), ed_public.size());
        init_message.set_initiator_identity_x25519_public(id_public.data(), id_public.size());
        init_message.set_initiator_ephemeral_x25519_public(eph_public.data(), eph_public.size());
        if (used_one_time_pre_key_id.has_value()) {
            init_message.set_one_time_pre_key_id(*used_one_time_pre_key_id);
        }
        init_message.set_kyber_ciphertext(kyber_ciphertext.data(), kyber_ciphertext.size());
        init_message.set_initiator_kyber_public(kyber_public.data(), kyber_public.size());
        init_message.set_max_messages_per_chain(max_messages_per_chain);

        auto transcript_hash_result = BuildTranscriptHash(peer_bundle, init_message);
        if (transcript_hash_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe;
            auto _wipe_eph = SodiumInterop::SecureWipe(std::span(eph_private));
            (void) _wipe_eph;
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Err(
                transcript_hash_result.UnwrapErr());
        }
        auto transcript_hash = transcript_hash_result.Unwrap();
        auto confirmation_result = ComputeHmacSha256(
            std::span<const uint8_t>(kc_i.data(), kc_i.size()),
            std::span<const uint8_t>(transcript_hash.data(), transcript_hash.size()));
        auto _wipe_kc_i = SodiumInterop::SecureWipe(std::span(kc_i));
        (void) _wipe_kc_i;
        if (confirmation_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe;
            auto _wipe_eph = SodiumInterop::SecureWipe(std::span(eph_private));
            (void) _wipe_eph;
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Err(
                confirmation_result.UnwrapErr());
        }
        auto key_confirmation_mac = confirmation_result.Unwrap();
        init_message.set_key_confirmation_mac(key_confirmation_mac.data(), key_confirmation_mac.size());

        std::string serialized;
        if (!init_message.SerializeToString(&serialized)) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe;
            auto _wipe_eph = SodiumInterop::SecureWipe(std::span(eph_private));
            (void) _wipe_eph;
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Err(
                ProtocolFailure::Encode("Failed to serialize HandshakeInit"));
        }

        auto nonce_result = NonceGenerator::Create();
        if (nonce_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe;
            auto _wipe_eph = SodiumInterop::SecureWipe(std::span(eph_private));
            (void) _wipe_eph;
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Err(
                nonce_result.UnwrapErr());
        }
        auto nonce_generator = nonce_result.Unwrap().ExportState();

        auto kyber_secret_handle_result = identity_keys.CloneKyberSecretKey();
        if (kyber_secret_handle_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe;
            auto _wipe_eph = SodiumInterop::SecureWipe(std::span(eph_private));
            (void) _wipe_eph;
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Err(
                kyber_secret_handle_result.UnwrapErr());
        }
        auto kyber_secret_handle = std::move(kyber_secret_handle_result).Unwrap();
        auto kyber_secret_result = kyber_secret_handle.ReadBytes(kKyberSecretKeyBytes);
        if (kyber_secret_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe;
            auto _wipe_eph = SodiumInterop::SecureWipe(std::span(eph_private));
            (void) _wipe_eph;
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(kyber_secret_result.UnwrapErr()));
        }
        auto kyber_secret = kyber_secret_result.Unwrap();

        auto state_result = BuildProtocolState(
            true,
            std::span<const uint8_t>(root_key.data(), root_key.size()),
            std::span<const uint8_t>(session_id.data(), session_id.size()),
            std::span<const uint8_t>(metadata_key.data(), metadata_key.size()),
            std::span<const uint8_t>(eph_private.data(), eph_private.size()),
            std::span<const uint8_t>(eph_public.data(), eph_public.size()),
            std::span(reinterpret_cast<const uint8_t*>(peer_bundle.signed_pre_key_public().data()),
                      peer_bundle.signed_pre_key_public().size()),
            std::span<const uint8_t>(eph_public.data(), eph_public.size()),
            std::span(reinterpret_cast<const uint8_t*>(peer_bundle.signed_pre_key_public().data()),
                      peer_bundle.signed_pre_key_public().size()),
            std::span<const uint8_t>(kyber_secret.data(), kyber_secret.size()),
            std::span<const uint8_t>(kyber_public.data(), kyber_public.size()),
            std::span(reinterpret_cast<const uint8_t*>(peer_bundle.kyber_public().data()),
                      peer_bundle.kyber_public().size()),
            max_messages_per_chain,
            nonce_generator);
        auto _wipe_identity = SodiumInterop::SecureWipe(std::span(identity_private));
        (void) _wipe_identity;
        auto _wipe_eph = SodiumInterop::SecureWipe(std::span(eph_private));
        (void) _wipe_eph;
        auto _wipe_kyber_secret = SodiumInterop::SecureWipe(std::span(kyber_secret));
        (void) _wipe_kyber_secret;
        if (state_result.IsErr()) {
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            auto _wipe_meta = SodiumInterop::SecureWipe(std::span(metadata_key));
            (void) _wipe_meta;
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Err(
                state_result.UnwrapErr());
        }
        auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
        (void) _wipe_root;
        auto _wipe_meta = SodiumInterop::SecureWipe(std::span(metadata_key));
        (void) _wipe_meta;
        auto _wipe_session = SodiumInterop::SecureWipe(std::span(session_id));
        (void) _wipe_session;

        auto expected_ack_result = ComputeHmacSha256(
            std::span<const uint8_t>(kc_r.data(), kc_r.size()),
            std::span<const uint8_t>(transcript_hash.data(), transcript_hash.size()));
        auto _wipe_kc_r = SodiumInterop::SecureWipe(std::span(kc_r));
        (void) _wipe_kc_r;
        if (expected_ack_result.IsErr()) {
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            auto _wipe_meta = SodiumInterop::SecureWipe(std::span(metadata_key));
            (void) _wipe_meta;
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Err(
                expected_ack_result.UnwrapErr());
        }
        auto expected_ack_mac = expected_ack_result.Unwrap();

        identity_keys.ClearEphemeralKeyPair();

        auto handshake = std::unique_ptr<HandshakeInitiator>(new HandshakeInitiator());
        handshake->init_message_ = std::move(init_message);
        handshake->init_bytes_ = std::vector<uint8_t>(serialized.begin(), serialized.end());
        handshake->state_ = std::make_unique<State>();
        handshake->state_->expected_ack_mac = std::move(expected_ack_mac);
        handshake->state_->session_state.state = std::move(state_result.Unwrap());
        handshake->state_->session_state.kyber_shared_secret = std::move(kyber_shared_secret);
        return Result<std::unique_ptr<HandshakeInitiator>, ProtocolFailure>::Ok(std::move(handshake));
    }

    const ecliptix::proto::protocol::HandshakeInit& HandshakeInitiator::Message() const {
        return init_message_;
    }

    const std::vector<uint8_t>& HandshakeInitiator::EncodedMessage() const {
        return init_bytes_;
    }

    Result<std::unique_ptr<Session>, ProtocolFailure> HandshakeInitiator::Finish(
        const ecliptix::proto::protocol::HandshakeAck& ack) {
        if (!state_) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidState("Handshake initiator not initialized"));
        }
        if (ack.version() != kProtocolVersion) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Invalid HandshakeAck version"));
        }
        if (ack.key_confirmation_mac().size() != kHmacBytes) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Invalid acknowledgement MAC size"));
        }
        auto compare_result = SodiumInterop::ConstantTimeEquals(
            std::span(state_->expected_ack_mac.data(), state_->expected_ack_mac.size()),
            std::span(reinterpret_cast<const uint8_t*>(ack.key_confirmation_mac().data()),
                      ack.key_confirmation_mac().size()));
        if (compare_result.IsErr()) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(compare_result.UnwrapErr()));
        }
        if (!compare_result.Unwrap()) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                ProtocolFailure::Handshake("Responder key confirmation failed"));
        }
        auto session_result = Session::FromHandshakeState(std::move(state_->session_state));
        if (session_result.IsErr()) {
            return session_result;
        }
        state_.reset();
        return session_result;
    }

    Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure> HandshakeResponder::Process(
        identity::IdentityKeys& identity_keys,
        const ecliptix::proto::protocol::PreKeyBundle& local_bundle,
        std::span<const uint8_t> init_message_bytes,
        uint32_t max_messages_per_chain) {
        if (auto validate_result = ValidateBundle(local_bundle); validate_result.IsErr()) {
            return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                validate_result.UnwrapErr());
        }
        if (auto chain_limit = ValidateMaxMessagesPerChain(max_messages_per_chain);
            chain_limit.IsErr()) {
            return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                chain_limit.UnwrapErr());
        }

        ecliptix::proto::protocol::HandshakeInit init_message;
        if (!init_message.ParseFromArray(init_message_bytes.data(),
                                         static_cast<int>(init_message_bytes.size()))) {
            return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                ProtocolFailure::Decode("Failed to parse HandshakeInit"));
        }
        if (auto validate_init = ValidateInitMessage(init_message); validate_init.IsErr()) {
            return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                validate_init.UnwrapErr());
        }
        if (init_message.max_messages_per_chain() != max_messages_per_chain) {
            return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Handshake ratchet config mismatch"));
        }

        std::optional<uint32_t> used_one_time_pre_key_id;
        std::vector<uint8_t> opk_private;
        if (init_message.has_one_time_pre_key_id()) {
            used_one_time_pre_key_id = init_message.one_time_pre_key_id();
            const auto* opk = identity_keys.FindOneTimePreKeyById(*used_one_time_pre_key_id);
            if (!opk) {
                return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                    ProtocolFailure::Handshake("Requested OPK not found"));
            }
            auto opk_private_result = opk->GetPrivateKeyHandle().ReadBytes(kX25519PrivateKeyBytes);
            if (opk_private_result.IsErr()) {
                return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                    ProtocolFailure::FromSodiumFailure(opk_private_result.UnwrapErr()));
            }
            opk_private = opk_private_result.Unwrap();
        }

        auto spk_private_result = identity_keys.GetSignedPreKeyPrivateCopy();
        if (spk_private_result.IsErr()) {
            return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                spk_private_result.UnwrapErr());
        }
        auto identity_private_result = identity_keys.GetIdentityX25519PrivateKeyCopy();
        if (identity_private_result.IsErr()) {
            return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                identity_private_result.UnwrapErr());
        }

        auto spk_private = spk_private_result.Unwrap();
        auto identity_private = identity_private_result.Unwrap();

        auto dh1_result = ComputeDh(
            std::span<const uint8_t>(spk_private.data(), spk_private.size()),
            std::span(reinterpret_cast<const uint8_t*>(init_message.initiator_identity_x25519_public().data()),
                      init_message.initiator_identity_x25519_public().size()),
            "DH1");
        auto dh2_result = ComputeDh(
            std::span<const uint8_t>(identity_private.data(), identity_private.size()),
            std::span(reinterpret_cast<const uint8_t*>(init_message.initiator_ephemeral_x25519_public().data()),
                      init_message.initiator_ephemeral_x25519_public().size()),
            "DH2");
        auto dh3_result = ComputeDh(
            std::span<const uint8_t>(spk_private.data(), spk_private.size()),
            std::span(reinterpret_cast<const uint8_t*>(init_message.initiator_ephemeral_x25519_public().data()),
                      init_message.initiator_ephemeral_x25519_public().size()),
            "DH3");
        if (dh1_result.IsErr() || dh2_result.IsErr() || dh3_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(spk_private));
            (void) _wipe;
            auto _wipe_id = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe_id;
            if (!opk_private.empty()) {
                auto _wipe_opk = SodiumInterop::SecureWipe(std::span(opk_private));
                (void) _wipe_opk;
            }
            return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                dh1_result.IsErr() ? dh1_result.UnwrapErr() :
                (dh2_result.IsErr() ? dh2_result.UnwrapErr() : dh3_result.UnwrapErr()));
        }

        std::vector<uint8_t> dh4;
        if (used_one_time_pre_key_id.has_value()) {
            auto dh4_result = ComputeDh(
                std::span<const uint8_t>(opk_private.data(), opk_private.size()),
                std::span(reinterpret_cast<const uint8_t*>(init_message.initiator_ephemeral_x25519_public().data()),
                          init_message.initiator_ephemeral_x25519_public().size()),
                "DH4");
            if (dh4_result.IsErr()) {
                auto _wipe = SodiumInterop::SecureWipe(std::span(spk_private));
                (void) _wipe;
                auto _wipe_id = SodiumInterop::SecureWipe(std::span(identity_private));
                (void) _wipe_id;
                if (!opk_private.empty()) {
                    auto _wipe_opk = SodiumInterop::SecureWipe(std::span(opk_private));
                    (void) _wipe_opk;
                }
                return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                    dh4_result.UnwrapErr());
            }
            dh4 = dh4_result.Unwrap();
        }

        std::vector<uint8_t> dh1 = dh1_result.Unwrap();
        std::vector<uint8_t> dh2 = dh2_result.Unwrap();
        std::vector<uint8_t> dh3 = dh3_result.Unwrap();

        size_t dh_total = dh1.size() + dh2.size() + dh3.size() + dh4.size();
        std::vector<uint8_t> ikm(kX25519PublicKeyBytes + dh_total, 0xFF);
        size_t offset = kX25519PublicKeyBytes;
        auto append = [&](const std::vector<uint8_t>& dh) {
            std::copy(dh.begin(), dh.end(), ikm.begin() + static_cast<long>(offset));
            offset += dh.size();
        };
        append(dh1);
        append(dh2);
        append(dh3);
        if (!dh4.empty()) {
            append(dh4);
        }

        auto classical_shared_result = DeriveKeyBytes(
            std::span<const uint8_t>(ikm.data(), ikm.size()),
            kRootKeyBytes,
            {},
            kX3dhInfo);
        auto _wipe_ikm = SodiumInterop::SecureWipe(std::span(ikm));
        (void) _wipe_ikm;
        auto _wipe_dh1 = SodiumInterop::SecureWipe(std::span(dh1));
        (void) _wipe_dh1;
        auto _wipe_dh2 = SodiumInterop::SecureWipe(std::span(dh2));
        (void) _wipe_dh2;
        auto _wipe_dh3 = SodiumInterop::SecureWipe(std::span(dh3));
        (void) _wipe_dh3;
        if (!dh4.empty()) {
            auto _wipe_dh4 = SodiumInterop::SecureWipe(std::span(dh4));
            (void) _wipe_dh4;
        }

        if (classical_shared_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(spk_private));
            (void) _wipe;
            auto _wipe_id = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe_id;
            if (!opk_private.empty()) {
                auto _wipe_opk = SodiumInterop::SecureWipe(std::span(opk_private));
                (void) _wipe_opk;
            }
            return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                classical_shared_result.UnwrapErr());
        }
        auto classical_shared = classical_shared_result.Unwrap();

        auto decap_result = identity_keys.DecapsulateKyberCiphertext(
            std::span(reinterpret_cast<const uint8_t*>(init_message.kyber_ciphertext().data()),
                      init_message.kyber_ciphertext().size()));
        if (decap_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(spk_private));
            (void) _wipe;
            auto _wipe_id = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe_id;
            if (!opk_private.empty()) {
                auto _wipe_opk = SodiumInterop::SecureWipe(std::span(opk_private));
                (void) _wipe_opk;
            }
            auto _wipe_classical = SodiumInterop::SecureWipe(std::span(classical_shared));
            (void) _wipe_classical;
            return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                decap_result.UnwrapErr());
        }
        auto artifacts = decap_result.Unwrap();
        auto kyber_shared_secret = artifacts.kyber_shared_secret;

        std::vector<uint8_t> hybrid_ikm;
        hybrid_ikm.reserve(classical_shared.size() + kyber_shared_secret.size());
        hybrid_ikm.insert(hybrid_ikm.end(), classical_shared.begin(), classical_shared.end());
        hybrid_ikm.insert(hybrid_ikm.end(), kyber_shared_secret.begin(), kyber_shared_secret.end());
        auto root_key_result = DeriveKeyBytes(
            std::span<const uint8_t>(hybrid_ikm.data(), hybrid_ikm.size()),
            kRootKeyBytes,
            {},
            kHybridX3dhInfo);
        auto _wipe_hybrid = SodiumInterop::SecureWipe(std::span(hybrid_ikm));
        (void) _wipe_hybrid;
        auto _wipe_classical = SodiumInterop::SecureWipe(std::span(classical_shared));
        (void) _wipe_classical;
        if (root_key_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(spk_private));
            (void) _wipe;
            auto _wipe_id = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe_id;
            if (!opk_private.empty()) {
                auto _wipe_opk = SodiumInterop::SecureWipe(std::span(opk_private));
                (void) _wipe_opk;
            }
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                root_key_result.UnwrapErr());
        }
        auto root_key = root_key_result.Unwrap();

        auto session_id_result = DeriveKeyBytes(
            std::span<const uint8_t>(root_key.data(), root_key.size()),
            kSessionIdBytes,
            {},
            kSessionIdInfo);
        if (session_id_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(spk_private));
            (void) _wipe;
            auto _wipe_id = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe_id;
            if (!opk_private.empty()) {
                auto _wipe_opk = SodiumInterop::SecureWipe(std::span(opk_private));
                (void) _wipe_opk;
            }
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                session_id_result.UnwrapErr());
        }
        auto session_id = session_id_result.Unwrap();

        auto metadata_context = BuildMetadataContext(
            std::span(reinterpret_cast<const uint8_t*>(local_bundle.signed_pre_key_public().data()),
                      local_bundle.signed_pre_key_public().size()),
            std::span(reinterpret_cast<const uint8_t*>(init_message.initiator_ephemeral_x25519_public().data()),
                      init_message.initiator_ephemeral_x25519_public().size()),
            std::span<const uint8_t>(session_id.data(), session_id.size()));
        auto metadata_key_result = DeriveKeyBytes(
            std::span<const uint8_t>(root_key.data(), root_key.size()),
            kMetadataKeyBytes,
            std::span<const uint8_t>(metadata_context.data(), metadata_context.size()),
            kMetadataKeyInfo);
        if (metadata_key_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(spk_private));
            (void) _wipe;
            auto _wipe_id = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe_id;
            if (!opk_private.empty()) {
                auto _wipe_opk = SodiumInterop::SecureWipe(std::span(opk_private));
                (void) _wipe_opk;
            }
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                metadata_key_result.UnwrapErr());
        }
        auto metadata_key = metadata_key_result.Unwrap();

        auto kc_i_result = DeriveKeyBytes(
            std::span<const uint8_t>(root_key.data(), root_key.size()),
            kHmacBytes,
            {},
            kKeyConfirmInitInfo);
        auto kc_r_result = DeriveKeyBytes(
            std::span<const uint8_t>(root_key.data(), root_key.size()),
            kHmacBytes,
            {},
            kKeyConfirmRespInfo);
        if (kc_i_result.IsErr() || kc_r_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(spk_private));
            (void) _wipe;
            auto _wipe_id = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe_id;
            if (!opk_private.empty()) {
                auto _wipe_opk = SodiumInterop::SecureWipe(std::span(opk_private));
                (void) _wipe_opk;
            }
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                kc_i_result.IsErr() ? kc_i_result.UnwrapErr() : kc_r_result.UnwrapErr());
        }
        auto kc_i = kc_i_result.Unwrap();
        auto kc_r = kc_r_result.Unwrap();

        auto transcript_hash_result = BuildTranscriptHash(local_bundle, init_message);
        if (transcript_hash_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(spk_private));
            (void) _wipe;
            auto _wipe_id = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe_id;
            if (!opk_private.empty()) {
                auto _wipe_opk = SodiumInterop::SecureWipe(std::span(opk_private));
                (void) _wipe_opk;
            }
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                transcript_hash_result.UnwrapErr());
        }
        auto transcript_hash = transcript_hash_result.Unwrap();
        auto expected_init_result = ComputeHmacSha256(
            std::span<const uint8_t>(kc_i.data(), kc_i.size()),
            std::span<const uint8_t>(transcript_hash.data(), transcript_hash.size()));
        auto _wipe_kc_i = SodiumInterop::SecureWipe(std::span(kc_i));
        (void) _wipe_kc_i;
        if (expected_init_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(spk_private));
            (void) _wipe;
            auto _wipe_id = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe_id;
            if (!opk_private.empty()) {
                auto _wipe_opk = SodiumInterop::SecureWipe(std::span(opk_private));
                (void) _wipe_opk;
            }
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                expected_init_result.UnwrapErr());
        }
        auto expected_init_mac = expected_init_result.Unwrap();
        auto compare_result = SodiumInterop::ConstantTimeEquals(
            std::span(expected_init_mac.data(), expected_init_mac.size()),
            std::span(reinterpret_cast<const uint8_t*>(init_message.key_confirmation_mac().data()),
                      init_message.key_confirmation_mac().size()));
        if (compare_result.IsErr()) {
            return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(compare_result.UnwrapErr()));
        }
        if (!compare_result.Unwrap()) {
            return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                ProtocolFailure::Handshake("Initiator key confirmation failed"));
        }

        auto ack_mac_result = ComputeHmacSha256(
            std::span<const uint8_t>(kc_r.data(), kc_r.size()),
            std::span<const uint8_t>(transcript_hash.data(), transcript_hash.size()));
        auto _wipe_kc_r = SodiumInterop::SecureWipe(std::span(kc_r));
        (void) _wipe_kc_r;
        if (ack_mac_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(spk_private));
            (void) _wipe;
            auto _wipe_id = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe_id;
            if (!opk_private.empty()) {
                auto _wipe_opk = SodiumInterop::SecureWipe(std::span(opk_private));
                (void) _wipe_opk;
            }
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                ack_mac_result.UnwrapErr());
        }
        auto ack_mac = ack_mac_result.Unwrap();

        ecliptix::proto::protocol::HandshakeAck ack_message;
        ack_message.set_version(kProtocolVersion);
        ack_message.set_key_confirmation_mac(ack_mac.data(), ack_mac.size());
        std::string ack_serialized;
        if (!ack_message.SerializeToString(&ack_serialized)) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(spk_private));
            (void) _wipe;
            auto _wipe_id = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe_id;
            if (!opk_private.empty()) {
                auto _wipe_opk = SodiumInterop::SecureWipe(std::span(opk_private));
                (void) _wipe_opk;
            }
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                ProtocolFailure::Encode("Failed to serialize HandshakeAck"));
        }

        auto nonce_result = NonceGenerator::Create();
        if (nonce_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(spk_private));
            (void) _wipe;
            auto _wipe_id = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe_id;
            if (!opk_private.empty()) {
                auto _wipe_opk = SodiumInterop::SecureWipe(std::span(opk_private));
                (void) _wipe_opk;
            }
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                nonce_result.UnwrapErr());
        }
        auto nonce_generator = nonce_result.Unwrap().ExportState();

        auto kyber_secret_handle_result = identity_keys.CloneKyberSecretKey();
        if (kyber_secret_handle_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(spk_private));
            (void) _wipe;
            auto _wipe_id = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe_id;
            if (!opk_private.empty()) {
                auto _wipe_opk = SodiumInterop::SecureWipe(std::span(opk_private));
                (void) _wipe_opk;
            }
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                kyber_secret_handle_result.UnwrapErr());
        }
        auto kyber_secret_handle = std::move(kyber_secret_handle_result).Unwrap();
        auto kyber_secret_result = kyber_secret_handle.ReadBytes(kKyberSecretKeyBytes);
        if (kyber_secret_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(spk_private));
            (void) _wipe;
            auto _wipe_id = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe_id;
            if (!opk_private.empty()) {
                auto _wipe_opk = SodiumInterop::SecureWipe(std::span(opk_private));
                (void) _wipe_opk;
            }
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(kyber_secret_result.UnwrapErr()));
        }
        auto kyber_secret = kyber_secret_result.Unwrap();
        auto kyber_public = identity_keys.GetKyberPublicCopy();
        if (kyber_public.size() != kKyberPublicKeyBytes) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(spk_private));
            (void) _wipe;
            auto _wipe_id = SodiumInterop::SecureWipe(std::span(identity_private));
            (void) _wipe_id;
            if (!opk_private.empty()) {
                auto _wipe_opk = SodiumInterop::SecureWipe(std::span(opk_private));
                (void) _wipe_opk;
            }
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                ProtocolFailure::PrepareLocal("Invalid local Kyber public key size"));
        }

        auto state_result = BuildProtocolState(
            false,
            std::span<const uint8_t>(root_key.data(), root_key.size()),
            std::span<const uint8_t>(session_id.data(), session_id.size()),
            std::span<const uint8_t>(metadata_key.data(), metadata_key.size()),
            std::span<const uint8_t>(spk_private.data(), spk_private.size()),
            std::span(reinterpret_cast<const uint8_t*>(local_bundle.signed_pre_key_public().data()),
                      local_bundle.signed_pre_key_public().size()),
            std::span(reinterpret_cast<const uint8_t*>(init_message.initiator_ephemeral_x25519_public().data()),
                      init_message.initiator_ephemeral_x25519_public().size()),
            std::span(reinterpret_cast<const uint8_t*>(local_bundle.signed_pre_key_public().data()),
                      local_bundle.signed_pre_key_public().size()),
            std::span(reinterpret_cast<const uint8_t*>(init_message.initiator_ephemeral_x25519_public().data()),
                      init_message.initiator_ephemeral_x25519_public().size()),
            std::span<const uint8_t>(kyber_secret.data(), kyber_secret.size()),
            std::span<const uint8_t>(kyber_public.data(), kyber_public.size()),
            std::span(reinterpret_cast<const uint8_t*>(init_message.initiator_kyber_public().data()),
                      init_message.initiator_kyber_public().size()),
            max_messages_per_chain,
            nonce_generator);
        auto _wipe_spk = SodiumInterop::SecureWipe(std::span(spk_private));
        (void) _wipe_spk;
        auto _wipe_identity = SodiumInterop::SecureWipe(std::span(identity_private));
        (void) _wipe_identity;
        if (!opk_private.empty()) {
            auto _wipe_opk = SodiumInterop::SecureWipe(std::span(opk_private));
            (void) _wipe_opk;
        }
        auto _wipe_kyber_secret = SodiumInterop::SecureWipe(std::span(kyber_secret));
        (void) _wipe_kyber_secret;
        if (state_result.IsErr()) {
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
            (void) _wipe_root;
            auto _wipe_meta = SodiumInterop::SecureWipe(std::span(metadata_key));
            (void) _wipe_meta;
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
            (void) _wipe_pq;
            return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                state_result.UnwrapErr());
        }
        auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
        (void) _wipe_root;
        auto _wipe_meta = SodiumInterop::SecureWipe(std::span(metadata_key));
        (void) _wipe_meta;
        auto _wipe_session = SodiumInterop::SecureWipe(std::span(session_id));
        (void) _wipe_session;

        if (used_one_time_pre_key_id.has_value()) {
            auto consume_result = identity_keys.ConsumeOneTimePreKeyById(*used_one_time_pre_key_id);
            if (consume_result.IsErr()) {
                auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key));
                (void) _wipe_root;
                auto _wipe_meta = SodiumInterop::SecureWipe(std::span(metadata_key));
                (void) _wipe_meta;
                auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_shared_secret));
                (void) _wipe_pq;
                return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Err(
                    consume_result.UnwrapErr());
            }
        }

        auto handshake = std::unique_ptr<HandshakeResponder>(new HandshakeResponder());
        handshake->ack_message_ = std::move(ack_message);
        handshake->ack_bytes_ = std::vector<uint8_t>(ack_serialized.begin(), ack_serialized.end());
        handshake->state_ = std::make_unique<State>();
        handshake->state_->session_state.state = std::move(state_result.Unwrap());
        handshake->state_->session_state.kyber_shared_secret = std::move(kyber_shared_secret);
        return Result<std::unique_ptr<HandshakeResponder>, ProtocolFailure>::Ok(std::move(handshake));
    }

    const ecliptix::proto::protocol::HandshakeAck& HandshakeResponder::Ack() const {
        return ack_message_;
    }

    const std::vector<uint8_t>& HandshakeResponder::EncodedAck() const {
        return ack_bytes_;
    }

    Result<std::unique_ptr<Session>, ProtocolFailure> HandshakeResponder::Finish() {
        if (!state_) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidState("Handshake responder not initialized"));
        }
        auto session_result = Session::FromHandshakeState(std::move(state_->session_state));
        if (session_result.IsErr()) {
            return session_result;
        }
        state_.reset();
        return session_result;
    }

}  // namespace ecliptix::protocol
