#include "ecliptix/protocol/session.hpp"
#include "ecliptix/protocol/constants.hpp"
#include "ecliptix/protocol/nonce.hpp"
#include "ecliptix/crypto/aes_gcm.hpp"
#include "ecliptix/crypto/hkdf.hpp"
#include "ecliptix/crypto/kyber_interop.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include "ecliptix/security/validation/dh_validator.hpp"
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <google/protobuf/message.h>
#include <google/protobuf/timestamp.pb.h>
#include <sodium.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <limits>
#include <string>
#include <unordered_set>
#include <utility>

namespace ecliptix::protocol {
    using crypto::AesGcm;
    using crypto::Hkdf;
    using crypto::KyberInterop;
    using crypto::SodiumInterop;
    using crypto::SecureMemoryHandle;
    using security::DhValidator;

    namespace {
        void AppendUint32LE(std::vector<uint8_t>& out, uint32_t value) {
            out.push_back(static_cast<uint8_t>(value & 0xFF));
            out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
            out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
        }

        void AppendUint64LE(std::vector<uint8_t>& out, uint64_t value) {
            for (size_t i = 0; i < 8; ++i) {
                out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
            }
        }

        Result<std::vector<uint8_t>, ProtocolFailure> DeriveKeyBytes(
            std::span<const uint8_t> ikm,
            size_t out_len,
            std::span<const uint8_t> salt,
            std::string_view info) {
            std::vector<uint8_t> info_bytes(info.begin(), info.end());
            return Hkdf::DeriveKeyBytes(ikm, out_len, salt, info_bytes);
        }

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

        bool IsAllZero(std::span<const uint8_t> bytes) {
            return std::all_of(bytes.begin(), bytes.end(),
                               [](const uint8_t value) { return value == 0; });
        }

        Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, ProtocolFailure>
        DeriveMessageAndChainKey(std::span<const uint8_t> chain_key) {
            auto message_key_result = DeriveKeyBytes(
                chain_key,
                kMessageKeyBytes,
                {},
                kMessageInfo);
            if (message_key_result.IsErr()) {
                return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, ProtocolFailure>::Err(
                    message_key_result.UnwrapErr());
            }
            auto next_chain_key_result = DeriveKeyBytes(
                chain_key,
                kChainKeyBytes,
                {},
                kChainInfo);
            if (next_chain_key_result.IsErr()) {
                return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, ProtocolFailure>::Err(
                    next_chain_key_result.UnwrapErr());
            }
            return Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, ProtocolFailure>::Ok(
                std::make_pair(message_key_result.Unwrap(), next_chain_key_result.Unwrap()));
        }

        Result<std::vector<uint8_t>, ProtocolFailure> ComputeDh(
            std::span<const uint8_t> private_key,
            std::span<const uint8_t> public_key,
            std::string_view label) {
            if (private_key.size() != kX25519PrivateKeyBytes ||
                public_key.size() != kX25519PublicKeyBytes) {
                return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Invalid X25519 key sizes"));
            }
            std::vector<uint8_t> shared(kX25519PublicKeyBytes);
            if (crypto_scalarmult(shared.data(), private_key.data(), public_key.data()) != 0) {
                return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                    ProtocolFailure::Handshake(
                        std::string("X25519 DH failed for ") + std::string(label)));
            }
            return Result<std::vector<uint8_t>, ProtocolFailure>::Ok(std::move(shared));
        }

        Result<Unit, ProtocolFailure> ValidateDhPublicKey(std::span<const uint8_t> public_key) {
            return DhValidator::ValidateX25519PublicKey(public_key);
        }

        Result<std::vector<uint8_t>, ProtocolFailure> BuildMetadataAad(
            const ecliptix::proto::protocol::ProtocolState& state,
            uint64_t ratchet_epoch) {
            if (state.session_id().size() != kSessionIdBytes) {
                return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Invalid session id size"));
            }
            std::vector<uint8_t> ad;
            ad.reserve(kSessionIdBytes + 8 + 4);
            ad.insert(ad.end(), state.session_id().begin(), state.session_id().end());
            AppendUint64LE(ad, ratchet_epoch);
            AppendUint32LE(ad, kProtocolVersion);
            return Result<std::vector<uint8_t>, ProtocolFailure>::Ok(std::move(ad));
        }

        Result<std::vector<uint8_t>, ProtocolFailure> BuildPayloadAad(
            const ecliptix::proto::protocol::ProtocolState& state,
            uint64_t ratchet_epoch,
            uint64_t message_index) {
            if (state.session_id().size() != kSessionIdBytes) {
                return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Invalid session id size"));
            }
            std::vector<uint8_t> ad;
            ad.reserve(kSessionIdBytes + 8 + 8 + 4);
            ad.insert(ad.end(), state.session_id().begin(), state.session_id().end());
            AppendUint64LE(ad, ratchet_epoch);
            AppendUint64LE(ad, message_index);
            AppendUint32LE(ad, kProtocolVersion);
            return Result<std::vector<uint8_t>, ProtocolFailure>::Ok(std::move(ad));
        }

        Result<uint32_t, ProtocolFailure> ExtractNonceIndex(std::span<const uint8_t> nonce) {
            if (nonce.size() != kAesGcmNonceBytes) {
                return Result<uint32_t, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Invalid nonce size"));
            }
            const size_t offset = kNoncePrefixBytes + kNonceCounterBytes;
            uint32_t index = 0;
            for (size_t i = 0; i < kNonceIndexBytes; ++i) {
                index |= static_cast<uint32_t>(nonce[offset + i]) << (i * 8);
            }
            return Result<uint32_t, ProtocolFailure>::Ok(index);
        }

        Result<NonceGenerator, ProtocolFailure> LoadNonceGenerator(
            const ecliptix::proto::protocol::ProtocolState& state) {
            if (state.nonce_generator().prefix().size() != kNoncePrefixBytes) {
                return Result<NonceGenerator, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Invalid nonce prefix size"));
            }
            NonceGenerator::State nonce_generator;
            std::copy(state.nonce_generator().prefix().begin(),
                      state.nonce_generator().prefix().end(),
                      nonce_generator.prefix.begin());
            nonce_generator.counter = state.nonce_generator().counter();
            return NonceGenerator::FromState(nonce_generator);
        }

        void StoreNonceState(
            ecliptix::proto::protocol::ProtocolState& state,
            const NonceGenerator::State& nonce_generator) {
            state.mutable_nonce_generator()->set_prefix(
                nonce_generator.prefix.data(), nonce_generator.prefix.size());
            state.mutable_nonce_generator()->set_counter(nonce_generator.counter);
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
    }

    Session::Session(
        ecliptix::proto::protocol::ProtocolState state,
        std::vector<uint8_t> pending_kyber_shared_secret)
        : is_initiator_(state.is_initiator())
        , state_(std::move(state))
        , pending_kyber_shared_secret_(std::move(pending_kyber_shared_secret)) {
        ResetReplayTracking(state_.recv_ratchet_epoch());
    }

    void Session::ResetReplayTracking(uint64_t epoch) {
        replay_epoch_ = epoch;
        seen_payload_nonces_.clear();
    }

    Result<std::unique_ptr<Session>, ProtocolFailure> Session::FromHandshakeState(
        HandshakeState state) {
        if (state.state.version() != kProtocolVersion) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Invalid protocol version in handshake state"));
        }
        auto session = std::unique_ptr<Session>(
            new Session(std::move(state.state), std::move(state.kyber_shared_secret)));
        auto init_result = session->InitializeFromHandshake();
        if (init_result.IsErr()) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                init_result.UnwrapErr());
        }
        return Result<std::unique_ptr<Session>, ProtocolFailure>::Ok(std::move(session));
    }

    Result<std::unique_ptr<Session>, ProtocolFailure> Session::FromState(
        const ecliptix::proto::protocol::ProtocolState& state) {
        if (state.version() != kProtocolVersion) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Invalid protocol version in state"));
        }
        if (state.session_id().size() != kSessionIdBytes ||
            state.root_key().size() != kRootKeyBytes ||
            state.metadata_key().size() != kMetadataKeyBytes) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Invalid session key material sizes"));
        }
        if (state.dh_local().private_key().size() != kX25519PrivateKeyBytes ||
            state.dh_local().public_key().size() != kX25519PublicKeyBytes ||
            state.dh_remote_public().size() != kX25519PublicKeyBytes) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Invalid DH key sizes in state"));
        }
        if (state.dh_local_initial_public().size() != kX25519PublicKeyBytes ||
            state.dh_remote_initial_public().size() != kX25519PublicKeyBytes) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Invalid initial DH public key sizes in state"));
        }
        if (state.kyber_local().secret_key().size() != kKyberSecretKeyBytes ||
            state.kyber_local().public_key().size() != kKyberPublicKeyBytes ||
            state.kyber_remote_public().size() != kKyberPublicKeyBytes) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Invalid Kyber key sizes in state"));
        }
        if (state.send_chain().chain_key().size() != kChainKeyBytes ||
            state.recv_chain().chain_key().size() != kChainKeyBytes) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Invalid chain key sizes in state"));
        }
        if (state.nonce_generator().prefix().size() != kNoncePrefixBytes) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Invalid nonce prefix size in state"));
        }
        const uint64_t max_messages_per_chain = state.max_messages_per_chain();
        if (max_messages_per_chain == 0 || max_messages_per_chain > kMaxMessagesPerChain) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Invalid max messages per chain in state"));
        }
        if (state.send_chain().message_index() > max_messages_per_chain ||
            state.recv_chain().message_index() > max_messages_per_chain) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Chain index exceeds max messages per chain"));
        }
        if (state.nonce_generator().counter() > kMaxNonceCounter) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidState("Nonce counter exceeds maximum"));
        }
        if (IsAllZero(std::span(
            reinterpret_cast<const uint8_t*>(state.dh_local().private_key().data()),
            state.dh_local().private_key().size()))) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("DH private key is all zeros"));
        }
        if (IsAllZero(std::span(
            reinterpret_cast<const uint8_t*>(state.kyber_local().secret_key().data()),
            state.kyber_local().secret_key().size()))) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Kyber secret key is all zeros"));
        }

        auto dh_local_public = std::span(
            reinterpret_cast<const uint8_t*>(state.dh_local().public_key().data()),
            state.dh_local().public_key().size());
        if (auto dh_check = ValidateDhPublicKey(dh_local_public); dh_check.IsErr()) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(dh_check.UnwrapErr());
        }
        auto dh_remote_public = std::span(
            reinterpret_cast<const uint8_t*>(state.dh_remote_public().data()),
            state.dh_remote_public().size());
        if (auto dh_check = ValidateDhPublicKey(dh_remote_public); dh_check.IsErr()) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(dh_check.UnwrapErr());
        }
        auto dh_local_initial_public = std::span(
            reinterpret_cast<const uint8_t*>(state.dh_local_initial_public().data()),
            state.dh_local_initial_public().size());
        if (auto dh_check = ValidateDhPublicKey(dh_local_initial_public); dh_check.IsErr()) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(dh_check.UnwrapErr());
        }
        auto dh_remote_initial_public = std::span(
            reinterpret_cast<const uint8_t*>(state.dh_remote_initial_public().data()),
            state.dh_remote_initial_public().size());
        if (auto dh_check = ValidateDhPublicKey(dh_remote_initial_public); dh_check.IsErr()) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(dh_check.UnwrapErr());
        }

        auto kyber_public = std::span(
            reinterpret_cast<const uint8_t*>(state.kyber_local().public_key().data()),
            state.kyber_local().public_key().size());
        if (auto pq_check = KyberInterop::ValidatePublicKey(kyber_public); pq_check.IsErr()) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(pq_check.UnwrapErr()));
        }
        auto peer_kyber_public = std::span(
            reinterpret_cast<const uint8_t*>(state.kyber_remote_public().data()),
            state.kyber_remote_public().size());
        if (auto pq_check = KyberInterop::ValidatePublicKey(peer_kyber_public); pq_check.IsErr()) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(pq_check.UnwrapErr()));
        }
        if (state.state_hmac().size() != kHmacBytes) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Missing or invalid state HMAC"));
        }

        auto mac_key_result = DeriveKeyBytes(
            std::span(reinterpret_cast<const uint8_t*>(state.root_key().data()),
                      state.root_key().size()),
            kHmacBytes,
            {},
            kStateHmacInfo);
        if (mac_key_result.IsErr()) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                mac_key_result.UnwrapErr());
        }
        auto mac_key = mac_key_result.Unwrap();
        auto wipe_bytes = [](std::vector<uint8_t>& bytes) {
            if (!bytes.empty()) {
                auto _wipe = SodiumInterop::SecureWipe(std::span(bytes));
                (void) _wipe;
            }
        };

        auto mac_state = state;
        mac_state.clear_state_hmac();
        auto serialized_result = SerializeDeterministic(mac_state);
        if (serialized_result.IsErr()) {
            wipe_bytes(mac_key);
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                serialized_result.UnwrapErr());
        }
        auto serialized = serialized_result.Unwrap();

        auto expected_result = ComputeHmacSha256(std::span(mac_key), std::span(serialized));
        if (expected_result.IsErr()) {
            wipe_bytes(serialized);
            wipe_bytes(mac_key);
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                expected_result.UnwrapErr());
        }
        auto expected_mac = expected_result.Unwrap();

        const bool mac_ok = expected_mac.size() == state.state_hmac().size() &&
            sodium_memcmp(expected_mac.data(), state.state_hmac().data(), expected_mac.size()) == 0;
        wipe_bytes(expected_mac);
        wipe_bytes(serialized);
        wipe_bytes(mac_key);
        if (!mac_ok) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("State HMAC verification failed"));
        }

        if (!state.send_chain().skipped_message_keys().empty()) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Send chain must not include skipped message keys"));
        }

        std::map<uint64_t, std::vector<uint8_t>> skipped_message_keys;
        const auto& cached_keys = state.recv_chain().skipped_message_keys();
        if (static_cast<size_t>(cached_keys.size()) > kMaxSkippedMessageKeys) {
            return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Too many skipped message keys in state"));
        }
        std::unordered_set<uint64_t> cached_indices;
        cached_indices.reserve(cached_keys.size());
        for (const auto& cached : cached_keys) {
            if (cached.message_key().size() != kMessageKeyBytes) {
                return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Invalid skipped message key size in state"));
            }
            if (cached.message_index() > kMaxMessageIndex) {
                return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Cached message key index exceeds maximum"));
            }
            if (cached.message_index() >= state.recv_chain().message_index()) {
                return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Cached message key index out of range"));
            }
            if (!cached_indices.insert(cached.message_index()).second) {
                return Result<std::unique_ptr<Session>, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Duplicate skipped message key index"));
            }
            skipped_message_keys.emplace(
                cached.message_index(),
                std::vector<uint8_t>(cached.message_key().begin(), cached.message_key().end()));
        }

        auto sanitized_state = state;
        sanitized_state.clear_state_hmac();
        sanitized_state.mutable_send_chain()->clear_skipped_message_keys();
        sanitized_state.mutable_recv_chain()->clear_skipped_message_keys();
        auto session = std::unique_ptr<Session>(
            new Session(std::move(sanitized_state), std::vector<uint8_t>{}));
        if (!skipped_message_keys.empty()) {
            session->skipped_message_keys_ = std::move(skipped_message_keys);
        }
        return Result<std::unique_ptr<Session>, ProtocolFailure>::Ok(std::move(session));
    }

    Result<ecliptix::proto::protocol::ProtocolState, ProtocolFailure> Session::ExportState() {
        std::lock_guard<std::mutex> guard(lock_);
        if (state_.state_counter() == std::numeric_limits<uint64_t>::max()) {
            return Result<ecliptix::proto::protocol::ProtocolState, ProtocolFailure>::Err(
                ProtocolFailure::InvalidState("State counter overflow"));
        }

        const uint64_t next_generation = state_.state_counter() + 1;
        ecliptix::proto::protocol::ProtocolState copy = state_;
        copy.mutable_send_chain()->clear_skipped_message_keys();
        copy.mutable_recv_chain()->clear_skipped_message_keys();
        copy.set_state_counter(next_generation);
        copy.clear_state_hmac();

        auto mac_key_result = DeriveKeyBytes(
            std::span(reinterpret_cast<const uint8_t*>(state_.root_key().data()),
                      state_.root_key().size()),
            kHmacBytes,
            {},
            kStateHmacInfo);
        if (mac_key_result.IsErr()) {
            return Result<ecliptix::proto::protocol::ProtocolState, ProtocolFailure>::Err(
                mac_key_result.UnwrapErr());
        }
        auto mac_key = mac_key_result.Unwrap();
        auto wipe_bytes = [](std::vector<uint8_t>& bytes) {
            if (!bytes.empty()) {
                auto _wipe = SodiumInterop::SecureWipe(std::span(bytes));
                (void) _wipe;
            }
        };

        auto serialized_result = SerializeDeterministic(copy);
        if (serialized_result.IsErr()) {
            wipe_bytes(mac_key);
            return Result<ecliptix::proto::protocol::ProtocolState, ProtocolFailure>::Err(
                serialized_result.UnwrapErr());
        }
        auto serialized = serialized_result.Unwrap();

        auto mac_result = ComputeHmacSha256(std::span(mac_key), std::span(serialized));
        if (mac_result.IsErr()) {
            wipe_bytes(serialized);
            wipe_bytes(mac_key);
            return Result<ecliptix::proto::protocol::ProtocolState, ProtocolFailure>::Err(
                mac_result.UnwrapErr());
        }
        auto mac = mac_result.Unwrap();
        copy.set_state_hmac(mac.data(), mac.size());

        state_.set_state_counter(next_generation);

        wipe_bytes(mac);
        wipe_bytes(serialized);
        wipe_bytes(mac_key);
        return Result<ecliptix::proto::protocol::ProtocolState, ProtocolFailure>::Ok(std::move(copy));
    }

    Result<Unit, ProtocolFailure> Session::InitializeFromHandshake() {
        std::lock_guard<std::mutex> guard(lock_);
        auto wipe_pending = [&]() {
            if (!pending_kyber_shared_secret_.empty()) {
                auto _wipe = SodiumInterop::SecureWipe(std::span(pending_kyber_shared_secret_));
                (void) _wipe;
                pending_kyber_shared_secret_.clear();
            }
        };
        if (pending_kyber_shared_secret_.size() != kKyberSharedSecretBytes) {
            wipe_pending();
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::InvalidState("Missing Kyber shared secret for handshake init"));
        }
        if (state_.root_key().size() != kRootKeyBytes) {
            wipe_pending();
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Invalid root key size"));
        }
        if (state_.dh_local().private_key().size() != kX25519PrivateKeyBytes ||
            state_.dh_remote_public().size() != kX25519PublicKeyBytes) {
            wipe_pending();
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Invalid DH keys for handshake init"));
        }
        auto dh_peer = std::span(reinterpret_cast<const uint8_t*>(state_.dh_remote_public().data()),
                                 state_.dh_remote_public().size());
        if (auto dh_check = ValidateDhPublicKey(dh_peer); dh_check.IsErr()) {
            wipe_pending();
            return dh_check;
        }

        auto dh_init_result = ComputeDh(
            std::span(reinterpret_cast<const uint8_t*>(state_.dh_local().private_key().data()),
                      state_.dh_local().private_key().size()),
            dh_peer,
            "DH-Init");
        if (dh_init_result.IsErr()) {
            wipe_pending();
            return Result<Unit, ProtocolFailure>::Err(dh_init_result.UnwrapErr());
        }
        auto dh_init = dh_init_result.Unwrap();

        std::vector<uint8_t> hybrid_ikm;
        hybrid_ikm.reserve(dh_init.size() + pending_kyber_shared_secret_.size());
        hybrid_ikm.insert(hybrid_ikm.end(), dh_init.begin(), dh_init.end());
        hybrid_ikm.insert(hybrid_ikm.end(), pending_kyber_shared_secret_.begin(),
                          pending_kyber_shared_secret_.end());

        auto root_key_bytes = std::span(reinterpret_cast<const uint8_t*>(state_.root_key().data()),
                                        state_.root_key().size());
        auto hybrid_result = DeriveKeyBytes(
            std::span<const uint8_t>(hybrid_ikm.data(), hybrid_ikm.size()),
            kRootKeyBytes * 2,
            root_key_bytes,
            kHybridRatchetInfo);
        auto _wipe_ikm = SodiumInterop::SecureWipe(std::span(hybrid_ikm));
        (void) _wipe_ikm;
        auto _wipe_dh = SodiumInterop::SecureWipe(std::span(dh_init));
        (void) _wipe_dh;
        if (hybrid_result.IsErr()) {
            wipe_pending();
            return Result<Unit, ProtocolFailure>::Err(hybrid_result.UnwrapErr());
        }

        auto hybrid_out = hybrid_result.Unwrap();
        if (hybrid_out.size() != kRootKeyBytes * 2) {
            wipe_pending();
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::InvalidState("Hybrid ratchet output size mismatch"));
        }
        std::vector<uint8_t> new_root(hybrid_out.begin(), hybrid_out.begin() + kRootKeyBytes);
        std::vector<uint8_t> ck_unused(hybrid_out.begin() + kRootKeyBytes, hybrid_out.end());
        auto _wipe_unused = SodiumInterop::SecureWipe(std::span(ck_unused));
        (void) _wipe_unused;

        auto chain_init_result = DeriveKeyBytes(
            std::span<const uint8_t>(new_root.data(), new_root.size()),
            kChainKeyBytes * 2,
            {},
            kChainInitInfo);
        if (chain_init_result.IsErr()) {
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(new_root));
            (void) _wipe_root;
            wipe_pending();
            return Result<Unit, ProtocolFailure>::Err(chain_init_result.UnwrapErr());
        }
        auto chain_init = chain_init_result.Unwrap();
        if (chain_init.size() != kChainKeyBytes * 2) {
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(new_root));
            (void) _wipe_root;
            wipe_pending();
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::InvalidState("Chain init output size mismatch"));
        }
        std::vector<uint8_t> send_chain(chain_init.begin(), chain_init.begin() + kChainKeyBytes);
        std::vector<uint8_t> recv_chain(chain_init.begin() + kChainKeyBytes, chain_init.end());
        if (!is_initiator_) {
            std::swap(send_chain, recv_chain);
        }

        state_.set_root_key(new_root.data(), new_root.size());
        state_.mutable_send_chain()->set_chain_key(send_chain.data(), send_chain.size());
        state_.mutable_recv_chain()->set_chain_key(recv_chain.data(), recv_chain.size());
        state_.mutable_send_chain()->set_message_index(0);
        state_.mutable_recv_chain()->set_message_index(0);
        state_.mutable_send_chain()->clear_skipped_message_keys();
        state_.mutable_recv_chain()->clear_skipped_message_keys();
        state_.set_send_ratchet_epoch(0);
        state_.set_recv_ratchet_epoch(0);

        auto _wipe_root = SodiumInterop::SecureWipe(std::span(new_root));
        (void) _wipe_root;
        auto _wipe_send = SodiumInterop::SecureWipe(std::span(send_chain));
        (void) _wipe_send;
        auto _wipe_recv = SodiumInterop::SecureWipe(std::span(recv_chain));
        (void) _wipe_recv;
        wipe_pending();
        skipped_message_keys_.clear();
        return Result<Unit, ProtocolFailure>::Ok(Unit{});
    }

    Result<std::vector<uint8_t>, ProtocolFailure> Session::NextSendMessageKey(
        uint64_t& message_index) {
        auto* chain = state_.mutable_send_chain();
        if (chain->chain_key().size() != kChainKeyBytes) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidState("Sending chain key missing"));
        }
        message_index = chain->message_index();
        if (message_index > kMaxMessageIndex) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidState("Message index exceeds maximum"));
        }

        auto chain_key = std::vector<uint8_t>(
            chain->chain_key().begin(), chain->chain_key().end());
        auto derived_result = DeriveMessageAndChainKey(chain_key);
        auto _wipe_chain = SodiumInterop::SecureWipe(std::span(chain_key));
        (void) _wipe_chain;
        if (derived_result.IsErr()) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                derived_result.UnwrapErr());
        }
        auto [message_key, next_chain_key] = derived_result.Unwrap();
        chain->set_chain_key(next_chain_key.data(), next_chain_key.size());
        chain->set_message_index(message_index + 1);
        auto _wipe_next = SodiumInterop::SecureWipe(std::span(next_chain_key));
        (void) _wipe_next;
        return Result<std::vector<uint8_t>, ProtocolFailure>::Ok(std::move(message_key));
    }

    Result<std::vector<uint8_t>, ProtocolFailure> Session::GetRecvMessageKey(
        uint64_t message_index) {
        auto* chain = state_.mutable_recv_chain();
        if (chain->chain_key().size() != kChainKeyBytes) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidState("Receiving chain key missing"));
        }
        if (message_index > kMaxMessageIndex) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Message index exceeds maximum"));
        }

        const uint64_t current_index = chain->message_index();
        if (message_index < current_index) {
            auto it = skipped_message_keys_.find(message_index);
            if (it == skipped_message_keys_.end()) {
                return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                    ProtocolFailure::ReplayAttack("Replay attack detected: message index already processed"));
            }
            auto key = it->second;
            skipped_message_keys_.erase(it);
            return Result<std::vector<uint8_t>, ProtocolFailure>::Ok(std::move(key));
        }

        std::vector<uint8_t> chain_key(
            chain->chain_key().begin(), chain->chain_key().end());
        uint64_t index = current_index;
        while (index <= message_index) {
            auto derived_result = DeriveMessageAndChainKey(chain_key);
            auto _wipe_chain = SodiumInterop::SecureWipe(std::span(chain_key));
            (void) _wipe_chain;
            if (derived_result.IsErr()) {
                return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                    derived_result.UnwrapErr());
            }
            auto [message_key, next_chain_key] = derived_result.Unwrap();
            if (index < message_index) {
                if (skipped_message_keys_.size() >= kMaxSkippedMessageKeys) {
                    auto _wipe_msg = SodiumInterop::SecureWipe(std::span(message_key));
                    (void) _wipe_msg;
                    auto _wipe_next = SodiumInterop::SecureWipe(std::span(next_chain_key));
                    (void) _wipe_next;
                    return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                        ProtocolFailure::InvalidState("Message key cache overflow"));
                }
                skipped_message_keys_.emplace(index, std::move(message_key));
            } else {
                chain->set_chain_key(next_chain_key.data(), next_chain_key.size());
                chain->set_message_index(message_index + 1);
                auto _wipe_next = SodiumInterop::SecureWipe(std::span(next_chain_key));
                (void) _wipe_next;
                return Result<std::vector<uint8_t>, ProtocolFailure>::Ok(std::move(message_key));
            }
            chain_key = std::move(next_chain_key);
            index += 1;
        }
        return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
            ProtocolFailure::InvalidState("Failed to derive message key"));
    }

    Result<Unit, ProtocolFailure> Session::MaybeRotateSendRatchet(
        ecliptix::proto::protocol::SecureEnvelope& envelope) {
        auto* chain = state_.mutable_send_chain();
        const uint64_t max_messages_per_chain = state_.max_messages_per_chain();
        if (max_messages_per_chain == 0 || max_messages_per_chain > kMaxMessagesPerChain) {
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::InvalidState("Invalid max messages per chain"));
        }
        if (chain->message_index() < max_messages_per_chain) {
            return Result<Unit, ProtocolFailure>::Ok(Unit{});
        }
        if (state_.dh_remote_public().size() != kX25519PublicKeyBytes ||
            state_.root_key().size() != kRootKeyBytes) {
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::InvalidState("Cannot rotate ratchet: missing key material"));
        }
        if (state_.kyber_remote_public().size() != kKyberPublicKeyBytes) {
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::InvalidState("Peer Kyber public key missing"));
        }

        auto new_keypair_result = SodiumInterop::GenerateX25519KeyPair("ratchet");
        if (new_keypair_result.IsErr()) {
            return Result<Unit, ProtocolFailure>::Err(new_keypair_result.UnwrapErr());
        }
        auto [new_private_handle, new_public] = std::move(new_keypair_result).Unwrap();
        auto new_private_result = new_private_handle.ReadBytes(kX25519PrivateKeyBytes);
        if (new_private_result.IsErr()) {
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(new_private_result.UnwrapErr()));
        }
        auto new_private = new_private_result.Unwrap();

        auto peer_dh = std::span(reinterpret_cast<const uint8_t*>(state_.dh_remote_public().data()),
                                 state_.dh_remote_public().size());
        if (auto dh_check = ValidateDhPublicKey(peer_dh); dh_check.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(new_private));
            (void) _wipe;
            return dh_check;
        }

        auto dh_secret_result = ComputeDh(
            std::span<const uint8_t>(new_private.data(), new_private.size()),
            peer_dh,
            "DH-Ratchet-Send");
        if (dh_secret_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(new_private));
            (void) _wipe;
            return Result<Unit, ProtocolFailure>::Err(dh_secret_result.UnwrapErr());
        }
        auto dh_secret = dh_secret_result.Unwrap();

        auto encap_result = KyberInterop::Encapsulate(
            std::span(reinterpret_cast<const uint8_t*>(state_.kyber_remote_public().data()),
                      state_.kyber_remote_public().size()));
        if (encap_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(new_private));
            (void) _wipe;
            auto _wipe_dh = SodiumInterop::SecureWipe(std::span(dh_secret));
            (void) _wipe_dh;
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(encap_result.UnwrapErr()));
        }
        auto [kyber_ct, kyber_ss_handle] = std::move(encap_result).Unwrap();
        auto kyber_ss_result = kyber_ss_handle.ReadBytes(kKyberSharedSecretBytes);
        if (kyber_ss_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(new_private));
            (void) _wipe;
            auto _wipe_dh = SodiumInterop::SecureWipe(std::span(dh_secret));
            (void) _wipe_dh;
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(kyber_ss_result.UnwrapErr()));
        }
        auto kyber_ss = kyber_ss_result.Unwrap();

        std::vector<uint8_t> hybrid_ikm;
        hybrid_ikm.reserve(dh_secret.size() + kyber_ss.size());
        hybrid_ikm.insert(hybrid_ikm.end(), dh_secret.begin(), dh_secret.end());
        hybrid_ikm.insert(hybrid_ikm.end(), kyber_ss.begin(), kyber_ss.end());

        auto root_key_bytes = std::span(reinterpret_cast<const uint8_t*>(state_.root_key().data()),
                                        state_.root_key().size());
        auto ratchet_result = DeriveKeyBytes(
            std::span<const uint8_t>(hybrid_ikm.data(), hybrid_ikm.size()),
            kRootKeyBytes * 2,
            root_key_bytes,
            kHybridRatchetInfo);
        auto _wipe_ikm = SodiumInterop::SecureWipe(std::span(hybrid_ikm));
        (void) _wipe_ikm;
        auto _wipe_dh = SodiumInterop::SecureWipe(std::span(dh_secret));
        (void) _wipe_dh;
        auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_ss));
        (void) _wipe_pq;
        if (ratchet_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(new_private));
            (void) _wipe;
            return Result<Unit, ProtocolFailure>::Err(ratchet_result.UnwrapErr());
        }
        auto ratchet_out = ratchet_result.Unwrap();
        if (ratchet_out.size() != kRootKeyBytes * 2) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(new_private));
            (void) _wipe;
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::InvalidState("Ratchet output size mismatch"));
        }
        std::vector<uint8_t> new_root(ratchet_out.begin(), ratchet_out.begin() + kRootKeyBytes);
        std::vector<uint8_t> new_chain(ratchet_out.begin() + kRootKeyBytes, ratchet_out.end());

        state_.set_root_key(new_root.data(), new_root.size());
        state_.mutable_send_chain()->set_chain_key(new_chain.data(), new_chain.size());
        state_.mutable_send_chain()->set_message_index(0);
        state_.set_send_ratchet_epoch(state_.send_ratchet_epoch() + 1);
        state_.mutable_dh_local()->set_private_key(new_private.data(), new_private.size());
        state_.mutable_dh_local()->set_public_key(new_public.data(), new_public.size());

        envelope.set_dh_public_key(new_public.data(), new_public.size());
        envelope.set_kyber_ciphertext(kyber_ct.data(), kyber_ct.size());

        auto _wipe_root = SodiumInterop::SecureWipe(std::span(new_root));
        (void) _wipe_root;
        auto _wipe_chain = SodiumInterop::SecureWipe(std::span(new_chain));
        (void) _wipe_chain;
        auto _wipe_private = SodiumInterop::SecureWipe(std::span(new_private));
        (void) _wipe_private;
        return Result<Unit, ProtocolFailure>::Ok(Unit{});
    }

    Result<Unit, ProtocolFailure> Session::ApplyRecvRatchet(
        const ecliptix::proto::protocol::SecureEnvelope& envelope) {
        if (!envelope.has_dh_public_key() || !envelope.has_kyber_ciphertext()) {
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Ratchet header missing"));
        }
        if (envelope.dh_public_key().size() != kX25519PublicKeyBytes ||
            envelope.kyber_ciphertext().size() != kKyberCiphertextBytes) {
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Invalid ratchet header sizes"));
        }
        auto dh_public = std::span(
            reinterpret_cast<const uint8_t*>(envelope.dh_public_key().data()),
            envelope.dh_public_key().size());
        if (auto dh_check = ValidateDhPublicKey(dh_public); dh_check.IsErr()) {
            return dh_check;
        }
        if (auto pq_check = KyberInterop::ValidateCiphertext(
            std::span(reinterpret_cast<const uint8_t*>(envelope.kyber_ciphertext().data()),
                      envelope.kyber_ciphertext().size())); pq_check.IsErr()) {
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(pq_check.UnwrapErr()));
        }
        if (state_.kyber_local().secret_key().size() != kKyberSecretKeyBytes) {
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::InvalidState("Missing Kyber secret key"));
        }
        if (state_.root_key().size() != kRootKeyBytes ||
            state_.dh_local().private_key().size() != kX25519PrivateKeyBytes) {
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::InvalidState("Missing ratchet key material"));
        }

        auto dh_secret_result = ComputeDh(
            std::span(reinterpret_cast<const uint8_t*>(state_.dh_local().private_key().data()),
                      state_.dh_local().private_key().size()),
            dh_public,
            "DH-Ratchet-Recv");
        if (dh_secret_result.IsErr()) {
            return Result<Unit, ProtocolFailure>::Err(dh_secret_result.UnwrapErr());
        }
        auto dh_secret = dh_secret_result.Unwrap();

        auto sk_handle_result = SecureMemoryHandle::Allocate(kKyberSecretKeyBytes);
        if (sk_handle_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(dh_secret));
            (void) _wipe;
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(sk_handle_result.UnwrapErr()));
        }
        auto sk_handle = std::move(sk_handle_result).Unwrap();
        auto write_result = sk_handle.Write(
            std::span(reinterpret_cast<const uint8_t*>(state_.kyber_local().secret_key().data()),
                      state_.kyber_local().secret_key().size()));
        if (write_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(dh_secret));
            (void) _wipe;
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(write_result.UnwrapErr()));
        }
        auto decap_result = KyberInterop::Decapsulate(
            std::span(reinterpret_cast<const uint8_t*>(envelope.kyber_ciphertext().data()),
                      envelope.kyber_ciphertext().size()),
            sk_handle);
        if (decap_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(dh_secret));
            (void) _wipe;
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(decap_result.UnwrapErr()));
        }
        auto ss_handle = std::move(decap_result).Unwrap();
        auto ss_bytes_result = ss_handle.ReadBytes(kKyberSharedSecretBytes);
        if (ss_bytes_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(dh_secret));
            (void) _wipe;
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(ss_bytes_result.UnwrapErr()));
        }
        auto kyber_ss = ss_bytes_result.Unwrap();

        std::vector<uint8_t> hybrid_ikm;
        hybrid_ikm.reserve(dh_secret.size() + kyber_ss.size());
        hybrid_ikm.insert(hybrid_ikm.end(), dh_secret.begin(), dh_secret.end());
        hybrid_ikm.insert(hybrid_ikm.end(), kyber_ss.begin(), kyber_ss.end());

        auto root_key_bytes = std::span(reinterpret_cast<const uint8_t*>(state_.root_key().data()),
                                        state_.root_key().size());
        auto ratchet_result = DeriveKeyBytes(
            std::span<const uint8_t>(hybrid_ikm.data(), hybrid_ikm.size()),
            kRootKeyBytes * 2,
            root_key_bytes,
            kHybridRatchetInfo);
        auto _wipe_ikm = SodiumInterop::SecureWipe(std::span(hybrid_ikm));
        (void) _wipe_ikm;
        auto _wipe_dh = SodiumInterop::SecureWipe(std::span(dh_secret));
        (void) _wipe_dh;
        auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_ss));
        (void) _wipe_pq;
        if (ratchet_result.IsErr()) {
            return Result<Unit, ProtocolFailure>::Err(ratchet_result.UnwrapErr());
        }
        auto ratchet_out = ratchet_result.Unwrap();
        if (ratchet_out.size() != kRootKeyBytes * 2) {
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::InvalidState("Ratchet output size mismatch"));
        }
        std::vector<uint8_t> new_root(ratchet_out.begin(), ratchet_out.begin() + kRootKeyBytes);
        std::vector<uint8_t> new_chain(ratchet_out.begin() + kRootKeyBytes, ratchet_out.end());

        state_.set_root_key(new_root.data(), new_root.size());
        state_.mutable_recv_chain()->set_chain_key(new_chain.data(), new_chain.size());
        state_.mutable_recv_chain()->set_message_index(0);
        state_.set_recv_ratchet_epoch(state_.recv_ratchet_epoch() + 1);
        state_.set_dh_remote_public(dh_public.data(), dh_public.size());
        skipped_message_keys_.clear();
        ResetReplayTracking(state_.recv_ratchet_epoch());

        auto _wipe_root = SodiumInterop::SecureWipe(std::span(new_root));
        (void) _wipe_root;
        auto _wipe_chain = SodiumInterop::SecureWipe(std::span(new_chain));
        (void) _wipe_chain;
        return Result<Unit, ProtocolFailure>::Ok(Unit{});
    }

    Result<ecliptix::proto::protocol::SecureEnvelope, ProtocolFailure> Session::Encrypt(
        std::span<const uint8_t> payload,
        ecliptix::proto::protocol::EnvelopeType envelope_type,
        uint32_t envelope_id,
        std::string_view correlation_id) {
        std::lock_guard<std::mutex> guard(lock_);
        if (state_.metadata_key().size() != kMetadataKeyBytes) {
            return Result<ecliptix::proto::protocol::SecureEnvelope, ProtocolFailure>::Err(
                ProtocolFailure::InvalidState("Metadata key not initialized"));
        }

        ecliptix::proto::protocol::SecureEnvelope envelope;
        envelope.set_version(kProtocolVersion);

        auto rotate_result = MaybeRotateSendRatchet(envelope);
        if (rotate_result.IsErr()) {
            return Result<ecliptix::proto::protocol::SecureEnvelope, ProtocolFailure>::Err(
                rotate_result.UnwrapErr());
        }

        const uint64_t ratchet_epoch = state_.send_ratchet_epoch();
        envelope.set_ratchet_epoch(ratchet_epoch);

        uint64_t message_index = 0;
        auto message_key_result = NextSendMessageKey(message_index);
        if (message_key_result.IsErr()) {
            return Result<ecliptix::proto::protocol::SecureEnvelope, ProtocolFailure>::Err(
                message_key_result.UnwrapErr());
        }
        auto message_key = message_key_result.Unwrap();

        auto nonce_gen_result = LoadNonceGenerator(state_);
        if (nonce_gen_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(message_key));
            (void) _wipe;
            return Result<ecliptix::proto::protocol::SecureEnvelope, ProtocolFailure>::Err(
                nonce_gen_result.UnwrapErr());
        }
        auto nonce_generator = nonce_gen_result.Unwrap();
        auto payload_nonce_result = nonce_generator.Next(message_index);
        if (payload_nonce_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(message_key));
            (void) _wipe;
            return Result<ecliptix::proto::protocol::SecureEnvelope, ProtocolFailure>::Err(
                payload_nonce_result.UnwrapErr());
        }
        auto payload_nonce = payload_nonce_result.Unwrap();
        StoreNonceState(state_, nonce_generator.ExportState());

        ecliptix::proto::protocol::EnvelopeMetadata metadata;
        metadata.set_message_index(message_index);
        metadata.set_payload_nonce(payload_nonce.data(), payload_nonce.size());
        metadata.set_envelope_type(envelope_type);
        metadata.set_envelope_id(envelope_id);
        if (!correlation_id.empty()) {
            metadata.set_correlation_id(std::string(correlation_id));
        }

        std::string metadata_bytes;
        if (!metadata.SerializeToString(&metadata_bytes)) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(message_key));
            (void) _wipe;
            return Result<ecliptix::proto::protocol::SecureEnvelope, ProtocolFailure>::Err(
                ProtocolFailure::Encode("Failed to serialize metadata"));
        }

        auto header_nonce = SodiumInterop::GetRandomBytes(kAesGcmNonceBytes);
        if (header_nonce.size() != kAesGcmNonceBytes) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(message_key));
            (void) _wipe;
            return Result<ecliptix::proto::protocol::SecureEnvelope, ProtocolFailure>::Err(
                ProtocolFailure::Generic("Failed to generate header nonce"));
        }

        auto metadata_aad_result = BuildMetadataAad(state_, ratchet_epoch);
        if (metadata_aad_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(message_key));
            (void) _wipe;
            return Result<ecliptix::proto::protocol::SecureEnvelope, ProtocolFailure>::Err(
                metadata_aad_result.UnwrapErr());
        }
        auto metadata_aad = metadata_aad_result.Unwrap();

        auto metadata_encrypt_result = AesGcm::Encrypt(
            std::span(reinterpret_cast<const uint8_t*>(state_.metadata_key().data()),
                      state_.metadata_key().size()),
            header_nonce,
            std::span(reinterpret_cast<const uint8_t*>(metadata_bytes.data()), metadata_bytes.size()),
            metadata_aad);
        if (metadata_encrypt_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(message_key));
            (void) _wipe;
            return Result<ecliptix::proto::protocol::SecureEnvelope, ProtocolFailure>::Err(
                metadata_encrypt_result.UnwrapErr());
        }
        auto encrypted_metadata = metadata_encrypt_result.Unwrap();

        auto payload_aad_result = BuildPayloadAad(state_, ratchet_epoch, message_index);
        if (payload_aad_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(message_key));
            (void) _wipe;
            return Result<ecliptix::proto::protocol::SecureEnvelope, ProtocolFailure>::Err(
                payload_aad_result.UnwrapErr());
        }
        auto payload_aad = payload_aad_result.Unwrap();

        auto payload_encrypt_result = AesGcm::Encrypt(
            std::span<const uint8_t>(message_key.data(), message_key.size()),
            payload_nonce,
            payload,
            payload_aad);
        auto _wipe_msg = SodiumInterop::SecureWipe(std::span(message_key));
        (void) _wipe_msg;
        if (payload_encrypt_result.IsErr()) {
            return Result<ecliptix::proto::protocol::SecureEnvelope, ProtocolFailure>::Err(
                payload_encrypt_result.UnwrapErr());
        }
        auto encrypted_payload = payload_encrypt_result.Unwrap();

        envelope.set_encrypted_metadata(encrypted_metadata.data(), encrypted_metadata.size());
        envelope.set_encrypted_payload(encrypted_payload.data(), encrypted_payload.size());
        envelope.set_header_nonce(header_nonce.data(), header_nonce.size());
        SetTimestampNow(envelope.mutable_sent_at());

        return Result<ecliptix::proto::protocol::SecureEnvelope, ProtocolFailure>::Ok(std::move(envelope));
    }

    Result<Session::DecryptResult, ProtocolFailure> Session::Decrypt(
        const ecliptix::proto::protocol::SecureEnvelope& envelope) {
        std::lock_guard<std::mutex> guard(lock_);
        if (envelope.version() != kProtocolVersion) {
            return Result<Session::DecryptResult, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Invalid envelope version"));
        }
        if (envelope.header_nonce().size() != kAesGcmNonceBytes) {
            return Result<Session::DecryptResult, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Invalid header nonce size"));
        }
        if (state_.metadata_key().size() != kMetadataKeyBytes) {
            return Result<Session::DecryptResult, ProtocolFailure>::Err(
                ProtocolFailure::InvalidState("Metadata key not initialized"));
        }
        const uint64_t max_messages_per_chain = state_.max_messages_per_chain();
        if (max_messages_per_chain == 0 || max_messages_per_chain > kMaxMessagesPerChain) {
            return Result<Session::DecryptResult, ProtocolFailure>::Err(
                ProtocolFailure::InvalidState("Invalid max messages per chain"));
        }

        const uint64_t envelope_epoch = envelope.ratchet_epoch();
        if (envelope.has_dh_public_key() || envelope.has_kyber_ciphertext()) {
            if (!envelope.has_dh_public_key() || !envelope.has_kyber_ciphertext()) {
                return Result<Session::DecryptResult, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidInput("Incomplete ratchet header"));
            }
            if (envelope_epoch != state_.recv_ratchet_epoch() + 1) {
                return Result<Session::DecryptResult, ProtocolFailure>::Err(
                    ProtocolFailure::InvalidState("Unexpected ratchet epoch"));
            }
            auto ratchet_result = ApplyRecvRatchet(envelope);
            if (ratchet_result.IsErr()) {
                return Result<Session::DecryptResult, ProtocolFailure>::Err(
                    ratchet_result.UnwrapErr());
            }
        } else if (envelope_epoch != state_.recv_ratchet_epoch()) {
            return Result<Session::DecryptResult, ProtocolFailure>::Err(
                ProtocolFailure::InvalidState("Stale or future ratchet epoch"));
        }

        auto metadata_aad_result = BuildMetadataAad(state_, envelope_epoch);
        if (metadata_aad_result.IsErr()) {
            return Result<Session::DecryptResult, ProtocolFailure>::Err(
                metadata_aad_result.UnwrapErr());
        }
        auto metadata_aad = metadata_aad_result.Unwrap();

        auto metadata_decrypt_result = AesGcm::Decrypt(
            std::span(reinterpret_cast<const uint8_t*>(state_.metadata_key().data()),
                      state_.metadata_key().size()),
            std::span(reinterpret_cast<const uint8_t*>(envelope.header_nonce().data()),
                      envelope.header_nonce().size()),
            std::span(reinterpret_cast<const uint8_t*>(envelope.encrypted_metadata().data()),
                      envelope.encrypted_metadata().size()),
            metadata_aad);
        if (metadata_decrypt_result.IsErr()) {
            return Result<Session::DecryptResult, ProtocolFailure>::Err(
                metadata_decrypt_result.UnwrapErr());
        }
        auto metadata_bytes = metadata_decrypt_result.Unwrap();
        ecliptix::proto::protocol::EnvelopeMetadata metadata;
        if (!metadata.ParseFromArray(metadata_bytes.data(), static_cast<int>(metadata_bytes.size()))) {
            return Result<Session::DecryptResult, ProtocolFailure>::Err(
                ProtocolFailure::Decode("Failed to parse metadata"));
        }

        if (metadata.payload_nonce().size() != kAesGcmNonceBytes) {
            return Result<Session::DecryptResult, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Invalid payload nonce size"));
        }
        if (metadata.message_index() > kMaxMessageIndex) {
            return Result<Session::DecryptResult, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Message index exceeds maximum"));
        }
        if (metadata.message_index() >= max_messages_per_chain) {
            return Result<Session::DecryptResult, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Message index exceeds per-chain limit"));
        }

        auto nonce_index_result = ExtractNonceIndex(
            std::span(reinterpret_cast<const uint8_t*>(metadata.payload_nonce().data()),
                      metadata.payload_nonce().size()));
        if (nonce_index_result.IsErr()) {
            return Result<Session::DecryptResult, ProtocolFailure>::Err(
                nonce_index_result.UnwrapErr());
        }
        if (nonce_index_result.Unwrap() != metadata.message_index()) {
            return Result<Session::DecryptResult, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Nonce index mismatch"));
        }

        if (replay_epoch_ != state_.recv_ratchet_epoch()) {
            ResetReplayTracking(state_.recv_ratchet_epoch());
        }

        std::string payload_nonce_key(
            metadata.payload_nonce().data(),
            metadata.payload_nonce().size());
        if (seen_payload_nonces_.find(payload_nonce_key) != seen_payload_nonces_.end()) {
            return Result<Session::DecryptResult, ProtocolFailure>::Err(
                ProtocolFailure::ReplayAttack("Replay attack detected: payload nonce reused"));
        }

        auto message_key_result = GetRecvMessageKey(metadata.message_index());
        if (message_key_result.IsErr()) {
            return Result<Session::DecryptResult, ProtocolFailure>::Err(
                message_key_result.UnwrapErr());
        }
        auto message_key = message_key_result.Unwrap();

        auto payload_aad_result = BuildPayloadAad(state_, envelope_epoch, metadata.message_index());
        if (payload_aad_result.IsErr()) {
            auto _wipe = SodiumInterop::SecureWipe(std::span(message_key));
            (void) _wipe;
            return Result<Session::DecryptResult, ProtocolFailure>::Err(
                payload_aad_result.UnwrapErr());
        }
        auto payload_aad = payload_aad_result.Unwrap();

        auto payload_decrypt_result = AesGcm::Decrypt(
            std::span<const uint8_t>(message_key.data(), message_key.size()),
            std::span(reinterpret_cast<const uint8_t*>(metadata.payload_nonce().data()),
                      metadata.payload_nonce().size()),
            std::span(reinterpret_cast<const uint8_t*>(envelope.encrypted_payload().data()),
                      envelope.encrypted_payload().size()),
            payload_aad);
        auto _wipe_msg = SodiumInterop::SecureWipe(std::span(message_key));
        (void) _wipe_msg;
        if (payload_decrypt_result.IsErr()) {
            return Result<Session::DecryptResult, ProtocolFailure>::Err(
                payload_decrypt_result.UnwrapErr());
        }

        seen_payload_nonces_.insert(std::move(payload_nonce_key));

        Session::DecryptResult result;
        result.plaintext = payload_decrypt_result.Unwrap();
        result.metadata = std::move(metadata);
        return Result<Session::DecryptResult, ProtocolFailure>::Ok(std::move(result));
    }

    uint32_t Session::Version() const noexcept {
        return kProtocolVersion;
    }

    bool Session::IsInitiator() const noexcept {
        return is_initiator_;
    }

}  // namespace ecliptix::protocol
