#include "ecliptix/protocol/connection/ecliptix_protocol_connection.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/kyber_interop.hpp"
#include "ecliptix/crypto/aes_gcm.hpp"
#include "ecliptix/crypto/hkdf.hpp"
#include "ecliptix/security/validation/dh_validator.hpp"
#include "protocol/protocol_state.pb.h"
#include <cstdlib>
#include <sodium.h>
#include <chrono>
#include <format>
#include <string>
#include <mutex>
#include <optional>
#include <array>

namespace ecliptix::protocol::connection {
    using namespace ecliptix::protocol::crypto;
    using namespace ecliptix::protocol::security;
    using namespace ecliptix::protocol::chain_step;
    using namespace ecliptix::protocol::enums;
    using ProtocolConstants = ProtocolConstants;

    namespace {
        Result<std::vector<uint8_t>, EcliptixProtocolFailure> GetStateMacSecret() {
            static std::once_flag init_flag;
            static std::optional<std::vector<uint8_t> > cached_secret;
            static std::string init_error;
            std::call_once(init_flag, []() {
                const char *env = std::getenv("ECLIPTIX_STATE_MAC_SECRET");
                if (env == nullptr) {
#ifdef ECLIPTIX_TEST_BUILD
                    env = "test-state-mac-secret-ecliptix-derive-key-material";
#else
                    init_error = "ECLIPTIX_STATE_MAC_SECRET is required for state integrity";
                    return;
#endif
                }
                const std::string secret_str(env);
                if (secret_str.size() < crypto_generichash_KEYBYTES) {
#ifdef ECLIPTIX_TEST_BUILD
                    init_error.clear();
                    cached_secret = std::vector<uint8_t>(
                        crypto_generichash_KEYBYTES, 0x42);
                    return;
#else
                    init_error = "ECLIPTIX_STATE_MAC_SECRET must be at least 32 bytes";
                    return;
#endif
                }
                std::vector<uint8_t> hashed(crypto_generichash_KEYBYTES);
                crypto_generichash(
                    hashed.data(),
                    hashed.size(),
                    reinterpret_cast<const unsigned char *>(secret_str.data()),
                    secret_str.size(),
                    nullptr,
                    0);
                cached_secret = std::move(hashed);
            });
            if (!cached_secret.has_value()) {
                return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic(init_error));
            }
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Ok(*cached_secret);
        }

        Result<std::vector<uint8_t>, EcliptixProtocolFailure> DeriveHybridDhSecret(
            std::span<const uint8_t> x25519_secret,
            std::span<const uint8_t> current_root_key,
            const std::optional<std::vector<uint8_t>>& kyber_ss_opt) {
            if (x25519_secret.size() != Constants::X_25519_KEY_SIZE ||
                current_root_key.size() != Constants::X_25519_KEY_SIZE) {
                return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::InvalidInput("Hybrid secret derivation requires 32-byte inputs"));
            }
            if (!kyber_ss_opt || kyber_ss_opt->empty()) {
                return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Kyber shared secret is required for hybrid ratchet"));
            }
            std::vector<uint8_t> kyber_ss = *kyber_ss_opt;
            auto hybrid_handle_result = KyberInterop::CombineHybridSecrets(
                x25519_secret,
                kyber_ss,
                std::string(ProtocolConstants::HYBRID_DH_RATCHET_INFO));
            auto _wipe_pq = SodiumInterop::SecureWipe(std::span(kyber_ss));
            (void) _wipe_pq;
            if (hybrid_handle_result.IsErr()) {
                return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                    hybrid_handle_result.UnwrapErr());
            }
            auto hybrid_handle = std::move(hybrid_handle_result).Unwrap();
            auto hybrid_bytes_result = hybrid_handle.ReadBytes(Constants::X_25519_KEY_SIZE);
        if (hybrid_bytes_result.IsErr()) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(hybrid_bytes_result.UnwrapErr()));
        }
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Ok(hybrid_bytes_result.Unwrap());
        }

        Result<std::vector<uint8_t>, EcliptixProtocolFailure> DeriveKyberWrapKey(
            std::span<const uint8_t> root_key_bytes,
            const uint32_t connection_id,
            std::span<const uint8_t> session_id,
            std::span<const uint8_t> kyber_public_key,
            std::span<const uint8_t> peer_kyber_public_key,
            std::span<const uint8_t> kyber_ciphertext) {
            std::vector<uint8_t> info;
            info.insert(info.end(),
                        ProtocolConstants::KYBER_SK_WRAP_INFO.begin(),
                        ProtocolConstants::KYBER_SK_WRAP_INFO.end());
            info.push_back(static_cast<uint8_t>((connection_id >> 24) & 0xFF));
            info.push_back(static_cast<uint8_t>((connection_id >> 16) & 0xFF));
            info.push_back(static_cast<uint8_t>((connection_id >> 8) & 0xFF));
            info.push_back(static_cast<uint8_t>(connection_id & 0xFF));
            info.insert(info.end(), session_id.begin(), session_id.end());
            info.insert(info.end(), kyber_public_key.begin(), kyber_public_key.end());
            info.insert(info.end(), peer_kyber_public_key.begin(), peer_kyber_public_key.end());
            info.insert(info.end(), kyber_ciphertext.begin(), kyber_ciphertext.end());
            auto wrap_key_result = Hkdf::DeriveKeyBytes(
                root_key_bytes,
                Constants::AES_KEY_SIZE,
                std::vector<uint8_t>(),
                info);
            if (wrap_key_result.IsErr()) {
                return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(wrap_key_result.UnwrapErr());
            }
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Ok(wrap_key_result.Unwrap());
        }

        std::vector<uint8_t> BuildKyberWrapAssociatedData(
            std::span<const uint8_t> session_id,
            std::span<const uint8_t> kyber_public_key,
            std::span<const uint8_t> peer_kyber_public_key,
            std::span<const uint8_t> kyber_ciphertext) {
            std::vector<uint8_t> ad;
            ad.insert(ad.end(), session_id.begin(), session_id.end());
            ad.insert(ad.end(), kyber_public_key.begin(), kyber_public_key.end());
            ad.insert(ad.end(), peer_kyber_public_key.begin(), peer_kyber_public_key.end());
            ad.insert(ad.end(), kyber_ciphertext.begin(), kyber_ciphertext.end());
            return ad;
        }
    }

    EcliptixProtocolConnection::EcliptixProtocolConnection(
        uint32_t connection_id,
        const bool is_initiator,
        RatchetConfig ratchet_config,
        PubKeyExchangeType exchange_type,
        SecureMemoryHandle initial_sending_dh_private_handle,
        std::vector<uint8_t> initial_sending_dh_public,
        SecureMemoryHandle persistent_dh_private_handle,
        std::vector<uint8_t> persistent_dh_public,
        EcliptixProtocolChainStep sending_step)
        : lock_(std::make_unique<std::mutex>())
          , id_(connection_id)
          , created_at_(std::chrono::system_clock::now())
          , session_id_(SodiumInterop::GetRandomBytes(16))
          , is_initiator_(is_initiator)
          , exchange_type_(exchange_type)
          , ratchet_config_(ratchet_config)
          , root_key_handle_()
          , metadata_encryption_key_handle_()
          , initial_sending_dh_private_handle_(std::move(initial_sending_dh_private_handle))
          , initial_sending_dh_public_(initial_sending_dh_public)
          , current_sending_dh_private_handle_()
          , current_sending_dh_public_(initial_sending_dh_public)
          , persistent_dh_private_handle_(std::move(persistent_dh_private_handle))
          , persistent_dh_public_(std::move(persistent_dh_public))
          , sending_step_(std::move(sending_step))
          , receiving_step_()
          , peer_bundle_()
          , peer_dh_public_key_()
          , replay_protection_(connection_id)
          , nonce_counter_(ProtocolConstants::INITIAL_NONCE_COUNTER)
          , pending_send_index_(std::nullopt)
          , rate_limit_window_start_ns_(0)
          , nonces_in_current_window_(0)
          , dh_ratchet_rate_limit_window_start_ns_(0)
          , dh_ratchets_in_current_window_(0)
          , disposed_(false)
          , is_first_receiving_ratchet_(true)
          , received_new_dh_key_(false)
          , ratchet_warning_triggered_(false)
          , receiving_ratchet_epoch_(0)
          , event_handler_(nullptr) {
    }

    EcliptixProtocolConnection::EcliptixProtocolConnection(
        uint32_t connection_id,
        bool is_initiator,
        RatchetConfig ratchet_config,
        PubKeyExchangeType exchange_type,
        std::chrono::system_clock::time_point created_at,
        std::vector<uint8_t> session_id,
        uint64_t nonce_counter,
        SecureMemoryHandle root_key_handle,
        SecureMemoryHandle metadata_encryption_key_handle,
        EcliptixProtocolChainStep sending_step,
        std::optional<EcliptixProtocolChainStep> receiving_step,
        std::optional<LocalPublicKeyBundle> peer_bundle,
        std::optional<std::vector<uint8_t> > peer_dh_public_key,
        std::optional<std::vector<uint8_t> > peer_kyber_public_key,
        std::optional<std::vector<uint8_t> > kyber_ciphertext,
        std::optional<std::vector<uint8_t> > kyber_shared_secret,
        SecureMemoryHandle kyber_secret_key_handle,
        std::vector<uint8_t> kyber_public_key,
        SecureMemoryHandle initial_sending_dh_private_handle,
        std::vector<uint8_t> initial_sending_dh_public,
        SecureMemoryHandle current_sending_dh_private_handle,
        SecureMemoryHandle persistent_dh_private_handle,
        std::vector<uint8_t> persistent_dh_public,
        bool is_first_receiving_ratchet)
        : lock_(std::make_unique<std::mutex>())
          , id_(connection_id)
          , created_at_(created_at)
          , session_id_(std::move(session_id))
          , is_initiator_(is_initiator)
          , exchange_type_(exchange_type)
          , ratchet_config_(ratchet_config)
          , root_key_handle_(std::move(root_key_handle))
          , metadata_encryption_key_handle_(std::move(metadata_encryption_key_handle))
          , initial_sending_dh_private_handle_(std::move(initial_sending_dh_private_handle))
          , initial_sending_dh_public_(initial_sending_dh_public)
          , current_sending_dh_private_handle_(std::move(current_sending_dh_private_handle))
          , current_sending_dh_public_(initial_sending_dh_public)
          , persistent_dh_private_handle_(std::move(persistent_dh_private_handle))
          , persistent_dh_public_(std::move(persistent_dh_public))
          , sending_step_(std::move(sending_step))
          , receiving_step_(receiving_step ? std::make_optional(std::move(*receiving_step)) : std::nullopt)
          , peer_bundle_(std::move(peer_bundle))
          , peer_dh_public_key_(std::move(peer_dh_public_key))
          , peer_kyber_public_key_(std::move(peer_kyber_public_key))
          , kyber_ciphertext_(std::move(kyber_ciphertext))
          , kyber_shared_secret_(std::move(kyber_shared_secret))
          , kyber_secret_key_handle_(std::move(kyber_secret_key_handle))
          , kyber_public_key_(std::move(kyber_public_key))
          , replay_protection_(connection_id)
          , nonce_counter_(nonce_counter)
          , pending_send_index_(std::nullopt)
          , rate_limit_window_start_ns_(0)
          , nonces_in_current_window_(0)
          , dh_ratchet_rate_limit_window_start_ns_(0)
          , dh_ratchets_in_current_window_(0)
          , disposed_(false)
          , is_first_receiving_ratchet_(is_first_receiving_ratchet)
          , received_new_dh_key_(false)
          , ratchet_warning_triggered_(false)
          , receiving_ratchet_epoch_(0)
          , event_handler_(nullptr) {
    }

    Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>
    EcliptixProtocolConnection::Create(uint32_t connection_id, bool is_initiator) {
        return Create(connection_id, is_initiator, RatchetConfig::Default());
    }

    Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>
    EcliptixProtocolConnection::Create(
        uint32_t connection_id,
        bool is_initiator,
        const RatchetConfig &ratchet_config) {
        const auto &config = ratchet_config;
        try {
            auto initial_dh_result = SodiumInterop::GenerateX25519KeyPair("Initial sending DH key");
            if (initial_dh_result.IsErr()) {
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    initial_dh_result.UnwrapErr());
            }
            auto [initial_dh_private, initial_dh_public] = std::move(initial_dh_result).Unwrap();
            auto initial_private_bytes_result = initial_dh_private.ReadBytes(Constants::X_25519_PRIVATE_KEY_SIZE);
            if (initial_private_bytes_result.IsErr()) {
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Failed to read initial DH private key"));
            }
            auto initial_private_bytes = initial_private_bytes_result.Unwrap();
            auto persistent_dh_result = SodiumInterop::GenerateX25519KeyPair("Persistent DH key");
            if (persistent_dh_result.IsErr()) {
                auto wipe_result = SodiumInterop::SecureWipe(std::span(initial_private_bytes));
                (void) wipe_result;
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    persistent_dh_result.UnwrapErr());
            }
            auto [persistent_dh_private, persistent_dh_public] = std::move(persistent_dh_result).Unwrap();
            std::vector temp_chain_key(Constants::X_25519_KEY_SIZE,
                                       static_cast<uint8_t>(ProtocolConstants::ZERO_VALUE));
            auto sending_step_result = EcliptixProtocolChainStep::Create(
                ChainStepType::SENDER,
                temp_chain_key,
                initial_private_bytes,
                initial_dh_public);
            auto wipe1 = SodiumInterop::SecureWipe(std::span(temp_chain_key));
            auto wipe2 = SodiumInterop::SecureWipe(std::span(initial_private_bytes));
            (void) wipe1;
            (void) wipe2;
            if (sending_step_result.IsErr()) {
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    sending_step_result.UnwrapErr());
            }
            auto sending_step = std::move(sending_step_result).Unwrap();
            auto kyber_keypair_result = KyberInterop::GenerateKyber768KeyPair("Initial Kyber key");
            if (kyber_keypair_result.IsErr()) {
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::FromSodiumFailure(kyber_keypair_result.UnwrapErr()));
            }
            auto [kyber_sk_handle, kyber_pk] = std::move(kyber_keypair_result).Unwrap();
            auto connection = std::unique_ptr<EcliptixProtocolConnection>(
                new EcliptixProtocolConnection(
                    connection_id,
                    is_initiator,
                    config,
                    PubKeyExchangeType::X3DH,
                    std::move(initial_dh_private),
                    std::move(initial_dh_public),
                    std::move(persistent_dh_private),
                    std::move(persistent_dh_public),
                    std::move(sending_step)));
            connection->kyber_secret_key_handle_ = std::move(kyber_sk_handle);
            connection->kyber_public_key_ = std::move(kyber_pk);
            auto initial_copy_result = connection->initial_sending_dh_private_handle_.ReadBytes(
                Constants::X_25519_PRIVATE_KEY_SIZE);
            if (initial_copy_result.IsErr()) {
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Failed to copy initial DH key"));
            }
            auto initial_copy_bytes = initial_copy_result.Unwrap();
            auto current_dh_alloc = SecureMemoryHandle::Allocate(Constants::X_25519_PRIVATE_KEY_SIZE);
            if (current_dh_alloc.IsErr()) {
                auto wipe_result = SodiumInterop::SecureWipe(std::span(initial_copy_bytes));
                (void) wipe_result;
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::FromSodiumFailure(current_dh_alloc.UnwrapErr()));
            }
            auto current_dh_handle = std::move(current_dh_alloc).Unwrap();
            auto write_result = current_dh_handle.Write(initial_copy_bytes);
            auto wipe3 = SodiumInterop::SecureWipe(std::span(initial_copy_bytes));
            (void) wipe3;
            if (write_result.IsErr()) {
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::FromSodiumFailure(write_result.UnwrapErr()));
            }
            connection->current_sending_dh_private_handle_ = std::move(current_dh_handle);
            return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Ok(
                std::move(connection));
        } catch (const std::exception &ex) {
            return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    std::format("Unexpected error creating connection {}: {}",
                                connection_id, ex.what())));
        }
    }

    Result<std::vector<uint8_t>, EcliptixProtocolFailure>
    EcliptixProtocolConnection::DeriveOpaqueMessagingRoot(
        std::span<const uint8_t> opaque_session_key,
        std::span<const uint8_t> user_context) {
        if (opaque_session_key.size() != Constants::X_25519_KEY_SIZE) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput(
                    std::format("OPAQUE session key must be {} bytes, got {}",
                                Constants::X_25519_KEY_SIZE, opaque_session_key.size())));
        }
        if (user_context.empty()) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("OPAQUE user context must not be empty"));
        }
        auto root_result = Hkdf::DeriveKeyBytes(
            opaque_session_key,
            Constants::X_25519_KEY_SIZE,
            user_context,
            std::span(reinterpret_cast<const uint8_t *>(ProtocolConstants::OPAQUE_MSG_ROOT_INFO.data()),
                      ProtocolConstants::OPAQUE_MSG_ROOT_INFO.size()));
        if (root_result.IsErr()) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                std::move(root_result).UnwrapErr());
        }
        return root_result;
    }

    Result<Unit, EcliptixProtocolFailure>
    EcliptixProtocolConnection::FinalizeChainAndDhKeys(
        std::span<const uint8_t> initial_root_key,
        std::span<const uint8_t> initial_peer_dh_public_key) {
        std::lock_guard lock(*lock_);
        if (root_key_handle_.has_value()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Connection already finalized"));
        }
        if (initial_root_key.size() != Constants::X_25519_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput(
                    std::format("Initial root key must be {} bytes, got {}",
                                Constants::X_25519_KEY_SIZE, initial_root_key.size())));
        }
        if (initial_peer_dh_public_key.size() != Constants::X_25519_PUBLIC_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput(
                    std::format("Initial peer DH public key must be {} bytes, got {}",
                                Constants::X_25519_PUBLIC_KEY_SIZE, initial_peer_dh_public_key.size())));
        }
        auto validation_result = DhValidator::ValidateX25519PublicKey(initial_peer_dh_public_key);
        if (validation_result.IsErr()) {
            return validation_result;
        }
        if (!peer_kyber_public_key_ || peer_kyber_public_key_->size() != KyberInterop::KYBER_768_PUBLIC_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Peer Kyber public key required for hybrid ratchet"));
        }
        if (!kyber_shared_secret_ || kyber_shared_secret_->size() != KyberInterop::KYBER_768_SHARED_SECRET_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Kyber shared secret missing before finalization"));
        }
        if (std::equal(initial_peer_dh_public_key.begin(), initial_peer_dh_public_key.end(),
                       initial_sending_dh_public_.begin())) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    std::string(ErrorMessages::REFLECTION_ATTACK)));
        }
        std::vector<uint8_t> dh_secret;
        std::vector<uint8_t> hybrid_secret;
        std::vector<uint8_t> new_root_key;
        std::vector<uint8_t> sender_chain_key;
        std::vector<uint8_t> receiver_chain_key;
        std::vector<uint8_t> persistent_private_bytes;
        std::vector peer_dh_public_copy(
            initial_peer_dh_public_key.begin(),
            initial_peer_dh_public_key.end());
        try {
            auto private_key_result = initial_sending_dh_private_handle_.ReadBytes(
                Constants::X_25519_PRIVATE_KEY_SIZE);
            if (private_key_result.IsErr()) {
                return Result<Unit, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Failed to read initial DH private key"));
            }
            persistent_private_bytes = private_key_result.Unwrap();
            dh_secret.resize(Constants::X_25519_KEY_SIZE);
            if (crypto_scalarmult(dh_secret.data(), persistent_private_bytes.data(), peer_dh_public_copy.data()) != 0) {
                {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(persistent_private_bytes));
                    (void) __wipe;
                }
                return Result<Unit, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::DeriveKey("Failed to compute DH shared secret"));
            }
            auto hybrid_secret_result = DeriveHybridDhSecret(
                dh_secret,
                std::span(initial_root_key.begin(), initial_root_key.end()),
                kyber_shared_secret_);
            if (hybrid_secret_result.IsErr()) {
                auto __wipe = SodiumInterop::SecureWipe(std::span(persistent_private_bytes));
                (void) __wipe;
                auto __wipe_dh = SodiumInterop::SecureWipe(std::span(dh_secret));
                (void) __wipe_dh;
                return Result<Unit, EcliptixProtocolFailure>::Err(hybrid_secret_result.UnwrapErr());
            }
            hybrid_secret = hybrid_secret_result.Unwrap();
            std::vector<uint8_t> hkdf_output(Constants::X_25519_KEY_SIZE * 2);
            auto root_derive_result = Hkdf::DeriveKeyBytes(
                hybrid_secret,
                Constants::X_25519_KEY_SIZE * 2,
                std::vector(initial_root_key.begin(), initial_root_key.end()),
                std::vector<uint8_t>(ProtocolConstants::HYBRID_DH_RATCHET_INFO.begin(),
                                     ProtocolConstants::HYBRID_DH_RATCHET_INFO.end()));
            if (root_derive_result.IsErr()) {
                {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(persistent_private_bytes));
                    (void) __wipe;
                } {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(dh_secret));
                    (void) __wipe;
                } {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(hybrid_secret));
                    (void) __wipe;
                }
                return Result<Unit, EcliptixProtocolFailure>::Err(root_derive_result.UnwrapErr());
            }
            hkdf_output = root_derive_result.Unwrap();
            new_root_key.assign(hkdf_output.begin(), hkdf_output.begin() + Constants::X_25519_KEY_SIZE);
            auto sender_chain_result = Hkdf::DeriveKeyBytes(
                new_root_key,
                Constants::X_25519_KEY_SIZE,
                std::vector<uint8_t>(),
                std::vector<uint8_t>(ProtocolConstants::INITIAL_SENDER_CHAIN_INFO.begin(),
                                     ProtocolConstants::INITIAL_SENDER_CHAIN_INFO.end()));
            if (sender_chain_result.IsErr()) {
                {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(persistent_private_bytes));
                    (void) __wipe;
                } {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(dh_secret));
                    (void) __wipe;
                } {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(new_root_key));
                    (void) __wipe;
                }
                return Result<Unit, EcliptixProtocolFailure>::Err(sender_chain_result.UnwrapErr());
            }
            auto receiver_chain_result = Hkdf::DeriveKeyBytes(
                new_root_key,
                Constants::X_25519_KEY_SIZE,
                std::vector<uint8_t>(),
                std::vector<uint8_t>(ProtocolConstants::INITIAL_RECEIVER_CHAIN_INFO.begin(),
                                     ProtocolConstants::INITIAL_RECEIVER_CHAIN_INFO.end()));
            if (receiver_chain_result.IsErr()) {
                {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(persistent_private_bytes));
                    (void) __wipe;
                } {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(dh_secret));
                    (void) __wipe;
                } {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(new_root_key));
                    (void) __wipe;
                }
                return Result<Unit, EcliptixProtocolFailure>::Err(receiver_chain_result.UnwrapErr());
            }
            auto sender_derived = sender_chain_result.Unwrap();
            auto receiver_derived = receiver_chain_result.Unwrap();
            if (is_initiator_) {
                sender_chain_key = std::move(sender_derived);
                receiver_chain_key = std::move(receiver_derived);
            } else {
                sender_chain_key = std::move(receiver_derived);
                receiver_chain_key = std::move(sender_derived);
            } {
                auto __wipe = SodiumInterop::SecureWipe(std::span(dh_secret));
                (void) __wipe;
            } {
                auto __wipe = SodiumInterop::SecureWipe(std::span(hkdf_output));
                (void) __wipe;
            }
            auto update_result = sending_step_.UpdateKeysAfterDhRatchet(sender_chain_key);
            if (update_result.IsErr()) {
                {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(persistent_private_bytes));
                    (void) __wipe;
                } {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(new_root_key));
                    (void) __wipe;
                } {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(sender_chain_key));
                    (void) __wipe;
                } {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(receiver_chain_key));
                    (void) __wipe;
                }
                return update_result;
            }
            auto receiving_step_result = EcliptixProtocolChainStep::Create(
                ChainStepType::RECEIVER,
                receiver_chain_key,
                persistent_private_bytes,
                persistent_dh_public_); {
                auto __wipe = SodiumInterop::SecureWipe(std::span(persistent_private_bytes));
                (void) __wipe;
            } {
                auto __wipe = SodiumInterop::SecureWipe(std::span(sender_chain_key));
                (void) __wipe;
            } {
                auto __wipe = SodiumInterop::SecureWipe(std::span(receiver_chain_key));
                (void) __wipe;
            }
            if (receiving_step_result.IsErr()) {
                {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(new_root_key));
                    (void) __wipe;
                }
                return Result<Unit, EcliptixProtocolFailure>::Err(
                    receiving_step_result.UnwrapErr());
            }
            auto root_handle_result = SecureMemoryHandle::Allocate(Constants::X_25519_KEY_SIZE);
            if (root_handle_result.IsErr()) {
                {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(new_root_key));
                    (void) __wipe;
                } {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(hybrid_secret));
                    (void) __wipe;
                }
                return Result<Unit, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::FromSodiumFailure(root_handle_result.UnwrapErr()));
            }
            auto root_handle = std::move(root_handle_result).Unwrap();
            auto root_write_result = root_handle.Write(new_root_key); {
                auto __wipe = SodiumInterop::SecureWipe(std::span(new_root_key));
                (void) __wipe;
            }
            if (root_write_result.IsErr()) {
                return Result<Unit, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::FromSodiumFailure(root_write_result.UnwrapErr()));
            }
            root_key_handle_ = std::move(root_handle);
            receiving_step_ = std::move(receiving_step_result).Unwrap();
            peer_dh_public_key_ = std::move(peer_dh_public_copy);
            auto metadata_result = DeriveMetadataEncryptionKey();
            if (metadata_result.IsErr()) {
                return metadata_result;
            }
            auto _wipe_hybrid = SodiumInterop::SecureWipe(std::span(hybrid_secret));
            (void) _wipe_hybrid;
            if (event_handler_) {
                event_handler_->OnProtocolStateChanged(id_);
            }
            return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
        } catch (const std::exception &ex) {
            {
                auto __wipe = SodiumInterop::SecureWipe(std::span(persistent_private_bytes));
                (void) __wipe;
            } {
                auto __wipe = SodiumInterop::SecureWipe(std::span(dh_secret));
                (void) __wipe;
            } {
                auto __wipe = SodiumInterop::SecureWipe(std::span(new_root_key));
                (void) __wipe;
            } {
                auto __wipe = SodiumInterop::SecureWipe(std::span(sender_chain_key));
                (void) __wipe;
            } {
                auto __wipe = SodiumInterop::SecureWipe(std::span(receiver_chain_key));
                (void) __wipe;
            } {
                auto __wipe = SodiumInterop::SecureWipe(std::span(hybrid_secret));
                (void) __wipe;
            }
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    std::format("Unexpected error during finalization: {}", ex.what())));
        }
    }

    Result<Unit, EcliptixProtocolFailure>
    EcliptixProtocolConnection::DeriveMetadataEncryptionKey() {
        if (!root_key_handle_.has_value()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Root key not initialized"));
        }
        auto root_bytes_result = root_key_handle_->ReadBytes(Constants::X_25519_KEY_SIZE);
        if (root_bytes_result.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Failed to read root key"));
        }
        auto root_bytes = root_bytes_result.Unwrap();
        // In hybrid mode, incorporate Kyber peer key (or placeholder) into metadata key derivation to prevent
        // reflection and ensure metadata keys bind to both classical and PQ identities.
        std::vector<uint8_t> sender_dh = current_sending_dh_public_;
        std::vector<uint8_t> peer_dh = peer_dh_public_key_.value_or(initial_sending_dh_public_);
        if (!kyber_shared_secret_ || kyber_shared_secret_->empty()) {
            auto __wipe = SodiumInterop::SecureWipe(std::span(root_bytes));
            (void) __wipe;
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Kyber shared secret required for metadata key derivation"));
        }
        auto pq_ss = *kyber_shared_secret_;
        std::vector<uint8_t> info;
        info.insert(info.end(),
                    ProtocolConstants::METADATA_ENCRYPTION_INFO.begin(),
                    ProtocolConstants::METADATA_ENCRYPTION_INFO.end());
        std::array<std::vector<uint8_t>, 2> dh_publics = {sender_dh, peer_dh};
        if (dh_publics[0] > dh_publics[1]) {
            std::swap(dh_publics[0], dh_publics[1]);
        }
        info.insert(info.end(), dh_publics[0].begin(), dh_publics[0].end());
        info.insert(info.end(), dh_publics[1].begin(), dh_publics[1].end());
        info.insert(info.end(), pq_ss.begin(), pq_ss.end());
        auto metadata_key_result = Hkdf::DeriveKeyBytes(
            root_bytes,
            Constants::AES_KEY_SIZE,
            std::vector<uint8_t>(),
            info); {
            auto __wipe = SodiumInterop::SecureWipe(std::span(root_bytes));
            (void) __wipe;
        }
        if (metadata_key_result.IsErr()) {
            auto __wipe = SodiumInterop::SecureWipe(std::span(pq_ss));
            (void) __wipe;
            return Result<Unit, EcliptixProtocolFailure>::Err(metadata_key_result.UnwrapErr());
        }
        auto metadata_key_bytes = metadata_key_result.Unwrap();
        auto __wipe_pq = SodiumInterop::SecureWipe(std::span(pq_ss));
        (void) __wipe_pq;
        auto metadata_handle_result = SecureMemoryHandle::Allocate(Constants::AES_KEY_SIZE);
        if (metadata_handle_result.IsErr()) {
            {
                auto __wipe = SodiumInterop::SecureWipe(std::span(metadata_key_bytes));
                (void) __wipe;
            }
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(metadata_handle_result.UnwrapErr()));
        }
        auto metadata_handle = std::move(metadata_handle_result).Unwrap();
        auto write_result = metadata_handle.Write(metadata_key_bytes); {
            auto __wipe = SodiumInterop::SecureWipe(std::span(metadata_key_bytes));
            (void) __wipe;
        }
        if (write_result.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(write_result.UnwrapErr()));
        }
        metadata_encryption_key_handle_ = std::move(metadata_handle);
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Result<std::vector<uint8_t>, EcliptixProtocolFailure>
    EcliptixProtocolConnection::DeriveMetadataEncryptionKeyBytes(
        std::span<const uint8_t> root_bytes,
        std::span<const uint8_t> sender_dh_public,
        std::span<const uint8_t> peer_dh_public) {
        if (!kyber_shared_secret_ || kyber_shared_secret_->empty()) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Kyber shared secret required for metadata key derivation"));
        }
        auto pq_ss = *kyber_shared_secret_;
        std::vector<uint8_t> info;
        info.insert(info.end(),
                    ProtocolConstants::METADATA_ENCRYPTION_INFO.begin(),
                    ProtocolConstants::METADATA_ENCRYPTION_INFO.end());
        std::array<std::vector<uint8_t>, 2> dh_publics = {
            std::vector<uint8_t>(sender_dh_public.begin(), sender_dh_public.end()),
            std::vector<uint8_t>(peer_dh_public.begin(), peer_dh_public.end())
        };
        if (dh_publics[0] > dh_publics[1]) {
            std::swap(dh_publics[0], dh_publics[1]);
        }
        info.insert(info.end(), dh_publics[0].begin(), dh_publics[0].end());
        info.insert(info.end(), dh_publics[1].begin(), dh_publics[1].end());
        info.insert(info.end(), pq_ss.begin(), pq_ss.end());
        auto metadata_key_result = Hkdf::DeriveKeyBytes(
            root_bytes,
            Constants::AES_KEY_SIZE,
            std::vector<uint8_t>(),
            info);
        auto _wipe = SodiumInterop::SecureWipe(std::span(pq_ss));
        (void) _wipe;
        return metadata_key_result;
    }

    Result<std::vector<uint8_t>, EcliptixProtocolFailure> EcliptixProtocolConnection::DeriveStateMacKey(
        std::span<const uint8_t> root_key_bytes,
        std::span<const uint8_t> session_id,
        const bool is_initiator,
        const uint32_t connection_id,
        std::span<const uint8_t> initial_sending_dh_public,
        std::span<const uint8_t> current_sending_dh_public,
        std::span<const uint8_t> kyber_public_key,
        std::span<const uint8_t> peer_kyber_public_key,
        std::span<const uint8_t> kyber_ciphertext) {
        auto secret_result = GetStateMacSecret();
        if (secret_result.IsErr()) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(secret_result.UnwrapErr());
        }
        const auto &mac_secret = secret_result.Unwrap();
        if (root_key_bytes.size() != Constants::X_25519_KEY_SIZE) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Invalid root key size for state MAC derivation"));
        }
        if (session_id.size() != 16) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Session id must be 16 bytes for state MAC derivation"));
        }
        if (initial_sending_dh_public.size() != Constants::X_25519_PUBLIC_KEY_SIZE ||
            current_sending_dh_public.size() != Constants::X_25519_PUBLIC_KEY_SIZE) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("DH public keys must be 32 bytes for state MAC derivation"));
        }
        if (kyber_public_key.size() != KyberInterop::KYBER_768_PUBLIC_KEY_SIZE ||
            peer_kyber_public_key.size() != KyberInterop::KYBER_768_PUBLIC_KEY_SIZE ||
            kyber_ciphertext.size() != KyberInterop::KYBER_768_CIPHERTEXT_SIZE) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Kyber artifacts must match expected hybrid sizes"));
        }
        std::vector<uint8_t> info;
        info.insert(info.end(),
                    ProtocolConstants::STATE_MAC_INFO.begin(),
                    ProtocolConstants::STATE_MAC_INFO.end());
        info.push_back(static_cast<uint8_t>(is_initiator ? 0x01 : 0x00));
        info.push_back(static_cast<uint8_t>((connection_id >> 24) & 0xFF));
        info.push_back(static_cast<uint8_t>((connection_id >> 16) & 0xFF));
        info.push_back(static_cast<uint8_t>((connection_id >> 8) & 0xFF));
        info.push_back(static_cast<uint8_t>(connection_id & 0xFF));
        info.insert(info.end(), session_id.begin(), session_id.end());
        info.insert(info.end(), initial_sending_dh_public.begin(), initial_sending_dh_public.end());
        info.insert(info.end(), current_sending_dh_public.begin(), current_sending_dh_public.end());
        info.insert(info.end(), kyber_public_key.begin(), kyber_public_key.end());
        info.insert(info.end(), peer_kyber_public_key.begin(), peer_kyber_public_key.end());
        info.insert(info.end(), kyber_ciphertext.begin(), kyber_ciphertext.end());

        auto mac_key_result = Hkdf::DeriveKeyBytes(
            root_key_bytes,
            crypto_generichash_KEYBYTES,
            mac_secret,
            info);
        if (mac_key_result.IsErr()) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(mac_key_result.UnwrapErr());
        }
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Ok(mac_key_result.Unwrap());
    }

    Result<std::vector<uint8_t>, EcliptixProtocolFailure> EcliptixProtocolConnection::ComputeStateMac(
        proto::protocol::RatchetState state,
        std::span<const uint8_t> mac_key) {
        state.clear_state_mac();
        std::string serialized;
        if (!state.SerializeToString(&serialized)) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Failed to serialize ratchet state for MAC"));
        }
        std::vector<uint8_t> mac(crypto_generichash_BYTES);
        crypto_generichash(
            mac.data(),
            mac.size(),
            reinterpret_cast<const unsigned char *>(serialized.data()),
            serialized.size(),
            mac_key.data(),
            mac_key.size());
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Ok(std::move(mac));
    }

    Result<Unit, EcliptixProtocolFailure> EcliptixProtocolConnection::VerifyStateMac(
        const proto::protocol::RatchetState &proto,
        const uint32_t expected_connection_id) {
        if (proto.state_mac().size() != crypto_generichash_BYTES) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Invalid or missing state MAC"));
        }
        if (proto.root_key().size() != Constants::X_25519_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Invalid root key size in stored state"));
        }
        if (proto.session_id().size() != 16) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Missing or invalid session id in stored state"));
        }
        if (proto.initial_sending_dh_public().size() != Constants::X_25519_PUBLIC_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Missing or invalid initial sending DH public key in stored state"));
        }
        if (!proto.current_sending_dh_public().empty() &&
            proto.current_sending_dh_public().size() != Constants::X_25519_PUBLIC_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Invalid current sending DH public key size in stored state"));
        }
        if (proto.kyber_public_key().size() != KyberInterop::KYBER_768_PUBLIC_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Missing or invalid Kyber public key in stored state"));
        }
        if (proto.peer_kyber_public_key().size() != KyberInterop::KYBER_768_PUBLIC_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Missing or invalid peer Kyber public key in stored state"));
        }
        if (proto.kyber_ciphertext().size() != KyberInterop::KYBER_768_CIPHERTEXT_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Missing or invalid Kyber ciphertext in stored state"));
        }
        std::vector<uint8_t> session_id_bytes(proto.session_id().begin(), proto.session_id().end());
        auto mac_key_result = DeriveStateMacKey(
            std::span(reinterpret_cast<const uint8_t *>(proto.root_key().data()), proto.root_key().size()),
            session_id_bytes,
            proto.is_initiator(),
            expected_connection_id,
            std::span(reinterpret_cast<const uint8_t *>(proto.initial_sending_dh_public().data()),
                      proto.initial_sending_dh_public().size()),
            proto.current_sending_dh_public().empty()
                ? std::span(reinterpret_cast<const uint8_t *>(proto.initial_sending_dh_public().data()),
                            proto.initial_sending_dh_public().size())
                : std::span(reinterpret_cast<const uint8_t *>(proto.current_sending_dh_public().data()),
                            proto.current_sending_dh_public().size()),
            std::span(reinterpret_cast<const uint8_t *>(proto.kyber_public_key().data()),
                      proto.kyber_public_key().size()),
            std::span(reinterpret_cast<const uint8_t *>(proto.peer_kyber_public_key().data()),
                      proto.peer_kyber_public_key().size()),
            std::span(reinterpret_cast<const uint8_t *>(proto.kyber_ciphertext().data()),
                      proto.kyber_ciphertext().size()));
        if (mac_key_result.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(mac_key_result.UnwrapErr());
        }
        auto computed_mac_result = ComputeStateMac(proto, mac_key_result.Unwrap());
        if (computed_mac_result.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(computed_mac_result.UnwrapErr());
        }
        auto computed_mac = std::move(computed_mac_result.Unwrap());
        if (sodium_memcmp(computed_mac.data(), proto.state_mac().data(), computed_mac.size()) != 0) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("State MAC verification failed"));
        }
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    EcliptixProtocolConnection::~EcliptixProtocolConnection() {
    }

    Result<Unit, EcliptixProtocolFailure>
    EcliptixProtocolConnection::CheckDisposed() const {
        if (disposed_.load()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Connection has been disposed"));
        }
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Result<Unit, EcliptixProtocolFailure>
    EcliptixProtocolConnection::EnsureNotExpired() const {
        auto now = std::chrono::system_clock::now();
        auto age = now - created_at_;
#ifdef ECLIPTIX_TEST_BUILD
        constexpr auto SESSION_TIMEOUT = std::chrono::seconds(5);
#else
        constexpr auto SESSION_TIMEOUT = std::chrono::hours(24);
#endif
        if (age > SESSION_TIMEOUT) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    "Session expired (age: " + std::to_string(
                        std::chrono::duration_cast<std::chrono::seconds>(age).count()) + " seconds)"));
        }
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Result<Unit, EcliptixProtocolFailure>
    EcliptixProtocolConnection::CheckIfFinalized() const {
        if (!root_key_handle_.has_value()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Connection not finalized - root key not set"));
        }
        if (!receiving_step_.has_value()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Connection not finalized - receiving step not initialized"));
        }
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Result<Unit, EcliptixProtocolFailure>
    EcliptixProtocolConnection::CheckIfNotFinalized() const {
        if (root_key_handle_.has_value() || receiving_step_.has_value()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Connection already finalized"));
        }
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Result<Unit, EcliptixProtocolFailure>
    EcliptixProtocolConnection::ValidateInitialKeys(
        std::span<const uint8_t> root_key,
        std::span<const uint8_t> peer_dh_public_key) {
        if (root_key.size() != Constants::X_25519_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput(
                    "Initial root key must be " + std::to_string(Constants::X_25519_KEY_SIZE) +
                    " bytes, got " + std::to_string(root_key.size())));
        }
        if (peer_dh_public_key.size() != Constants::X_25519_PUBLIC_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput(
                    "Initial peer DH public key must be " + std::to_string(Constants::X_25519_PUBLIC_KEY_SIZE) +
                    " bytes, got " + std::to_string(peer_dh_public_key.size())));
        }
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Result<Unit, EcliptixProtocolFailure>
    EcliptixProtocolConnection::DeriveRatchetKeys(
        std::span<const uint8_t> dh_secret,
        std::span<const uint8_t> current_root_key,
        std::span<uint8_t> new_root_key,
        std::span<uint8_t> new_chain_key) {
        if (dh_secret.size() != Constants::X_25519_KEY_SIZE ||
            current_root_key.size() != Constants::X_25519_KEY_SIZE ||
            new_root_key.size() != Constants::X_25519_KEY_SIZE ||
            new_chain_key.size() != Constants::X_25519_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Hybrid ratchet inputs must be 32 bytes"));
        }
        std::vector<uint8_t> derived_keys(64);
        auto hkdf_result = Hkdf::DeriveKey(
            std::span(dh_secret),
            std::span(derived_keys),
            std::span(current_root_key),
            std::span(
                reinterpret_cast<const uint8_t *>(ProtocolConstants::HYBRID_DH_RATCHET_INFO.data()),
                ProtocolConstants::HYBRID_DH_RATCHET_INFO.size())
        );
        if (hkdf_result.IsErr()) {
            return hkdf_result;
        }
        std::copy_n(derived_keys.begin(), 32, new_root_key.begin());
        std::copy_n(derived_keys.begin() + 32, 32, new_chain_key.begin()); {
            auto __wipe = SodiumInterop::SecureWipe(std::span(derived_keys));
            (void) __wipe;
        }
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    bool EcliptixProtocolConnection::IsInitiator() const noexcept {
        return is_initiator_;
    }

    PubKeyExchangeType EcliptixProtocolConnection::ExchangeType() const noexcept {
        return exchange_type_;
    }

    Result<LocalPublicKeyBundle, EcliptixProtocolFailure>
    EcliptixProtocolConnection::GetPeerBundle() const {
        std::lock_guard lock(*lock_);
        auto disposed_check = CheckDisposed();
        if (disposed_check.IsErr()) {
            return Result<LocalPublicKeyBundle, EcliptixProtocolFailure>::Err(
                disposed_check.UnwrapErr());
        }
        if (!peer_bundle_.has_value()) {
            return Result<LocalPublicKeyBundle, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Peer bundle not set"));
        }
        return Result<LocalPublicKeyBundle, EcliptixProtocolFailure>::Ok(*peer_bundle_);
    }

    Result<Option<std::vector<uint8_t> >, EcliptixProtocolFailure>
    EcliptixProtocolConnection::GetCurrentPeerDhPublicKey() const {
        std::lock_guard lock(*lock_);
        auto disposed_check = CheckDisposed();
        if (disposed_check.IsErr()) {
            return Result<Option<std::vector<uint8_t> >, EcliptixProtocolFailure>::Err(
                disposed_check.UnwrapErr());
        }
        if (!peer_dh_public_key_.has_value()) {
            return Result<Option<std::vector<uint8_t> >, EcliptixProtocolFailure>::Ok(
                None<std::vector<uint8_t> >());
        }
        return Result<Option<std::vector<uint8_t> >, EcliptixProtocolFailure>::Ok(
            Some(*peer_dh_public_key_));
    }

    Result<Option<std::vector<uint8_t> >, EcliptixProtocolFailure>
    EcliptixProtocolConnection::GetCurrentSenderDhPublicKey() const {
        std::lock_guard lock(*lock_);
        if (auto disposed_check = CheckDisposed(); disposed_check.IsErr()) {
            return Result<Option<std::vector<uint8_t> >, EcliptixProtocolFailure>::Err(
                disposed_check.UnwrapErr());
        }
        if (current_sending_dh_public_.empty()) {
            return Result<Option<std::vector<uint8_t> >, EcliptixProtocolFailure>::Ok(
                None<std::vector<uint8_t> >());
        }
        return Result<Option<std::vector<uint8_t> >, EcliptixProtocolFailure>::Ok(
            Some(current_sending_dh_public_));
    }

    Result<std::vector<uint8_t>, EcliptixProtocolFailure>
    EcliptixProtocolConnection::GetMetadataEncryptionKey() const {
        std::lock_guard lock(*lock_);
        if (auto disposed_check = CheckDisposed(); disposed_check.IsErr()) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                disposed_check.UnwrapErr());
        }
        if (!metadata_encryption_key_handle_.has_value()) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Metadata encryption key not initialized"));
        }
        auto read_result = metadata_encryption_key_handle_->ReadBytes(Constants::AES_KEY_SIZE);
        if (read_result.IsErr()) {
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::FromSodiumFailure(read_result.UnwrapErr()));
    }
    return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Ok(read_result.Unwrap());
}

Result<Option<std::vector<uint8_t> >, EcliptixProtocolFailure>
EcliptixProtocolConnection::GetCurrentKyberCiphertext() const {
    std::lock_guard lock(*lock_);
    if (auto disposed_check = CheckDisposed(); disposed_check.IsErr()) {
        return Result<Option<std::vector<uint8_t> >, EcliptixProtocolFailure>::Err(
            disposed_check.UnwrapErr());
    }
    if (!kyber_ciphertext_.has_value() || kyber_ciphertext_->empty()) {
        return Result<Option<std::vector<uint8_t> >, EcliptixProtocolFailure>::Ok(
            None<std::vector<uint8_t> >());
    }
    return Result<Option<std::vector<uint8_t> >, EcliptixProtocolFailure>::Ok(
        Some(*kyber_ciphertext_));
}

    Result<Unit, EcliptixProtocolFailure>
    EcliptixProtocolConnection::SetLocalKyberKeyPair(
        SecureMemoryHandle secret_key_handle,
        std::span<const uint8_t> public_key) {
        std::lock_guard lock(*lock_);
        if (auto disposed_check = CheckDisposed(); disposed_check.IsErr()) {
            return disposed_check;
        }
        if (auto finalized_check = CheckIfNotFinalized(); finalized_check.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Cannot override Kyber keys after finalization"));
        }
        if (public_key.size() != KyberInterop::KYBER_768_PUBLIC_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Kyber public key must be 1184 bytes"));
        }
        auto validate = KyberInterop::ValidateSecretKey(secret_key_handle);
        if (validate.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(validate.UnwrapErr()));
        }
        kyber_secret_key_handle_ = std::move(secret_key_handle);
        kyber_public_key_.assign(public_key.begin(), public_key.end());
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Result<Unit, EcliptixProtocolFailure>
    EcliptixProtocolConnection::SetHybridHandshakeSecrets(
        std::span<const uint8_t> kyber_ciphertext,
        std::span<const uint8_t> kyber_shared_secret) {
        std::lock_guard lock(*lock_);
        if (auto disposed_check = CheckDisposed(); disposed_check.IsErr()) {
            return disposed_check;
        }
        if (auto finalized_check = CheckIfNotFinalized(); finalized_check.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Connection already finalized"));
        }
        if (!kyber_ciphertext.empty()) {
            auto validate_ct = KyberInterop::ValidateCiphertext(kyber_ciphertext);
            if (validate_ct.IsErr()) {
                return Result<Unit, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::FromSodiumFailure(validate_ct.UnwrapErr()));
            }
            kyber_ciphertext_ = std::vector<uint8_t>(kyber_ciphertext.begin(), kyber_ciphertext.end());
        }
        if (kyber_shared_secret.size() != KyberInterop::KYBER_768_SHARED_SECRET_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Kyber shared secret must be 32 bytes"));
        }
        kyber_shared_secret_ = std::vector<uint8_t>(kyber_shared_secret.begin(), kyber_shared_secret.end());
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Result<Unit, EcliptixProtocolFailure>
    EcliptixProtocolConnection::DeriveKyberSharedSecretFromCiphertext(
        std::span<const uint8_t> kyber_ciphertext) {
        std::lock_guard lock(*lock_);
        if (auto disposed_check = CheckDisposed(); disposed_check.IsErr()) {
            return disposed_check;
        }
        if (auto finalized_check = CheckIfNotFinalized(); finalized_check.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Connection already finalized"));
        }
        auto validate_ct = KyberInterop::ValidateCiphertext(kyber_ciphertext);
        if (validate_ct.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(validate_ct.UnwrapErr()));
        }
        auto decap_result = KyberInterop::Decapsulate(kyber_ciphertext, kyber_secret_key_handle_);
        if (decap_result.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(decap_result.UnwrapErr()));
        }
        auto ss_handle = std::move(decap_result).Unwrap();
        auto ss_bytes_result = ss_handle.ReadBytes(KyberInterop::KYBER_768_SHARED_SECRET_SIZE);
        if (ss_bytes_result.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(ss_bytes_result.UnwrapErr()));
        }
        kyber_ciphertext_ = std::vector<uint8_t>(kyber_ciphertext.begin(), kyber_ciphertext.end());
        kyber_shared_secret_ = ss_bytes_result.Unwrap();
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Result<Unit, EcliptixProtocolFailure> EcliptixProtocolConnection::UpdateKyberSecretFromCiphertext(
        std::span<const uint8_t> kyber_ct) {
        if (kyber_ct.size() != KyberInterop::KYBER_768_CIPHERTEXT_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Kyber ciphertext must be 1088 bytes"));
        }
        auto validate_ct = KyberInterop::ValidateCiphertext(kyber_ct);
        if (validate_ct.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(validate_ct.UnwrapErr()));
        }
        auto decap_result = KyberInterop::Decapsulate(kyber_ct, kyber_secret_key_handle_);
        if (decap_result.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(decap_result.UnwrapErr()));
        }
        auto ss_handle = std::move(decap_result).Unwrap();
        auto ss_bytes_result = ss_handle.ReadBytes(KyberInterop::KYBER_768_SHARED_SECRET_SIZE);
        if (ss_bytes_result.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(ss_bytes_result.UnwrapErr()));
        }
        kyber_ciphertext_ = std::vector<uint8_t>(kyber_ct.begin(), kyber_ct.end());
        kyber_shared_secret_ = ss_bytes_result.Unwrap();
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    std::vector<uint8_t> EcliptixProtocolConnection::GetKyberPublicKeyCopy() const {
        std::lock_guard lock(*lock_);
        if (auto disposed_check = CheckDisposed(); disposed_check.IsErr()) {
            return {};
        }
        return kyber_public_key_;
    }

#ifdef ECLIPTIX_TEST_BUILD
    std::vector<uint8_t> EcliptixProtocolConnection::DebugGetRootKey() const {
        std::lock_guard lock(*lock_);
        if (!root_key_handle_.has_value()) {
            return {};
        }
        auto read = root_key_handle_->ReadBytes(Constants::X_25519_KEY_SIZE);
        if (read.IsErr()) {
            return {};
        }
        return read.Unwrap();
    }

    std::vector<uint8_t> EcliptixProtocolConnection::DebugGetCurrentDhPrivate() const {
        std::lock_guard lock(*lock_);
        if (!current_sending_dh_private_handle_.has_value()) {
            return {};
        }
        auto read = current_sending_dh_private_handle_->ReadBytes(Constants::X_25519_PRIVATE_KEY_SIZE);
        if (read.IsErr()) {
            return {};
        }
        return read.Unwrap();
    }

    std::vector<uint8_t> EcliptixProtocolConnection::DebugGetKyberSharedSecret() const {
        std::lock_guard lock(*lock_);
        if (!kyber_shared_secret_.has_value()) {
            return {};
        }
        return *kyber_shared_secret_;
    }

    Result<Unit, EcliptixProtocolFailure> EcliptixProtocolConnection::DebugSetPeerKyberPublicKey(
        std::span<const uint8_t> peer_kyber_public_key) {
        std::lock_guard lock(*lock_);
        if (peer_kyber_public_key.size() != KyberInterop::KYBER_768_PUBLIC_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Peer Kyber public key must be 1184 bytes"));
        }
        peer_kyber_public_key_ = std::vector<uint8_t>(peer_kyber_public_key.begin(), peer_kyber_public_key.end());
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }
#endif

    Result<Unit, EcliptixProtocolFailure>
    EcliptixProtocolConnection::SetPeerBundle(const LocalPublicKeyBundle &peer_bundle) {
        std::lock_guard lock(*lock_);
        if (auto disposed_check = CheckDisposed(); disposed_check.IsErr()) {
            return disposed_check;
        }
        if (auto finalized_check = CheckIfNotFinalized(); finalized_check.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Cannot set peer bundle after connection finalized"));
        }
        if (!peer_bundle.HasKyberKey() || !peer_bundle.GetKyberPublicKey().has_value()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Peer Kyber public key required for PQ mode"));
        }
        auto &kyber_pk = peer_bundle.GetKyberPublicKey().value();
        if (kyber_pk.size() != KyberInterop::KYBER_768_PUBLIC_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Peer Kyber public key must be 1184 bytes"));
        }
        peer_kyber_public_key_ = kyber_pk;
        peer_bundle_ = peer_bundle;
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Result<EcliptixProtocolConnection::ReceivingRatchetPreview, EcliptixProtocolFailure>
    EcliptixProtocolConnection::PrepareReceivingRatchet(
        std::span<const uint8_t> received_dh_public_key,
        std::span<const uint8_t> received_kyber_ciphertext) {
        std::lock_guard lock(*lock_);
        if (auto disposed_check = CheckDisposed(); disposed_check.IsErr()) {
            return Result<ReceivingRatchetPreview, EcliptixProtocolFailure>::Err(disposed_check.UnwrapErr());
        }
        if (auto finalized_check = CheckIfFinalized(); finalized_check.IsErr()) {
            return Result<ReceivingRatchetPreview, EcliptixProtocolFailure>::Err(finalized_check.UnwrapErr());
        }
        if (!receiving_step_.has_value()) {
            return Result<ReceivingRatchetPreview, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Receiving chain step not initialized"));
        }
        if (received_dh_public_key.size() != Constants::X_25519_PUBLIC_KEY_SIZE) {
            return Result<ReceivingRatchetPreview, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput(
                    std::format("Received DH public key must be {} bytes, got {}",
                                Constants::X_25519_PUBLIC_KEY_SIZE, received_dh_public_key.size())));
        }
        if (received_kyber_ciphertext.size() != KyberInterop::KYBER_768_CIPHERTEXT_SIZE) {
            return Result<ReceivingRatchetPreview, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput(
                    std::format("Received Kyber ciphertext must be {} bytes, got {}",
                                KyberInterop::KYBER_768_CIPHERTEXT_SIZE, received_kyber_ciphertext.size())));
        }
        if (auto validation_result = DhValidator::ValidateX25519PublicKey(received_dh_public_key); validation_result.
            IsErr()) {
            return Result<ReceivingRatchetPreview, EcliptixProtocolFailure>::Err(validation_result.UnwrapErr());
        }
        if (!current_sending_dh_private_handle_.has_value()) {
            return Result<ReceivingRatchetPreview, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Current sending DH private key not set"));
        }
        std::vector<uint8_t> dh_secret;
        std::vector<uint8_t> our_priv_bytes;
        std::vector<uint8_t> root_bytes;
        std::vector<uint8_t> hybrid_secret;
        std::vector<uint8_t> hkdf_output;
        std::vector<uint8_t> new_root_key;
        std::vector<uint8_t> new_chain_key;
        try {
            auto our_priv_bytes_result = current_sending_dh_private_handle_->ReadBytes(
                Constants::X_25519_PRIVATE_KEY_SIZE);
            if (our_priv_bytes_result.IsErr()) {
                return Result<ReceivingRatchetPreview, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Failed to read current DH private key"));
            }
            our_priv_bytes = our_priv_bytes_result.Unwrap();
            dh_secret.resize(Constants::X_25519_KEY_SIZE);
            if (crypto_scalarmult(dh_secret.data(), our_priv_bytes.data(), received_dh_public_key.data()) != 0) {
                auto _wipe = SodiumInterop::SecureWipe(std::span(our_priv_bytes));
                (void) _wipe;
                return Result<ReceivingRatchetPreview, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::DeriveKey("Failed to compute receiver DH secret"));
            }
            auto kyber_update = UpdateKyberSecretFromCiphertext(received_kyber_ciphertext);
            if (kyber_update.IsErr()) {
                auto _wipe = SodiumInterop::SecureWipe(std::span(our_priv_bytes));
                (void) _wipe;
                return Result<ReceivingRatchetPreview, EcliptixProtocolFailure>::Err(kyber_update.UnwrapErr());
            }
            auto root_bytes_result = root_key_handle_->ReadBytes(Constants::X_25519_KEY_SIZE);
            if (root_bytes_result.IsErr()) {
                {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(our_priv_bytes));
                    (void) _wipe;
                } {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(dh_secret));
                    (void) _wipe;
                }
                return Result<ReceivingRatchetPreview, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Failed to read root key"));
            }
            root_bytes = root_bytes_result.Unwrap();
            auto hybrid_result = DeriveHybridDhSecret(
                dh_secret,
                root_bytes,
                kyber_shared_secret_);
            if (hybrid_result.IsErr()) {
                {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(our_priv_bytes));
                    (void) _wipe;
                } {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(dh_secret));
                    (void) _wipe;
                } {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(root_bytes));
                    (void) _wipe;
                }
                return Result<ReceivingRatchetPreview, EcliptixProtocolFailure>::Err(
                    hybrid_result.UnwrapErr());
            }
            hybrid_secret = hybrid_result.Unwrap();
            auto hkdf_output_result = Hkdf::DeriveKeyBytes(
                hybrid_secret,
                Constants::X_25519_KEY_SIZE * 2,
                root_bytes,
                std::vector<uint8_t>(ProtocolConstants::HYBRID_DH_RATCHET_INFO.begin(),
                                     ProtocolConstants::HYBRID_DH_RATCHET_INFO.end())); {
                auto _wipe = SodiumInterop::SecureWipe(std::span(root_bytes));
                (void) _wipe;
            } {
                auto _wipe = SodiumInterop::SecureWipe(std::span(dh_secret));
                (void) _wipe;
            } {
                auto _wipe = SodiumInterop::SecureWipe(std::span(hybrid_secret));
                (void) _wipe;
            }
            if (hkdf_output_result.IsErr()) {
                auto _wipe = SodiumInterop::SecureWipe(std::span(our_priv_bytes));
                (void) _wipe;
                return Result<ReceivingRatchetPreview, EcliptixProtocolFailure>::Err(
                    hkdf_output_result.UnwrapErr());
            }
            hkdf_output = hkdf_output_result.Unwrap();
            new_root_key.assign(hkdf_output.begin(), hkdf_output.begin() + Constants::X_25519_KEY_SIZE);
            new_chain_key.assign(hkdf_output.begin() + Constants::X_25519_KEY_SIZE, hkdf_output.end());
            auto receiving_proto_result = receiving_step_->ToProtoState();
            if (receiving_proto_result.IsErr()) {
                {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(our_priv_bytes));
                    (void) _wipe;
                } {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(hkdf_output));
                    (void) _wipe;
                } {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(new_root_key));
                    (void) _wipe;
                } {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(new_chain_key));
                    (void) _wipe;
                }
                return Result<ReceivingRatchetPreview, EcliptixProtocolFailure>::Err(
                    receiving_proto_result.UnwrapErr());
            }
            auto receiving_clone_result = EcliptixProtocolChainStep::FromProtoState(
                ChainStepType::RECEIVER,
                receiving_proto_result.Unwrap());
            if (receiving_clone_result.IsErr()) {
                {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(our_priv_bytes));
                    (void) _wipe;
                } {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(hkdf_output));
                    (void) _wipe;
                } {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(new_root_key));
                    (void) _wipe;
                } {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(new_chain_key));
                    (void) _wipe;
                }
                return Result<ReceivingRatchetPreview, EcliptixProtocolFailure>::Err(
                    receiving_clone_result.UnwrapErr());
            }
            auto clone = std::move(receiving_clone_result).Unwrap();
            auto update_result = clone.UpdateKeysAfterDhRatchet(new_chain_key);
            if (update_result.IsErr()) {
                {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(our_priv_bytes));
                    (void) _wipe;
                } {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(hkdf_output));
                    (void) _wipe;
                } {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(new_root_key));
                    (void) _wipe;
                } {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(new_chain_key));
                    (void) _wipe;
                }
                return Result<ReceivingRatchetPreview, EcliptixProtocolFailure>::Err(update_result.UnwrapErr());
            }
            auto metadata_key_result = DeriveMetadataEncryptionKeyBytes(
                new_root_key,
                current_sending_dh_public_,
                std::span(received_dh_public_key.data(), received_dh_public_key.size()));
            if (metadata_key_result.IsErr()) {
                {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(our_priv_bytes));
                    (void) _wipe;
                } {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(hkdf_output));
                    (void) _wipe;
                } {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(new_root_key));
                    (void) _wipe;
                } {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(new_chain_key));
                    (void) _wipe;
                }
                return Result<ReceivingRatchetPreview, EcliptixProtocolFailure>::Err(
                    metadata_key_result.UnwrapErr());
            }
            ReceivingRatchetPreview preview{
                .metadata_key = metadata_key_result.Unwrap(),
                .new_root_key = new_root_key,
                .receiving_step = std::move(clone),
                .peer_dh_public_key = std::vector<uint8_t>(received_dh_public_key.begin(), received_dh_public_key.end()),
                .new_receiving_epoch = receiving_ratchet_epoch_.load(std::memory_order_acquire) + 1
            };
            auto _wipe_priv = SodiumInterop::SecureWipe(std::span(our_priv_bytes));
            (void) _wipe_priv;
            auto _wipe_hkdf = SodiumInterop::SecureWipe(std::span(hkdf_output));
            (void) _wipe_hkdf;
            auto _wipe_chain = SodiumInterop::SecureWipe(std::span(new_chain_key));
            (void) _wipe_chain;
            return Result<ReceivingRatchetPreview, EcliptixProtocolFailure>::Ok(std::move(preview));
        } catch (const std::exception &ex) {
            auto _wipe_priv = SodiumInterop::SecureWipe(std::span(our_priv_bytes));
            (void) _wipe_priv;
            auto _wipe_dh = SodiumInterop::SecureWipe(std::span(dh_secret));
            (void) _wipe_dh;
            auto _wipe_hybrid = SodiumInterop::SecureWipe(std::span(hybrid_secret));
            (void) _wipe_hybrid;
            auto _wipe_hkdf = SodiumInterop::SecureWipe(std::span(hkdf_output));
            (void) _wipe_hkdf;
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(new_root_key));
            (void) _wipe_root;
            auto _wipe_chain = SodiumInterop::SecureWipe(std::span(new_chain_key));
            (void) _wipe_chain;
            return Result<ReceivingRatchetPreview, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Exception during receiving ratchet preparation: " +
                                                 std::string(ex.what())));
        }
    }

    Result<Unit, EcliptixProtocolFailure>
    EcliptixProtocolConnection::CommitReceivingRatchet(ReceivingRatchetPreview &&preview) {
        std::lock_guard lock(*lock_);
        if (auto disposed_check = CheckDisposed(); disposed_check.IsErr()) {
            return disposed_check;
        }
        if (auto finalized_check = CheckIfFinalized(); finalized_check.IsErr()) {
            return finalized_check;
        }
        auto metadata_handle_result = SecureMemoryHandle::Allocate(Constants::AES_KEY_SIZE);
        if (metadata_handle_result.IsErr()) {
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(preview.new_root_key));
            (void) _wipe_root;
            auto _wipe_meta = SodiumInterop::SecureWipe(std::span(preview.metadata_key));
            (void) _wipe_meta;
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(metadata_handle_result.UnwrapErr()));
        }
        auto metadata_handle = std::move(metadata_handle_result).Unwrap();
        auto metadata_write = metadata_handle.Write(preview.metadata_key);
        auto _wipe_meta = SodiumInterop::SecureWipe(std::span(preview.metadata_key));
        (void) _wipe_meta;
        if (metadata_write.IsErr()) {
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(preview.new_root_key));
            (void) _wipe_root;
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(metadata_write.UnwrapErr()));
        }
        auto write_root = root_key_handle_->Write(preview.new_root_key);
        if (write_root.IsErr()) {
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(preview.new_root_key));
            (void) _wipe_root;
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(write_root.UnwrapErr()));
        }
        metadata_encryption_key_handle_ = std::move(metadata_handle);
        receiving_step_ = std::move(preview.receiving_step);
        peer_dh_public_key_ = std::move(preview.peer_dh_public_key);
        ratchet_warning_triggered_.store(false, std::memory_order_seq_cst);
        receiving_ratchet_epoch_.store(preview.new_receiving_epoch, std::memory_order_release);
        replay_protection_.ResetMessageWindows();
        received_new_dh_key_.store(true, std::memory_order_seq_cst);
        auto _wipe_root = SodiumInterop::SecureWipe(std::span(preview.new_root_key));
        (void) _wipe_root;
        if (event_handler_) {
            event_handler_->OnProtocolStateChanged(id_);
        }
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Result<Unit, EcliptixProtocolFailure>
    EcliptixProtocolConnection::PerformReceivingRatchet(
        std::span<const uint8_t> received_dh_public_key,
        std::span<const uint8_t> received_kyber_ciphertext) {
        auto preview_result = PrepareReceivingRatchet(received_dh_public_key, received_kyber_ciphertext);
        if (preview_result.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(preview_result.UnwrapErr());
        }
        return CommitReceivingRatchet(std::move(preview_result.Unwrap()));
    }

    void EcliptixProtocolConnection::NotifyRatchetRotation() {
        received_new_dh_key_.store(true);
    }

    void EcliptixProtocolConnection::SetEventHandler(std::shared_ptr<IProtocolEventHandler> handler) {
        std::lock_guard lock(*lock_);
        event_handler_ = std::move(handler);
    }

    Result<bool, EcliptixProtocolFailure>
    EcliptixProtocolConnection::MaybePerformSendingDhRatchet() {
        std::lock_guard lock(*lock_);
        if (auto disposed_check = CheckDisposed(); disposed_check.IsErr()) {
            return Result<bool, EcliptixProtocolFailure>::Err(disposed_check.UnwrapErr());
        }
        if (auto finalized_check = CheckIfFinalized(); finalized_check.IsErr()) {
            return Result<bool, EcliptixProtocolFailure>::Err(finalized_check.UnwrapErr());
        }
        auto current_index_result = sending_step_.GetCurrentIndex();
        if (current_index_result.IsErr()) {
            return Result<bool, EcliptixProtocolFailure>::Err(current_index_result.UnwrapErr());
        }
        uint32_t current_index = current_index_result.Unwrap();
        if (bool should_ratchet = ratchet_config_.ShouldRatchet(current_index, received_new_dh_key_.load()); !
            should_ratchet) {
            return Result<bool, EcliptixProtocolFailure>::Ok(false);
        }
        if (auto ratchet_result = PerformDhRatchet(true, {}, {}); ratchet_result.IsErr()) {
            return Result<bool, EcliptixProtocolFailure>::Err(ratchet_result.UnwrapErr());
        }
        received_new_dh_key_.store(false);
        return Result<bool, EcliptixProtocolFailure>::Ok(true);
    }

    Result<Unit, EcliptixProtocolFailure>
    EcliptixProtocolConnection::SyncWithRemoteState(
        uint32_t remote_sending_chain_length,
        uint32_t remote_receiving_chain_length) {
        std::lock_guard lock(*lock_);
        if (auto disposed_check = CheckDisposed(); disposed_check.IsErr()) {
            return disposed_check;
        }
        if (auto finalized_check = CheckIfFinalized(); finalized_check.IsErr()) {
            return finalized_check;
        }
        if (!receiving_step_.has_value()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Receiving chain step not initialized"));
        }
        if (auto receiving_skip_result = receiving_step_->SkipKeysUntil(remote_sending_chain_length);
            receiving_skip_result.IsErr()) {
            return receiving_skip_result;
        }
        if (auto sending_skip_result = sending_step_.SkipKeysUntil(remote_receiving_chain_length); sending_skip_result.
            IsErr()) {
            return sending_skip_result;
        }
        if (event_handler_) {
            event_handler_->OnProtocolStateChanged(id_);
        }
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Result<std::vector<uint8_t>, EcliptixProtocolFailure>
    EcliptixProtocolConnection::GenerateNextNonce(std::optional<uint32_t> message_index) {
        std::lock_guard lock(*lock_);
        if (auto expired_check = EnsureNotExpired(); expired_check.IsErr()) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                std::move(expired_check).UnwrapErr());
        }
        auto disposed_check = CheckDisposed();
        if (disposed_check.IsErr()) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(disposed_check.UnwrapErr());
        }
        constexpr int64_t ONE_SECOND_NS = 1'000'000'000LL;
        const auto now = std::chrono::steady_clock::now();
        const int64_t now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        int64_t window_start = rate_limit_window_start_ns_.load(std::memory_order_seq_cst);
        if (window_start == 0 || (now_ns - window_start) >= ONE_SECOND_NS) {
            rate_limit_window_start_ns_.store(now_ns, std::memory_order_seq_cst);
            nonces_in_current_window_.store(0, std::memory_order_seq_cst);
            window_start = now_ns;
        }
        const uint32_t nonces_in_window = nonces_in_current_window_.fetch_add(1, std::memory_order_seq_cst);
#ifdef ECLIPTIX_TEST_BUILD
        constexpr uint32_t NONCE_RATE_LIMIT = 100'000;
#else
        constexpr uint32_t NONCE_RATE_LIMIT = ProtocolConstants::NONCE_RATE_LIMIT_PER_SECOND;
#endif
        if (nonces_in_window >= NONCE_RATE_LIMIT) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    "Nonce generation rate limit exceeded (" +
                    std::to_string(NONCE_RATE_LIMIT) +
                    " nonces per second)"));
        }
        constexpr size_t NONCE_SIZE = 12;
        constexpr size_t COUNTER_SIZE = 8;
        constexpr size_t INDEX_SIZE = 4;
        std::vector<uint8_t> nonce(NONCE_SIZE);
        const uint64_t counter = nonce_counter_.fetch_add(1, std::memory_order_seq_cst);
        uint32_t index = message_index
                             ? *message_index
                             : (pending_send_index_.has_value()
                                ? *pending_send_index_
                                : static_cast<uint32_t>(counter));
        pending_send_index_.reset();
        if (counter >= ProtocolConstants::MAX_NONCE_COUNTER) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    "Nonce counter overflow - must rotate keys (ratchet) before continuing"));
        }
        constexpr auto RATCHET_THRESHOLD =
                static_cast<uint64_t>(ProtocolConstants::MAX_NONCE_COUNTER * 0.95);
        if (counter >= RATCHET_THRESHOLD && !ratchet_warning_triggered_.load(std::memory_order_seq_cst)) {
            ratchet_warning_triggered_.store(true, std::memory_order_seq_cst);
            if (event_handler_) {
                event_handler_->OnRatchetRequired(id_, "Nonce counter approaching maximum - ratchet required");
            }
        }
        for (size_t i = ProtocolConstants::ZERO_VALUE; i < COUNTER_SIZE; ++i) {
            nonce[i] = static_cast<uint8_t>(
                (counter >> (i * ComparisonConstants::BIT_SHIFT_BYTE)) & ComparisonConstants::BYTE_MASK);
        }
        for (size_t i = ProtocolConstants::ZERO_VALUE; i < INDEX_SIZE; ++i) {
            nonce[COUNTER_SIZE + i] = static_cast<uint8_t>(
                (index >> (i * ComparisonConstants::BIT_SHIFT_BYTE)) & ComparisonConstants::BYTE_MASK);
        }
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Ok(nonce);
    }

    Result<Unit, EcliptixProtocolFailure>
    EcliptixProtocolConnection::CheckReplayProtection(
        const std::span<const uint8_t> nonce,
        const uint64_t message_index) {
        const uint64_t chain_index = receiving_ratchet_epoch_.load(std::memory_order_acquire);
        return replay_protection_.CheckAndRecordMessage(nonce, message_index, chain_index);
    }

    Result<std::pair<RatchetChainKey, bool>, EcliptixProtocolFailure>
    EcliptixProtocolConnection::PrepareNextSendMessage() {
        std::lock_guard lock(*lock_);
        if (auto expired_check = EnsureNotExpired(); expired_check.IsErr()) {
            return Result<std::pair<RatchetChainKey, bool>, EcliptixProtocolFailure>::Err(
                std::move(expired_check).UnwrapErr());
        }
        if (!root_key_handle_.has_value()) {
            return Result<std::pair<RatchetChainKey, bool>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Connection not finalized - call FinalizeChainAndDhKeys() first"));
        }
        if (disposed_.load()) {
            return Result<std::pair<RatchetChainKey, bool>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::ObjectDisposed("EcliptixProtocolConnection"));
        }
        auto current_index_result = sending_step_.GetCurrentIndex();
        if (current_index_result.IsErr()) {
            return Result<std::pair<RatchetChainKey, bool>, EcliptixProtocolFailure>::Err(
                current_index_result.UnwrapErr());
        }
        uint32_t next_index = current_index_result.Unwrap();
        bool should_ratchet = ratchet_config_.ShouldRatchet(next_index, received_new_dh_key_.load());
        bool include_dh_key = false;
        if (should_ratchet) {
            if (auto ratchet_result = PerformDhRatchet(true, {}, {}); ratchet_result.IsErr()) {
                return Result<std::pair<RatchetChainKey, bool>, EcliptixProtocolFailure>::Err(
                    ratchet_result.UnwrapErr());
            }
            include_dh_key = true;
            received_new_dh_key_.store(false);

            auto new_index_result = sending_step_.GetCurrentIndex();
            if (new_index_result.IsErr()) {
                return Result<std::pair<RatchetChainKey, bool>, EcliptixProtocolFailure>::Err(
                    new_index_result.UnwrapErr());
            }
            next_index = new_index_result.Unwrap();
        }
        auto derived_key_result = sending_step_.GetOrDeriveKeyFor(next_index);
        if (derived_key_result.IsErr()) {
            return Result<std::pair<RatchetChainKey, bool>, EcliptixProtocolFailure>::Err(
                derived_key_result.UnwrapErr());
        }
        auto derived_key = derived_key_result.Unwrap();
        pending_send_index_ = next_index;
        sending_step_.PruneOldKeys();
        if (event_handler_) {
            event_handler_->OnProtocolStateChanged(id_);
        }
        return Result<std::pair<RatchetChainKey, bool>, EcliptixProtocolFailure>::Ok(
            std::make_pair(derived_key, include_dh_key));
    }

    Result<Unit, EcliptixProtocolFailure>
    EcliptixProtocolConnection::PerformDhRatchet(
        bool is_sender,
        std::span<const uint8_t> received_dh_public_key,
        std::span<const uint8_t> received_kyber_ciphertext) {
        if (!root_key_handle_.has_value()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Root key not initialized"));
        }

        constexpr int64_t ONE_MINUTE_NS = 60'000'000'000LL;
        const auto now = std::chrono::steady_clock::now();
        const int64_t now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        if (int64_t window_start = dh_ratchet_rate_limit_window_start_ns_.load(std::memory_order_seq_cst);
            window_start == 0 || (now_ns - window_start) >= ONE_MINUTE_NS) {
            dh_ratchet_rate_limit_window_start_ns_.store(now_ns, std::memory_order_seq_cst);
            dh_ratchets_in_current_window_.store(0, std::memory_order_seq_cst);
        }
        const uint32_t ratchets_in_window [[maybe_unused]] = dh_ratchets_in_current_window_.fetch_add(
            1, std::memory_order_seq_cst);
#ifndef ECLIPTIX_TEST_BUILD
        if (ratchets_in_window >= ProtocolConstants::MAX_DH_RATCHETS_PER_MINUTE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(std::format(
                    "DH ratchet rate limit exceeded: {} ratchets per minute maximum (DoS protection)",
                    ProtocolConstants::MAX_DH_RATCHETS_PER_MINUTE)));
        }
#endif
        if (!received_dh_public_key.empty()) {
            if (auto validation_result = DhValidator::ValidateX25519PublicKey(received_dh_public_key); validation_result
                .IsErr()) {
                return validation_result;
            }
        }
        std::vector<uint8_t> dh_secret;
        std::vector<uint8_t> hybrid_secret;
        std::vector<uint8_t> new_root_key;
        std::vector<uint8_t> new_chain_key;
        std::vector<uint8_t> new_dh_private;
        try {
            std::vector<uint8_t> new_dh_public;
            if (is_sender) {
                auto new_keypair_result = SodiumInterop::GenerateX25519KeyPair("Ratchet ephemeral DH key");
                if (new_keypair_result.IsErr()) {
                    return Result<Unit, EcliptixProtocolFailure>::Err(
                        new_keypair_result.UnwrapErr());
                }
                auto [new_priv_handle, new_pub] = std::move(new_keypair_result).Unwrap();
                auto priv_bytes_result = new_priv_handle.ReadBytes(Constants::X_25519_PRIVATE_KEY_SIZE);
                if (priv_bytes_result.IsErr()) {
                    return Result<Unit, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::Generic("Failed to read new DH private key"));
                }
                new_dh_private = priv_bytes_result.Unwrap();
                new_dh_public = std::move(new_pub);
                if (!peer_dh_public_key_.has_value() || peer_dh_public_key_->empty()) {
                    {
                        auto _wipe = SodiumInterop::SecureWipe(std::span(new_dh_private));
                        (void) _wipe;
                    }
                    return Result<Unit, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::Generic("Peer DH public key not set"));
                }
                dh_secret.resize(Constants::X_25519_KEY_SIZE);
                if (crypto_scalarmult(dh_secret.data(), new_dh_private.data(), peer_dh_public_key_->data()) != 0) {
                    {
                        auto _wipe = SodiumInterop::SecureWipe(std::span(new_dh_private));
                        (void) _wipe;
                    }
                    return Result<Unit, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::DeriveKey("Failed to compute sender DH secret"));
                }
            } else {
                if (received_dh_public_key.empty()) {
                    return Result<Unit, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::InvalidInput("Received DH public key required for receiver ratchet"));
                }
                if (!current_sending_dh_private_handle_.has_value()) {
                    return Result<Unit, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::Generic("Current sending DH private key not set"));
                }
                auto our_priv_bytes_result = current_sending_dh_private_handle_->ReadBytes(
                    Constants::X_25519_PRIVATE_KEY_SIZE);
                if (our_priv_bytes_result.IsErr()) {
                    return Result<Unit, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::Generic("Failed to read current DH private key"));
                }
                auto our_priv_bytes = our_priv_bytes_result.Unwrap();
                dh_secret.resize(Constants::X_25519_KEY_SIZE);
                if (crypto_scalarmult(dh_secret.data(), our_priv_bytes.data(), received_dh_public_key.data()) != 0) {
                    {
                        auto _wipe = SodiumInterop::SecureWipe(std::span(our_priv_bytes));
                        (void) _wipe;
                    }
                    return Result<Unit, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::DeriveKey("Failed to compute receiver DH secret"));
                } {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(our_priv_bytes));
                    (void) _wipe;
                }
                peer_dh_public_key_ = std::vector(received_dh_public_key.begin(), received_dh_public_key.end());
            }
            if (is_sender) {
                if (!peer_kyber_public_key_.has_value() || peer_kyber_public_key_->size() != KyberInterop::
                    KYBER_768_PUBLIC_KEY_SIZE) {
                    auto _wipe_priv = SodiumInterop::SecureWipe(std::span(new_dh_private));
                    (void) _wipe_priv;
                    auto _wipe_dh = SodiumInterop::SecureWipe(std::span(dh_secret));
                    (void) _wipe_dh;
                    return Result<Unit, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::Generic("Peer Kyber public key missing for hybrid ratchet"));
                }
                auto encap_result = KyberInterop::Encapsulate(*peer_kyber_public_key_);
                if (encap_result.IsErr()) {
                    auto _wipe_priv = SodiumInterop::SecureWipe(std::span(new_dh_private));
                    (void) _wipe_priv;
                    auto _wipe_dh = SodiumInterop::SecureWipe(std::span(dh_secret));
                    (void) _wipe_dh;
                    return Result<Unit, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::FromSodiumFailure(encap_result.UnwrapErr()));
                }
                auto [ct, ss_handle] = std::move(encap_result).Unwrap();
                auto ss_bytes_result = ss_handle.ReadBytes(KyberInterop::KYBER_768_SHARED_SECRET_SIZE);
                if (ss_bytes_result.IsErr()) {
                    auto _wipe_priv = SodiumInterop::SecureWipe(std::span(new_dh_private));
                    (void) _wipe_priv;
                    auto _wipe_dh = SodiumInterop::SecureWipe(std::span(dh_secret));
                    (void) _wipe_dh;
                    return Result<Unit, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::FromSodiumFailure(ss_bytes_result.UnwrapErr()));
                }
                kyber_ciphertext_ = std::move(ct);
                kyber_shared_secret_ = ss_bytes_result.Unwrap();
            } else {
                auto kyber_update = UpdateKyberSecretFromCiphertext(received_kyber_ciphertext);
                if (kyber_update.IsErr()) {
                    auto _wipe_priv = SodiumInterop::SecureWipe(std::span(new_dh_private));
                    (void) _wipe_priv;
                    auto _wipe_dh = SodiumInterop::SecureWipe(std::span(dh_secret));
                    (void) _wipe_dh;
                    return kyber_update;
                }
            }
            auto root_bytes_result = root_key_handle_->ReadBytes(Constants::X_25519_KEY_SIZE);
            if (root_bytes_result.IsErr()) {
                {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(dh_secret));
                    (void) _wipe;
                } {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(new_dh_private));
                    (void) _wipe;
                }
                return Result<Unit, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Failed to read root key"));
            }
            auto root_bytes = root_bytes_result.Unwrap();
            auto hybrid_secret_result = DeriveHybridDhSecret(
                dh_secret,
                root_bytes,
                kyber_shared_secret_);
            if (hybrid_secret_result.IsErr()) {
                {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(root_bytes));
                    (void) _wipe;
                } {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(dh_secret));
                    (void) _wipe;
                } {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(new_dh_private));
                    (void) _wipe;
                }
                return Result<Unit, EcliptixProtocolFailure>::Err(hybrid_secret_result.UnwrapErr());
            }
            hybrid_secret = hybrid_secret_result.Unwrap();
            auto hkdf_output_result = Hkdf::DeriveKeyBytes(
                hybrid_secret,
                Constants::X_25519_KEY_SIZE * 2,
                root_bytes,
                std::vector<uint8_t>(ProtocolConstants::HYBRID_DH_RATCHET_INFO.begin(),
                                     ProtocolConstants::HYBRID_DH_RATCHET_INFO.end())); {
                auto _wipe = SodiumInterop::SecureWipe(std::span(root_bytes));
                (void) _wipe;
            } {
                auto _wipe = SodiumInterop::SecureWipe(std::span(dh_secret));
                (void) _wipe;
            } {
                auto _wipe = SodiumInterop::SecureWipe(std::span(hybrid_secret));
                (void) _wipe;
            }
            if (hkdf_output_result.IsErr()) {
                {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(new_dh_private));
                    (void) _wipe;
                }
                return Result<Unit, EcliptixProtocolFailure>::Err(
                    hkdf_output_result.UnwrapErr());
            }
            auto hkdf_output = hkdf_output_result.Unwrap();
            new_root_key.assign(hkdf_output.begin(), hkdf_output.begin() + Constants::X_25519_KEY_SIZE);
            new_chain_key.assign(hkdf_output.begin() + Constants::X_25519_KEY_SIZE, hkdf_output.end()); {
                auto _wipe = SodiumInterop::SecureWipe(std::span(hkdf_output));
                (void) _wipe;
            }
            if (auto write_result = root_key_handle_->Write(new_root_key); write_result.IsErr()) {
                {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(new_root_key));
                    (void) _wipe;
                } {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(new_chain_key));
                    (void) _wipe;
                } {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(new_dh_private));
                    (void) _wipe;
                }
                return Result<Unit, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::FromSodiumFailure(write_result.UnwrapErr()));
            } {
                auto _wipe = SodiumInterop::SecureWipe(std::span(new_root_key));
                (void) _wipe;
            }
            if (is_sender) {
                if (auto update_result = sending_step_.UpdateKeysAfterDhRatchet(new_chain_key); update_result.IsErr()) {
                    {
                        auto _wipe = SodiumInterop::SecureWipe(std::span(new_chain_key));
                        (void) _wipe;
                    } {
                        auto _wipe = SodiumInterop::SecureWipe(std::span(new_dh_private));
                        (void) _wipe;
                    }
                    return update_result;
                }
                auto new_dh_handle_result = SecureMemoryHandle::Allocate(Constants::X_25519_PRIVATE_KEY_SIZE);
                if (new_dh_handle_result.IsErr()) {
                    {
                        auto _wipe = SodiumInterop::SecureWipe(std::span(new_chain_key));
                        (void) _wipe;
                    } {
                        auto _wipe = SodiumInterop::SecureWipe(std::span(new_dh_private));
                        (void) _wipe;
                    }
                    return Result<Unit, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::FromSodiumFailure(new_dh_handle_result.UnwrapErr()));
                }
                auto new_dh_handle = std::move(new_dh_handle_result).Unwrap();
                auto dh_write_result = new_dh_handle.Write(new_dh_private); {
                    auto _wipe = SodiumInterop::SecureWipe(std::span(new_dh_private));
                    (void) _wipe;
                }
                if (dh_write_result.IsErr()) {
                    {
                        auto _wipe = SodiumInterop::SecureWipe(std::span(new_chain_key));
                        (void) _wipe;
                    }
                    return Result<Unit, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::FromSodiumFailure(dh_write_result.UnwrapErr()));
                }
                current_sending_dh_private_handle_ = std::move(new_dh_handle);
                current_sending_dh_public_ = std::move(new_dh_public);
            } else {
                if (!receiving_step_.has_value()) {
                    {
                        auto _wipe = SodiumInterop::SecureWipe(std::span(new_chain_key));
                        (void) _wipe;
                    }
                    return Result<Unit, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::Generic("Receiving step not initialized"));
                }
                if (auto update_result = receiving_step_->UpdateKeysAfterDhRatchet(new_chain_key); update_result.
                    IsErr()) {
                    {
                        auto _wipe = SodiumInterop::SecureWipe(std::span(new_chain_key));
                        (void) _wipe;
                    }
                    return update_result;
                }
            } {
                auto _wipe = SodiumInterop::SecureWipe(std::span(new_chain_key));
                (void) _wipe;
            }
        if (auto metadata_result = DeriveMetadataEncryptionKey(); metadata_result.IsErr()) {
            return metadata_result;
        }

        // SECURITY: Do NOT reset nonce_counter here!
        // Nonces must be globally unique for the entire session lifetime to prevent replay attacks.
        // The nonce counter increments monotonically and never resets, even across DH ratchets.
        // Only the message index (embedded in nonce bytes [8-11]) resets to 0.

            ratchet_warning_triggered_.store(false, std::memory_order_seq_cst);

            // Increment receiving ratchet epoch to track DH ratchet chains in replay protection
            // This allows message indices to reset to 0 after each ratchet while maintaining
            // proper replay protection by tracking each ratchet epoch separately
            if (!is_sender) {
                receiving_ratchet_epoch_.fetch_add(1, std::memory_order_release);
            }

            // Reset message window tracking when performing a DH ratchet
            // Each ratchet epoch uses a different chain_index (receiving_ratchet_epoch_),
            // so we clear windows to start fresh for each epoch and prevent unbounded memory growth
            // SECURITY: We only clear message windows, NOT nonce tracking - nonces must remain
            // tracked across ALL ratchets to prevent replay attacks
            replay_protection_.ResetMessageWindows();

            return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
        } catch (const std::exception &ex) {
            {
                auto _wipe = SodiumInterop::SecureWipe(std::span(dh_secret));
                (void) _wipe;
            } {
                auto _wipe = SodiumInterop::SecureWipe(std::span(new_root_key));
                (void) _wipe;
            } {
                auto _wipe = SodiumInterop::SecureWipe(std::span(new_chain_key));
                (void) _wipe;
            } {
                auto _wipe = SodiumInterop::SecureWipe(std::span(hybrid_secret));
                (void) _wipe;
            }
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Exception during DH ratchet: " + std::string(ex.what())));
        }
    }

    Result<RatchetChainKey, EcliptixProtocolFailure>
    EcliptixProtocolConnection::ProcessReceivedMessage(
        uint32_t received_index,
        std::span<const uint8_t> nonce) {
        std::lock_guard lock(*lock_);
        if (auto disposed_check = CheckDisposed(); disposed_check.IsErr()) {
            return Result<RatchetChainKey, EcliptixProtocolFailure>::Err(
                disposed_check.UnwrapErr());
        }
        if (auto expired_check = EnsureNotExpired(); expired_check.IsErr()) {
            return Result<RatchetChainKey, EcliptixProtocolFailure>::Err(
                expired_check.UnwrapErr());
        }
        if (!receiving_step_) {
            return Result<RatchetChainKey, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Receiving step not initialized"));
        }
        if (constexpr uint32_t INDEX_OVERFLOW_BUFFER = 1000;
            received_index > std::numeric_limits<uint32_t>::max() - INDEX_OVERFLOW_BUFFER) {
            return Result<RatchetChainKey, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    "Received index too large: " + std::to_string(received_index)));
        }
        if (nonce.size() != Constants::AES_GCM_NONCE_SIZE) {
            return Result<RatchetChainKey, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput(
                    std::format("Nonce must be {} bytes, got {}", Constants::AES_GCM_NONCE_SIZE, nonce.size())));
        }
        // Enforce nonce/index binding: lower 4 bytes of nonce must match the message index (little endian).
        uint32_t nonce_index = 0;
        for (size_t i = 0; i < 4; ++i) {
            constexpr size_t COUNTER_OFFSET = 8;
            nonce_index |= static_cast<uint32_t>(nonce[COUNTER_OFFSET + i]) << (i * 8);
        }
        if (nonce_index != received_index) {
            return Result<RatchetChainKey, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Nonce/index binding failed"));
        }
        if (auto replay_result = CheckReplayProtection(nonce, received_index); replay_result.IsErr()) {
            return Result<RatchetChainKey, EcliptixProtocolFailure>::Err(replay_result.UnwrapErr());
        }
        EcliptixProtocolChainStep &receiving_step = *receiving_step_;
        auto derived_key_result = receiving_step.GetOrDeriveKeyFor(received_index);
        if (derived_key_result.IsErr()) {
            return Result<RatchetChainKey, EcliptixProtocolFailure>::Err(
                derived_key_result.UnwrapErr());
        }
        RatchetChainKey derived_key = derived_key_result.Unwrap();
        PerformCleanupIfNeeded(received_index);
        return Result<RatchetChainKey, EcliptixProtocolFailure>::Ok(derived_key);
    }

    void EcliptixProtocolConnection::PerformCleanupIfNeeded(uint32_t received_index) {
        if (receiving_step_) {
            receiving_step_->PruneOldKeys();
        }
    }

    Result<Unit, EcliptixProtocolFailure> EcliptixProtocolConnection::ValidateHybridPersistenceInvariants() const {
        if (kyber_public_key_.size() != KyberInterop::KYBER_768_PUBLIC_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("PQ persistence invariant violated: kyber public key missing"));
        }
        if (!peer_kyber_public_key_ || peer_kyber_public_key_->size() != KyberInterop::KYBER_768_PUBLIC_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("PQ persistence invariant violated: peer kyber public key missing"));
        }
        if (!kyber_ciphertext_ || kyber_ciphertext_->size() != KyberInterop::KYBER_768_CIPHERTEXT_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("PQ persistence invariant violated: kyber ciphertext missing"));
        }
        if (!kyber_shared_secret_ || kyber_shared_secret_->size() != KyberInterop::KYBER_768_SHARED_SECRET_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("PQ persistence invariant violated: kyber shared secret missing"));
        }
        auto kyber_sk_bytes = kyber_secret_key_handle_.ReadBytes(KyberInterop::KYBER_768_SECRET_KEY_SIZE);
        if (kyber_sk_bytes.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::FromSodiumFailure(kyber_sk_bytes.UnwrapErr()));
        }
        auto kyber_sk_plain = kyber_sk_bytes.Unwrap();
        if (kyber_sk_plain.size() != KyberInterop::KYBER_768_SECRET_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("PQ persistence invariant violated: kyber secret key size incorrect"));
        }
        auto _wipe = SodiumInterop::SecureWipe(std::span(kyber_sk_plain));
        (void) _wipe;
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Result<Unit, EcliptixProtocolFailure> EcliptixProtocolConnection::ValidateHybridPersistenceInvariants(
        const proto::protocol::RatchetState &proto) {
        if (proto.kyber_public_key().size() != KyberInterop::KYBER_768_PUBLIC_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("PQ persistence invariant violated: kyber public key missing"));
        }
        if (proto.peer_kyber_public_key().size() != KyberInterop::KYBER_768_PUBLIC_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("PQ persistence invariant violated: peer kyber public key missing"));
        }
        if (proto.kyber_ciphertext().size() != KyberInterop::KYBER_768_CIPHERTEXT_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("PQ persistence invariant violated: kyber ciphertext missing"));
        }
        if (proto.kyber_shared_secret().size() != KyberInterop::KYBER_768_SHARED_SECRET_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("PQ persistence invariant violated: kyber shared secret missing"));
        }
        constexpr size_t SEALED_KYBER_SK_SIZE =
            KyberInterop::KYBER_768_SECRET_KEY_SIZE + Constants::AES_GCM_TAG_SIZE;
        if (proto.kyber_secret_key().size() != SEALED_KYBER_SK_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("PQ persistence invariant violated: kyber secret key missing"));
        }
        if (proto.kyber_secret_key_nonce().size() != Constants::AES_GCM_NONCE_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("PQ persistence invariant violated: kyber secret key nonce missing"));
        }
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Result<proto::protocol::RatchetState, EcliptixProtocolFailure>
    EcliptixProtocolConnection::ToProtoState() const {
        std::lock_guard lock(*lock_);
        if (disposed_) {
            return Result<proto::protocol::RatchetState, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Cannot serialize disposed connection"));
        }
        if (exchange_type_ == PubKeyExchangeType::SERVER_STREAMING) {
            return Result<proto::protocol::RatchetState, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Server streaming connections cannot be persisted"));
        }
        try {
            auto hybrid_check = ValidateHybridPersistenceInvariants();
            if (hybrid_check.IsErr()) {
                return Result<proto::protocol::RatchetState, EcliptixProtocolFailure>::Err(
                    hybrid_check.UnwrapErr());
            }
            proto::protocol::RatchetState proto;
            proto.set_is_initiator(is_initiator_);
            proto.set_nonce_counter(nonce_counter_.load());
            proto.set_is_first_receiving_ratchet(is_first_receiving_ratchet_);
            auto time_since_epoch = created_at_.time_since_epoch();
            auto seconds = std::chrono::duration_cast<std::chrono::seconds>(time_since_epoch);
            auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(time_since_epoch - seconds);
            proto.mutable_created_at()->set_seconds(seconds.count());
            proto.mutable_created_at()->set_nanos(static_cast<int32_t>(nanos.count()));
            proto.set_session_id(session_id_.data(), session_id_.size());
            if (peer_dh_public_key_ && !peer_dh_public_key_->empty()) {
                proto.set_peer_dh_public_key(peer_dh_public_key_->data(), peer_dh_public_key_->size());
            }
            if (!peer_kyber_public_key_ || peer_kyber_public_key_->size() != KyberInterop::KYBER_768_PUBLIC_KEY_SIZE) {
                return Result<proto::protocol::RatchetState, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Peer Kyber public key missing for state serialization"));
            }
            proto.set_peer_kyber_public_key(peer_kyber_public_key_->data(), peer_kyber_public_key_->size());
            if (kyber_public_key_.size() != KyberInterop::KYBER_768_PUBLIC_KEY_SIZE) {
                return Result<proto::protocol::RatchetState, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Kyber public key missing for state serialization"));
            }
            proto.set_kyber_public_key(kyber_public_key_.data(), kyber_public_key_.size());
            if (!kyber_ciphertext_ || kyber_ciphertext_->size() != KyberInterop::KYBER_768_CIPHERTEXT_SIZE) {
                return Result<proto::protocol::RatchetState, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Kyber ciphertext missing for state serialization"));
            }
            proto.set_kyber_ciphertext(kyber_ciphertext_->data(), kyber_ciphertext_->size());
            if (!kyber_shared_secret_ || kyber_shared_secret_->size() != KyberInterop::KYBER_768_SHARED_SECRET_SIZE) {
                return Result<proto::protocol::RatchetState, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Kyber shared secret missing for state serialization"));
            }
            proto.set_kyber_shared_secret(kyber_shared_secret_->data(), kyber_shared_secret_->size());
            std::vector<uint8_t> root_key_bytes;
            if (root_key_handle_) {
                auto root_key_result = root_key_handle_->ReadBytes(Constants::X_25519_KEY_SIZE);
                if (root_key_result.IsErr()) {
                    return Result<proto::protocol::RatchetState, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::FromSodiumFailure(root_key_result.UnwrapErr()));
                }
                root_key_bytes = root_key_result.Unwrap();
                proto.set_root_key(root_key_bytes.data(), root_key_bytes.size());
            } else {
                return Result<proto::protocol::RatchetState, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Root key missing - cannot serialize state"));
            }
            auto kyber_secret_key_result = kyber_secret_key_handle_.ReadBytes(KyberInterop::KYBER_768_SECRET_KEY_SIZE);
            if (kyber_secret_key_result.IsErr()) {
                return Result<proto::protocol::RatchetState, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::FromSodiumFailure(kyber_secret_key_result.UnwrapErr()));
            }
            auto wrap_key_result = DeriveKyberWrapKey(
                root_key_bytes,
                id_,
                session_id_,
                kyber_public_key_,
                *peer_kyber_public_key_,
                *kyber_ciphertext_);
            if (wrap_key_result.IsErr()) {
                return Result<proto::protocol::RatchetState, EcliptixProtocolFailure>::Err(wrap_key_result.UnwrapErr());
            }
            auto wrap_key = wrap_key_result.Unwrap();
            auto wrap_nonce = SodiumInterop::GetRandomBytes(Constants::AES_GCM_NONCE_SIZE);
            auto ad = BuildKyberWrapAssociatedData(
                session_id_,
                kyber_public_key_,
                *peer_kyber_public_key_,
                *kyber_ciphertext_);
            auto kyber_secret_key = kyber_secret_key_result.Unwrap();
            auto wrap_result = AesGcm::Encrypt(
                wrap_key,
                wrap_nonce,
                kyber_secret_key,
                ad);
            auto _wipe_wrap_key = SodiumInterop::SecureWipe(std::span(wrap_key));
            (void) _wipe_wrap_key;
            auto _wipe_plain_sk = SodiumInterop::SecureWipe(std::span(kyber_secret_key));
            (void) _wipe_plain_sk;
            if (wrap_result.IsErr()) {
                return Result<proto::protocol::RatchetState, EcliptixProtocolFailure>::Err(wrap_result.UnwrapErr());
            }
            auto sealed_sk = wrap_result.Unwrap();
            proto.set_kyber_secret_key(sealed_sk.data(), sealed_sk.size());
            proto.set_kyber_secret_key_nonce(wrap_nonce.data(), wrap_nonce.size());
            if (!initial_sending_dh_public_.empty()) {
                proto.set_initial_sending_dh_public(
                    initial_sending_dh_public_.data(),
                    initial_sending_dh_public_.size());
            }
            if (!current_sending_dh_public_.empty()) {
                proto.set_current_sending_dh_public(
                    current_sending_dh_public_.data(),
                    current_sending_dh_public_.size());
            }
            auto sending_step_result = sending_step_.ToProtoState();
            if (sending_step_result.IsErr()) {
                return Result<proto::protocol::RatchetState, EcliptixProtocolFailure>::Err(
                    sending_step_result.UnwrapErr());
            }
            *proto.mutable_sending_step() = sending_step_result.Unwrap();
            if (receiving_step_) {
                auto receiving_step_result = receiving_step_->ToProtoState();
                if (receiving_step_result.IsErr()) {
                    return Result<proto::protocol::RatchetState, EcliptixProtocolFailure>::Err(
                        receiving_step_result.UnwrapErr());
                }
                *proto.mutable_receiving_step() = receiving_step_result.Unwrap();
            }
            auto mac_key_result = DeriveStateMacKey(
                root_key_bytes,
                session_id_,
                is_initiator_,
                id_,
                initial_sending_dh_public_,
                current_sending_dh_public_,
                kyber_public_key_,
                *peer_kyber_public_key_,
                *kyber_ciphertext_);
            if (mac_key_result.IsErr()) {
                auto _wipe = SodiumInterop::SecureWipe(std::span(root_key_bytes));
                (void) _wipe;
                return Result<proto::protocol::RatchetState, EcliptixProtocolFailure>::Err(
                    mac_key_result.UnwrapErr());
            }
            auto mac_result = ComputeStateMac(proto, mac_key_result.Unwrap());
            auto _wipe_root = SodiumInterop::SecureWipe(std::span(root_key_bytes));
            (void) _wipe_root;
            if (mac_result.IsErr()) {
                return Result<proto::protocol::RatchetState, EcliptixProtocolFailure>::Err(mac_result.UnwrapErr());
            }
            auto mac = mac_result.Unwrap();
            proto.set_state_mac(mac.data(), mac.size());
            return Result<proto::protocol::RatchetState, EcliptixProtocolFailure>::Ok(std::move(proto));
        } catch (const std::exception &ex) {
            return Result<proto::protocol::RatchetState, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Failed to export proto state: " + std::string(ex.what())));
        }
    }

    Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>
    EcliptixProtocolConnection::FromProtoState(
        uint32_t connection_id,
        const proto::protocol::RatchetState &proto,
        RatchetConfig ratchet_config,
        PubKeyExchangeType exchange_type) {
        try {
            if (proto.root_key().size() != Constants::X_25519_KEY_SIZE) {
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Invalid root key size in stored state"));
            }
            auto hybrid_check = ValidateHybridPersistenceInvariants(proto);
            if (hybrid_check.IsErr()) {
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    hybrid_check.UnwrapErr());
            }
            std::vector<uint8_t> root_key_bytes(proto.root_key().begin(), proto.root_key().end());
            if (proto.session_id().size() != 16) {
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Invalid session_id size in stored state"));
            }
            if (!proto.peer_dh_public_key().empty() &&
                proto.peer_dh_public_key().size() != Constants::X_25519_PUBLIC_KEY_SIZE) {
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Invalid peer DH public key size in stored state"));
            }
            if (!proto.peer_kyber_public_key().empty() &&
                proto.peer_kyber_public_key().size() != KyberInterop::KYBER_768_PUBLIC_KEY_SIZE) {
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Invalid peer Kyber public key size in stored state"));
            }
            if (!proto.kyber_ciphertext().empty() &&
                proto.kyber_ciphertext().size() != KyberInterop::KYBER_768_CIPHERTEXT_SIZE) {
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Invalid Kyber ciphertext size in stored state"));
            }
            if (!proto.kyber_shared_secret().empty() &&
                proto.kyber_shared_secret().size() != Constants::X_25519_KEY_SIZE) {
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Invalid Kyber shared secret size in stored state"));
            }
            if (proto.initial_sending_dh_public().empty() ||
                proto.initial_sending_dh_public().size() != Constants::X_25519_PUBLIC_KEY_SIZE) {
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic(
                        "Invalid or missing initial sending DH public key in stored state"));
            }
            if (!proto.kyber_shared_secret().empty() &&
                proto.kyber_shared_secret().size() != Constants::X_25519_KEY_SIZE) {
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Invalid Kyber shared secret size in stored state"));
            }
            std::vector<uint8_t> initial_sending_dh_public(
                proto.initial_sending_dh_public().begin(),
                proto.initial_sending_dh_public().end());
            std::vector<uint8_t> current_sending_dh_public;
            if (!proto.current_sending_dh_public().empty()) {
                if (proto.current_sending_dh_public().size() != Constants::X_25519_PUBLIC_KEY_SIZE) {
                    return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::Generic("Invalid current sending DH public key size in stored state"));
                }
                current_sending_dh_public.assign(
                    proto.current_sending_dh_public().begin(),
                    proto.current_sending_dh_public().end());
            } else {
                current_sending_dh_public = initial_sending_dh_public;
            }
            auto mac_verify_result = VerifyStateMac(proto, connection_id);
            if (mac_verify_result.IsErr()) {
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    mac_verify_result.UnwrapErr());
            }
            auto sending_step_result = EcliptixProtocolChainStep::FromProtoState(
                ChainStepType::SENDER,
                proto.sending_step());
            if (sending_step_result.IsErr()) {
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    sending_step_result.UnwrapErr());
            }
            EcliptixProtocolChainStep sending_step = std::move(sending_step_result.Unwrap());
            std::optional<EcliptixProtocolChainStep> receiving_step;
            if (proto.has_receiving_step()) {
                auto receiving_step_result = EcliptixProtocolChainStep::FromProtoState(
                    ChainStepType::RECEIVER,
                    proto.receiving_step());
                if (receiving_step_result.IsErr()) {
                    return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                        receiving_step_result.UnwrapErr());
                }
                receiving_step.emplace(std::move(receiving_step_result.Unwrap()));
            }
            auto root_key_alloc_result = SecureMemoryHandle::Allocate(root_key_bytes.size());
            if (root_key_alloc_result.IsErr()) {
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::FromSodiumFailure(root_key_alloc_result.UnwrapErr()));
            }
            auto root_key_handle = std::move(root_key_alloc_result.Unwrap());
            auto write_result = root_key_handle.Write(root_key_bytes);
            if (write_result.IsErr()) {
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::FromSodiumFailure(write_result.UnwrapErr()));
            }
            SecureMemoryHandle metadata_key_handle;
            auto total_nanos = std::chrono::nanoseconds(
                proto.created_at().seconds() * 1'000'000'000LL +
                proto.created_at().nanos());
            auto system_duration = std::chrono::duration_cast<std::chrono::system_clock::duration>(total_nanos);
            std::chrono::system_clock::time_point created_at(system_duration);
            std::vector<uint8_t> session_id;
            if (!proto.session_id().empty()) {
                session_id.assign(proto.session_id().begin(), proto.session_id().end());
                if (session_id.size() != 16) {
                    return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::Generic(
                            "Invalid session_id size: " + std::to_string(session_id.size()) + " (expected 16 bytes)"));
                }
            } else {
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Session restore attack detected: missing session_id"));
            }
            std::optional<LocalPublicKeyBundle> peer_bundle;
            std::optional<std::vector<uint8_t> > peer_dh_public_key;
            std::optional<std::vector<uint8_t> > peer_kyber_public_key;
            std::optional<std::vector<uint8_t> > kyber_ciphertext;
            std::optional<std::vector<uint8_t> > kyber_shared_secret;
            if (!proto.peer_dh_public_key().empty()) {
                peer_dh_public_key = std::vector<uint8_t>(
                    proto.peer_dh_public_key().begin(),
                    proto.peer_dh_public_key().end());
            }
            std::vector<uint8_t> peer_kyber_pk(
                proto.peer_kyber_public_key().begin(),
                proto.peer_kyber_public_key().end());
            peer_kyber_public_key = peer_kyber_pk;
            std::vector<uint8_t> kyber_ct(
                proto.kyber_ciphertext().begin(),
                proto.kyber_ciphertext().end());
            kyber_ciphertext = kyber_ct;
            std::vector<uint8_t> kyber_ss(
                proto.kyber_shared_secret().begin(),
                proto.kyber_shared_secret().end());
            kyber_shared_secret = kyber_ss;
            SecureMemoryHandle initial_sending_dh_private_handle;
            SecureMemoryHandle current_sending_dh_private_handle;
            SecureMemoryHandle persistent_dh_private_handle;
            std::vector<uint8_t> persistent_dh_public;
            SecureMemoryHandle kyber_secret_key_handle;
            std::vector<uint8_t> kyber_public_key;
            kyber_public_key.assign(proto.kyber_public_key().begin(), proto.kyber_public_key().end());
            std::vector<uint8_t> kyber_sk_nonce(
                proto.kyber_secret_key_nonce().begin(),
                proto.kyber_secret_key_nonce().end());
            std::vector<uint8_t> sealed_kyber_secret_key(
                proto.kyber_secret_key().begin(),
                proto.kyber_secret_key().end());
            auto wrap_key_result = DeriveKyberWrapKey(
                root_key_bytes,
                connection_id,
                session_id,
                kyber_public_key,
                peer_kyber_pk,
                kyber_ct);
            if (wrap_key_result.IsErr()) {
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    wrap_key_result.UnwrapErr());
            }
            auto wrap_key = wrap_key_result.Unwrap();
            auto ad = BuildKyberWrapAssociatedData(
                session_id,
                kyber_public_key,
                peer_kyber_pk,
                kyber_ct);
            auto unwrap_result = AesGcm::Decrypt(
                wrap_key,
                kyber_sk_nonce,
                sealed_kyber_secret_key,
                ad);
            auto _wipe_wrap = SodiumInterop::SecureWipe(
                std::span(wrap_key));
            (void) _wipe_wrap;
            if (unwrap_result.IsErr()) {
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    unwrap_result.UnwrapErr());
            }
            auto kyber_sk_plain = unwrap_result.Unwrap();
            if (kyber_sk_plain.size() != KyberInterop::KYBER_768_SECRET_KEY_SIZE) {
                auto _wipe_plain = SodiumInterop::SecureWipe(std::span(kyber_sk_plain));
                (void) _wipe_plain;
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Unwrapped Kyber secret key size invalid"));
            }
            auto kyber_sk_alloc = SecureMemoryHandle::Allocate(kyber_sk_plain.size());
            if (kyber_sk_alloc.IsErr()) {
                auto _wipe_plain = SodiumInterop::SecureWipe(std::span(kyber_sk_plain));
                (void) _wipe_plain;
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::FromSodiumFailure(kyber_sk_alloc.UnwrapErr()));
            }
            kyber_secret_key_handle = std::move(kyber_sk_alloc).Unwrap();
            auto kyber_sk_write = kyber_secret_key_handle.Write(kyber_sk_plain);
            auto _wipe_plain = SodiumInterop::SecureWipe(std::span(kyber_sk_plain));
            (void) _wipe_plain;
            if (kyber_sk_write.IsErr()) {
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::FromSodiumFailure(kyber_sk_write.UnwrapErr()));
            }
            std::unique_ptr<EcliptixProtocolConnection> connection(
                new EcliptixProtocolConnection(
                    connection_id,
                    proto.is_initiator(),
                    ratchet_config,
                    exchange_type,
                    created_at,
                    std::move(session_id),
                    proto.nonce_counter(),
                    std::move(root_key_handle),
                    std::move(metadata_key_handle),
                    std::move(sending_step),
                    std::move(receiving_step),
                    std::move(peer_bundle),
                    std::move(peer_dh_public_key),
                    std::move(peer_kyber_public_key),
                    std::move(kyber_ciphertext),
                    std::move(kyber_shared_secret),
                    std::move(kyber_secret_key_handle),
                    std::move(kyber_public_key),
                    std::move(initial_sending_dh_private_handle),
                    std::move(initial_sending_dh_public),
                    std::move(current_sending_dh_private_handle),
                    std::move(persistent_dh_private_handle),
                    std::move(persistent_dh_public),
                    proto.is_first_receiving_ratchet()
                )
            );
            // Rehydrate current DH private/public material from the sending chain state
            if (auto sender_dh_handle = sending_step.GetDhPrivateKeyHandle(); sender_dh_handle.has_value()) {
                auto dh_bytes_result = (*sender_dh_handle)->ReadBytes(Constants::X_25519_PRIVATE_KEY_SIZE);
                if (dh_bytes_result.IsErr()) {
                    return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::FromSodiumFailure(dh_bytes_result.UnwrapErr()));
                }
                auto dh_copy = std::move(dh_bytes_result).Unwrap();
                auto alloc_priv = SecureMemoryHandle::Allocate(Constants::X_25519_PRIVATE_KEY_SIZE);
                if (alloc_priv.IsErr()) {
                    SodiumInterop::SecureWipe(std::span(dh_copy));
                    return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::FromSodiumFailure(alloc_priv.UnwrapErr()));
                }
                auto alloc_initial = SecureMemoryHandle::Allocate(Constants::X_25519_PRIVATE_KEY_SIZE);
                if (alloc_initial.IsErr()) {
                    SodiumInterop::SecureWipe(std::span(dh_copy));
                    return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::FromSodiumFailure(alloc_initial.UnwrapErr()));
                }
                auto current_priv = std::move(alloc_priv).Unwrap();
                auto initial_priv = std::move(alloc_initial).Unwrap();
                auto write_priv = current_priv.Write(dh_copy);
                if (write_priv.IsErr()) {
                    SodiumInterop::SecureWipe(std::span(dh_copy));
                    return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::FromSodiumFailure(write_priv.UnwrapErr()));
                }
                auto write_initial = initial_priv.Write(dh_copy);
                SodiumInterop::SecureWipe(std::span(dh_copy));
                if (write_initial.IsErr()) {
                    return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::FromSodiumFailure(write_initial.UnwrapErr()));
                }
                connection->current_sending_dh_private_handle_ = std::move(current_priv);
                connection->initial_sending_dh_private_handle_ = std::move(initial_priv);
            }
            connection->current_sending_dh_public_ = std::move(current_sending_dh_public);
            auto metadata_result = connection->DeriveMetadataEncryptionKey();
            if (metadata_result.IsErr()) {
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    metadata_result.UnwrapErr());
            }
            return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Ok(
                std::move(connection));
        } catch (const std::exception &ex) {
            return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Failed to rehydrate from proto state: " + std::string(ex.what())));
        }
    }
}
