#include "ecliptix/protocol/connection/ecliptix_protocol_connection.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/hkdf.hpp"
#include "ecliptix/security/validation/dh_validator.hpp"
#include "protocol/protocol_state.pb.h"
#include <sodium.h>
#include <chrono>
#include <format>

namespace ecliptix::protocol::connection {
    using namespace ecliptix::protocol::crypto;
    using namespace ecliptix::protocol::security;
    using namespace ecliptix::protocol::chain_step;
    using namespace ecliptix::protocol::enums;
    using ProtocolConstants = ProtocolConstants;

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
          , initial_sending_dh_public_(std::move(initial_sending_dh_public))
          , current_sending_dh_private_handle_()
          , persistent_dh_private_handle_(std::move(persistent_dh_private_handle))
          , persistent_dh_public_(std::move(persistent_dh_public))
          , sending_step_(std::move(sending_step))
          , receiving_step_()
          , peer_bundle_()
          , peer_dh_public_key_()
          , nonce_counter_(ProtocolConstants::INITIAL_NONCE_COUNTER)
          , rate_limit_window_start_ns_(0)
          , nonces_in_current_window_(0)
          , dh_ratchet_rate_limit_window_start_ns_(0)
          , dh_ratchets_in_current_window_(0)
          , disposed_(false)
          , is_first_receiving_ratchet_(true)
          , received_new_dh_key_(false)
          , ratchet_warning_triggered_(false)
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
          , initial_sending_dh_public_(std::move(initial_sending_dh_public))
          , current_sending_dh_private_handle_(std::move(current_sending_dh_private_handle))
          , persistent_dh_private_handle_(std::move(persistent_dh_private_handle))
          , persistent_dh_public_(std::move(persistent_dh_public))
          , sending_step_(std::move(sending_step))
          , receiving_step_(receiving_step ? std::make_optional(std::move(*receiving_step)) : std::nullopt)
          , peer_bundle_(std::move(peer_bundle))
          , peer_dh_public_key_(std::move(peer_dh_public_key))
          , nonce_counter_(nonce_counter)
          , rate_limit_window_start_ns_(0)
          , nonces_in_current_window_(0)
          , dh_ratchet_rate_limit_window_start_ns_(0)
          , dh_ratchets_in_current_window_(0)
          , disposed_(false)
          , is_first_receiving_ratchet_(is_first_receiving_ratchet)
          , received_new_dh_key_(false)
          , ratchet_warning_triggered_(false)
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
        if (std::equal(initial_peer_dh_public_key.begin(), initial_peer_dh_public_key.end(),
                       initial_sending_dh_public_.begin())) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    std::string(ErrorMessages::REFLECTION_ATTACK)));
        }
        std::vector<uint8_t> dh_secret;
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
            std::vector<uint8_t> hkdf_output(Constants::X_25519_KEY_SIZE * 2);
            auto root_derive_result = Hkdf::DeriveKeyBytes(
                dh_secret,
                Constants::X_25519_KEY_SIZE * 2,
                std::vector(initial_root_key.begin(), initial_root_key.end()),
                std::vector<uint8_t>(ProtocolConstants::DH_RATCHET_INFO.begin(),
                                     ProtocolConstants::DH_RATCHET_INFO.end()));
            if (root_derive_result.IsErr()) {
                {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(persistent_private_bytes));
                    (void) __wipe;
                } {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(dh_secret));
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
        auto metadata_key_result = Hkdf::DeriveKeyBytes(
            root_bytes,
            Constants::AES_KEY_SIZE,
            std::vector<uint8_t>(),
            std::vector<uint8_t>(ProtocolConstants::METADATA_ENCRYPTION_INFO.begin(),
                                 ProtocolConstants::METADATA_ENCRYPTION_INFO.end())); {
            auto __wipe = SodiumInterop::SecureWipe(std::span(root_bytes));
            (void) __wipe;
        }
        if (metadata_key_result.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(metadata_key_result.UnwrapErr());
        }
        auto metadata_key_bytes = metadata_key_result.Unwrap();
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
        if (dh_secret.size() != Constants::X_25519_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("DH secret must be 32 bytes"));
        }
        if (current_root_key.size() != Constants::X_25519_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Current root key must be 32 bytes"));
        }
        if (new_root_key.size() != Constants::X_25519_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("New root key buffer must be 32 bytes"));
        }
        if (new_chain_key.size() != Constants::X_25519_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("New chain key buffer must be 32 bytes"));
        }
        std::vector<uint8_t> derived_keys(64);
        auto hkdf_result = Hkdf::DeriveKey(
            std::span(dh_secret),
            std::span(derived_keys),
            std::span(current_root_key),
            std::span(
                reinterpret_cast<const uint8_t *>(ProtocolConstants::DH_RATCHET_INFO.data()),
                ProtocolConstants::DH_RATCHET_INFO.size())
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
        auto disposed_check = CheckDisposed();
        if (disposed_check.IsErr()) {
            return Result<Option<std::vector<uint8_t> >, EcliptixProtocolFailure>::Err(
                disposed_check.UnwrapErr());
        }
        if (initial_sending_dh_public_.empty()) {
            return Result<Option<std::vector<uint8_t> >, EcliptixProtocolFailure>::Ok(
                None<std::vector<uint8_t> >());
        }
        return Result<Option<std::vector<uint8_t> >, EcliptixProtocolFailure>::Ok(
            Some(initial_sending_dh_public_));
    }

    Result<std::vector<uint8_t>, EcliptixProtocolFailure>
    EcliptixProtocolConnection::GetMetadataEncryptionKey() const {
        std::lock_guard lock(*lock_);
        auto disposed_check = CheckDisposed();
        if (disposed_check.IsErr()) {
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

    Result<Unit, EcliptixProtocolFailure>
    EcliptixProtocolConnection::SetPeerBundle(const LocalPublicKeyBundle &peer_bundle) {
        std::lock_guard lock(*lock_);
        auto disposed_check = CheckDisposed();
        if (disposed_check.IsErr()) {
            return disposed_check;
        }
        auto finalized_check = CheckIfNotFinalized();
        if (finalized_check.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Cannot set peer bundle after connection finalized"));
        }
        peer_bundle_ = peer_bundle;
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Result<Unit, EcliptixProtocolFailure>
    EcliptixProtocolConnection::PerformReceivingRatchet(std::span<const uint8_t> received_dh_public_key) {
        std::lock_guard lock(*lock_);
        auto disposed_check = CheckDisposed();
        if (disposed_check.IsErr()) {
            return disposed_check;
        }
        auto finalized_check = CheckIfFinalized();
        if (finalized_check.IsErr()) {
            return finalized_check;
        }
        if (received_dh_public_key.size() != Constants::X_25519_PUBLIC_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput(
                    std::format("Received DH public key must be {} bytes, got {}",
                                Constants::X_25519_PUBLIC_KEY_SIZE, received_dh_public_key.size())));
        }
        auto ratchet_result = PerformDhRatchet(false, received_dh_public_key);
        if (ratchet_result.IsErr()) {
            return ratchet_result;
        }
        received_new_dh_key_.store(true);
        if (event_handler_) {
            event_handler_->OnProtocolStateChanged(id_);
        }
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
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
        auto disposed_check = CheckDisposed();
        if (disposed_check.IsErr()) {
            return Result<bool, EcliptixProtocolFailure>::Err(disposed_check.UnwrapErr());
        }
        auto finalized_check = CheckIfFinalized();
        if (finalized_check.IsErr()) {
            return Result<bool, EcliptixProtocolFailure>::Err(finalized_check.UnwrapErr());
        }
        auto current_index_result = sending_step_.GetCurrentIndex();
        if (current_index_result.IsErr()) {
            return Result<bool, EcliptixProtocolFailure>::Err(current_index_result.UnwrapErr());
        }
        uint32_t current_index = current_index_result.Unwrap();
        bool should_ratchet = ratchet_config_.ShouldRatchet(current_index, received_new_dh_key_.load());
        if (!should_ratchet) {
            return Result<bool, EcliptixProtocolFailure>::Ok(false);
        }
        auto ratchet_result = PerformDhRatchet(true, {});
        if (ratchet_result.IsErr()) {
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
        auto disposed_check = CheckDisposed();
        if (disposed_check.IsErr()) {
            return disposed_check;
        }
        auto finalized_check = CheckIfFinalized();
        if (finalized_check.IsErr()) {
            return finalized_check;
        }
        if (!receiving_step_.has_value()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Receiving chain step not initialized"));
        }
        auto receiving_skip_result = receiving_step_->SkipKeysUntil(remote_sending_chain_length);
        if (receiving_skip_result.IsErr()) {
            return receiving_skip_result;
        }
        auto sending_skip_result = sending_step_.SkipKeysUntil(remote_receiving_chain_length);
        if (sending_skip_result.IsErr()) {
            return sending_skip_result;
        }
        if (event_handler_) {
            event_handler_->OnProtocolStateChanged(id_);
        }
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Result<std::vector<uint8_t>, EcliptixProtocolFailure>
    EcliptixProtocolConnection::GenerateNextNonce() {
        auto expired_check = EnsureNotExpired();
        if (expired_check.IsErr()) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                std::move(expired_check).UnwrapErr());
        }

#ifdef ECLIPTIX_TEST_BUILD
        constexpr uint32_t NONCE_RATE_LIMIT = 100'000;
#else
        constexpr uint32_t NONCE_RATE_LIMIT = ProtocolConstants::NONCE_RATE_LIMIT_PER_SECOND;
#endif
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
        if (nonces_in_window >= NONCE_RATE_LIMIT) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    "Nonce generation rate limit exceeded (" +
                    std::to_string(NONCE_RATE_LIMIT) +
                    " nonces per second)"));
        }
        constexpr size_t NONCE_SIZE = 12;
        constexpr size_t RANDOM_SIZE = 8;
        constexpr size_t COUNTER_SIZE = 4;
        std::vector<uint8_t> nonce(NONCE_SIZE);
        std::vector<uint8_t> random_bytes = SodiumInterop::GetRandomBytes(RANDOM_SIZE);
        std::copy_n(random_bytes.begin(), RANDOM_SIZE, nonce.begin());
        const uint64_t counter = nonce_counter_.fetch_add(1, std::memory_order_seq_cst);
        if (counter >= ProtocolConstants::MAX_NONCE_COUNTER) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    "Nonce counter overflow - must rotate keys (ratchet) before continuing"));
        }
        constexpr uint64_t RATCHET_THRESHOLD =
                static_cast<uint64_t>(ProtocolConstants::MAX_NONCE_COUNTER * 0.95);
        if (counter >= RATCHET_THRESHOLD && !ratchet_warning_triggered_.load(std::memory_order_seq_cst)) {
            ratchet_warning_triggered_.store(true, std::memory_order_seq_cst);
            if (event_handler_) {
                event_handler_->OnRatchetRequired(id_, "Nonce counter approaching maximum - ratchet required");
            }
        }
        for (size_t i = ProtocolConstants::ZERO_VALUE; i < COUNTER_SIZE; ++i) {
            nonce[RANDOM_SIZE + i] = static_cast<uint8_t>(
                (counter >> (i * ComparisonConstants::BIT_SHIFT_BYTE)) & ComparisonConstants::BYTE_MASK);
        }
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Ok(nonce);
    }

    Result<Unit, EcliptixProtocolFailure>
    EcliptixProtocolConnection::CheckReplayProtection(
        std::span<const uint8_t> nonce,
        uint64_t message_index) {
        constexpr size_t NONCE_SIZE = 12;
        if (nonce.size() != NONCE_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput(
                    std::format("Nonce must be {} bytes, got {}", NONCE_SIZE, nonce.size())));
        }
        (void) message_index;
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Result<std::pair<RatchetChainKey, bool>, EcliptixProtocolFailure>
    EcliptixProtocolConnection::PrepareNextSendMessage() {
        std::lock_guard lock(*lock_);
        auto expired_check = EnsureNotExpired();
        if (expired_check.IsErr()) {
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
        uint32_t current_index = current_index_result.Unwrap();
        uint32_t next_index = current_index + 1;
        bool should_ratchet = ratchet_config_.ShouldRatchet(next_index, received_new_dh_key_.load());
        bool include_dh_key = false;
        if (should_ratchet) {
            auto ratchet_result = PerformDhRatchet(true, {});
            if (ratchet_result.IsErr()) {
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
            next_index = new_index_result.Unwrap() + 1;
        }
        auto derived_key_result = sending_step_.GetOrDeriveKeyFor(next_index);
        if (derived_key_result.IsErr()) {
            return Result<std::pair<RatchetChainKey, bool>, EcliptixProtocolFailure>::Err(
                derived_key_result.UnwrapErr());
        }
        auto derived_key = derived_key_result.Unwrap();
        auto set_index_result = sending_step_.SetCurrentIndex(next_index);
        if (set_index_result.IsErr()) {
            return Result<std::pair<RatchetChainKey, bool>, EcliptixProtocolFailure>::Err(
                set_index_result.UnwrapErr());
        }
        sending_step_.PruneOldKeys();
        if (event_handler_) {
            event_handler_->OnProtocolStateChanged(id_);
        }
        return Result<std::pair<RatchetChainKey, bool>, EcliptixProtocolFailure>::Ok(
            std::make_pair(derived_key, include_dh_key));
    }

    Result<Unit, EcliptixProtocolFailure>
    EcliptixProtocolConnection::PerformDhRatchet(bool is_sender, std::span<const uint8_t> received_dh_public_key) {
        if (!root_key_handle_.has_value()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Root key not initialized"));
        }

#ifdef ECLIPTIX_TEST_BUILD
        constexpr uint32_t DH_RATCHET_RATE_LIMIT = 1000;
#else
        constexpr uint32_t DH_RATCHET_RATE_LIMIT = ProtocolConstants::MAX_DH_RATCHETS_PER_MINUTE;
#endif
        constexpr int64_t ONE_MINUTE_NS = 60'000'000'000LL;
        const auto now = std::chrono::steady_clock::now();
        const int64_t now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        int64_t window_start = dh_ratchet_rate_limit_window_start_ns_.load(std::memory_order_seq_cst);
        if (window_start == 0 || (now_ns - window_start) >= ONE_MINUTE_NS) {
            dh_ratchet_rate_limit_window_start_ns_.store(now_ns, std::memory_order_seq_cst);
            dh_ratchets_in_current_window_.store(0, std::memory_order_seq_cst);
        }
        const uint32_t ratchets_in_window = dh_ratchets_in_current_window_.fetch_add(1, std::memory_order_seq_cst);
        if (ratchets_in_window >= DH_RATCHET_RATE_LIMIT) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(std::format(
                    "DH ratchet rate limit exceeded: {} ratchets per minute maximum (DoS protection)",
                    DH_RATCHET_RATE_LIMIT)));
        }
        if (!received_dh_public_key.empty()) {
            auto validation_result = DhValidator::ValidateX25519PublicKey(received_dh_public_key);
            if (validation_result.IsErr()) {
                return validation_result;
            }
        }
        std::vector<uint8_t> dh_secret;
        std::vector<uint8_t> new_root_key;
        std::vector<uint8_t> new_chain_key;
        std::vector<uint8_t> new_dh_private;
        std::vector<uint8_t> new_dh_public;
        try {
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
                        auto __wipe = SodiumInterop::SecureWipe(std::span(new_dh_private));
                        (void) __wipe;
                    }
                    return Result<Unit, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::Generic("Peer DH public key not set"));
                }
                dh_secret.resize(Constants::X_25519_KEY_SIZE);
                if (crypto_scalarmult(dh_secret.data(), new_dh_private.data(), peer_dh_public_key_->data()) != 0) {
                    {
                        auto __wipe = SodiumInterop::SecureWipe(std::span(new_dh_private));
                        (void) __wipe;
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
                        auto __wipe = SodiumInterop::SecureWipe(std::span(our_priv_bytes));
                        (void) __wipe;
                    }
                    return Result<Unit, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::DeriveKey("Failed to compute receiver DH secret"));
                } {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(our_priv_bytes));
                    (void) __wipe;
                }
                peer_dh_public_key_ = std::vector(received_dh_public_key.begin(), received_dh_public_key.end());
            }
            auto root_bytes_result = root_key_handle_->ReadBytes(Constants::X_25519_KEY_SIZE);
            if (root_bytes_result.IsErr()) {
                {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(dh_secret));
                    (void) __wipe;
                } {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(new_dh_private));
                    (void) __wipe;
                }
                return Result<Unit, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Failed to read root key"));
            }
            auto root_bytes = root_bytes_result.Unwrap();
            auto hkdf_output_result = Hkdf::DeriveKeyBytes(
                dh_secret,
                Constants::X_25519_KEY_SIZE * 2,
                root_bytes,
                std::vector<uint8_t>(ProtocolConstants::DH_RATCHET_INFO.begin(),
                                     ProtocolConstants::DH_RATCHET_INFO.end())); {
                auto __wipe = SodiumInterop::SecureWipe(std::span(root_bytes));
                (void) __wipe;
            } {
                auto __wipe = SodiumInterop::SecureWipe(std::span(dh_secret));
                (void) __wipe;
            }
            if (hkdf_output_result.IsErr()) {
                {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(new_dh_private));
                    (void) __wipe;
                }
                return Result<Unit, EcliptixProtocolFailure>::Err(
                    hkdf_output_result.UnwrapErr());
            }
            auto hkdf_output = hkdf_output_result.Unwrap();
            new_root_key.assign(hkdf_output.begin(), hkdf_output.begin() + Constants::X_25519_KEY_SIZE);
            new_chain_key.assign(hkdf_output.begin() + Constants::X_25519_KEY_SIZE, hkdf_output.end()); {
                auto __wipe = SodiumInterop::SecureWipe(std::span(hkdf_output));
                (void) __wipe;
            }
            auto write_result = root_key_handle_->Write(new_root_key);
            if (write_result.IsErr()) {
                {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(new_root_key));
                    (void) __wipe;
                } {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(new_chain_key));
                    (void) __wipe;
                } {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(new_dh_private));
                    (void) __wipe;
                }
                return Result<Unit, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::FromSodiumFailure(write_result.UnwrapErr()));
            } {
                auto __wipe = SodiumInterop::SecureWipe(std::span(new_root_key));
                (void) __wipe;
            }
            if (is_sender) {
                auto update_result = sending_step_.UpdateKeysAfterDhRatchet(new_chain_key);
                if (update_result.IsErr()) {
                    {
                        auto __wipe = SodiumInterop::SecureWipe(std::span(new_chain_key));
                        (void) __wipe;
                    } {
                        auto __wipe = SodiumInterop::SecureWipe(std::span(new_dh_private));
                        (void) __wipe;
                    }
                    return update_result;
                }
                auto new_dh_handle_result = SecureMemoryHandle::Allocate(Constants::X_25519_PRIVATE_KEY_SIZE);
                if (new_dh_handle_result.IsErr()) {
                    {
                        auto __wipe = SodiumInterop::SecureWipe(std::span(new_chain_key));
                        (void) __wipe;
                    } {
                        auto __wipe = SodiumInterop::SecureWipe(std::span(new_dh_private));
                        (void) __wipe;
                    }
                    return Result<Unit, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::FromSodiumFailure(new_dh_handle_result.UnwrapErr()));
                }
                auto new_dh_handle = std::move(new_dh_handle_result).Unwrap();
                auto dh_write_result = new_dh_handle.Write(new_dh_private); {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(new_dh_private));
                    (void) __wipe;
                }
                if (dh_write_result.IsErr()) {
                    {
                        auto __wipe = SodiumInterop::SecureWipe(std::span(new_chain_key));
                        (void) __wipe;
                    }
                    return Result<Unit, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::FromSodiumFailure(dh_write_result.UnwrapErr()));
                }
                current_sending_dh_private_handle_ = std::move(new_dh_handle);
            } else {
                if (!receiving_step_.has_value()) {
                    {
                        auto __wipe = SodiumInterop::SecureWipe(std::span(new_chain_key));
                        (void) __wipe;
                    }
                    return Result<Unit, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::Generic("Receiving step not initialized"));
                }
                auto update_result = receiving_step_->UpdateKeysAfterDhRatchet(new_chain_key);
                if (update_result.IsErr()) {
                    {
                        auto __wipe = SodiumInterop::SecureWipe(std::span(new_chain_key));
                        (void) __wipe;
                    }
                    return update_result;
                }
            } {
                auto __wipe = SodiumInterop::SecureWipe(std::span(new_chain_key));
                (void) __wipe;
            }
            auto metadata_result = DeriveMetadataEncryptionKey();
            if (metadata_result.IsErr()) {
                return metadata_result;
            }
            nonce_counter_.store(ProtocolConstants::INITIAL_NONCE_COUNTER, std::memory_order_seq_cst);
            ratchet_warning_triggered_.store(false, std::memory_order_seq_cst);
            return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
        } catch (const std::exception &ex) {
            {
                auto __wipe = SodiumInterop::SecureWipe(std::span(dh_secret));
                (void) __wipe;
            } {
                auto __wipe = SodiumInterop::SecureWipe(std::span(new_root_key));
                (void) __wipe;
            } {
                auto __wipe = SodiumInterop::SecureWipe(std::span(new_chain_key));
                (void) __wipe;
            }
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Exception during DH ratchet: " + std::string(ex.what())));
        }
    }

    Result<RatchetChainKey, EcliptixProtocolFailure>
    EcliptixProtocolConnection::ProcessReceivedMessage(uint32_t received_index) {
        std::lock_guard lock(*lock_);
        auto disposed_check = CheckDisposed();
        if (disposed_check.IsErr()) {
            return Result<RatchetChainKey, EcliptixProtocolFailure>::Err(
                disposed_check.UnwrapErr());
        }
        auto expired_check = EnsureNotExpired();
        if (expired_check.IsErr()) {
            return Result<RatchetChainKey, EcliptixProtocolFailure>::Err(
                expired_check.UnwrapErr());
        }
        if (!receiving_step_) {
            return Result<RatchetChainKey, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Receiving step not initialized"));
        }
        constexpr uint32_t INDEX_OVERFLOW_BUFFER = 1000;
        if (received_index > std::numeric_limits<uint32_t>::max() - INDEX_OVERFLOW_BUFFER) {
            return Result<RatchetChainKey, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    "Received index too large: " + std::to_string(received_index)));
        }
        EcliptixProtocolChainStep &receiving_step = *receiving_step_;
        auto derived_key_result = receiving_step.GetOrDeriveKeyFor(received_index);
        if (derived_key_result.IsErr()) {
            return Result<RatchetChainKey, EcliptixProtocolFailure>::Err(
                derived_key_result.UnwrapErr());
        }
        RatchetChainKey derived_key = derived_key_result.Unwrap();
        auto set_index_result = receiving_step.SetCurrentIndex(derived_key.Index());
        if (set_index_result.IsErr()) {
            return Result<RatchetChainKey, EcliptixProtocolFailure>::Err(
                set_index_result.UnwrapErr());
        }
        PerformCleanupIfNeeded(received_index);
        return Result<RatchetChainKey, EcliptixProtocolFailure>::Ok(derived_key);
    }

    void EcliptixProtocolConnection::PerformCleanupIfNeeded(uint32_t received_index) {
        if (receiving_step_) {
            receiving_step_->PruneOldKeys();
        }
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
            if (root_key_handle_) {
                auto root_key_result = root_key_handle_->ReadBytes(Constants::X_25519_KEY_SIZE);
                if (root_key_result.IsErr()) {
                    return Result<proto::protocol::RatchetState, EcliptixProtocolFailure>::Err(
                        EcliptixProtocolFailure::FromSodiumFailure(root_key_result.UnwrapErr()));
                }
                std::vector<uint8_t> root_key_bytes = root_key_result.Unwrap();
                proto.set_root_key(root_key_bytes.data(), root_key_bytes.size()); {
                    auto __wipe = SodiumInterop::SecureWipe(std::span(root_key_bytes));
                    (void) __wipe;
                }
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
            auto root_key_alloc_result = SecureMemoryHandle::Allocate(proto.root_key().size());
            if (root_key_alloc_result.IsErr()) {
                return Result<std::unique_ptr<EcliptixProtocolConnection>, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::FromSodiumFailure(root_key_alloc_result.UnwrapErr()));
            }
            auto root_key_handle = std::move(root_key_alloc_result.Unwrap());
            auto write_result = root_key_handle.Write(std::span(
                reinterpret_cast<const uint8_t *>(proto.root_key().data()),
                proto.root_key().size()));
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
            if (!proto.peer_dh_public_key().empty()) {
                peer_dh_public_key = std::vector<uint8_t>(
                    proto.peer_dh_public_key().begin(),
                    proto.peer_dh_public_key().end());
            }
            SecureMemoryHandle initial_sending_dh_private_handle;
            std::vector<uint8_t> initial_sending_dh_public;
            SecureMemoryHandle current_sending_dh_private_handle;
            SecureMemoryHandle persistent_dh_private_handle;
            std::vector<uint8_t> persistent_dh_public;
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
                    std::move(initial_sending_dh_private_handle),
                    std::move(initial_sending_dh_public),
                    std::move(current_sending_dh_private_handle),
                    std::move(persistent_dh_private_handle),
                    std::move(persistent_dh_public),
                    proto.is_first_receiving_ratchet()
                )
            );
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
