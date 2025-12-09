#include "ecliptix/protocol/chain_step/ecliptix_protocol_chain_step.hpp"
#include "ecliptix/core/constants.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/hkdf.hpp"
#include <algorithm>
#include "protocol/protocol_state.pb.h"

namespace ecliptix::protocol::chain_step {
    using crypto::SodiumInterop;
    using crypto::Hkdf;
    using proto::protocol::ChainStepState;

    namespace {
        template<typename T>
        Result<T, EcliptixProtocolFailure> ConvertSodiumResult(Result<T, SodiumFailure> &&result) {
            if (result.IsOk()) {
                return Result<T, EcliptixProtocolFailure>::Ok(std::move(result).Unwrap());
            }
            return Result<T, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Sodium operation failed"));
        }
    }

    EcliptixProtocolChainStep::EcliptixProtocolChainStep(
        const ChainStepType step_type,
        SecureMemoryHandle chain_key_handle,
        const uint32_t initial_index,
        std::optional<SecureMemoryHandle> dh_private_key_handle,
        std::optional<std::vector<uint8_t> > dh_public_key)
        : lock_(std::make_unique<std::mutex>())
          , step_type_(step_type)
          , chain_key_handle_(std::move(chain_key_handle))
          , current_index_(initial_index)
          , dh_private_key_handle_(std::move(dh_private_key_handle))
          , dh_public_key_(std::move(dh_public_key))
          , disposed_(false) {
    }

    EcliptixProtocolChainStep::~EcliptixProtocolChainStep() {
        if (lock_) {
            std::lock_guard guard(*lock_);
            disposed_ = true;
            if (dh_public_key_.has_value()) {
                SodiumInterop::SecureWipe(std::span(*dh_public_key_));
            }
        }
    }

    Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> EcliptixProtocolChainStep::Create(
        ChainStepType step_type,
        std::span<const uint8_t> initial_chain_key,
        std::optional<std::span<const uint8_t> > dh_private_key,
        std::optional<std::span<const uint8_t> > dh_public_key) {
        if (auto validate_result = ValidateChainKey(initial_chain_key); validate_result.IsErr()) {
            return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Err(validate_result.UnwrapErr());
        }
        auto chain_key_result = ConvertSodiumResult(SecureMemoryHandle::Allocate(Constants::X_25519_KEY_SIZE));
        if (chain_key_result.IsErr()) {
            return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Err(chain_key_result.UnwrapErr());
        }
        auto chain_key_handle = std::move(chain_key_result).Unwrap();
        if (auto write_result = chain_key_handle.Write(initial_chain_key); write_result.IsErr()) {
            return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Failed to write chain key to secure memory"));
        }
        std::optional<SecureMemoryHandle> dh_private_key_handle;
        if (dh_private_key.has_value()) {
            if (dh_private_key->size() != Constants::X_25519_PRIVATE_KEY_SIZE) {
                return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::InvalidInput("DH private key must be 32 bytes"));
            }
            auto dh_sk_result = ConvertSodiumResult(SecureMemoryHandle::Allocate(Constants::X_25519_PRIVATE_KEY_SIZE));
            if (dh_sk_result.IsErr()) {
                return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Err(dh_sk_result.UnwrapErr());
            }
            auto dh_sk_handle = std::move(dh_sk_result).Unwrap();
            if (auto dh_write_result = dh_sk_handle.Write(*dh_private_key); dh_write_result.IsErr()) {
                return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Failed to write DH private key to secure memory"));
            }
            dh_private_key_handle = std::move(dh_sk_handle);
        }
        std::optional<std::vector<uint8_t> > dh_public_key_copy;
        if (dh_public_key.has_value()) {
            if (dh_public_key->size() != Constants::X_25519_PUBLIC_KEY_SIZE) {
                return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::InvalidInput("DH public key must be 32 bytes"));
            }
            dh_public_key_copy = std::vector(dh_public_key->begin(), dh_public_key->end());
        }
        return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Ok(
            EcliptixProtocolChainStep(
                step_type,
                std::move(chain_key_handle),
                ProtocolConstants::INITIAL_INDEX,
                std::move(dh_private_key_handle),
                std::move(dh_public_key_copy)
            )
        );
    }

    Result<EcliptixProtocolChainStep, EcliptixProtocolFailure> EcliptixProtocolChainStep::FromProtoState(
        ChainStepType step_type,
        const ChainStepState &proto) {
        if (proto.chain_key().size() != Constants::X_25519_KEY_SIZE) {
            return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Invalid chain key size in protobuf state"));
        }
        std::vector<uint8_t> chain_key_bytes(proto.chain_key().begin(), proto.chain_key().end());
        std::optional<std::span<const uint8_t> > dh_private_key;
        std::vector<uint8_t> dh_private_key_bytes;
        if (!proto.dh_private_key().empty()) {
            if (proto.dh_private_key().size() != Constants::X_25519_PRIVATE_KEY_SIZE) {
                SodiumInterop::SecureWipe(std::span(chain_key_bytes));
                return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::InvalidInput("Invalid DH private key size in protobuf state"));
            }
            dh_private_key_bytes = std::vector<uint8_t>(proto.dh_private_key().begin(), proto.dh_private_key().end());
            dh_private_key = std::span<const uint8_t>(dh_private_key_bytes);
        }
        std::optional<std::span<const uint8_t> > dh_public_key;
        std::vector<uint8_t> dh_public_key_bytes;
        if (!proto.dh_public_key().empty()) {
            if (proto.dh_public_key().size() != Constants::X_25519_PUBLIC_KEY_SIZE) {
                SodiumInterop::SecureWipe(std::span(chain_key_bytes));
                if (!dh_private_key_bytes.empty()) {
                    SodiumInterop::SecureWipe(std::span(dh_private_key_bytes));
                }
                return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::InvalidInput("Invalid DH public key size in protobuf state"));
            }
            dh_public_key_bytes = std::vector<uint8_t>(proto.dh_public_key().begin(), proto.dh_public_key().end());
            dh_public_key = std::span<const uint8_t>(dh_public_key_bytes);
        }
        auto result = Create(step_type, chain_key_bytes, dh_private_key, dh_public_key);
        SodiumInterop::SecureWipe(std::span(chain_key_bytes));
        if (!dh_private_key_bytes.empty()) {
            SodiumInterop::SecureWipe(std::span(dh_private_key_bytes));
        }
        if (result.IsErr()) {
            return result;
        }
        auto chain_step = std::move(result).Unwrap();
        if (auto set_index_result = chain_step.SetCurrentIndex(proto.current_index()); set_index_result.IsErr()) {
            return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Err(set_index_result.UnwrapErr());
        }
        return Result<EcliptixProtocolChainStep, EcliptixProtocolFailure>::Ok(std::move(chain_step));
    }

    Result<Unit, EcliptixProtocolFailure> EcliptixProtocolChainStep::DeriveNextChainKeys(
        const std::span<const uint8_t> current_chain_key,
        const std::span<uint8_t> next_chain_key,
        const std::span<uint8_t> message_key) {
        if (current_chain_key.size() != Constants::X_25519_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Chain key must be 32 bytes"));
        }
        if (next_chain_key.size() != Constants::X_25519_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Next chain key buffer must be 32 bytes"));
        }
        if (message_key.size() != Constants::X_25519_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Message key buffer must be 32 bytes"));
        }
        TRY_UNIT(Hkdf::DeriveKey(
            current_chain_key,
            message_key,
            {},
            std::span(
                reinterpret_cast<const uint8_t*>(ProtocolConstants::MSG_INFO.data()),
                ProtocolConstants::MSG_INFO.size()
            )
        ));
        TRY_UNIT(Hkdf::DeriveKey(
            current_chain_key,
            next_chain_key,
            {},
            std::span(
                reinterpret_cast<const uint8_t*>(ProtocolConstants::CHAIN_INFO.data()),
                ProtocolConstants::CHAIN_INFO.size()
            )
        ));
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Result<Unit, EcliptixProtocolFailure> EcliptixProtocolChainStep::ExecuteWithKey(
        uint32_t index,
        std::function<Result<Unit, EcliptixProtocolFailure>(std::span<const uint8_t>)> operation) {
        std::lock_guard guard(*lock_);
        TRY_UNIT(CheckDisposed());
        if (auto cached_key_opt = TakeCachedMessageKey(index); cached_key_opt.has_value()) {
            SecureMemoryHandle cached_handle = std::move(*cached_key_opt);
            auto key_bytes_result = ConvertSodiumResult(cached_handle.ReadBytes(Constants::X_25519_KEY_SIZE));
            if (key_bytes_result.IsErr()) {
                return Result<Unit, EcliptixProtocolFailure>::Err(key_bytes_result.UnwrapErr());
            }
            auto key_bytes = std::move(key_bytes_result).Unwrap();
            auto result = operation(key_bytes);
            SodiumInterop::SecureWipe(std::span(key_bytes));
            return result;
        }
        if (index == current_index_) {
            auto chain_key_result = ConvertSodiumResult(chain_key_handle_.ReadBytes(Constants::X_25519_KEY_SIZE));
            if (chain_key_result.IsErr()) {
                return Result<Unit, EcliptixProtocolFailure>::Err(chain_key_result.UnwrapErr());
            }
            auto current_chain_key = std::move(chain_key_result).Unwrap();
            std::vector<uint8_t> message_key(Constants::X_25519_KEY_SIZE);
            std::vector<uint8_t> next_chain_key(Constants::X_25519_KEY_SIZE);
            auto derive_result = DeriveNextChainKeys(
                current_chain_key,
                next_chain_key,
                message_key
            );
            SodiumInterop::SecureWipe(std::span(current_chain_key));
            if (derive_result.IsErr()) {
                SodiumInterop::SecureWipe(std::span(next_chain_key));
                SodiumInterop::SecureWipe(std::span(message_key));
                return derive_result;
            }
            auto write_result = chain_key_handle_.Write(next_chain_key);
            SodiumInterop::SecureWipe(std::span(next_chain_key));
            if (write_result.IsErr()) {
                SodiumInterop::SecureWipe(std::span(message_key));
                return Result<Unit, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Failed to update chain key"));
            }
            current_index_++;
            auto result = operation(message_key);
            SodiumInterop::SecureWipe(std::span(message_key));
            return result;
        }
        if (index > current_index_) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Cannot access future key - call SkipKeysUntil first"));
        }
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic("Key not available - already used or pruned"));
    }

    Result<RatchetChainKey, EcliptixProtocolFailure>
    EcliptixProtocolChainStep::GetOrDeriveKeyFor(const uint32_t index) {
        std::lock_guard guard(*lock_);
        if (auto disposed_check = CheckDisposed(); disposed_check.IsErr()) {
            return Result<RatchetChainKey, EcliptixProtocolFailure>::Err(disposed_check.UnwrapErr());
        }
        if (index >= ProtocolConstants::MAX_CHAIN_LENGTH) {
            return Result<RatchetChainKey, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic(
                    "Chain length exceeded maximum - DH ratchet required (index: " +
                    std::to_string(index) + ", max: " + std::to_string(ProtocolConstants::MAX_CHAIN_LENGTH) + ")"));
        }
        if (index > current_index_) {
            if (auto skip_result = SkipKeysUntil(index); skip_result.IsErr()) {
                return Result<RatchetChainKey, EcliptixProtocolFailure>::Err(skip_result.UnwrapErr());
            }
        }
        return Result<RatchetChainKey, EcliptixProtocolFailure>::Ok(
            RatchetChainKey(this, index)
        );
    }

    Result<std::vector<uint8_t>, EcliptixProtocolFailure> EcliptixProtocolChainStep::GetCurrentChainKey() const {
        std::lock_guard guard(*lock_);
        if (auto disposed_check = CheckDisposed(); disposed_check.IsErr()) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(disposed_check.UnwrapErr());
        }
        auto bytes_result = ConvertSodiumResult(chain_key_handle_.ReadBytes(Constants::X_25519_KEY_SIZE));
        if (bytes_result.IsErr()) {
            return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Err(bytes_result.UnwrapErr());
        }
        return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Ok(std::move(bytes_result).Unwrap());
    }

    Result<uint32_t, EcliptixProtocolFailure> EcliptixProtocolChainStep::GetCurrentIndex() const {
        std::lock_guard guard(*lock_);
        if (auto disposed_check = CheckDisposed(); disposed_check.IsErr()) {
            return Result<uint32_t, EcliptixProtocolFailure>::Err(disposed_check.UnwrapErr());
        }
        return Result<uint32_t, EcliptixProtocolFailure>::Ok(current_index_);
    }

    Result<Unit, EcliptixProtocolFailure> EcliptixProtocolChainStep::SetCurrentIndex(const uint32_t new_index) {
        std::lock_guard guard(*lock_);
        if (auto disposed_check = CheckDisposed(); disposed_check.IsErr()) {
            return disposed_check;
        }
        current_index_ = new_index;
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Result<Unit, EcliptixProtocolFailure> EcliptixProtocolChainStep::SkipKeysUntil(uint32_t target_index) {
        if (target_index <= current_index_) {
            return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
        }
        if (uint32_t skip_count = target_index - current_index_;
            skip_count > ProtocolConstants::MAX_SKIP_MESSAGE_KEYS) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Skip gap too large - possible DoS attempt"));
        }
        auto chain_key_result = ConvertSodiumResult(chain_key_handle_.ReadBytes(Constants::X_25519_KEY_SIZE));
        if (chain_key_result.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(chain_key_result.UnwrapErr());
        }
        auto mut_chain_key = std::move(chain_key_result).Unwrap();
        for (uint32_t i = current_index_ + 1; i < target_index; ++i) {
            std::vector<uint8_t> message_key(Constants::X_25519_KEY_SIZE);
            std::vector<uint8_t> next_chain_key(Constants::X_25519_KEY_SIZE);
            if (auto derive_result = DeriveNextChainKeys(mut_chain_key, next_chain_key, message_key); derive_result.
                IsErr()) {
                SodiumInterop::SecureWipe(std::span(mut_chain_key));
                SodiumInterop::SecureWipe(std::span(message_key));
                SodiumInterop::SecureWipe(std::span(next_chain_key));
                return derive_result;
            }
            auto store_result = StoreMessageKey(i, message_key);
            SodiumInterop::SecureWipe(std::span(message_key));
            if (store_result.IsErr()) {
                SodiumInterop::SecureWipe(std::span(mut_chain_key));
                SodiumInterop::SecureWipe(std::span(next_chain_key));
                return store_result;
            }
            mut_chain_key = std::move(next_chain_key);
        }
        auto write_result = chain_key_handle_.Write(mut_chain_key);
        SodiumInterop::SecureWipe(std::span(mut_chain_key));
        if (write_result.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Failed to update chain key after skip"));
        }
        current_index_ = target_index;
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    void EcliptixProtocolChainStep::PruneOldKeys() {
        std::lock_guard guard(*lock_);
        if (disposed_) {
            return;
        }
        if (cached_message_keys_.size() <= ProtocolConstants::MESSAGE_KEY_CACHE_WINDOW) {
            return;
        }
        const uint32_t cutoff_index = current_index_ > ProtocolConstants::MESSAGE_KEY_CACHE_WINDOW
                                          ? current_index_ - ProtocolConstants::MESSAGE_KEY_CACHE_WINDOW
                                          : 0;
        auto it = cached_message_keys_.begin();
        while (it != cached_message_keys_.end() && it->first < cutoff_index) {
            it = cached_message_keys_.erase(it);
        }
    }

    Result<Unit, EcliptixProtocolFailure> EcliptixProtocolChainStep::UpdateKeysAfterDhRatchet(
        std::span<const uint8_t> new_chain_key,
        std::optional<std::span<const uint8_t> > new_dh_private_key,
        std::optional<std::span<const uint8_t> > new_dh_public_key) {
        std::lock_guard guard(*lock_);
        if (auto disposed_check = CheckDisposed(); disposed_check.IsErr()) {
            return disposed_check;
        }
        if (auto validate_result = ValidateChainKey(new_chain_key); validate_result.IsErr()) {
            return validate_result;
        }
        if (auto write_result = chain_key_handle_.Write(new_chain_key); write_result.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Failed to write new chain key"));
        }
        current_index_ = ProtocolConstants::RESET_INDEX;
        cached_message_keys_.clear();
        if (new_dh_private_key.has_value()) {
            if (new_dh_private_key->size() != Constants::X_25519_PRIVATE_KEY_SIZE) {
                return Result<Unit, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::InvalidInput("DH private key must be 32 bytes"));
            }
            auto handle_result = ConvertSodiumResult(SecureMemoryHandle::Allocate(Constants::X_25519_PRIVATE_KEY_SIZE));
            if (handle_result.IsErr()) {
                return Result<Unit, EcliptixProtocolFailure>::Err(handle_result.UnwrapErr());
            }
            auto new_handle = std::move(handle_result).Unwrap();
            if (auto new_write_result = new_handle.Write(*new_dh_private_key); new_write_result.IsErr()) {
                return Result<Unit, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Failed to write new DH private key"));
            }
            dh_private_key_handle_ = std::move(new_handle);
        }
        if (new_dh_public_key.has_value()) {
            if (new_dh_public_key->size() != Constants::X_25519_PUBLIC_KEY_SIZE) {
                return Result<Unit, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::InvalidInput("DH public key must be 32 bytes"));
            }
            if (dh_public_key_.has_value()) {
                SodiumInterop::SecureWipe(std::span(*dh_public_key_));
            }
            dh_public_key_ = std::vector(new_dh_public_key->begin(), new_dh_public_key->end());
        }
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Result<Option<std::vector<uint8_t> >, EcliptixProtocolFailure> EcliptixProtocolChainStep::ReadDhPublicKey() const {
        std::lock_guard guard(*lock_);
        if (auto disposed_check = CheckDisposed(); disposed_check.IsErr()) {
            return Result<Option<std::vector<uint8_t> >, EcliptixProtocolFailure>::Err(disposed_check.UnwrapErr());
        }
        if (!dh_public_key_.has_value()) {
            return Result<Option<std::vector<uint8_t> >, EcliptixProtocolFailure>::Ok(std::nullopt);
        }
        std::vector copy(*dh_public_key_);
        return Result<Option<std::vector<uint8_t> >, EcliptixProtocolFailure>::Ok(std::move(copy));
    }

    Option<const SecureMemoryHandle *> EcliptixProtocolChainStep::GetDhPrivateKeyHandle() const {
        std::lock_guard guard(*lock_);
        if (disposed_ || !dh_private_key_handle_.has_value()) {
            return std::nullopt;
        }
        return &*dh_private_key_handle_;
    }

    Result<ChainStepState, EcliptixProtocolFailure> EcliptixProtocolChainStep::ToProtoState() const {
        std::lock_guard guard(*lock_);
        if (auto disposed_check = CheckDisposed(); disposed_check.IsErr()) {
            return Result<ChainStepState, EcliptixProtocolFailure>::Err(disposed_check.UnwrapErr());
        }
        ChainStepState proto;
        proto.set_current_index(current_index_);
        auto chain_key_result = chain_key_handle_.ReadBytes(Constants::X_25519_KEY_SIZE);
        if (chain_key_result.IsErr()) {
            return Result<ChainStepState, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Failed to read chain key for serialization"));
        }
        auto chain_key_bytes = chain_key_result.Unwrap();
        proto.set_chain_key(chain_key_bytes.data(), chain_key_bytes.size());
        SodiumInterop::SecureWipe(std::span(chain_key_bytes));
        if (dh_private_key_handle_.has_value()) {
            auto dh_sk_result = dh_private_key_handle_->ReadBytes(Constants::X_25519_PRIVATE_KEY_SIZE);
            if (dh_sk_result.IsErr()) {
                return Result<ChainStepState, EcliptixProtocolFailure>::Err(
                    EcliptixProtocolFailure::Generic("Failed to read DH private key for serialization"));
            }
            auto dh_sk_bytes = dh_sk_result.Unwrap();
            proto.set_dh_private_key(dh_sk_bytes.data(), dh_sk_bytes.size());
            SodiumInterop::SecureWipe(std::span(dh_sk_bytes));
        }
        if (dh_public_key_.has_value()) {
            proto.set_dh_public_key(dh_public_key_->data(), dh_public_key_->size());
        }
        return Result<ChainStepState, EcliptixProtocolFailure>::Ok(std::move(proto));
    }

    Result<Unit, EcliptixProtocolFailure> EcliptixProtocolChainStep::StoreMessageKey(
        const uint32_t index,
        const std::span<const uint8_t> message_key) {
        auto handle_result = ConvertSodiumResult(SecureMemoryHandle::Allocate(Constants::X_25519_KEY_SIZE));
        if (handle_result.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(handle_result.UnwrapErr());
        }
        auto handle = std::move(handle_result).Unwrap();
        if (const auto store_write_result = handle.Write(message_key); store_write_result.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Failed to store message key in cache"));
        }
        cached_message_keys_[index] = std::move(handle);
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Option<SecureMemoryHandle> EcliptixProtocolChainStep::TakeCachedMessageKey(const uint32_t index) {
        const auto it = cached_message_keys_.find(index);
        if (it == cached_message_keys_.end()) {
            return std::nullopt;
        }
        SecureMemoryHandle handle = std::move(it->second);
        cached_message_keys_.erase(it);
        return std::move(handle);
    }

    Result<Unit, EcliptixProtocolFailure> EcliptixProtocolChainStep::CheckDisposed() const {
        if (disposed_) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("ChainStep has been disposed"));
        }
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }

    Result<Unit, EcliptixProtocolFailure> EcliptixProtocolChainStep::ValidateChainKey(
        const std::span<const uint8_t> chain_key) {
        if (chain_key.size() != Constants::X_25519_KEY_SIZE) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::InvalidInput("Chain key must be 32 bytes"));
        }
        return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
    }
}
