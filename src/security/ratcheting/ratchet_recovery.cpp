#include "ecliptix/security/ratcheting/ratchet_recovery.hpp"
#include "ecliptix/crypto/hkdf.hpp"
#include <algorithm>

namespace ecliptix::protocol::security {
    RatchetRecovery::RatchetRecovery()
        : RatchetRecovery(ProtocolConstants::MAX_SKIP_MESSAGE_KEYS) {
    }

    RatchetRecovery::RatchetRecovery(const uint32_t max_skipped_keys)
        : max_skipped_keys_(max_skipped_keys) {
    }

    Result<Unit, ProtocolFailure> RatchetRecovery::StoreSkippedMessageKeys(
        std::span<const uint8_t> current_chain_key,
        const uint32_t from_index,
        const uint32_t to_index) {
        std::lock_guard guard(lock_);
        if (to_index <= from_index) {
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput(
                    "Invalid range: to_index must be greater than from_index"));
        }
        if (const uint32_t keys_to_add = to_index - from_index;
            skipped_message_keys_.size() + keys_to_add > max_skipped_keys_) {
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::Generic(
                    "Cannot store skipped keys: would exceed maximum limit"));
        }
        std::vector chain_key_buffer(current_chain_key.begin(), current_chain_key.end());
        for (uint32_t i = from_index; i < to_index; ++i) {
            auto msg_key_result = DeriveMessageKey(chain_key_buffer, i);
            if (msg_key_result.IsErr()) {
                return Result<Unit, ProtocolFailure>::Err(
                    std::move(msg_key_result).UnwrapErr());
            }
            skipped_message_keys_[i] = std::move(msg_key_result).Unwrap();
            if (i + 1 < to_index) {
                if (auto advance_result = AdvanceChainKey(chain_key_buffer); advance_result.IsErr()) {
                    return advance_result;
                }
            }
        }
        return Result<Unit, ProtocolFailure>::Ok(Unit{});
    }

    Result<std::optional<SecureMemoryHandle>, ProtocolFailure>
    RatchetRecovery::TryGetSkippedMessageKey(const uint32_t message_index) {
        std::lock_guard guard(lock_);
        const auto it = skipped_message_keys_.find(message_index);
        if (it == skipped_message_keys_.end()) {
            return Result<std::optional<SecureMemoryHandle>, ProtocolFailure>::Ok(
                std::nullopt);
        }
        SecureMemoryHandle key = std::move(it->second);
        skipped_message_keys_.erase(it);
        return Result<std::optional<SecureMemoryHandle>, ProtocolFailure>::Ok(
            std::make_optional(std::move(key)));
    }

    bool RatchetRecovery::HasSkippedMessageKey(const uint32_t message_index) const {
        std::lock_guard guard(lock_);
        return skipped_message_keys_.count(message_index) > ProtocolConstants::ZERO_VALUE;
    }

    size_t RatchetRecovery::GetSkippedKeyCount() const {
        std::lock_guard guard(lock_);
        return skipped_message_keys_.size();
    }

    void RatchetRecovery::CleanupOldKeys(const uint32_t min_index_to_keep) {
        std::lock_guard guard(lock_);
        auto it = skipped_message_keys_.begin();
        while (it != skipped_message_keys_.end()) {
            if (it->first < min_index_to_keep) {
                it = skipped_message_keys_.erase(it);
            } else {
                ++it;
            }
        }
    }

    void RatchetRecovery::Reset() {
        std::lock_guard guard(lock_);
        skipped_message_keys_.clear();
    }

    Result<SecureMemoryHandle, ProtocolFailure> RatchetRecovery::DeriveMessageKey(
        std::span<const uint8_t> chain_key,
        uint32_t message_index) {
        std::string info = std::string(ProtocolConstants::MSG_INFO) + "-" +
                           std::to_string(message_index);
        auto key_bytes_result = crypto::Hkdf::DeriveKeyBytes(
            chain_key,
            Constants::AES_KEY_SIZE,
            std::span<const uint8_t>{},
            std::span(
                reinterpret_cast<const uint8_t *>(info.data()),
                info.size()));
        if (key_bytes_result.IsErr()) {
            return Result<SecureMemoryHandle, ProtocolFailure>::Err(
                ProtocolFailure::DeriveKey(
                    "Failed to derive message key for ratchet recovery"));
        }
        auto key_bytes = std::move(key_bytes_result).Unwrap();
        auto handle_result = SecureMemoryHandle::Allocate(Constants::AES_KEY_SIZE);
        if (handle_result.IsErr()) {
            return Result<SecureMemoryHandle, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(
                    std::move(handle_result).UnwrapErr()));
        }
        auto handle = std::move(handle_result).Unwrap();
        if (auto write_result = handle.Write(key_bytes); write_result.IsErr()) {
            return Result<SecureMemoryHandle, ProtocolFailure>::Err(
                ProtocolFailure::FromSodiumFailure(
                    std::move(write_result).UnwrapErr()));
        }
        return Result<SecureMemoryHandle, ProtocolFailure>::Ok(
            std::move(handle));
    }

    Result<Unit, ProtocolFailure> RatchetRecovery::AdvanceChainKey(
        std::span<uint8_t> chain_key_buffer) {
        auto next_key_result = crypto::Hkdf::DeriveKeyBytes(
            chain_key_buffer,
            Constants::AES_KEY_SIZE,
            std::span<const uint8_t>{},
            std::span(
                reinterpret_cast<const uint8_t *>(ProtocolConstants::CHAIN_INFO.data()),
                ProtocolConstants::CHAIN_INFO.size()));
        if (next_key_result.IsErr()) {
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::DeriveKey(
                    "Failed to advance chain key"));
        }
        auto next_key_bytes = std::move(next_key_result).Unwrap();
        if (next_key_bytes.size() != chain_key_buffer.size()) {
            return Result<Unit, ProtocolFailure>::Err(
                ProtocolFailure::Generic(
                    "Derived chain key size mismatch"));
        }
        std::ranges::copy(next_key_bytes, chain_key_buffer.begin());
        return Result<Unit, ProtocolFailure>::Ok(Unit{});
    }
}
