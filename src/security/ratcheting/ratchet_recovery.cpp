#include "ecliptix/security/ratcheting/ratchet_recovery.hpp"
#include "ecliptix/crypto/hkdf.hpp"
#include <algorithm>

namespace ecliptix::protocol::security {

RatchetRecovery::RatchetRecovery()
    : RatchetRecovery(ProtocolConstants::MAX_SKIP_MESSAGE_KEYS)
{
}

RatchetRecovery::RatchetRecovery(uint32_t max_skipped_keys)
    : max_skipped_keys_(max_skipped_keys)
{
}

Result<Unit, EcliptixProtocolFailure> RatchetRecovery::StoreSkippedMessageKeys(
    std::span<const uint8_t> current_chain_key,
    uint32_t from_index,
    uint32_t to_index) {

    std::lock_guard<std::mutex> guard(lock_);

    // Validate indices
    if (to_index <= from_index) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::InvalidInput(
                "Invalid range: to_index must be greater than from_index"));
    }

    // Check if storing these keys would exceed limit
    uint32_t keys_to_add = to_index - from_index;
    if (skipped_message_keys_.size() + keys_to_add > max_skipped_keys_) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(
                "Cannot store skipped keys: would exceed maximum limit"));
    }

    // Create a working buffer for chain key advancement
    std::vector<uint8_t> chain_key_buffer(current_chain_key.begin(), current_chain_key.end());

    // Derive and store message keys for each skipped index
    for (uint32_t i = from_index; i < to_index; ++i) {
        // Derive message key from current chain key
        auto msg_key_result = DeriveMessageKey(chain_key_buffer, i);
        if (msg_key_result.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                std::move(msg_key_result).UnwrapErr());
        }

        // Store the message key
        skipped_message_keys_[i] = std::move(msg_key_result).Unwrap();

        // Advance chain key for next iteration
        if (i + 1 < to_index) {  // Don't advance after last key
            auto advance_result = AdvanceChainKey(chain_key_buffer);
            if (advance_result.IsErr()) {
                return advance_result;
            }
        }
    }

    return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
}

Result<std::optional<SecureMemoryHandle>, EcliptixProtocolFailure>
    RatchetRecovery::TryGetSkippedMessageKey(uint32_t message_index) {

    std::lock_guard<std::mutex> guard(lock_);

    auto it = skipped_message_keys_.find(message_index);
    if (it == skipped_message_keys_.end()) {
        // Key not found - not an error, just not cached
        return Result<std::optional<SecureMemoryHandle>, EcliptixProtocolFailure>::Ok(
            std::nullopt);
    }

    // Extract and remove the key (one-time use)
    SecureMemoryHandle key = std::move(it->second);
    skipped_message_keys_.erase(it);

    return Result<std::optional<SecureMemoryHandle>, EcliptixProtocolFailure>::Ok(
        std::make_optional(std::move(key)));
}

bool RatchetRecovery::HasSkippedMessageKey(uint32_t message_index) const {
    std::lock_guard<std::mutex> guard(lock_);
    return skipped_message_keys_.count(message_index) > 0;
}

size_t RatchetRecovery::GetSkippedKeyCount() const {
    std::lock_guard<std::mutex> guard(lock_);
    return skipped_message_keys_.size();
}

void RatchetRecovery::CleanupOldKeys(uint32_t min_index_to_keep) {
    std::lock_guard<std::mutex> guard(lock_);

    // Remove all keys below minimum index
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
    std::lock_guard<std::mutex> guard(lock_);
    skipped_message_keys_.clear();
}

Result<SecureMemoryHandle, EcliptixProtocolFailure> RatchetRecovery::DeriveMessageKey(
    std::span<const uint8_t> chain_key,
    uint32_t message_index) {

    // Use HKDF to derive message key
    // Domain separation via info string includes message index
    std::string info = std::string(ProtocolConstants::MSG_INFO) + "-" +
                      std::to_string(message_index);

    auto key_bytes_result = crypto::Hkdf::DeriveKeyBytes(
        chain_key,
        Constants::AES_KEY_SIZE,
        std::span<const uint8_t>{},  // No salt
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(info.data()),
            info.size()));

    if (key_bytes_result.IsErr()) {
        return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::DeriveKey(
                "Failed to derive message key for ratchet recovery"));
    }

    auto key_bytes = std::move(key_bytes_result).Unwrap();

    // Allocate secure memory
    auto handle_result = SecureMemoryHandle::Allocate(Constants::AES_KEY_SIZE);
    if (handle_result.IsErr()) {
        return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::FromSodiumFailure(
                std::move(handle_result).UnwrapErr()));
    }

    auto handle = std::move(handle_result).Unwrap();

    // Write key to secure memory
    auto write_result = handle.Write(key_bytes);
    if (write_result.IsErr()) {
        return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::FromSodiumFailure(
                std::move(write_result).UnwrapErr()));
    }

    return Result<SecureMemoryHandle, EcliptixProtocolFailure>::Ok(
        std::move(handle));
}

Result<Unit, EcliptixProtocolFailure> RatchetRecovery::AdvanceChainKey(
    std::span<uint8_t> chain_key_buffer) {

    // Derive next chain key using HKDF
    auto next_key_result = crypto::Hkdf::DeriveKeyBytes(
        chain_key_buffer,
        Constants::AES_KEY_SIZE,
        std::span<const uint8_t>{},  // No salt
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(ProtocolConstants::CHAIN_INFO.data()),
            ProtocolConstants::CHAIN_INFO.size()));

    if (next_key_result.IsErr()) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::DeriveKey(
                "Failed to advance chain key"));
    }

    // Copy new key into buffer
    auto next_key_bytes = std::move(next_key_result).Unwrap();
    if (next_key_bytes.size() != chain_key_buffer.size()) {
        return Result<Unit, EcliptixProtocolFailure>::Err(
            EcliptixProtocolFailure::Generic(
                "Derived chain key size mismatch"));
    }

    std::copy(next_key_bytes.begin(), next_key_bytes.end(), chain_key_buffer.begin());

    return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
}

} // namespace ecliptix::protocol::security
