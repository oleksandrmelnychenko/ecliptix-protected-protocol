#pragma once
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/constants.hpp"
#include "ecliptix/core/failures.hpp"
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include <unordered_map>
#include <span>
#include <mutex>
#include <optional>

namespace ecliptix::protocol::security {
    using crypto::SecureMemoryHandle;

    class RatchetRecovery {
    public:
        RatchetRecovery();

        explicit RatchetRecovery(uint32_t max_skipped_keys);

        RatchetRecovery(const RatchetRecovery &) = delete;

        RatchetRecovery &operator=(const RatchetRecovery &) = delete;

        RatchetRecovery(RatchetRecovery &&) = delete;

        RatchetRecovery &operator=(RatchetRecovery &&) = delete;

        ~RatchetRecovery() = default;

        Result<Unit, EcliptixProtocolFailure> StoreSkippedMessageKeys(
            std::span<const uint8_t> current_chain_key,
            uint32_t from_index,
            uint32_t to_index);

        Result<std::optional<SecureMemoryHandle>, EcliptixProtocolFailure>
        TryGetSkippedMessageKey(uint32_t message_index);

        bool HasSkippedMessageKey(uint32_t message_index) const;

        size_t GetSkippedKeyCount() const;

        void CleanupOldKeys(uint32_t min_index_to_keep);

        void Reset();

        uint32_t GetMaxSkippedKeys() const { return max_skipped_keys_; }

    private:
        static Result<SecureMemoryHandle, EcliptixProtocolFailure> DeriveMessageKey(
            std::span<const uint8_t> chain_key,
            uint32_t message_index);

        static Result<Unit, EcliptixProtocolFailure> AdvanceChainKey(
            std::span<uint8_t> chain_key_buffer);

        uint32_t max_skipped_keys_;
        mutable std::mutex lock_;
        std::unordered_map<uint32_t, SecureMemoryHandle> skipped_message_keys_;
    };
}
