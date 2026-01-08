#pragma once
#include "ecliptix/interfaces/i_key_provider.hpp"
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"
#include <map>
#include <vector>
#include <span>
#include <functional>

namespace ecliptix::protocol::test_helpers {

using protocol::Result;
using protocol::Unit;
using protocol::EcliptixProtocolFailure;
using crypto::SecureMemoryHandle;
using interfaces::IKeyProvider;

class MockKeyProvider : public IKeyProvider {
public:
    MockKeyProvider() = default;

    void SetKey(const uint32_t index, const std::span<const uint8_t> key_material) {
        auto handle_result = SecureMemoryHandle::Allocate(key_material.size());
        if (handle_result.IsErr()) {
            return;
        }
        auto handle = std::move(handle_result).Unwrap();
        const auto write_result = handle.Write(key_material);
        if (write_result.IsOk()) {
            keys_[index] = std::move(handle);
        }
    }

    [[nodiscard]] Result<Unit, EcliptixProtocolFailure> ExecuteWithKey(
        const uint32_t index,
        const std::function<Result<Unit, EcliptixProtocolFailure>(std::span<const uint8_t>)> operation) override {

        if (!keys_.contains(index)) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Mock key provider: Key index not found"));
        }

        std::vector<uint8_t> key_bytes(keys_[index].Size());
        const auto read_result = keys_[index].Read(key_bytes);
        if (read_result.IsErr()) {
            return Result<Unit, EcliptixProtocolFailure>::Err(
                EcliptixProtocolFailure::Generic("Mock key provider: Failed to read key"));
        }

        return operation(key_bytes);
    }

    void Clear() {
        keys_.clear();
    }

    [[nodiscard]] size_t KeyCount() const noexcept {
        return keys_.size();
    }

    [[nodiscard]] bool HasKey(const uint32_t index) const noexcept {
        return keys_.contains(index);
    }

    void PruneKeysBelow(const uint32_t min_index) noexcept {
        auto it = keys_.begin();
        while (it != keys_.end() && it->first < min_index) {
            it = keys_.erase(it);
        }
    }

    ~MockKeyProvider() override = default;

private:
    std::map<uint32_t, SecureMemoryHandle> keys_;
};

}
