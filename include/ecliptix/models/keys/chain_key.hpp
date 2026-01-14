#pragma once
#include "ecliptix/interfaces/i_key_provider.hpp"
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/failures.hpp"
#include <cstdint>
#include <functional>
#include <span>
namespace ecliptix::protocol::models {
using protocol::Result;
using protocol::Unit;
using protocol::ProtocolFailure;
using interfaces::IKeyProvider;
class ChainKey {
public:
    ChainKey(IKeyProvider* provider, const uint32_t index) noexcept
        : provider_(provider), index_(index) {}
    [[nodiscard]] uint32_t Index() const noexcept {
        return index_;
    }
    template<typename T>
    [[nodiscard]] Result<T, ProtocolFailure> WithKeyMaterial(
        std::function<Result<T, ProtocolFailure>(std::span<const uint8_t>)> operation) const {
        if (provider_ == nullptr) {
            return Result<T, ProtocolFailure>::Err(
                ProtocolFailure::Generic("Key provider is null"));
        }
        return provider_->ExecuteWithKeyTyped<T>(index_, operation);
    }
    [[nodiscard]] bool operator==(const ChainKey& other) const noexcept {
        return index_ == other.index_;
    }
    [[nodiscard]] bool operator!=(const ChainKey& other) const noexcept {
        return !(*this == other);
    }
    [[nodiscard]] bool operator<(const ChainKey& other) const noexcept {
        return index_ < other.index_;
    }
    ChainKey(const ChainKey&) = default;
    ChainKey& operator=(const ChainKey&) = default;
    ChainKey(ChainKey&&) noexcept = default;
    ChainKey& operator=(ChainKey&&) noexcept = default;
    ~ChainKey() = default;
private:
    IKeyProvider* provider_;
    uint32_t index_;
};
} 
