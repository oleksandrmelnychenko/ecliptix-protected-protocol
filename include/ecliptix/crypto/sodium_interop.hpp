#pragma once
#include "ecliptix/core/result.hpp"
#include "ecliptix/core/option.hpp"
#include "ecliptix/core/failures.hpp"
#include "ecliptix/core/constants.hpp"
#include <sodium.h>
#include <span>
#include <cstddef>
#include <memory>
#include <mutex>
#include <atomic>
namespace ecliptix::protocol::crypto {
class SecureMemoryHandle;
class SodiumInterop {
public:
    static Result<Unit, SodiumFailure> Initialize();
    static bool IsInitialized() noexcept;
    static Result<Unit, SodiumFailure> SecureWipe(std::span<uint8_t> buffer);
    static Result<Unit, SodiumFailure> SecureWipe(std::span<const uint8_t> buffer);
    static Result<bool, SodiumFailure> ConstantTimeEquals(
        std::span<const uint8_t> a,
        std::span<const uint8_t> b);
    static Result<std::pair<SecureMemoryHandle, std::vector<uint8_t>>, ProtocolFailure>
    GenerateX25519KeyPair(std::string_view key_purpose);
    static Result<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, ProtocolFailure>
    GenerateEd25519KeyPair();
    static std::vector<uint8_t> GetRandomBytes(size_t size);
    static uint32_t GenerateRandomUInt32(bool ensure_non_zero = false);
    static void* AllocateSecure(size_t size) noexcept;
    static void FreeSecure(void* ptr) noexcept;
    static constexpr size_t MAX_BUFFER_SIZE = 1'000'000'000;
private:
    static inline std::atomic<bool> initialized_{false};
    static inline std::once_flag init_flag_;
    static Result<Unit, SodiumFailure> WipeSmallBuffer(std::span<uint8_t> buffer);
    static Result<Unit, SodiumFailure> WipeLargeBuffer(std::span<uint8_t> buffer);
    SodiumInterop() = delete;
    ~SodiumInterop() = delete;
    SodiumInterop(const SodiumInterop&) = delete;
    SodiumInterop& operator=(const SodiumInterop&) = delete;
};
}
