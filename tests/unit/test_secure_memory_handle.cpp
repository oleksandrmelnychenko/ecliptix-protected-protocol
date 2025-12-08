#include <catch2/catch_test_macros.hpp>
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/core/constants.hpp"
using namespace ecliptix::protocol;
using namespace ecliptix::protocol::crypto;
TEST_CASE("SecureMemoryHandle - Allocation", "[crypto][memory]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Allocate valid size") {
        auto result = SecureMemoryHandle::Allocate(32);
        REQUIRE(result.IsOk());
        auto handle = std::move(result).Unwrap();
        REQUIRE_FALSE(handle.IsInvalid());
        REQUIRE(handle.Size() == 32);
    }
    SECTION("Cannot allocate zero bytes") {
        auto result = SecureMemoryHandle::Allocate(0);
        REQUIRE(result.IsErr());
    }
    SECTION("Multiple allocations succeed") {
        auto result1 = SecureMemoryHandle::Allocate(32);
        auto result2 = SecureMemoryHandle::Allocate(64);
        REQUIRE(result1.IsOk());
        REQUIRE(result2.IsOk());
    }
}
TEST_CASE("SecureMemoryHandle - Move Semantics", "[crypto][memory]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Move construction transfers ownership") {
        auto handle1 = SecureMemoryHandle::Allocate(32).Unwrap();
        auto size = handle1.Size();
        SecureMemoryHandle handle2(std::move(handle1));
        REQUIRE(handle1.IsInvalid());  
        REQUIRE_FALSE(handle2.IsInvalid());
        REQUIRE(handle2.Size() == size);
    }
    SECTION("Move assignment transfers ownership") {
        auto handle1 = SecureMemoryHandle::Allocate(32).Unwrap();
        auto handle2 = SecureMemoryHandle::Allocate(64).Unwrap();
        auto size1 = handle1.Size();
        handle2 = std::move(handle1);
        REQUIRE(handle1.IsInvalid());
        REQUIRE_FALSE(handle2.IsInvalid());
        REQUIRE(handle2.Size() == size1);
    }
}
TEST_CASE("SecureMemoryHandle - Write Operations", "[crypto][memory]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Write data successfully") {
        auto handle = SecureMemoryHandle::Allocate(32).Unwrap();
        std::vector<uint8_t> data(32, 0x42);
        auto result = handle.Write(data);
        REQUIRE(result.IsOk());
    }
    SECTION("Write data smaller than buffer") {
        auto handle = SecureMemoryHandle::Allocate(64).Unwrap();
        std::vector<uint8_t> data(32, 0x42);
        auto result = handle.Write(data);
        REQUIRE(result.IsOk());
    }
    SECTION("Write data larger than buffer fails") {
        auto handle = SecureMemoryHandle::Allocate(16).Unwrap();
        std::vector<uint8_t> data(32, 0x42);
        auto result = handle.Write(data);
        REQUIRE(result.IsErr());
    }
    SECTION("Write to invalid handle fails") {
        auto handle = SecureMemoryHandle::Allocate(32).Unwrap();
        auto moved = std::move(handle);
        std::vector<uint8_t> data(32, 0x42);
        auto result = handle.Write(data);  
        REQUIRE(result.IsErr());
    }
}
TEST_CASE("SecureMemoryHandle - Read Operations", "[crypto][memory]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Read data successfully") {
        auto handle = SecureMemoryHandle::Allocate(32).Unwrap();
        std::vector<uint8_t> write_data(32, 0x42);
        REQUIRE(handle.Write(write_data).IsOk());
        std::vector<uint8_t> read_data(32);
        auto result = handle.Read(read_data);
        REQUIRE(result.IsOk());
        REQUIRE(read_data == write_data);
    }
    SECTION("Read into too-small buffer fails") {
        auto handle = SecureMemoryHandle::Allocate(32).Unwrap();
        std::vector<uint8_t> buffer(16);
        auto result = handle.Read(buffer);
        REQUIRE(result.IsErr());
    }
    SECTION("ReadBytes returns vector") {
        auto handle = SecureMemoryHandle::Allocate(32).Unwrap();
        std::vector<uint8_t> write_data(32, 0x42);
        REQUIRE(handle.Write(write_data).IsOk());
        auto result = handle.ReadBytes(32);
        REQUIRE(result.IsOk());
        auto read_data = std::move(result).Unwrap();
        REQUIRE(read_data == write_data);
    }
    SECTION("ReadBytes with too-large size fails") {
        auto handle = SecureMemoryHandle::Allocate(32).Unwrap();
        auto result = handle.ReadBytes(64);
        REQUIRE(result.IsErr());
    }
}
TEST_CASE("SecureMemoryHandle - WithReadAccess", "[crypto][memory]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Read access provides correct span") {
        auto handle = SecureMemoryHandle::Allocate(32).Unwrap();
        std::vector<uint8_t> data(32, 0x42);
        REQUIRE(handle.Write(data).IsOk());
        auto result = handle.WithReadAccess([&](std::span<const uint8_t> span) {
            REQUIRE(span.size() == 32);
            REQUIRE(std::all_of(span.begin(), span.end(),
                [](uint8_t b) { return b == 0x42; }));
            return 42;
        });
        REQUIRE(result.IsOk());
        REQUIRE(result.Unwrap() == 42);
    }
}
TEST_CASE("SecureMemoryHandle - WithWriteAccess", "[crypto][memory]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Write access allows modification") {
        auto handle = SecureMemoryHandle::Allocate(32).Unwrap();
        auto result = handle.WithWriteAccess([](std::span<uint8_t> span) {
            std::fill(span.begin(), span.end(), 0xFF);
            return unit;
        });
        REQUIRE(result.IsOk());
        std::vector<uint8_t> read_data(32);
        REQUIRE(handle.Read(read_data).IsOk());
        REQUIRE(std::all_of(read_data.begin(), read_data.end(),
            [](uint8_t b) { return b == 0xFF; }));
    }
}
TEST_CASE("SecureMemoryHandle - RAII", "[crypto][memory]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Handle is freed on scope exit") {
        {
            auto handle = SecureMemoryHandle::Allocate(32).Unwrap();
            REQUIRE_FALSE(handle.IsInvalid());
        }
    }
}
