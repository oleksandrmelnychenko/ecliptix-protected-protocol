#include <catch2/catch_test_macros.hpp>
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/sodium_secure_memory_handle.hpp"
#include "ecliptix/core/constants.hpp"
using namespace ecliptix::protocol;
using namespace ecliptix::protocol::crypto;
TEST_CASE("SodiumInterop - Initialization", "[sodium][crypto]") {
    SECTION("Initialize succeeds") {
        auto result = SodiumInterop::Initialize();
        REQUIRE(result.IsOk());
        REQUIRE(SodiumInterop::IsInitialized());
    }
    SECTION("Multiple Initialize calls are safe") {
        auto result1 = SodiumInterop::Initialize();
        auto result2 = SodiumInterop::Initialize();
        REQUIRE(result1.IsOk());
        REQUIRE(result2.IsOk());
    }
}

TEST_CASE("SodiumInterop - Secure Wipe", "[sodium][crypto][security]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Wipe empty buffer succeeds") {
        std::vector<uint8_t> buffer;
        auto result = SodiumInterop::SecureWipe(std::span<uint8_t>(buffer));
        REQUIRE(result.IsOk());
    }
    SECTION("Wipe small buffer") {
        std::vector<uint8_t> buffer(100, 0xFF);
        auto result = SodiumInterop::SecureWipe(std::span<uint8_t>(buffer));
        REQUIRE(result.IsOk());
    }
    SECTION("Wipe large buffer") {
        std::vector<uint8_t> buffer(10000, 0xFF);
        auto result = SodiumInterop::SecureWipe(std::span<uint8_t>(buffer));
        REQUIRE(result.IsOk());
    }
    SECTION("Wipe too-large buffer fails") {
        REQUIRE(SodiumInterop::MAX_BUFFER_SIZE > 0);
    }
}

TEST_CASE("SodiumInterop - Constant Time Comparison", "[sodium][crypto][security]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Equal buffers return true") {
        std::vector<uint8_t> a = {1, 2, 3, 4, 5};
        std::vector<uint8_t> b = {1, 2, 3, 4, 5};
        auto result = SodiumInterop::ConstantTimeEquals(a, b);
        REQUIRE(result.IsOk());
        REQUIRE(result.Unwrap() == true);
    }
    SECTION("Different buffers return false") {
        std::vector<uint8_t> a = {1, 2, 3, 4, 5};
        std::vector<uint8_t> b = {1, 2, 3, 4, 6};
        auto result = SodiumInterop::ConstantTimeEquals(a, b);
        REQUIRE(result.IsOk());
        REQUIRE(result.Unwrap() == false);
    }
    SECTION("Different sizes return false") {
        std::vector<uint8_t> a = {1, 2, 3, 4, 5};
        std::vector<uint8_t> b = {1, 2, 3, 4};
        auto result = SodiumInterop::ConstantTimeEquals(a, b);
        REQUIRE(result.IsOk());
        REQUIRE(result.Unwrap() == false);
    }
    SECTION("Empty buffers are equal") {
        std::vector<uint8_t> a;
        std::vector<uint8_t> b;
        auto result = SodiumInterop::ConstantTimeEquals(a, b);
        REQUIRE(result.IsOk());
        REQUIRE(result.Unwrap() == true);
    }
}

TEST_CASE("SodiumInterop - X25519 Key Generation", "[sodium][crypto][keygen]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Generate valid key pair") {
        auto result = SodiumInterop::GenerateX25519KeyPair("test");
        REQUIRE(result.IsOk());
        auto [sk_handle, pk_bytes] = std::move(result).Unwrap();
        REQUIRE(sk_handle.Size() == kX25519PrivateKeyBytes);
        REQUIRE(pk_bytes.size() == kX25519PublicKeyBytes);
        REQUIRE_FALSE(sk_handle.IsInvalid());
    }
    SECTION("Generated keys are different") {
        auto result1 = SodiumInterop::GenerateX25519KeyPair("test1");
        auto result2 = SodiumInterop::GenerateX25519KeyPair("test2");
        REQUIRE(result1.IsOk());
        REQUIRE(result2.IsOk());
        auto [sk1, pk1] = std::move(result1).Unwrap();
        auto [sk2, pk2] = std::move(result2).Unwrap();
        REQUIRE(pk1 != pk2);
    }
}

TEST_CASE("SodiumInterop - Ed25519 Key Generation", "[sodium][crypto][keygen]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Generate valid key pair") {
        auto result = SodiumInterop::GenerateEd25519KeyPair();
        REQUIRE(result.IsOk());
        auto [sk, pk] = std::move(result).Unwrap();
        REQUIRE(sk.size() == kEd25519SecretKeyBytes);
        REQUIRE(pk.size() == kEd25519PublicKeyBytes);
    }
    SECTION("Generated keys are different") {
        auto result1 = SodiumInterop::GenerateEd25519KeyPair();
        auto result2 = SodiumInterop::GenerateEd25519KeyPair();
        REQUIRE(result1.IsOk());
        REQUIRE(result2.IsOk());
        auto [sk1, pk1] = std::move(result1).Unwrap();
        auto [sk2, pk2] = std::move(result2).Unwrap();
        REQUIRE(sk1 != sk2);
        REQUIRE(pk1 != pk2);
    }
}

TEST_CASE("SodiumInterop - Random Number Generation", "[sodium][crypto][random]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("GetRandomBytes generates correct size") {
        auto bytes = SodiumInterop::GetRandomBytes(32);
        REQUIRE(bytes.size() == 32);
    }
    SECTION("GetRandomBytes generates different values") {
        auto bytes1 = SodiumInterop::GetRandomBytes(32);
        auto bytes2 = SodiumInterop::GetRandomBytes(32);
        REQUIRE(bytes1 != bytes2);
    }
    SECTION("GenerateRandomUInt32 generates values") {
        auto value1 = SodiumInterop::GenerateRandomUInt32();
        auto value2 = SodiumInterop::GenerateRandomUInt32();
        REQUIRE(value1 != value2);
    }
    SECTION("GenerateRandomUInt32 with ensure_non_zero") {
        for (int i = 0; i < 10; ++i) {
            auto value = SodiumInterop::GenerateRandomUInt32(true);
            REQUIRE(value != 0);
        }
    }
}
