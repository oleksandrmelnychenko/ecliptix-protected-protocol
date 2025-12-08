#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_vector.hpp>
#include "ecliptix/protocol/chain_step/ecliptix_protocol_chain_step.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/core/constants.hpp"
using namespace ecliptix::protocol;
using namespace ecliptix::protocol::chain_step;
using namespace ecliptix::protocol::crypto;
using namespace ecliptix::protocol::enums;
TEST_CASE("EcliptixProtocolChainStep - Basic creation and initialization", "[chain_step]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Create SENDER chain with valid chain key") {
        std::vector<uint8_t> chain_key(Constants::X_25519_KEY_SIZE, 0x42);
        auto result = EcliptixProtocolChainStep::Create(
            ChainStepType::SENDER,
            chain_key,
            std::nullopt,
            std::nullopt
        );
        REQUIRE(result.IsOk());
        auto chain_step = std::move(result).Unwrap();
        auto index_result = chain_step.GetCurrentIndex();
        REQUIRE(index_result.IsOk());
        REQUIRE(index_result.Unwrap() == 0);
    }
    SECTION("Create RECEIVER chain with valid chain key") {
        std::vector<uint8_t> chain_key(Constants::X_25519_KEY_SIZE, 0x43);
        auto result = EcliptixProtocolChainStep::Create(
            ChainStepType::RECEIVER,
            chain_key,
            std::nullopt,
            std::nullopt
        );
        REQUIRE(result.IsOk());
        auto chain_step = std::move(result).Unwrap();
        auto index_result = chain_step.GetCurrentIndex();
        REQUIRE(index_result.IsOk());
        REQUIRE(index_result.Unwrap() == 0);
    }
    SECTION("Reject invalid chain key size") {
        std::vector<uint8_t> invalid_key(16, 0x44); 
        auto result = EcliptixProtocolChainStep::Create(
            ChainStepType::SENDER,
            invalid_key,
            std::nullopt,
            std::nullopt
        );
        REQUIRE(result.IsErr());
    }
    SECTION("Create with DH keys") {
        std::vector<uint8_t> chain_key(Constants::X_25519_KEY_SIZE, 0x45);
        std::vector<uint8_t> dh_private(Constants::X_25519_PRIVATE_KEY_SIZE, 0x46);
        std::vector<uint8_t> dh_public(Constants::X_25519_PUBLIC_KEY_SIZE, 0x47);
        auto result = EcliptixProtocolChainStep::Create(
            ChainStepType::SENDER,
            chain_key,
            dh_private,
            dh_public
        );
        REQUIRE(result.IsOk());
        auto chain_step = std::move(result).Unwrap();
        auto pk_result = chain_step.ReadDhPublicKey();
        REQUIRE(pk_result.IsOk());
        auto pk_opt = pk_result.Unwrap();
        REQUIRE(pk_opt.has_value());
        REQUIRE(pk_opt->size() == Constants::X_25519_PUBLIC_KEY_SIZE);
    }
}
TEST_CASE("EcliptixProtocolChainStep - Symmetric ratchet (sequential messages)", "[chain_step]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    std::vector<uint8_t> initial_chain_key(Constants::X_25519_KEY_SIZE, 0x50);
    auto result = EcliptixProtocolChainStep::Create(
        ChainStepType::SENDER,
        initial_chain_key,
        std::nullopt,
        std::nullopt
    );
    REQUIRE(result.IsOk());
    auto chain_step = std::move(result).Unwrap();
    SECTION("Derive key for current index (0)") {
        auto key_result = chain_step.GetOrDeriveKeyFor(0);
        REQUIRE(key_result.IsOk());
        auto key = key_result.Unwrap();
        REQUIRE(key.Index() == 0);
        auto operation_result = key.WithKeyMaterial<std::vector<uint8_t>>(
            [](std::span<const uint8_t> key_bytes) -> Result<std::vector<uint8_t>, EcliptixProtocolFailure> {
                REQUIRE(key_bytes.size() == Constants::X_25519_KEY_SIZE);
                return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Ok(
                    std::vector<uint8_t>(key_bytes.begin(), key_bytes.end())
                );
            }
        );
        REQUIRE(operation_result.IsOk());
        auto key_bytes = operation_result.Unwrap();
        REQUIRE(key_bytes.size() == Constants::X_25519_KEY_SIZE);
        auto new_index_result = chain_step.GetCurrentIndex();
        REQUIRE(new_index_result.IsOk());
        REQUIRE(new_index_result.Unwrap() == 1);
    }
    SECTION("Derive sequential keys") {
        std::vector<std::vector<uint8_t>> derived_keys;
        for (uint32_t i = 0; i < 3; ++i) {
            auto key_result = chain_step.GetOrDeriveKeyFor(i);
            REQUIRE(key_result.IsOk());
            auto key = key_result.Unwrap();
            auto bytes_result = key.WithKeyMaterial<std::vector<uint8_t>>(
                [](std::span<const uint8_t> key_bytes) -> Result<std::vector<uint8_t>, EcliptixProtocolFailure> {
                    return Result<std::vector<uint8_t>, EcliptixProtocolFailure>::Ok(
                        std::vector<uint8_t>(key_bytes.begin(), key_bytes.end())
                    );
                }
            );
            REQUIRE(bytes_result.IsOk());
            derived_keys.push_back(bytes_result.Unwrap());
        }
        REQUIRE(derived_keys[0] != derived_keys[1]);
        REQUIRE(derived_keys[1] != derived_keys[2]);
        REQUIRE(derived_keys[0] != derived_keys[2]);
        auto index_result = chain_step.GetCurrentIndex();
        REQUIRE(index_result.IsOk());
        REQUIRE(index_result.Unwrap() == 3);
    }
}
TEST_CASE("EcliptixProtocolChainStep - Out-of-order message support", "[chain_step]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    std::vector<uint8_t> initial_chain_key(Constants::X_25519_KEY_SIZE, 0x60);
    auto result = EcliptixProtocolChainStep::Create(
        ChainStepType::RECEIVER,
        initial_chain_key,
        std::nullopt,
        std::nullopt
    );
    REQUIRE(result.IsOk());
    auto chain_step = std::move(result).Unwrap();
    SECTION("Skip ahead and cache intermediate keys") {
        auto key5_result = chain_step.GetOrDeriveKeyFor(5);
        REQUIRE(key5_result.IsOk());
        auto index_result = chain_step.GetCurrentIndex();
        REQUIRE(index_result.IsOk());
        REQUIRE(index_result.Unwrap() == 5);
        auto key2_result = chain_step.GetOrDeriveKeyFor(2);
        REQUIRE(key2_result.IsOk());
        auto key2 = key2_result.Unwrap();
        auto use2_result = key2.WithKeyMaterial<Unit>(
            [](std::span<const uint8_t> bytes) -> Result<Unit, EcliptixProtocolFailure> {
                REQUIRE(bytes.size() == Constants::X_25519_KEY_SIZE);
                return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
            }
        );
        REQUIRE(use2_result.IsOk());
        auto index_after = chain_step.GetCurrentIndex();
        REQUIRE(index_after.IsOk());
        REQUIRE(index_after.Unwrap() == 5);
    }
    SECTION("Skip within limit") {
        auto key_result = chain_step.GetOrDeriveKeyFor(100);
        REQUIRE(key_result.IsOk());
        auto index_result = chain_step.GetCurrentIndex();
        REQUIRE(index_result.IsOk());
        REQUIRE(index_result.Unwrap() == 100);
    }
    SECTION("Reject skip beyond limit") {
        auto key_result = chain_step.GetOrDeriveKeyFor(1001);
        REQUIRE(key_result.IsErr());
        auto index_result = chain_step.GetCurrentIndex();
        REQUIRE(index_result.IsOk());
        REQUIRE(index_result.Unwrap() == 0);
    }
}
TEST_CASE("EcliptixProtocolChainStep - DH ratchet integration", "[chain_step]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    std::vector<uint8_t> initial_chain_key(Constants::X_25519_KEY_SIZE, 0x70);
    std::vector<uint8_t> initial_dh_private(Constants::X_25519_PRIVATE_KEY_SIZE, 0x71);
    std::vector<uint8_t> initial_dh_public(Constants::X_25519_PUBLIC_KEY_SIZE, 0x72);
    auto result = EcliptixProtocolChainStep::Create(
        ChainStepType::SENDER,
        initial_chain_key,
        initial_dh_private,
        initial_dh_public
    );
    REQUIRE(result.IsOk());
    auto chain_step = std::move(result).Unwrap();
    SECTION("Update keys after DH ratchet") {
        auto key0_result = chain_step.GetOrDeriveKeyFor(0);
        REQUIRE(key0_result.IsOk());
        auto use0 = key0_result.Unwrap().WithKeyMaterial<Unit>(
            [](std::span<const uint8_t>) { return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{}); }
        );
        REQUIRE(use0.IsOk());
        auto key1_result = chain_step.GetOrDeriveKeyFor(1);
        REQUIRE(key1_result.IsOk());
        auto use1 = key1_result.Unwrap().WithKeyMaterial<Unit>(
            [](std::span<const uint8_t>) { return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{}); }
        );
        REQUIRE(use1.IsOk());
        auto index_before = chain_step.GetCurrentIndex();
        REQUIRE(index_before.IsOk());
        REQUIRE(index_before.Unwrap() == 2);
        std::vector<uint8_t> new_chain_key(Constants::X_25519_KEY_SIZE, 0x80);
        std::vector<uint8_t> new_dh_private(Constants::X_25519_PRIVATE_KEY_SIZE, 0x81);
        std::vector<uint8_t> new_dh_public(Constants::X_25519_PUBLIC_KEY_SIZE, 0x82);
        auto update_result = chain_step.UpdateKeysAfterDhRatchet(
            new_chain_key,
            new_dh_private,
            new_dh_public
        );
        REQUIRE(update_result.IsOk());
        auto index_after = chain_step.GetCurrentIndex();
        REQUIRE(index_after.IsOk());
        REQUIRE(index_after.Unwrap() == 0);
        auto new_pk_result = chain_step.ReadDhPublicKey();
        REQUIRE(new_pk_result.IsOk());
        auto new_pk_opt = new_pk_result.Unwrap();
        REQUIRE(new_pk_opt.has_value());
        REQUIRE(*new_pk_opt == new_dh_public);
    }
    SECTION("Update chain key only (no new DH keys)") {
        std::vector<uint8_t> new_chain_key(Constants::X_25519_KEY_SIZE, 0x90);
        auto update_result = chain_step.UpdateKeysAfterDhRatchet(
            new_chain_key,
            std::nullopt,
            std::nullopt
        );
        REQUIRE(update_result.IsOk());
        auto pk_result = chain_step.ReadDhPublicKey();
        REQUIRE(pk_result.IsOk());
        auto pk_opt = pk_result.Unwrap();
        REQUIRE(pk_opt.has_value());
        REQUIRE(*pk_opt == initial_dh_public);
    }
}
TEST_CASE("EcliptixProtocolChainStep - Index management", "[chain_step]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    std::vector<uint8_t> chain_key(Constants::X_25519_KEY_SIZE, 0xA0);
    auto result = EcliptixProtocolChainStep::Create(
        ChainStepType::SENDER,
        chain_key,
        std::nullopt,
        std::nullopt
    );
    REQUIRE(result.IsOk());
    auto chain_step = std::move(result).Unwrap();
    SECTION("Get and set current index") {
        auto get_result = chain_step.GetCurrentIndex();
        REQUIRE(get_result.IsOk());
        REQUIRE(get_result.Unwrap() == 0);
        auto set_result = chain_step.SetCurrentIndex(42);
        REQUIRE(set_result.IsOk());
        auto get_result2 = chain_step.GetCurrentIndex();
        REQUIRE(get_result2.IsOk());
        REQUIRE(get_result2.Unwrap() == 42);
    }
}
TEST_CASE("EcliptixProtocolChainStep - Chain key access", "[chain_step]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    std::vector<uint8_t> chain_key(Constants::X_25519_KEY_SIZE, 0xB0);
    auto result = EcliptixProtocolChainStep::Create(
        ChainStepType::SENDER,
        chain_key,
        std::nullopt,
        std::nullopt
    );
    REQUIRE(result.IsOk());
    auto chain_step = std::move(result).Unwrap();
    SECTION("Read current chain key") {
        auto key_result = chain_step.GetCurrentChainKey();
        REQUIRE(key_result.IsOk());
        auto key_bytes = key_result.Unwrap();
        REQUIRE(key_bytes.size() == Constants::X_25519_KEY_SIZE);
        SodiumInterop::SecureWipe(std::span<uint8_t>(key_bytes));
    }
}
TEST_CASE("EcliptixProtocolChainStep - DH key handle access", "[chain_step]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    std::vector<uint8_t> chain_key(Constants::X_25519_KEY_SIZE, 0xC0);
    std::vector<uint8_t> dh_private(Constants::X_25519_PRIVATE_KEY_SIZE, 0xC1);
    std::vector<uint8_t> dh_public(Constants::X_25519_PUBLIC_KEY_SIZE, 0xC2);
    SECTION("SENDER has DH private key handle") {
        auto result = EcliptixProtocolChainStep::Create(
            ChainStepType::SENDER,
            chain_key,
            dh_private,
            dh_public
        );
        REQUIRE(result.IsOk());
        auto chain_step = std::move(result).Unwrap();
        auto handle_opt = chain_step.GetDhPrivateKeyHandle();
        REQUIRE(handle_opt.has_value());
        REQUIRE(*handle_opt != nullptr);
    }
    SECTION("RECEIVER without DH private key has no handle") {
        auto result = EcliptixProtocolChainStep::Create(
            ChainStepType::RECEIVER,
            chain_key,
            std::nullopt,
            dh_public
        );
        REQUIRE(result.IsOk());
        auto chain_step = std::move(result).Unwrap();
        auto handle_opt = chain_step.GetDhPrivateKeyHandle();
        REQUIRE_FALSE(handle_opt.has_value());
    }
}
TEST_CASE("EcliptixProtocolChainStep - IKeyProvider interface", "[chain_step]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    std::vector<uint8_t> chain_key(Constants::X_25519_KEY_SIZE, 0xD0);
    auto result = EcliptixProtocolChainStep::Create(
        ChainStepType::SENDER,
        chain_key,
        std::nullopt,
        std::nullopt
    );
    REQUIRE(result.IsOk());
    auto chain_step = std::move(result).Unwrap();
    SECTION("ExecuteWithKey provides key material") {
        bool callback_executed = false;
        auto exec_result = chain_step.ExecuteWithKey(
            0,
            [&callback_executed](std::span<const uint8_t> key_bytes) -> Result<Unit, EcliptixProtocolFailure> {
                callback_executed = true;
                REQUIRE(key_bytes.size() == Constants::X_25519_KEY_SIZE);
                return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
            }
        );
        REQUIRE(exec_result.IsOk());
        REQUIRE(callback_executed);
    }
    SECTION("ExecuteWithKey advances ratchet") {
        auto index_before = chain_step.GetCurrentIndex();
        REQUIRE(index_before.IsOk());
        REQUIRE(index_before.Unwrap() == 0);
        auto exec_result = chain_step.ExecuteWithKey(
            0,
            [](std::span<const uint8_t>) -> Result<Unit, EcliptixProtocolFailure> {
                return Result<Unit, EcliptixProtocolFailure>::Ok(Unit{});
            }
        );
        REQUIRE(exec_result.IsOk());
        auto index_after = chain_step.GetCurrentIndex();
        REQUIRE(index_after.IsOk());
        REQUIRE(index_after.Unwrap() == 1);
    }
}
