#include <catch2/catch_test_macros.hpp>
#include "ecliptix/protocol/connection/ecliptix_protocol_connection.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/core/constants.hpp"
#include "ecliptix/models/bundles/local_public_key_bundle.hpp"
#include <sodium.h>
#include <thread>
#include <vector>
#include <algorithm>

using namespace ecliptix::protocol::connection;
using namespace ecliptix::protocol::crypto;
using namespace ecliptix::protocol;
using namespace ecliptix::protocol::models;

namespace {

struct TestKeyMaterial {
    std::vector<uint8_t> root_key;
    std::vector<uint8_t> peer_dh_public_key;
    std::vector<uint8_t> ed25519_pub;
    std::vector<uint8_t> identity_x25519_pub;
    std::vector<uint8_t> signed_pre_key_pub;
    std::vector<uint8_t> signed_pre_key_sig;

    LocalPublicKeyBundle GetBundle() const {
        return LocalPublicKeyBundle(
            ed25519_pub,
            identity_x25519_pub,
            1,
            signed_pre_key_pub,
            signed_pre_key_sig,
            {}
        );
    }

    static TestKeyMaterial Generate() {
        TestKeyMaterial material;
        material.root_key = SodiumInterop::GetRandomBytes(Constants::X_25519_KEY_SIZE);
        material.peer_dh_public_key.resize(Constants::X_25519_PUBLIC_KEY_SIZE);

        std::vector<uint8_t> peer_dh_private(Constants::X_25519_PRIVATE_KEY_SIZE);
        const int dh_result = crypto_box_keypair(
            material.peer_dh_public_key.data(),
            peer_dh_private.data()
        );
        REQUIRE(dh_result == 0);

        material.ed25519_pub = SodiumInterop::GetRandomBytes(Constants::ED_25519_PUBLIC_KEY_SIZE);
        material.identity_x25519_pub = SodiumInterop::GetRandomBytes(Constants::X_25519_PUBLIC_KEY_SIZE);
        material.signed_pre_key_pub = material.peer_dh_public_key;
        material.signed_pre_key_sig = SodiumInterop::GetRandomBytes(Constants::ED_25519_SIGNATURE_SIZE);

        return material;
    }
};

auto CreateUnfinalizedConnection() {
    auto result = EcliptixProtocolConnection::Create(1, true);
    REQUIRE(result.IsOk());
    return std::move(result).Unwrap();
}

auto CreateFinalizedConnection(const TestKeyMaterial& material) {
    auto conn = CreateUnfinalizedConnection();

    auto peer_result = conn->SetPeerBundle(material.GetBundle());
    REQUIRE(peer_result.IsOk());

    auto finalize_result = conn->FinalizeChainAndDhKeys(
        material.root_key,
        material.peer_dh_public_key
    );
    REQUIRE(finalize_result.IsOk());

    return conn;
}

}

TEST_CASE("State Transitions - Normal Flow: Create → SetPeer → Finalize → Operate", "[boundaries][state][critical]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    REQUIRE(SodiumInterop::Initialize().IsOk());

    const auto material = TestKeyMaterial::Generate();
    auto conn = CreateUnfinalizedConnection();

    SECTION("Initial state allows SetPeerBundle") {
        auto peer_result = conn->SetPeerBundle(material.GetBundle());
        REQUIRE(peer_result.IsOk());
    }

    SECTION("After SetPeerBundle, FinalizeChainAndDhKeys succeeds") {
        auto peer_result = conn->SetPeerBundle(material.GetBundle());
        REQUIRE(peer_result.IsOk());

        auto finalize_result = conn->FinalizeChainAndDhKeys(
            material.root_key,
            material.peer_dh_public_key
        );
        REQUIRE(finalize_result.IsOk());
    }

    SECTION("After finalization, PrepareNextSendMessage succeeds") {
        auto peer_result = conn->SetPeerBundle(material.GetBundle());
        REQUIRE(peer_result.IsOk());

        auto finalize_result = conn->FinalizeChainAndDhKeys(
            material.root_key,
            material.peer_dh_public_key
        );
        REQUIRE(finalize_result.IsOk());

        auto send_result = conn->PrepareNextSendMessage();
        REQUIRE(send_result.IsOk());
    }

    SECTION("After finalization, GetMetadataEncryptionKey succeeds") {
        auto peer_result = conn->SetPeerBundle(material.GetBundle());
        REQUIRE(peer_result.IsOk());

        auto finalize_result = conn->FinalizeChainAndDhKeys(
            material.root_key,
            material.peer_dh_public_key
        );
        REQUIRE(finalize_result.IsOk());

        auto key_result = conn->GetMetadataEncryptionKey();
        REQUIRE(key_result.IsOk());

        auto key = std::move(key_result).Unwrap();
        REQUIRE(key.size() == Constants::AES_KEY_SIZE);
    }
}

TEST_CASE("State Transitions - Unfinalized Violations: PrepareNextSendMessage", "[boundaries][state][critical]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    auto conn = CreateUnfinalizedConnection();

    SECTION("PrepareNextSendMessage before SetPeerBundle must fail") {
        auto result = conn->PrepareNextSendMessage();
        REQUIRE(result.IsErr());

        auto err = std::move(result).UnwrapErr();
        REQUIRE(err.type == EcliptixProtocolFailureType::Generic);
    }

    SECTION("PrepareNextSendMessage after SetPeerBundle but before finalization must fail") {
        const auto material = TestKeyMaterial::Generate();

        auto peer_result = conn->SetPeerBundle(material.GetBundle());
        REQUIRE(peer_result.IsOk());

        auto send_result = conn->PrepareNextSendMessage();
        REQUIRE(send_result.IsErr());

        auto err = std::move(send_result).UnwrapErr();
        REQUIRE(err.type == EcliptixProtocolFailureType::Generic);
    }
}

TEST_CASE("State Transitions - Unfinalized Violations: ProcessReceivedMessage", "[boundaries][state][critical]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    auto conn = CreateUnfinalizedConnection();

    SECTION("ProcessReceivedMessage before finalization must fail") {
        std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE, 0xAA);
        auto result = conn->ProcessReceivedMessage(0, nonce);
        REQUIRE(result.IsErr());

        auto err = std::move(result).UnwrapErr();
        REQUIRE(err.type == EcliptixProtocolFailureType::Generic);
    }

    SECTION("ProcessReceivedMessage after SetPeerBundle but before finalization must fail") {
        const auto material = TestKeyMaterial::Generate();

        auto peer_result = conn->SetPeerBundle(material.GetBundle());
        REQUIRE(peer_result.IsOk());

        std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE, 0xAA);
        auto recv_result = conn->ProcessReceivedMessage(0, nonce);
        REQUIRE(recv_result.IsErr());

        auto err = std::move(recv_result).UnwrapErr();
        REQUIRE(err.type == EcliptixProtocolFailureType::Generic);
    }
}

TEST_CASE("State Transitions - Unfinalized Violations: GetMetadataEncryptionKey", "[boundaries][state][critical]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    auto conn = CreateUnfinalizedConnection();

    SECTION("GetMetadataEncryptionKey before finalization must fail") {
        auto result = conn->GetMetadataEncryptionKey();
        REQUIRE(result.IsErr());

        auto err = std::move(result).UnwrapErr();
        REQUIRE(err.type == EcliptixProtocolFailureType::Generic);
    }

    SECTION("GetMetadataEncryptionKey after SetPeerBundle but before finalization must fail") {
        const auto material = TestKeyMaterial::Generate();

        auto peer_result = conn->SetPeerBundle(material.GetBundle());
        REQUIRE(peer_result.IsOk());

        auto key_result = conn->GetMetadataEncryptionKey();
        REQUIRE(key_result.IsErr());

        auto err = std::move(key_result).UnwrapErr();
        REQUIRE(err.type == EcliptixProtocolFailureType::Generic);
    }
}

TEST_CASE("State Transitions - Unfinalized Violations: PerformReceivingRatchet", "[boundaries][state][critical]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    auto conn = CreateUnfinalizedConnection();

    SECTION("PerformReceivingRatchet before finalization must fail") {
        std::vector<uint8_t> fake_dh_key(Constants::X_25519_PUBLIC_KEY_SIZE, 0x42);

        auto result = conn->PerformReceivingRatchet(fake_dh_key);
        REQUIRE(result.IsErr());

        auto err = std::move(result).UnwrapErr();
        REQUIRE(err.type == EcliptixProtocolFailureType::Generic);
    }

    SECTION("PerformReceivingRatchet after SetPeerBundle but before finalization must fail") {
        const auto material = TestKeyMaterial::Generate();

        auto peer_result = conn->SetPeerBundle(material.GetBundle());
        REQUIRE(peer_result.IsOk());

        std::vector<uint8_t> fake_dh_key(Constants::X_25519_PUBLIC_KEY_SIZE, 0x42);
        auto ratchet_result = conn->PerformReceivingRatchet(fake_dh_key);
        REQUIRE(ratchet_result.IsErr());

        auto err = std::move(ratchet_result).UnwrapErr();
        REQUIRE(err.type == EcliptixProtocolFailureType::Generic);
    }
}

TEST_CASE("State Transitions - Double Finalization Attack", "[boundaries][state][critical]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    const auto material = TestKeyMaterial::Generate();
    auto conn = CreateUnfinalizedConnection();

    auto peer_result = conn->SetPeerBundle(material.GetBundle());
    REQUIRE(peer_result.IsOk());

    SECTION("First finalization succeeds") {
        auto first_finalize = conn->FinalizeChainAndDhKeys(
            material.root_key,
            material.peer_dh_public_key
        );
        REQUIRE(first_finalize.IsOk());
    }

    SECTION("Second finalization must fail") {
        auto first_finalize = conn->FinalizeChainAndDhKeys(
            material.root_key,
            material.peer_dh_public_key
        );
        REQUIRE(first_finalize.IsOk());

        const auto material2 = TestKeyMaterial::Generate();
        auto second_finalize = conn->FinalizeChainAndDhKeys(
            material2.root_key,
            material2.peer_dh_public_key
        );
        REQUIRE(second_finalize.IsErr());

        auto err = std::move(second_finalize).UnwrapErr();
        REQUIRE(err.type == EcliptixProtocolFailureType::Generic);
    }

    SECTION("Third finalization attempt also fails") {
        auto first_finalize = conn->FinalizeChainAndDhKeys(
            material.root_key,
            material.peer_dh_public_key
        );
        REQUIRE(first_finalize.IsOk());

        for (int i = 0; i < 3; ++i) {
            const auto material_extra = TestKeyMaterial::Generate();
            auto extra_finalize = conn->FinalizeChainAndDhKeys(
                material_extra.root_key,
                material_extra.peer_dh_public_key
            );
            REQUIRE(extra_finalize.IsErr());
        }
    }
}

TEST_CASE("State Transitions - SetPeerBundle After Finalization", "[boundaries][state][critical]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    const auto material = TestKeyMaterial::Generate();
    auto conn = CreateFinalizedConnection(material);

    SECTION("SetPeerBundle after finalization must fail") {
        const auto new_material = TestKeyMaterial::Generate();
        auto result = conn->SetPeerBundle(new_material.GetBundle());
        REQUIRE(result.IsErr());

        auto err = std::move(result).UnwrapErr();
        REQUIRE(err.type == EcliptixProtocolFailureType::Generic);
    }

    SECTION("Multiple SetPeerBundle attempts after finalization all fail") {
        for (int i = 0; i < 5; ++i) {
            const auto new_material = TestKeyMaterial::Generate();
            auto result = conn->SetPeerBundle(new_material.GetBundle());
            REQUIRE(result.IsErr());
        }
    }
}

TEST_CASE("State Transitions - Concurrent Finalization Attempts", "[boundaries][state][concurrency]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    const auto material = TestKeyMaterial::Generate();
    auto conn = CreateUnfinalizedConnection();

    auto peer_result = conn->SetPeerBundle(material.GetBundle());
    REQUIRE(peer_result.IsOk());

    SECTION("100 concurrent finalization attempts - only one succeeds") {
        constexpr int thread_count = 100;
        std::vector<std::thread> threads;
        std::atomic<int> success_count{0};
        std::atomic<int> failure_count{0};

        for (int i = 0; i < thread_count; ++i) {
            threads.emplace_back([&conn, &material, &success_count, &failure_count]() {
                auto result = conn->FinalizeChainAndDhKeys(
                    material.root_key,
                    material.peer_dh_public_key
                );

                if (result.IsOk()) {
                    success_count.fetch_add(1, std::memory_order_relaxed);
                } else {
                    failure_count.fetch_add(1, std::memory_order_relaxed);
                }
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        REQUIRE(success_count.load() == 1);
        REQUIRE(failure_count.load() == thread_count - 1);
    }
}

TEST_CASE("State Transitions - Operations After Successful Finalization", "[boundaries][state][critical]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    const auto material = TestKeyMaterial::Generate();
    auto conn = CreateFinalizedConnection(material);

    SECTION("PrepareNextSendMessage works after finalization") {
        for (int i = 0; i < 10; ++i) {
            auto result = conn->PrepareNextSendMessage();
            REQUIRE(result.IsOk());
        }
    }

    SECTION("GetMetadataEncryptionKey returns consistent key") {
        auto result1 = conn->GetMetadataEncryptionKey();
        REQUIRE(result1.IsOk());
        auto key1 = std::move(result1).Unwrap();

        auto result2 = conn->GetMetadataEncryptionKey();
        REQUIRE(result2.IsOk());
        auto key2 = std::move(result2).Unwrap();

        REQUIRE(key1.size() == key2.size());
        REQUIRE(std::equal(key1.begin(), key1.end(), key2.begin()));
    }

    SECTION("GenerateNextNonce produces unique nonces") {
        std::vector<std::vector<uint8_t>> nonces;

        for (int i = 0; i < 100; ++i) {
            auto result = conn->GenerateNextNonce();
            REQUIRE(result.IsOk());

            auto nonce = std::move(result).Unwrap();
            REQUIRE(nonce.size() == Constants::AES_GCM_NONCE_SIZE);

            nonces.push_back(std::move(nonce));
        }

        std::sort(nonces.begin(), nonces.end());
        auto it = std::unique(nonces.begin(), nonces.end());
        REQUIRE(it == nonces.end());
    }
}

TEST_CASE("State Transitions - Invalid Root Key Size", "[boundaries][state][validation]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    const auto material = TestKeyMaterial::Generate();
    auto conn = CreateUnfinalizedConnection();

    auto peer_result = conn->SetPeerBundle(material.GetBundle());
    REQUIRE(peer_result.IsOk());

    SECTION("Too short root key fails") {
        std::vector<uint8_t> short_root_key(Constants::X_25519_KEY_SIZE - 1, 0x42);

        auto result = conn->FinalizeChainAndDhKeys(
            short_root_key,
            material.peer_dh_public_key
        );
        REQUIRE(result.IsErr());
    }

    SECTION("Too long root key fails") {
        std::vector<uint8_t> long_root_key(Constants::X_25519_KEY_SIZE + 1, 0x42);

        auto result = conn->FinalizeChainAndDhKeys(
            long_root_key,
            material.peer_dh_public_key
        );
        REQUIRE(result.IsErr());
    }

    SECTION("Empty root key fails") {
        std::vector<uint8_t> empty_root_key;

        auto result = conn->FinalizeChainAndDhKeys(
            empty_root_key,
            material.peer_dh_public_key
        );
        REQUIRE(result.IsErr());
    }
}

TEST_CASE("State Transitions - Invalid DH Public Key Size", "[boundaries][state][validation]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    const auto material = TestKeyMaterial::Generate();
    auto conn = CreateUnfinalizedConnection();

    auto peer_result = conn->SetPeerBundle(material.GetBundle());
    REQUIRE(peer_result.IsOk());

    SECTION("Too short DH key fails") {
        std::vector<uint8_t> short_dh_key(Constants::X_25519_PUBLIC_KEY_SIZE - 1, 0x42);

        auto result = conn->FinalizeChainAndDhKeys(
            material.root_key,
            short_dh_key
        );
        REQUIRE(result.IsErr());
    }

    SECTION("Too long DH key fails") {
        std::vector<uint8_t> long_dh_key(Constants::X_25519_PUBLIC_KEY_SIZE + 1, 0x42);

        auto result = conn->FinalizeChainAndDhKeys(
            material.root_key,
            long_dh_key
        );
        REQUIRE(result.IsErr());
    }

    SECTION("Empty DH key fails") {
        std::vector<uint8_t> empty_dh_key;

        auto result = conn->FinalizeChainAndDhKeys(
            material.root_key,
            empty_dh_key
        );
        REQUIRE(result.IsErr());
    }
}

TEST_CASE("State Transitions - GetPeerBundle Behavior", "[boundaries][state][getters]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    const auto material = TestKeyMaterial::Generate();

    SECTION("GetPeerBundle fails before SetPeerBundle") {
        auto conn = CreateUnfinalizedConnection();

        auto result = conn->GetPeerBundle();
        REQUIRE(result.IsErr());
    }

    SECTION("GetPeerBundle succeeds after SetPeerBundle") {
        auto conn = CreateUnfinalizedConnection();

        auto peer_result = conn->SetPeerBundle(material.GetBundle());
        REQUIRE(peer_result.IsOk());

        auto get_result = conn->GetPeerBundle();
        REQUIRE(get_result.IsOk());

        auto bundle = std::move(get_result).Unwrap();
        REQUIRE(bundle.GetEd25519Public() == material.ed25519_pub);
        REQUIRE(bundle.GetSignedPreKeyPublic() == material.signed_pre_key_pub);
    }

    SECTION("GetPeerBundle succeeds after finalization") {
        auto conn = CreateFinalizedConnection(material);

        auto result = conn->GetPeerBundle();
        REQUIRE(result.IsOk());

        auto bundle = std::move(result).Unwrap();
        REQUIRE(bundle.GetEd25519Public() == material.ed25519_pub);
    }
}
