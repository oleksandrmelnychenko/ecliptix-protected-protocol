#include <catch2/catch_test_macros.hpp>
#include "ecliptix/protocol/session.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/crypto/kyber_interop.hpp"
#include "ecliptix/protocol/constants.hpp"
#include "protocol/state.pb.h"
#include <sodium.h>
#include <vector>
#include <algorithm>
#include <array>

using namespace ecliptix::protocol;
using namespace ecliptix::protocol::crypto;

namespace {

std::vector<uint8_t> ComputeIdentityBindingHash(
    const std::vector<uint8_t>& local_identity_ed25519,
    const std::vector<uint8_t>& local_identity_x25519,
    const std::vector<uint8_t>& peer_identity_ed25519,
    const std::vector<uint8_t>& peer_identity_x25519) {
    std::array<std::vector<uint8_t>, 2> ed_keys = {local_identity_ed25519, peer_identity_ed25519};
    if (ed_keys[0] > ed_keys[1]) {
        std::swap(ed_keys[0], ed_keys[1]);
    }
    std::array<std::vector<uint8_t>, 2> x_keys = {local_identity_x25519, peer_identity_x25519};
    if (x_keys[0] > x_keys[1]) {
        std::swap(x_keys[0], x_keys[1]);
    }
    std::vector<uint8_t> input;
    input.insert(input.end(), kIdentityBindingInfo.begin(), kIdentityBindingInfo.end());
    input.insert(input.end(), ed_keys[0].begin(), ed_keys[0].end());
    input.insert(input.end(), ed_keys[1].begin(), ed_keys[1].end());
    input.insert(input.end(), x_keys[0].begin(), x_keys[0].end());
    input.insert(input.end(), x_keys[1].begin(), x_keys[1].end());
    std::vector<uint8_t> hash(crypto_hash_sha256_BYTES);
    crypto_hash_sha256(hash.data(), input.data(), input.size());
    return hash;
}

struct TestKeys {
    std::vector<uint8_t> local_ed25519_public;
    std::vector<uint8_t> local_x25519_public;
    std::vector<uint8_t> peer_ed25519_public;
    std::vector<uint8_t> peer_x25519_public;
};

TestKeys GenerateTestIdentityKeys() {
    TestKeys keys;

    auto local_ed_result = SodiumInterop::GenerateEd25519KeyPair();
    REQUIRE(local_ed_result.IsOk());
    auto [local_ed_sk_handle, local_ed_pk] = std::move(local_ed_result).Unwrap();
    keys.local_ed25519_public = local_ed_pk;

    auto local_x_result = SodiumInterop::GenerateX25519KeyPair("local-x");
    REQUIRE(local_x_result.IsOk());
    auto [local_x_sk_handle, local_x_pk] = std::move(local_x_result).Unwrap();
    keys.local_x25519_public = local_x_pk;

    auto peer_ed_result = SodiumInterop::GenerateEd25519KeyPair();
    REQUIRE(peer_ed_result.IsOk());
    auto [peer_ed_sk_handle, peer_ed_pk] = std::move(peer_ed_result).Unwrap();
    keys.peer_ed25519_public = peer_ed_pk;

    auto peer_x_result = SodiumInterop::GenerateX25519KeyPair("peer-x");
    REQUIRE(peer_x_result.IsOk());
    auto [peer_x_sk_handle, peer_x_pk] = std::move(peer_x_result).Unwrap();
    keys.peer_x25519_public = peer_x_pk;

    return keys;
}

ecliptix::proto::protocol::ProtocolState CreateValidStateWithIdentity(const TestKeys& keys) {
    ecliptix::proto::protocol::ProtocolState state;

    state.set_version(kProtocolVersion);
    state.set_is_initiator(true);

    std::vector<uint8_t> session_id(kSessionIdBytes, 0x11);
    state.set_session_id(session_id.data(), session_id.size());

    std::vector<uint8_t> root_key(kRootKeyBytes, 0x22);
    state.set_root_key(root_key.data(), root_key.size());

    std::vector<uint8_t> metadata_key(kMetadataKeyBytes, 0x33);
    state.set_metadata_key(metadata_key.data(), metadata_key.size());

    auto dh_result = SodiumInterop::GenerateX25519KeyPair("test");
    REQUIRE(dh_result.IsOk());
    auto [dh_sk_handle, dh_pk] = std::move(dh_result).Unwrap();
    std::vector<uint8_t> dh_sk(kX25519PrivateKeyBytes);
    dh_sk_handle.WithReadAccess([&](std::span<const uint8_t> data) {
        std::copy(data.begin(), data.end(), dh_sk.begin());
        return Unit{};
    });

    state.mutable_dh_local()->set_private_key(dh_sk.data(), dh_sk.size());
    state.mutable_dh_local()->set_public_key(dh_pk.data(), dh_pk.size());

    auto peer_dh_result = SodiumInterop::GenerateX25519KeyPair("peer");
    REQUIRE(peer_dh_result.IsOk());
    auto [peer_sk_handle, peer_pk] = std::move(peer_dh_result).Unwrap();
    state.set_dh_remote_public(peer_pk.data(), peer_pk.size());

    state.set_dh_local_initial_public(dh_pk.data(), dh_pk.size());
    state.set_dh_remote_initial_public(peer_pk.data(), peer_pk.size());

    auto kyber_result = KyberInterop::GenerateKyber768KeyPair("test-kyber");
    REQUIRE(kyber_result.IsOk());
    auto [kyber_sk_handle, kyber_pk] = std::move(kyber_result).Unwrap();
    state.mutable_kyber_local()->set_public_key(kyber_pk.data(), kyber_pk.size());
    std::vector<uint8_t> kyber_sk_vec(kKyberSecretKeyBytes);
    kyber_sk_handle.WithReadAccess([&](std::span<const uint8_t> data) {
        std::copy(data.begin(), data.end(), kyber_sk_vec.begin());
        return Unit{};
    });
    state.mutable_kyber_local()->set_secret_key(kyber_sk_vec.data(), kyber_sk_vec.size());

    auto peer_kyber_result = KyberInterop::GenerateKyber768KeyPair("peer-kyber");
    REQUIRE(peer_kyber_result.IsOk());
    auto [peer_kyber_sk_handle, peer_kyber_pk] = std::move(peer_kyber_result).Unwrap();
    state.set_kyber_remote_public(peer_kyber_pk.data(), peer_kyber_pk.size());

    std::vector<uint8_t> chain_key(kChainKeyBytes, 0x44);
    state.mutable_send_chain()->set_chain_key(chain_key.data(), chain_key.size());
    state.mutable_send_chain()->set_message_index(0);
    state.mutable_recv_chain()->set_chain_key(chain_key.data(), chain_key.size());
    state.mutable_recv_chain()->set_message_index(0);

    std::vector<uint8_t> nonce_prefix(kNoncePrefixBytes, 0x55);
    state.mutable_nonce_generator()->set_prefix(nonce_prefix.data(), nonce_prefix.size());
    state.mutable_nonce_generator()->set_counter(0);

    state.set_state_counter(1);
    state.set_send_ratchet_epoch(0);
    state.set_recv_ratchet_epoch(0);
    state.set_max_messages_per_chain(static_cast<uint32_t>(kDefaultMessagesPerChain));

    state.set_local_identity_ed25519_public(keys.local_ed25519_public.data(), keys.local_ed25519_public.size());
    state.set_local_identity_x25519_public(keys.local_x25519_public.data(), keys.local_x25519_public.size());
    state.set_peer_identity_ed25519_public(keys.peer_ed25519_public.data(), keys.peer_ed25519_public.size());
    state.set_peer_identity_x25519_public(keys.peer_x25519_public.data(), keys.peer_x25519_public.size());

    auto binding_hash = ComputeIdentityBindingHash(
        keys.local_ed25519_public, keys.local_x25519_public,
        keys.peer_ed25519_public, keys.peer_x25519_public);
    state.set_identity_binding_hash(binding_hash.data(), binding_hash.size());

    std::vector<uint8_t> dummy_mac(kHmacBytes, 0x00);
    state.set_state_hmac(dummy_mac.data(), dummy_mac.size());

    return state;
}

}  // namespace

TEST_CASE("Identity Binding - Corrupted binding hash rejection", "[identity][binding][security]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    REQUIRE(KyberInterop::Initialize().IsOk());

    SECTION("Corrupted binding hash is rejected") {
        auto keys = GenerateTestIdentityKeys();
        auto state = CreateValidStateWithIdentity(keys);

        std::vector<uint8_t> corrupted_hash(kIdentityBindingHashBytes, 0xDE);
        state.set_identity_binding_hash(corrupted_hash.data(), corrupted_hash.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
        const auto& err_msg = result.UnwrapErr().message;
        REQUIRE((err_msg.find("binding") != std::string::npos ||
                 err_msg.find("HMAC") != std::string::npos));
    }

    SECTION("Truncated binding hash is rejected") {
        auto keys = GenerateTestIdentityKeys();
        auto state = CreateValidStateWithIdentity(keys);

        std::vector<uint8_t> short_hash(16, 0xAB);
        state.set_identity_binding_hash(short_hash.data(), short_hash.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }

    SECTION("Empty binding hash is rejected") {
        auto keys = GenerateTestIdentityKeys();
        auto state = CreateValidStateWithIdentity(keys);

        state.clear_identity_binding_hash();

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }
}

TEST_CASE("Identity Binding - Swapped identity keys rejection", "[identity][binding][security]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    REQUIRE(KyberInterop::Initialize().IsOk());

    SECTION("Swapped local/peer Ed25519 keys with original hash is rejected") {
        auto keys = GenerateTestIdentityKeys();
        auto state = CreateValidStateWithIdentity(keys);

        auto original_hash_bytes = state.identity_binding_hash();
        std::vector<uint8_t> original_hash(original_hash_bytes.begin(), original_hash_bytes.end());

        state.set_local_identity_ed25519_public(keys.peer_ed25519_public.data(), keys.peer_ed25519_public.size());
        state.set_peer_identity_ed25519_public(keys.local_ed25519_public.data(), keys.local_ed25519_public.size());

        state.set_identity_binding_hash(original_hash.data(), original_hash.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }

    SECTION("Swapped local/peer X25519 keys with original hash is rejected") {
        auto keys = GenerateTestIdentityKeys();
        auto state = CreateValidStateWithIdentity(keys);

        auto original_hash_bytes = state.identity_binding_hash();
        std::vector<uint8_t> original_hash(original_hash_bytes.begin(), original_hash_bytes.end());

        state.set_local_identity_x25519_public(keys.peer_x25519_public.data(), keys.peer_x25519_public.size());
        state.set_peer_identity_x25519_public(keys.local_x25519_public.data(), keys.local_x25519_public.size());

        state.set_identity_binding_hash(original_hash.data(), original_hash.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }
}

TEST_CASE("Identity Binding - Hash determinism", "[identity][binding]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Both parties compute the same binding hash regardless of local/peer order") {
        auto keys = GenerateTestIdentityKeys();

        auto hash_from_alice = ComputeIdentityBindingHash(
            keys.local_ed25519_public, keys.local_x25519_public,
            keys.peer_ed25519_public, keys.peer_x25519_public);

        auto hash_from_bob = ComputeIdentityBindingHash(
            keys.peer_ed25519_public, keys.peer_x25519_public,
            keys.local_ed25519_public, keys.local_x25519_public);

        REQUIRE(hash_from_alice == hash_from_bob);
    }

    SECTION("Different keys produce different hashes") {
        auto keys1 = GenerateTestIdentityKeys();
        auto keys2 = GenerateTestIdentityKeys();

        auto hash1 = ComputeIdentityBindingHash(
            keys1.local_ed25519_public, keys1.local_x25519_public,
            keys1.peer_ed25519_public, keys1.peer_x25519_public);

        auto hash2 = ComputeIdentityBindingHash(
            keys2.local_ed25519_public, keys2.local_x25519_public,
            keys2.peer_ed25519_public, keys2.peer_x25519_public);

        REQUIRE(hash1 != hash2);
    }
}

TEST_CASE("Identity Binding - Ed25519 key inclusion", "[identity][binding][security]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Same X25519 keys but different Ed25519 keys produce different hashes") {
        auto keys = GenerateTestIdentityKeys();

        auto different_ed_result = SodiumInterop::GenerateEd25519KeyPair();
        REQUIRE(different_ed_result.IsOk());
        auto [different_ed_sk_handle, different_ed_pk] = std::move(different_ed_result).Unwrap();

        auto hash_original = ComputeIdentityBindingHash(
            keys.local_ed25519_public, keys.local_x25519_public,
            keys.peer_ed25519_public, keys.peer_x25519_public);

        auto hash_different_ed = ComputeIdentityBindingHash(
            different_ed_pk, keys.local_x25519_public,
            keys.peer_ed25519_public, keys.peer_x25519_public);

        REQUIRE(hash_original != hash_different_ed);
    }
}

TEST_CASE("Identity Binding - All-zero key rejection", "[identity][binding][security]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    REQUIRE(KyberInterop::Initialize().IsOk());

    SECTION("All-zero Ed25519 public key in state is rejected") {
        auto keys = GenerateTestIdentityKeys();
        auto state = CreateValidStateWithIdentity(keys);

        std::vector<uint8_t> zero_key(kEd25519PublicKeyBytes, 0x00);
        state.set_local_identity_ed25519_public(zero_key.data(), zero_key.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }

    SECTION("All-zero X25519 public key in state is rejected") {
        auto keys = GenerateTestIdentityKeys();
        auto state = CreateValidStateWithIdentity(keys);

        std::vector<uint8_t> zero_key(kX25519PublicKeyBytes, 0x00);
        state.set_local_identity_x25519_public(zero_key.data(), zero_key.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }
}

TEST_CASE("Identity Binding - Invalid key sizes rejection", "[identity][binding]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    REQUIRE(KyberInterop::Initialize().IsOk());

    SECTION("Short Ed25519 public key is rejected") {
        auto keys = GenerateTestIdentityKeys();
        auto state = CreateValidStateWithIdentity(keys);

        std::vector<uint8_t> short_key(16, 0xAA);
        state.set_local_identity_ed25519_public(short_key.data(), short_key.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }

    SECTION("Short X25519 public key is rejected") {
        auto keys = GenerateTestIdentityKeys();
        auto state = CreateValidStateWithIdentity(keys);

        std::vector<uint8_t> short_key(16, 0xBB);
        state.set_local_identity_x25519_public(short_key.data(), short_key.size());

        auto result = Session::FromState(state);
        REQUIRE(result.IsErr());
    }
}
