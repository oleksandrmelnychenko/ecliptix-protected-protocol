#include <catch2/catch_test_macros.hpp>
#include "ecliptix/crypto/shamir_secret_sharing.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include <vector>

using namespace ecliptix::protocol::crypto;

TEST_CASE("ShamirSecretSharing - Split and reconstruct roundtrip", "[secret-sharing]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    auto secret = SodiumInterop::GetRandomBytes(32);
    auto split_result = ShamirSecretSharing::Split(secret, 3, 5);
    REQUIRE(split_result.IsOk());

    auto shares = split_result.Unwrap();
    REQUIRE(shares.size() == 5);

    std::vector<std::vector<uint8_t>> subset{shares[0], shares[2], shares[4]};
    auto reconstruct_result = ShamirSecretSharing::Reconstruct(subset);
    REQUIRE(reconstruct_result.IsOk());
    REQUIRE(reconstruct_result.Unwrap() == secret);

    const size_t share_length = shares[0].size();
    std::vector<uint8_t> blob(share_length * subset.size());
    for (size_t i = 0; i < subset.size(); ++i) {
        std::copy(
            subset[i].begin(),
            subset[i].end(),
            blob.begin() + static_cast<ptrdiff_t>(i * share_length));
    }

    auto serialized_result = ShamirSecretSharing::ReconstructSerialized(
        blob,
        share_length,
        subset.size());
    REQUIRE(serialized_result.IsOk());
    REQUIRE(serialized_result.Unwrap() == secret);
}

TEST_CASE("ShamirSecretSharing - Reject insufficient shares", "[secret-sharing]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    auto secret = SodiumInterop::GetRandomBytes(32);
    auto split_result = ShamirSecretSharing::Split(secret, 3, 5);
    REQUIRE(split_result.IsOk());

    auto shares = split_result.Unwrap();
    std::vector<std::vector<uint8_t>> subset{shares[0], shares[1]};
    auto reconstruct_result = ShamirSecretSharing::Reconstruct(subset);
    REQUIRE(reconstruct_result.IsErr());
}

TEST_CASE("ShamirSecretSharing - Authenticated shares detect tampering", "[secret-sharing]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    auto secret = SodiumInterop::GetRandomBytes(32);
    auto auth_key = SodiumInterop::GetRandomBytes(32);

    auto split_result = ShamirSecretSharing::Split(secret, 3, 5, auth_key);
    REQUIRE(split_result.IsOk());

    auto shares = split_result.Unwrap();
    shares[0][ShamirSecretSharing::HEADER_SIZE] ^= 0x01;

    std::vector<std::vector<uint8_t>> subset{shares[0], shares[1], shares[2]};
    auto reconstruct_result = ShamirSecretSharing::Reconstruct(subset, auth_key);
    REQUIRE(reconstruct_result.IsErr());
}

TEST_CASE("ShamirSecretSharing - Authenticated roundtrip", "[secret-sharing]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    auto secret = SodiumInterop::GetRandomBytes(32);
    auto auth_key = SodiumInterop::GetRandomBytes(32);

    auto split_result = ShamirSecretSharing::Split(secret, 3, 5, auth_key);
    REQUIRE(split_result.IsOk());

    auto shares = split_result.Unwrap();
    std::vector<std::vector<uint8_t>> subset{shares[1], shares[3], shares[4]};
    auto reconstruct_result = ShamirSecretSharing::Reconstruct(subset, auth_key);
    REQUIRE(reconstruct_result.IsOk());
    REQUIRE(reconstruct_result.Unwrap() == secret);

    const size_t share_length = shares[0].size();
    std::vector<uint8_t> blob(share_length * subset.size());
    for (size_t i = 0; i < subset.size(); ++i) {
        std::copy(
            subset[i].begin(),
            subset[i].end(),
            blob.begin() + static_cast<ptrdiff_t>(i * share_length));
    }

    auto serialized_result = ShamirSecretSharing::ReconstructSerialized(
        blob,
        share_length,
        subset.size(),
        auth_key);
    REQUIRE(serialized_result.IsOk());
    REQUIRE(serialized_result.Unwrap() == secret);
}

TEST_CASE("ShamirSecretSharing - Split rejects invalid inputs", "[secret-sharing]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Empty secret") {
        std::vector<uint8_t> empty;
        auto result = ShamirSecretSharing::Split(empty, 2, 3);
        REQUIRE(result.IsErr());
    }

    SECTION("Secret too large") {
        std::vector<uint8_t> large(ShamirSecretSharing::MAX_SECRET_LENGTH + 1, 0xAA);
        auto result = ShamirSecretSharing::Split(large, 2, 3);
        REQUIRE(result.IsErr());
    }

    SECTION("Threshold too small") {
        auto secret = SodiumInterop::GetRandomBytes(16);
        auto result = ShamirSecretSharing::Split(secret, 1, 3);
        REQUIRE(result.IsErr());
    }

    SECTION("Threshold exceeds share count") {
        auto secret = SodiumInterop::GetRandomBytes(16);
        auto result = ShamirSecretSharing::Split(secret, 4, 3);
        REQUIRE(result.IsErr());
    }

    SECTION("Share count too small") {
        auto secret = SodiumInterop::GetRandomBytes(16);
        auto result = ShamirSecretSharing::Split(secret, 2, 1);
        REQUIRE(result.IsErr());
    }

    // Note: Cannot test "share count too large" since MAX_SHARES=255 equals uint8_t max.
    // The type constraint prevents passing values > 255.

    SECTION("Auth key wrong size") {
        auto secret = SodiumInterop::GetRandomBytes(16);
        auto auth_key = SodiumInterop::GetRandomBytes(31);
        auto result = ShamirSecretSharing::Split(secret, 2, 3, auth_key);
        REQUIRE(result.IsErr());
    }
}

TEST_CASE("ShamirSecretSharing - Split supports maximum share count", "[secret-sharing]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    auto secret = SodiumInterop::GetRandomBytes(16);
    auto split_result = ShamirSecretSharing::Split(secret, 2, ShamirSecretSharing::MAX_SHARES);
    REQUIRE(split_result.IsOk());

    auto shares = split_result.Unwrap();
    REQUIRE(shares.size() == ShamirSecretSharing::MAX_SHARES);

    std::vector<std::vector<uint8_t>> subset{shares.front(), shares.back()};
    auto reconstruct_result = ShamirSecretSharing::Reconstruct(subset);
    REQUIRE(reconstruct_result.IsOk());
    REQUIRE(reconstruct_result.Unwrap() == secret);
}

TEST_CASE("ShamirSecretSharing - Reconstruct rejects invalid inputs", "[secret-sharing]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    auto secret = SodiumInterop::GetRandomBytes(16);
    auto split_result = ShamirSecretSharing::Split(secret, 2, 3);
    REQUIRE(split_result.IsOk());
    auto shares = split_result.Unwrap();

    SECTION("Empty shares") {
        std::vector<std::vector<uint8_t>> empty;
        auto result = ShamirSecretSharing::Reconstruct(empty);
        REQUIRE(result.IsErr());
    }

    SECTION("Single share") {
        std::vector<std::vector<uint8_t>> subset{shares[0]};
        auto result = ShamirSecretSharing::Reconstruct(subset);
        REQUIRE(result.IsErr());
    }

    SECTION("Auth key wrong size") {
        auto auth_key = SodiumInterop::GetRandomBytes(31);
        std::vector<std::vector<uint8_t>> subset{shares[0], shares[1]};
        auto result = ShamirSecretSharing::Reconstruct(subset, auth_key);
        REQUIRE(result.IsErr());
    }
}

TEST_CASE("ShamirSecretSharing - Reconstruct rejects malformed shares", "[secret-sharing]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    auto secret = SodiumInterop::GetRandomBytes(32);
    auto split_result = ShamirSecretSharing::Split(secret, 3, 5);
    REQUIRE(split_result.IsOk());
    auto shares = split_result.Unwrap();

    SECTION("Share smaller than header") {
        std::vector<uint8_t> tiny(ShamirSecretSharing::HEADER_SIZE - 1, 0x00);
        std::vector<std::vector<uint8_t>> subset{tiny, tiny};
        auto result = ShamirSecretSharing::Reconstruct(subset);
        REQUIRE(result.IsErr());
    }

    SECTION("Missing auth key for authenticated shares") {
        auto auth_key = SodiumInterop::GetRandomBytes(32);
        auto auth_split = ShamirSecretSharing::Split(secret, 3, 5, auth_key);
        REQUIRE(auth_split.IsOk());
        auto auth_shares = auth_split.Unwrap();
        std::vector<std::vector<uint8_t>> subset{auth_shares[0], auth_shares[1], auth_shares[2]};
        auto result = ShamirSecretSharing::Reconstruct(subset);
        REQUIRE(result.IsErr());
    }

    SECTION("Auth key provided for unauthenticated shares") {
        auto auth_key = SodiumInterop::GetRandomBytes(32);
        std::vector<std::vector<uint8_t>> subset{shares[0], shares[1], shares[2]};
        auto result = ShamirSecretSharing::Reconstruct(subset, auth_key);
        REQUIRE(result.IsErr());
    }

    SECTION("Wrong auth key fails verification") {
        auto auth_key = SodiumInterop::GetRandomBytes(32);
        auto other_key = SodiumInterop::GetRandomBytes(32);
        auto auth_split = ShamirSecretSharing::Split(secret, 3, 5, auth_key);
        REQUIRE(auth_split.IsOk());
        auto auth_shares = auth_split.Unwrap();
        std::vector<std::vector<uint8_t>> subset{auth_shares[0], auth_shares[1], auth_shares[2]};
        auto result = ShamirSecretSharing::Reconstruct(subset, other_key);
        REQUIRE(result.IsErr());
    }

    SECTION("Magic mismatch") {
        shares[0][0] ^= 0xFF;
        std::vector<std::vector<uint8_t>> subset{shares[0], shares[1], shares[2]};
        auto result = ShamirSecretSharing::Reconstruct(subset);
        REQUIRE(result.IsErr());
    }

    SECTION("Threshold invalid") {
        shares[0][4] = 1;
        std::vector<std::vector<uint8_t>> subset{shares[0], shares[1], shares[2]};
        auto result = ShamirSecretSharing::Reconstruct(subset);
        REQUIRE(result.IsErr());
    }

    SECTION("Share count invalid") {
        shares[0][5] = 1;
        std::vector<std::vector<uint8_t>> subset{shares[0], shares[1], shares[2]};
        auto result = ShamirSecretSharing::Reconstruct(subset);
        REQUIRE(result.IsErr());
    }

    SECTION("Share index invalid") {
        shares[0][6] = 0;
        std::vector<std::vector<uint8_t>> subset{shares[0], shares[1], shares[2]};
        auto result = ShamirSecretSharing::Reconstruct(subset);
        REQUIRE(result.IsErr());
    }

    SECTION("Secret length header mismatch") {
        shares[0][8] = 0;
        shares[0][9] = 0;
        shares[0][10] = 0;
        shares[0][11] = 0;
        std::vector<std::vector<uint8_t>> subset{shares[0], shares[1], shares[2]};
        auto result = ShamirSecretSharing::Reconstruct(subset);
        REQUIRE(result.IsErr());
    }

    SECTION("Share length truncated") {
        shares[0].pop_back();
        std::vector<std::vector<uint8_t>> subset{shares[0], shares[1], shares[2]};
        auto result = ShamirSecretSharing::Reconstruct(subset);
        REQUIRE(result.IsErr());
    }

    SECTION("Metadata mismatch across shares") {
        shares[1][4] = 2;
        std::vector<std::vector<uint8_t>> subset{shares[0], shares[1], shares[2]};
        auto result = ShamirSecretSharing::Reconstruct(subset);
        REQUIRE(result.IsErr());
    }

    SECTION("Duplicate share index") {
        shares[1][6] = shares[0][6];
        std::vector<std::vector<uint8_t>> subset{shares[0], shares[1], shares[2]};
        auto result = ShamirSecretSharing::Reconstruct(subset);
        REQUIRE(result.IsErr());
    }
}

TEST_CASE("ShamirSecretSharing - ReconstructSerialized validates inputs", "[secret-sharing]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    auto secret = SodiumInterop::GetRandomBytes(16);
    auto split_result = ShamirSecretSharing::Split(secret, 2, 3);
    REQUIRE(split_result.IsOk());
    auto shares = split_result.Unwrap();
    const size_t share_length = shares[0].size();

    std::vector<uint8_t> blob(share_length * shares.size());
    for (size_t i = 0; i < shares.size(); ++i) {
        std::copy(
            shares[i].begin(),
            shares[i].end(),
            blob.begin() + static_cast<ptrdiff_t>(i * share_length));
    }

    SECTION("Zero length") {
        auto result = ShamirSecretSharing::ReconstructSerialized(blob, 0, shares.size());
        REQUIRE(result.IsErr());
    }

    SECTION("Zero count") {
        auto result = ShamirSecretSharing::ReconstructSerialized(blob, share_length, 0);
        REQUIRE(result.IsErr());
    }

    SECTION("Buffer length mismatch") {
        auto result = ShamirSecretSharing::ReconstructSerialized(blob, share_length, shares.size() + 1);
        REQUIRE(result.IsErr());
    }

    SECTION("Authenticated shares require auth key") {
        auto auth_key = SodiumInterop::GetRandomBytes(32);
        auto auth_split = ShamirSecretSharing::Split(secret, 2, 3, auth_key);
        REQUIRE(auth_split.IsOk());
        auto auth_shares = auth_split.Unwrap();
        const size_t auth_share_length = auth_shares[0].size();

        std::vector<uint8_t> auth_blob(auth_share_length * auth_shares.size());
        for (size_t i = 0; i < auth_shares.size(); ++i) {
            std::copy(
                auth_shares[i].begin(),
                auth_shares[i].end(),
                auth_blob.begin() + static_cast<ptrdiff_t>(i * auth_share_length));
        }

        auto result = ShamirSecretSharing::ReconstructSerialized(
            auth_blob,
            auth_share_length,
            auth_shares.size());
        REQUIRE(result.IsErr());
    }

    SECTION("Authenticated shares wrong auth key") {
        auto auth_key = SodiumInterop::GetRandomBytes(32);
        auto other_key = SodiumInterop::GetRandomBytes(32);
        auto auth_split = ShamirSecretSharing::Split(secret, 2, 3, auth_key);
        REQUIRE(auth_split.IsOk());
        auto auth_shares = auth_split.Unwrap();
        const size_t auth_share_length = auth_shares[0].size();

        std::vector<uint8_t> auth_blob(auth_share_length * auth_shares.size());
        for (size_t i = 0; i < auth_shares.size(); ++i) {
            std::copy(
                auth_shares[i].begin(),
                auth_shares[i].end(),
                auth_blob.begin() + static_cast<ptrdiff_t>(i * auth_share_length));
        }

        auto result = ShamirSecretSharing::ReconstructSerialized(
            auth_blob,
            auth_share_length,
            auth_shares.size(),
            other_key);
        REQUIRE(result.IsErr());
    }

    SECTION("Authenticated shares roundtrip") {
        auto auth_key = SodiumInterop::GetRandomBytes(32);
        auto auth_split = ShamirSecretSharing::Split(secret, 2, 3, auth_key);
        REQUIRE(auth_split.IsOk());
        auto auth_shares = auth_split.Unwrap();
        const size_t auth_share_length = auth_shares[0].size();

        std::vector<uint8_t> auth_blob(auth_share_length * auth_shares.size());
        for (size_t i = 0; i < auth_shares.size(); ++i) {
            std::copy(
                auth_shares[i].begin(),
                auth_shares[i].end(),
                auth_blob.begin() + static_cast<ptrdiff_t>(i * auth_share_length));
        }

        auto result = ShamirSecretSharing::ReconstructSerialized(
            auth_blob,
            auth_share_length,
            auth_shares.size(),
            auth_key);
        REQUIRE(result.IsOk());
        REQUIRE(result.Unwrap() == secret);
    }

    SECTION("Invalid auth key length") {
        auto bad_key = SodiumInterop::GetRandomBytes(31);
        auto result = ShamirSecretSharing::ReconstructSerialized(
            blob,
            share_length,
            shares.size(),
            bad_key);
        REQUIRE(result.IsErr());
    }
}
