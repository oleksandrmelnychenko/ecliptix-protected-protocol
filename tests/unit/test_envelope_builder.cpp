#include <catch2/catch_test_macros.hpp>
#include "ecliptix/utilities/envelope_builder.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/core/constants.hpp"
#include "common/secure_envelope.pb.h"
using namespace ecliptix::protocol;
using namespace ecliptix::protocol::utilities;
TEST_CASE("EnvelopeBuilder - CreateEnvelopeMetadata", "[envelope_builder]") {
    REQUIRE(crypto::SodiumInterop::Initialize().IsOk());
    SECTION("Create metadata with all required fields") {
        uint32_t request_id = 12345;
        std::vector<uint8_t> nonce(12, 0xAA);
        uint32_t ratchet_index = 42;
        std::vector<uint8_t> channel_key_id(16, 0xBB);
        auto envelope_type = ecliptix::proto::common::EnvelopeType::REQUEST;
        std::string correlation_id = "test-correlation-123";
        auto metadata = EnvelopeBuilder::CreateEnvelopeMetadata(
            request_id,
            nonce,
            ratchet_index,
            channel_key_id,
            envelope_type,
            correlation_id);
        REQUIRE(metadata.envelope_id() == "12345");
        REQUIRE(metadata.nonce().size() == 12);
        REQUIRE(metadata.nonce() == std::string(nonce.begin(), nonce.end()));
        REQUIRE(metadata.ratchet_index() == 42);
        REQUIRE(metadata.channel_key_id().size() == 16);
        REQUIRE(metadata.channel_key_id() == std::string(channel_key_id.begin(), channel_key_id.end()));
        REQUIRE(metadata.envelope_type() == ecliptix::proto::common::EnvelopeType::REQUEST);
        REQUIRE(metadata.correlation_id() == "test-correlation-123");
    }
    SECTION("Create metadata with auto-generated channel key ID") {
        uint32_t request_id = 999;
        std::vector<uint8_t> nonce(12, 0xCC);
        uint32_t ratchet_index = 1;
        auto metadata = EnvelopeBuilder::CreateEnvelopeMetadata(
            request_id,
            nonce,
            ratchet_index);
        REQUIRE(metadata.channel_key_id().size() == 16);
        REQUIRE(metadata.envelope_id() == "999");
        REQUIRE(metadata.ratchet_index() == 1);
    }
    SECTION("Create metadata with empty correlation ID") {
        uint32_t request_id = 5555;
        std::vector<uint8_t> nonce(12, 0xDD);
        uint32_t ratchet_index = 10;
        auto metadata = EnvelopeBuilder::CreateEnvelopeMetadata(
            request_id,
            nonce,
            ratchet_index);
        REQUIRE(metadata.correlation_id().empty());
    }
    SECTION("Auto-generated channel key IDs are unique") {
        std::vector<uint8_t> nonce(12, 0xEE);
        auto metadata1 = EnvelopeBuilder::CreateEnvelopeMetadata(1, nonce, 0);
        auto metadata2 = EnvelopeBuilder::CreateEnvelopeMetadata(2, nonce, 0);
        REQUIRE(metadata1.channel_key_id() != metadata2.channel_key_id());
    }
}
TEST_CASE("EnvelopeBuilder - EncryptMetadata and DecryptMetadata", "[envelope_builder]") {
    REQUIRE(crypto::SodiumInterop::Initialize().IsOk());
    SECTION("Encrypt and decrypt round-trip") {
        std::vector<uint8_t> nonce(12, 0x11);
        auto metadata = EnvelopeBuilder::CreateEnvelopeMetadata(
            12345,
            nonce,
            42,
            {},
            ecliptix::proto::common::EnvelopeType::REQUEST,
            "correlation-test");
        std::vector<uint8_t> header_key(kAesKeyBytes, 0x22);
        std::vector<uint8_t> header_nonce(kAesGcmNonceBytes, 0x33);
        std::vector<uint8_t> associated_data = {'a', 'd', '_', 't', 'e', 's', 't'};
        auto encrypt_result = EnvelopeBuilder::EncryptMetadata(
            metadata,
            header_key,
            header_nonce,
            associated_data);
        REQUIRE(encrypt_result.IsOk());
        auto encrypted = encrypt_result.Unwrap();
        size_t expected_min_size = kAesGcmTagBytes;
        REQUIRE(encrypted.size() > expected_min_size);
        auto decrypt_result = EnvelopeBuilder::DecryptMetadata(
            encrypted,
            header_key,
            header_nonce,
            associated_data);
        REQUIRE(decrypt_result.IsOk());
        auto decrypted = decrypt_result.Unwrap();
        REQUIRE(decrypted.envelope_id() == metadata.envelope_id());
        REQUIRE(decrypted.nonce() == metadata.nonce());
        REQUIRE(decrypted.ratchet_index() == metadata.ratchet_index());
        REQUIRE(decrypted.channel_key_id() == metadata.channel_key_id());
        REQUIRE(decrypted.envelope_type() == metadata.envelope_type());
        REQUIRE(decrypted.correlation_id() == metadata.correlation_id());
    }
    SECTION("Encrypt metadata without associated data") {
        std::vector<uint8_t> nonce(12, 0x44);
        auto metadata = EnvelopeBuilder::CreateEnvelopeMetadata(
            999,
            nonce,
            10);
        std::vector<uint8_t> header_key(kAesKeyBytes, 0x55);
        std::vector<uint8_t> header_nonce(kAesGcmNonceBytes, 0x66);
        auto encrypt_result = EnvelopeBuilder::EncryptMetadata(
            metadata,
            header_key,
            header_nonce,
            {});
        REQUIRE(encrypt_result.IsOk());
        auto decrypt_result = EnvelopeBuilder::DecryptMetadata(
            encrypt_result.Unwrap(),
            header_key,
            header_nonce,
            {});
        REQUIRE(decrypt_result.IsOk());
        REQUIRE(decrypt_result.Unwrap().envelope_id() == "999");
    }
    SECTION("Large metadata encryption") {
        std::vector<uint8_t> nonce(12, 0x77);
        std::string large_correlation_id(10000, 'X');  
        auto metadata = EnvelopeBuilder::CreateEnvelopeMetadata(
            8888,
            nonce,
            100,
            {},
            ecliptix::proto::common::EnvelopeType::RESPONSE,
            large_correlation_id);
        std::vector<uint8_t> header_key(kAesKeyBytes, 0x88);
        std::vector<uint8_t> header_nonce(kAesGcmNonceBytes, 0x99);
        auto encrypt_result = EnvelopeBuilder::EncryptMetadata(
            metadata,
            header_key,
            header_nonce,
            {});
        REQUIRE(encrypt_result.IsOk());
        auto decrypt_result = EnvelopeBuilder::DecryptMetadata(
            encrypt_result.Unwrap(),
            header_key,
            header_nonce,
            {});
        REQUIRE(decrypt_result.IsOk());
        REQUIRE(decrypt_result.Unwrap().correlation_id() == large_correlation_id);
    }
}
TEST_CASE("EnvelopeBuilder - Decryption authentication failures", "[envelope_builder]") {
    REQUIRE(crypto::SodiumInterop::Initialize().IsOk());
    std::vector<uint8_t> nonce(12, 0xAA);
    auto metadata = EnvelopeBuilder::CreateEnvelopeMetadata(
        777,
        nonce,
        5,
        {},
        ecliptix::proto::common::EnvelopeType::REQUEST,
        "auth-test");
    std::vector<uint8_t> header_key(kAesKeyBytes, 0xBB);
    std::vector<uint8_t> header_nonce(kAesGcmNonceBytes, 0xCC);
    std::vector<uint8_t> associated_data = {'c', 'o', 'n', 't', 'e', 'x', 't'};
    auto encrypted = EnvelopeBuilder::EncryptMetadata(
        metadata,
        header_key,
        header_nonce,
        associated_data).Unwrap();
    SECTION("Decrypt with wrong key fails") {
        std::vector<uint8_t> wrong_key(kAesKeyBytes, 0xFF);
        auto result = EnvelopeBuilder::DecryptMetadata(
            encrypted,
            wrong_key,
            header_nonce,
            associated_data);
        REQUIRE(result.IsErr());
    }
    SECTION("Decrypt with wrong nonce fails") {
        std::vector<uint8_t> wrong_nonce(kAesGcmNonceBytes, 0xFF);
        auto result = EnvelopeBuilder::DecryptMetadata(
            encrypted,
            header_key,
            wrong_nonce,
            associated_data);
        REQUIRE(result.IsErr());
    }
    SECTION("Decrypt with wrong associated data fails") {
        std::vector<uint8_t> wrong_ad = {'w', 'r', 'o', 'n', 'g'};
        auto result = EnvelopeBuilder::DecryptMetadata(
            encrypted,
            header_key,
            header_nonce,
            wrong_ad);
        REQUIRE(result.IsErr());
    }
    SECTION("Decrypt with tampered ciphertext fails") {
        auto tampered = encrypted;
        tampered[0] ^= 0x01;  
        auto result = EnvelopeBuilder::DecryptMetadata(
            tampered,
            header_key,
            header_nonce,
            associated_data);
        REQUIRE(result.IsErr());
    }
    SECTION("Decrypt with tampered tag fails") {
        auto tampered = encrypted;
        tampered[tampered.size() - 1] ^= 0x01;  
        auto result = EnvelopeBuilder::DecryptMetadata(
            tampered,
            header_key,
            header_nonce,
            associated_data);
        REQUIRE(result.IsErr());
    }
    SECTION("Decrypt with no AD when encrypted with AD fails") {
        auto result = EnvelopeBuilder::DecryptMetadata(
            encrypted,
            header_key,
            header_nonce,
            {});  
        REQUIRE(result.IsErr());
    }
}
TEST_CASE("EnvelopeBuilder - Invalid inputs", "[envelope_builder]") {
    REQUIRE(crypto::SodiumInterop::Initialize().IsOk());
    std::vector<uint8_t> nonce(12, 0xDD);
    auto valid_metadata = EnvelopeBuilder::CreateEnvelopeMetadata(
        100,
        nonce,
        1);
    SECTION("Encrypt with invalid key size") {
        std::vector<uint8_t> short_key(16, 0xEE);  
        std::vector<uint8_t> valid_nonce(kAesGcmNonceBytes, 0xFF);
        auto result = EnvelopeBuilder::EncryptMetadata(
            valid_metadata,
            short_key,
            valid_nonce,
            {});
        REQUIRE(result.IsErr());
    }
    SECTION("Encrypt with invalid nonce size") {
        std::vector<uint8_t> valid_key(kAesKeyBytes, 0xAA);
        std::vector<uint8_t> short_nonce(8, 0xBB);  
        auto result = EnvelopeBuilder::EncryptMetadata(
            valid_metadata,
            valid_key,
            short_nonce,
            {});
        REQUIRE(result.IsErr());
    }
    SECTION("Decrypt with ciphertext too short") {
        std::vector<uint8_t> valid_key(kAesKeyBytes, 0xCC);
        std::vector<uint8_t> valid_nonce(kAesGcmNonceBytes, 0xDD);
        std::vector<uint8_t> too_short(10, 0xEE);  
        auto result = EnvelopeBuilder::DecryptMetadata(
            too_short,
            valid_key,
            valid_nonce,
            {});
        REQUIRE(result.IsErr());
    }
}
