#include <catch2/catch_test_macros.hpp>
#include "ecliptix/crypto/aes_gcm.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/core/constants.hpp"
using namespace ecliptix::protocol;
using namespace ecliptix::protocol::crypto;
TEST_CASE("AES-GCM - Basic encryption and decryption", "[aes_gcm]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    SECTION("Encrypt and decrypt round-trip") {
        std::vector<uint8_t> key(kAesKeyBytes, 0xAA);
        std::vector<uint8_t> nonce(kAesGcmNonceBytes, 0xBB);
        std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
        std::vector<uint8_t> ad = {'a', 'd'};
        auto encrypt_result = AesGcm::Encrypt(key, nonce, plaintext, ad);
        REQUIRE(encrypt_result.IsOk());
        auto ciphertext_with_tag = encrypt_result.Unwrap();
        REQUIRE(ciphertext_with_tag.size() == plaintext.size() + kAesGcmTagBytes);
        auto decrypt_result = AesGcm::Decrypt(key, nonce, ciphertext_with_tag, ad);
        REQUIRE(decrypt_result.IsOk());
        auto decrypted = decrypt_result.Unwrap();
        REQUIRE(decrypted == plaintext);
    }
    SECTION("Empty plaintext") {
        std::vector<uint8_t> key(kAesKeyBytes, 0x11);
        std::vector<uint8_t> nonce(kAesGcmNonceBytes, 0x22);
        std::vector<uint8_t> plaintext = {};
        auto encrypt_result = AesGcm::Encrypt(key, nonce, plaintext);
        REQUIRE(encrypt_result.IsOk());
        auto ciphertext = encrypt_result.Unwrap();
        REQUIRE(ciphertext.size() == kAesGcmTagBytes);
        auto decrypt_result = AesGcm::Decrypt(key, nonce, ciphertext);
        REQUIRE(decrypt_result.IsOk());
        REQUIRE(decrypt_result.Unwrap().empty());
    }
    SECTION("Large plaintext") {
        std::vector<uint8_t> key(kAesKeyBytes, 0x33);
        std::vector<uint8_t> nonce(kAesGcmNonceBytes, 0x44);
        std::vector<uint8_t> plaintext(10000, 0x55);
        auto encrypt_result = AesGcm::Encrypt(key, nonce, plaintext);
        REQUIRE(encrypt_result.IsOk());
        auto decrypt_result = AesGcm::Decrypt(key, nonce, encrypt_result.Unwrap());
        REQUIRE(decrypt_result.IsOk());
        REQUIRE(decrypt_result.Unwrap() == plaintext);
    }
}
TEST_CASE("AES-GCM - Authentication failures", "[aes_gcm]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    std::vector<uint8_t> key(kAesKeyBytes, 0x66);
    std::vector<uint8_t> nonce(kAesGcmNonceBytes, 0x77);
    std::vector<uint8_t> plaintext = {'s', 'e', 'c', 'r', 'e', 't'};
    std::vector<uint8_t> ad = {'c', 'o', 'n', 't', 'e', 'x', 't'};
    auto encrypt_result = AesGcm::Encrypt(key, nonce, plaintext, ad);
    REQUIRE(encrypt_result.IsOk());
    auto ciphertext = encrypt_result.Unwrap();
    SECTION("Wrong key") {
        std::vector<uint8_t> wrong_key(kAesKeyBytes, 0x99);
        auto result = AesGcm::Decrypt(wrong_key, nonce, ciphertext, ad);
        REQUIRE(result.IsErr());
    }
    SECTION("Wrong nonce") {
        std::vector<uint8_t> wrong_nonce(kAesGcmNonceBytes, 0x88);
        auto result = AesGcm::Decrypt(key, wrong_nonce, ciphertext, ad);
        REQUIRE(result.IsErr());
    }
    SECTION("Wrong associated data") {
        std::vector<uint8_t> wrong_ad = {'w', 'r', 'o', 'n', 'g'};
        auto result = AesGcm::Decrypt(key, nonce, ciphertext, wrong_ad);
        REQUIRE(result.IsErr());
    }
    SECTION("Tampered ciphertext") {
        auto tampered = ciphertext;
        tampered[0] ^= 0x01;  
        auto result = AesGcm::Decrypt(key, nonce, tampered, ad);
        REQUIRE(result.IsErr());
    }
    SECTION("Tampered tag") {
        auto tampered = ciphertext;
        tampered[tampered.size() - 1] ^= 0x01;  
        auto result = AesGcm::Decrypt(key, nonce, tampered, ad);
        REQUIRE(result.IsErr());
    }
}
TEST_CASE("AES-GCM - Input validation", "[aes_gcm]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    std::vector<uint8_t> valid_key(kAesKeyBytes, 0xAA);
    std::vector<uint8_t> valid_nonce(kAesGcmNonceBytes, 0xBB);
    std::vector<uint8_t> plaintext = {'t', 'e', 's', 't'};
    SECTION("Invalid key size") {
        std::vector<uint8_t> short_key(16, 0xCC);  
        auto result = AesGcm::Encrypt(short_key, valid_nonce, plaintext);
        REQUIRE(result.IsErr());
    }
    SECTION("Invalid nonce size") {
        std::vector<uint8_t> short_nonce(8, 0xDD);
        auto result = AesGcm::Encrypt(valid_key, short_nonce, plaintext);
        REQUIRE(result.IsErr());
    }
    SECTION("Ciphertext too short for decryption") {
        std::vector<uint8_t> too_short(10, 0xEE);  
        auto result = AesGcm::Decrypt(valid_key, valid_nonce, too_short);
        REQUIRE(result.IsErr());
    }
}
TEST_CASE("AES-GCM - Associated data variations", "[aes_gcm]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());
    std::vector<uint8_t> key(kAesKeyBytes, 0xFF);
    std::vector<uint8_t> nonce(kAesGcmNonceBytes, 0xEE);
    std::vector<uint8_t> plaintext = {'d', 'a', 't', 'a'};
    SECTION("No associated data") {
        auto encrypt_result = AesGcm::Encrypt(key, nonce, plaintext);
        REQUIRE(encrypt_result.IsOk());
        auto decrypt_result = AesGcm::Decrypt(key, nonce, encrypt_result.Unwrap());
        REQUIRE(decrypt_result.IsOk());
        REQUIRE(decrypt_result.Unwrap() == plaintext);
    }
    SECTION("With associated data") {
        std::vector<uint8_t> ad = {'m', 'e', 't', 'a', 'd', 'a', 't', 'a'};
        auto encrypt_result = AesGcm::Encrypt(key, nonce, plaintext, ad);
        REQUIRE(encrypt_result.IsOk());
        auto decrypt_result = AesGcm::Decrypt(key, nonce, encrypt_result.Unwrap(), ad);
        REQUIRE(decrypt_result.IsOk());
        REQUIRE(decrypt_result.Unwrap() == plaintext);
    }
    SECTION("Decrypt with AD when encrypted without fails") {
        auto encrypt_result = AesGcm::Encrypt(key, nonce, plaintext);
        REQUIRE(encrypt_result.IsOk());
        std::vector<uint8_t> ad = {'a', 'd'};
        auto decrypt_result = AesGcm::Decrypt(key, nonce, encrypt_result.Unwrap(), ad);
        REQUIRE(decrypt_result.IsErr());  
    }
}
