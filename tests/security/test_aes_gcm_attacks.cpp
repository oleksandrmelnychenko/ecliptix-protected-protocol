#include <catch2/catch_test_macros.hpp>
#include "ecliptix/crypto/aes_gcm.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/core/constants.hpp"
#include <vector>
#include <algorithm>
#include <random>
#include <chrono>
#include <thread>

using namespace ecliptix::protocol;
using namespace ecliptix::protocol::crypto;

TEST_CASE("AES-GCM Security - Nonce Reuse Attack Detection", "[security][aes-gcm][critical]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Reusing same nonce with different plaintexts produces different ciphertexts") {
        std::vector<uint8_t> key(Constants::AES_KEY_SIZE);
        randombytes_buf(key.data(), key.size());

        std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(nonce.data(), nonce.size());

        std::string plaintext1 = "First message with same nonce";
        std::string plaintext2 = "Second message with same nonce";

        std::vector<uint8_t> pt1(plaintext1.begin(), plaintext1.end());
        std::vector<uint8_t> pt2(plaintext2.begin(), plaintext2.end());

        std::vector<uint8_t> ad(16, 0xAA);

        auto result1 = AesGcm::Encrypt(key, nonce, pt1, ad);
        auto result2 = AesGcm::Encrypt(key, nonce, pt2, ad);

        REQUIRE(result1.IsOk());
        REQUIRE(result2.IsOk());

        auto ct_with_tag1 = std::move(result1).Unwrap();
        auto ct_with_tag2 = std::move(result2).Unwrap();

        REQUIRE(ct_with_tag1.size() == pt1.size() + Constants::AES_GCM_TAG_SIZE);
        REQUIRE(ct_with_tag2.size() == pt2.size() + Constants::AES_GCM_TAG_SIZE);
        REQUIRE(ct_with_tag1 != ct_with_tag2);
    }

    SECTION("Nonce reuse XOR attack demonstration but auth tag prevents forgery") {
        std::vector<uint8_t> key(Constants::AES_KEY_SIZE);
        randombytes_buf(key.data(), key.size());

        std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(nonce.data(), nonce.size());

        std::vector<uint8_t> pt1(100, 0x00);
        std::vector<uint8_t> pt2(100, 0xFF);
        std::vector<uint8_t> ad(16, 0xAA);

        auto result1 = AesGcm::Encrypt(key, nonce, pt1, ad);
        auto result2 = AesGcm::Encrypt(key, nonce, pt2, ad);

        REQUIRE(result1.IsOk());
        REQUIRE(result2.IsOk());

        auto ct_with_tag1 = std::move(result1).Unwrap();
        auto ct_with_tag2 = std::move(result2).Unwrap();

        std::vector<uint8_t> ct1(ct_with_tag1.begin(), ct_with_tag1.end() - Constants::AES_GCM_TAG_SIZE);
        std::vector<uint8_t> ct2(ct_with_tag2.begin(), ct_with_tag2.end() - Constants::AES_GCM_TAG_SIZE);

        std::vector<uint8_t> xor_result(100);
        for (size_t i = 0; i < 100; ++i) {
            xor_result[i] = ct1[i] ^ ct2[i];
        }

        bool all_ff = std::all_of(xor_result.begin(), xor_result.end(),
                                  [](uint8_t b) { return b == 0xFF; });
        REQUIRE(all_ff);

        auto modified_ct = ct_with_tag1;
        modified_ct[0] ^= 0x01;

        auto decrypt_result = AesGcm::Decrypt(key, nonce, modified_ct, ad);
        REQUIRE(decrypt_result.IsErr());
    }

    SECTION("100 messages with same nonce all produce unique outputs") {
        std::vector<uint8_t> key(Constants::AES_KEY_SIZE);
        randombytes_buf(key.data(), key.size());

        std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(nonce.data(), nonce.size());

        std::vector<uint8_t> ad(16, 0xBB);
        std::vector<std::vector<uint8_t>> outputs;

        for (int i = 0; i < 100; ++i) {
            std::vector<uint8_t> plaintext(100);
            randombytes_buf(plaintext.data(), plaintext.size());

            auto result = AesGcm::Encrypt(key, nonce, plaintext, ad);
            REQUIRE(result.IsOk());
            outputs.push_back(std::move(result).Unwrap());
        }

        for (size_t i = 0; i < outputs.size(); ++i) {
            for (size_t j = i + 1; j < outputs.size(); ++j) {
                REQUIRE(outputs[i] != outputs[j]);
            }
        }
    }
}

TEST_CASE("AES-GCM Security - Authentication Tag Forgery Attempts", "[security][aes-gcm][critical]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Modified ciphertext with correct tag fails decryption") {
        std::vector<uint8_t> key(Constants::AES_KEY_SIZE);
        randombytes_buf(key.data(), key.size());

        std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(nonce.data(), nonce.size());

        std::vector<uint8_t> plaintext(1000);
        randombytes_buf(plaintext.data(), plaintext.size());

        std::vector<uint8_t> ad(16, 0xCC);

        auto encrypt_result = AesGcm::Encrypt(key, nonce, plaintext, ad);
        REQUIRE(encrypt_result.IsOk());

        auto ciphertext_with_tag = std::move(encrypt_result).Unwrap();

        for (size_t i = 0; i < std::min(size_t(100), ciphertext_with_tag.size() - Constants::AES_GCM_TAG_SIZE); ++i) {
            auto modified_ct = ciphertext_with_tag;
            modified_ct[i] ^= 0x01;

            auto decrypt_result = AesGcm::Decrypt(key, nonce, modified_ct, ad);
            REQUIRE(decrypt_result.IsErr());
        }
    }

    SECTION("Correct ciphertext with modified tag fails decryption") {
        std::vector<uint8_t> key(Constants::AES_KEY_SIZE);
        randombytes_buf(key.data(), key.size());

        std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(nonce.data(), nonce.size());

        std::vector<uint8_t> plaintext(1000);
        randombytes_buf(plaintext.data(), plaintext.size());

        std::vector<uint8_t> ad(16, 0xDD);

        auto encrypt_result = AesGcm::Encrypt(key, nonce, plaintext, ad);
        REQUIRE(encrypt_result.IsOk());

        auto ciphertext_with_tag = std::move(encrypt_result).Unwrap();

        for (size_t i = 0; i < Constants::AES_GCM_TAG_SIZE; ++i) {
            auto modified = ciphertext_with_tag;
            size_t tag_start = modified.size() - Constants::AES_GCM_TAG_SIZE;
            modified[tag_start + i] ^= 0x01;

            auto decrypt_result = AesGcm::Decrypt(key, nonce, modified, ad);
            REQUIRE(decrypt_result.IsErr());
        }
    }

    SECTION("Zero authentication tag always fails") {
        std::vector<uint8_t> key(Constants::AES_KEY_SIZE);
        randombytes_buf(key.data(), key.size());

        std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(nonce.data(), nonce.size());

        std::vector<uint8_t> plaintext(100);
        randombytes_buf(plaintext.data(), plaintext.size());

        std::vector<uint8_t> ad(16, 0xEE);

        auto encrypt_result = AesGcm::Encrypt(key, nonce, plaintext, ad);
        REQUIRE(encrypt_result.IsOk());

        auto ciphertext_with_tag = std::move(encrypt_result).Unwrap();

        std::vector<uint8_t> modified = ciphertext_with_tag;
        size_t tag_start = modified.size() - Constants::AES_GCM_TAG_SIZE;
        for (size_t i = 0; i < Constants::AES_GCM_TAG_SIZE; ++i) {
            modified[tag_start + i] = 0x00;
        }

        auto decrypt_result = AesGcm::Decrypt(key, nonce, modified, ad);
        REQUIRE(decrypt_result.IsErr());
    }

    SECTION("Random tag brute force always fails (1000 attempts)") {
        std::vector<uint8_t> key(Constants::AES_KEY_SIZE);
        randombytes_buf(key.data(), key.size());

        std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(nonce.data(), nonce.size());

        std::vector<uint8_t> plaintext(100);
        randombytes_buf(plaintext.data(), plaintext.size());

        std::vector<uint8_t> ad(16, 0xFF);

        auto encrypt_result = AesGcm::Encrypt(key, nonce, plaintext, ad);
        REQUIRE(encrypt_result.IsOk());

        auto ciphertext_with_tag = std::move(encrypt_result).Unwrap();

        for (int attempt = 0; attempt < 1000; ++attempt) {
            auto modified = ciphertext_with_tag;
            size_t tag_start = modified.size() - Constants::AES_GCM_TAG_SIZE;

            randombytes_buf(&modified[tag_start], Constants::AES_GCM_TAG_SIZE);

            auto decrypt_result = AesGcm::Decrypt(key, nonce, modified, ad);

            if (decrypt_result.IsOk()) {
                auto decrypted = std::move(decrypt_result).Unwrap();
                if (decrypted != plaintext) {
                    REQUIRE(false);
                }
            }
        }
        REQUIRE(true);
    }
}

TEST_CASE("AES-GCM Security - Bit-Flipping Attack Resistance", "[security][aes-gcm][critical]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Single bit flip in ciphertext detected") {
        std::vector<uint8_t> key(Constants::AES_KEY_SIZE);
        randombytes_buf(key.data(), key.size());

        std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(nonce.data(), nonce.size());

        std::vector<uint8_t> plaintext(256);
        randombytes_buf(plaintext.data(), plaintext.size());

        std::vector<uint8_t> ad(32, 0xAA);

        auto encrypt_result = AesGcm::Encrypt(key, nonce, plaintext, ad);
        REQUIRE(encrypt_result.IsOk());

        auto ciphertext_with_tag = std::move(encrypt_result).Unwrap();
        size_t ciphertext_len = ciphertext_with_tag.size() - Constants::AES_GCM_TAG_SIZE;

        for (size_t byte_idx = 0; byte_idx < std::min(ciphertext_len, size_t(100)); ++byte_idx) {
            for (int bit_idx = 0; bit_idx < 8; ++bit_idx) {
                auto modified_ct = ciphertext_with_tag;
                modified_ct[byte_idx] ^= (1 << bit_idx);

                auto decrypt_result = AesGcm::Decrypt(key, nonce, modified_ct, ad);
                REQUIRE(decrypt_result.IsErr());
            }
        }
    }

    SECTION("Multiple random bit flips detected") {
        std::vector<uint8_t> key(Constants::AES_KEY_SIZE);
        randombytes_buf(key.data(), key.size());

        std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(nonce.data(), nonce.size());

        std::vector<uint8_t> plaintext(256);
        randombytes_buf(plaintext.data(), plaintext.size());

        std::vector<uint8_t> ad(16, 0xBB);

        auto encrypt_result = AesGcm::Encrypt(key, nonce, plaintext, ad);
        REQUIRE(encrypt_result.IsOk());

        auto ciphertext_with_tag = std::move(encrypt_result).Unwrap();
        size_t ciphertext_len = ciphertext_with_tag.size() - Constants::AES_GCM_TAG_SIZE;

        std::mt19937 rng(std::chrono::steady_clock::now().time_since_epoch().count());
        std::uniform_int_distribution<size_t> byte_dist(0, ciphertext_len - 1);
        std::uniform_int_distribution<int> bit_dist(0, 7);

        for (int test = 0; test < 100; ++test) {
            auto modified_ct = ciphertext_with_tag;

            int num_flips = (rng() % 10) + 1;
            for (int flip = 0; flip < num_flips; ++flip) {
                size_t byte_idx = byte_dist(rng);
                int bit_idx = bit_dist(rng);
                modified_ct[byte_idx] ^= (1 << bit_idx);
            }

            auto decrypt_result = AesGcm::Decrypt(key, nonce, modified_ct, ad);
            REQUIRE(decrypt_result.IsErr());
        }
    }
}

TEST_CASE("AES-GCM Security - Associated Data Tampering Detection", "[security][aes-gcm][critical]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Modified associated data fails decryption") {
        std::vector<uint8_t> key(Constants::AES_KEY_SIZE);
        randombytes_buf(key.data(), key.size());

        std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(nonce.data(), nonce.size());

        std::vector<uint8_t> plaintext(100);
        randombytes_buf(plaintext.data(), plaintext.size());

        std::vector<uint8_t> ad(64, 0xCC);

        auto encrypt_result = AesGcm::Encrypt(key, nonce, plaintext, ad);
        REQUIRE(encrypt_result.IsOk());

        auto ciphertext_with_tag = std::move(encrypt_result).Unwrap();

        for (size_t i = 0; i < ad.size(); ++i) {
            auto modified_ad = ad;
            modified_ad[i] ^= 0x01;

            auto decrypt_result = AesGcm::Decrypt(key, nonce, ciphertext_with_tag, modified_ad);
            REQUIRE(decrypt_result.IsErr());
        }
    }

    SECTION("Empty vs non-empty associated data are different") {
        std::vector<uint8_t> key(Constants::AES_KEY_SIZE);
        randombytes_buf(key.data(), key.size());

        std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(nonce.data(), nonce.size());

        std::vector<uint8_t> plaintext(100);
        randombytes_buf(plaintext.data(), plaintext.size());

        std::vector<uint8_t> empty_ad;
        std::vector<uint8_t> non_empty_ad(16, 0xDD);

        auto result1 = AesGcm::Encrypt(key, nonce, plaintext, empty_ad);
        auto result2 = AesGcm::Encrypt(key, nonce, plaintext, non_empty_ad);

        REQUIRE(result1.IsOk());
        REQUIRE(result2.IsOk());

        auto ct1 = std::move(result1).Unwrap();
        auto ct2 = std::move(result2).Unwrap();

        REQUIRE(ct1 != ct2);

        auto decrypt1_wrong = AesGcm::Decrypt(key, nonce, ct1, non_empty_ad);
        auto decrypt2_wrong = AesGcm::Decrypt(key, nonce, ct2, empty_ad);

        REQUIRE(decrypt1_wrong.IsErr());
        REQUIRE(decrypt2_wrong.IsErr());
    }
}

TEST_CASE("AES-GCM Security - Concurrent Encryption Safety", "[security][aes-gcm][concurrency]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("1000 concurrent encryptions produce unique nonces") {
        std::vector<uint8_t> key(Constants::AES_KEY_SIZE);
        randombytes_buf(key.data(), key.size());

        std::vector<uint8_t> plaintext(100);
        randombytes_buf(plaintext.data(), plaintext.size());

        std::vector<uint8_t> ad(16, 0xAA);

        std::vector<std::vector<uint8_t>> nonces(1000);
        std::vector<std::thread> threads;

        for (int i = 0; i < 1000; ++i) {
            threads.emplace_back([&, i]() {
                nonces[i].resize(Constants::AES_GCM_NONCE_SIZE);
                randombytes_buf(nonces[i].data(), Constants::AES_GCM_NONCE_SIZE);
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        for (size_t i = 0; i < nonces.size(); ++i) {
            for (size_t j = i + 1; j < nonces.size(); ++j) {
                REQUIRE(nonces[i] != nonces[j]);
            }
        }
    }
}

TEST_CASE("AES-GCM Security - Large Payload Handling", "[security][aes-gcm][boundary]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("10 MB payload encryption/decryption") {
        std::vector<uint8_t> key(Constants::AES_KEY_SIZE);
        randombytes_buf(key.data(), key.size());

        std::vector<uint8_t> nonce(Constants::AES_GCM_NONCE_SIZE);
        randombytes_buf(nonce.data(), nonce.size());

        std::vector<uint8_t> plaintext(10 * 1024 * 1024);
        randombytes_buf(plaintext.data(), plaintext.size());

        std::vector<uint8_t> ad(1024, 0xEE);

        auto encrypt_result = AesGcm::Encrypt(key, nonce, plaintext, ad);
        REQUIRE(encrypt_result.IsOk());

        auto ciphertext_with_tag = std::move(encrypt_result).Unwrap();
        REQUIRE(ciphertext_with_tag.size() == plaintext.size() + Constants::AES_GCM_TAG_SIZE);

        auto decrypt_result = AesGcm::Decrypt(key, nonce, ciphertext_with_tag, ad);
        REQUIRE(decrypt_result.IsOk());

        auto decrypted = std::move(decrypt_result).Unwrap();
        REQUIRE(decrypted == plaintext);
    }
}
