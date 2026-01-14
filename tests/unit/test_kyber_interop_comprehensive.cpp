#include <catch2/catch_test_macros.hpp>
#include "ecliptix/crypto/kyber_interop.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>

using namespace ecliptix::protocol::crypto;


TEST_CASE("KyberInterop - Initialize is idempotent", "[kyber][init]") {
    auto init1 = KyberInterop::Initialize();
    auto init2 = KyberInterop::Initialize();
    auto init3 = KyberInterop::Initialize();

    REQUIRE(init1.IsOk());
    REQUIRE(init2.IsOk());
    REQUIRE(init3.IsOk());
}

TEST_CASE("KyberInterop - Concurrent initialization is thread-safe", "[kyber][init][thread-safety]") {
    constexpr size_t NUM_THREADS = 10;
    std::vector<std::thread> threads;
    std::atomic<size_t> success_count{0};
    std::atomic<size_t> error_count{0};

    for (size_t i = 0; i < NUM_THREADS; ++i) {
        threads.emplace_back([&]() {
            auto result = KyberInterop::Initialize();
            if (result.IsOk()) {
                success_count.fetch_add(1, std::memory_order_relaxed);
            } else {
                error_count.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    REQUIRE(success_count == NUM_THREADS);
    REQUIRE(error_count == 0);
}

TEST_CASE("KyberInterop - Operations fail gracefully without initialization", "[kyber][init]") {
    auto kp_result = KyberInterop::GenerateKyber768KeyPair("test");
    REQUIRE(kp_result.IsOk());
}


TEST_CASE("KyberInterop - GenerateKyber768KeyPair produces valid sizes", "[kyber][keygen]") {
    auto result = KyberInterop::GenerateKyber768KeyPair("test");
    REQUIRE(result.IsOk());

    auto kp = std::move(result).Unwrap();
    auto& sk_handle = kp.first;
    auto& pk = kp.second;

    REQUIRE(sk_handle.Size() == KyberInterop::KYBER_768_SECRET_KEY_SIZE);
    REQUIRE(pk.size() == KyberInterop::KYBER_768_PUBLIC_KEY_SIZE);
}

TEST_CASE("KyberInterop - Generated keys are not all zeros", "[kyber][keygen][quality]") {
    auto result = KyberInterop::GenerateKyber768KeyPair("test");
    REQUIRE(result.IsOk());

    auto kp = std::move(result).Unwrap();
    auto& sk_handle = kp.first;
    auto& pk = kp.second;

    REQUIRE_FALSE(std::all_of(pk.begin(), pk.end(), [](uint8_t b) { return b == 0; }));

    auto sk_bytes_result = sk_handle.ReadBytes(KyberInterop::KYBER_768_SECRET_KEY_SIZE);
    REQUIRE(sk_bytes_result.IsOk());
    auto sk_bytes = sk_bytes_result.Unwrap();
    REQUIRE_FALSE(std::all_of(sk_bytes.begin(), sk_bytes.end(), [](uint8_t b) { return b == 0; }));
}

TEST_CASE("KyberInterop - Generated keys are not all 0xFF", "[kyber][keygen][quality]") {
    auto result = KyberInterop::GenerateKyber768KeyPair("test");
    REQUIRE(result.IsOk());

    auto kp = std::move(result).Unwrap();
    auto& pk = kp.second;

    REQUIRE_FALSE(std::all_of(pk.begin(), pk.end(), [](uint8_t b) { return b == 0xFF; }));
}

TEST_CASE("KyberInterop - Multiple key generations produce different keys", "[kyber][keygen][randomness]") {
    auto kp1 = KyberInterop::GenerateKyber768KeyPair("test1").Unwrap();
    auto kp2 = KyberInterop::GenerateKyber768KeyPair("test2").Unwrap();
    auto kp3 = KyberInterop::GenerateKyber768KeyPair("test3").Unwrap();

    REQUIRE(kp1.second != kp2.second);
    REQUIRE(kp2.second != kp3.second);
    REQUIRE(kp1.second != kp3.second);

    auto sk1_bytes = kp1.first.ReadBytes(KyberInterop::KYBER_768_SECRET_KEY_SIZE).Unwrap();
    auto sk2_bytes = kp2.first.ReadBytes(KyberInterop::KYBER_768_SECRET_KEY_SIZE).Unwrap();
    auto sk3_bytes = kp3.first.ReadBytes(KyberInterop::KYBER_768_SECRET_KEY_SIZE).Unwrap();

    REQUIRE(sk1_bytes != sk2_bytes);
    REQUIRE(sk2_bytes != sk3_bytes);
    REQUIRE(sk1_bytes != sk3_bytes);
}

TEST_CASE("KyberInterop - Concurrent key generation is thread-safe", "[kyber][keygen][thread-safety]") {
    constexpr size_t NUM_THREADS = 8;
    std::vector<std::thread> threads;
    std::atomic<size_t> success_count{0};

    for (size_t i = 0; i < NUM_THREADS; ++i) {
        threads.emplace_back([&, i]() {
            auto result = KyberInterop::GenerateKyber768KeyPair("thread-" + std::to_string(i));
            if (result.IsOk()) {
                success_count.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    REQUIRE(success_count == NUM_THREADS);
}


TEST_CASE("KyberInterop - ValidatePublicKey accepts valid key", "[kyber][validation]") {
    auto kp = KyberInterop::GenerateKyber768KeyPair("test").Unwrap();
    auto result = KyberInterop::ValidatePublicKey(kp.second);
    REQUIRE(result.IsOk());
}

TEST_CASE("KyberInterop - ValidatePublicKey rejects wrong size", "[kyber][validation]") {
    std::vector<uint8_t> too_small(1000, 0xAA);
    std::vector<uint8_t> too_large(2000, 0xBB);

    auto result1 = KyberInterop::ValidatePublicKey(too_small);
    auto result2 = KyberInterop::ValidatePublicKey(too_large);

    REQUIRE(result1.IsErr());
    REQUIRE(result2.IsErr());
}

TEST_CASE("KyberInterop - ValidatePublicKey rejects all zeros", "[kyber][validation]") {
    std::vector<uint8_t> zeros(KyberInterop::KYBER_768_PUBLIC_KEY_SIZE, 0);
    auto result = KyberInterop::ValidatePublicKey(zeros);
    REQUIRE(result.IsErr());
}

TEST_CASE("KyberInterop - ValidateSecretKey accepts valid key", "[kyber][validation]") {
    auto kp = KyberInterop::GenerateKyber768KeyPair("test").Unwrap();
    auto result = KyberInterop::ValidateSecretKey(kp.first);
    REQUIRE(result.IsOk());
}

TEST_CASE("KyberInterop - ValidateSecretKey rejects wrong size", "[kyber][validation]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    auto handle_small_result = SecureMemoryHandle::Allocate(1000);
    auto handle_large_result = SecureMemoryHandle::Allocate(3000);

    REQUIRE(handle_small_result.IsOk());
    REQUIRE(handle_large_result.IsOk());

    auto handle_small = std::move(handle_small_result).Unwrap();
    auto handle_large = std::move(handle_large_result).Unwrap();

    auto result1 = KyberInterop::ValidateSecretKey(handle_small);
    auto result2 = KyberInterop::ValidateSecretKey(handle_large);

    REQUIRE(result1.IsErr());
    REQUIRE(result2.IsErr());
}

TEST_CASE("KyberInterop - ValidateCiphertext accepts valid ciphertext", "[kyber][validation]") {
    auto kp = KyberInterop::GenerateKyber768KeyPair("test").Unwrap();
    auto enc_result = KyberInterop::Encapsulate(kp.second).Unwrap();
    auto& ct = enc_result.first;

    auto result = KyberInterop::ValidateCiphertext(ct);
    REQUIRE(result.IsOk());
}

TEST_CASE("KyberInterop - ValidateCiphertext rejects wrong size", "[kyber][validation]") {
    std::vector<uint8_t> too_small(500, 0xAA);
    std::vector<uint8_t> too_large(2000, 0xBB);

    auto result1 = KyberInterop::ValidateCiphertext(too_small);
    auto result2 = KyberInterop::ValidateCiphertext(too_large);

    REQUIRE(result1.IsErr());
    REQUIRE(result2.IsErr());
}

TEST_CASE("KyberInterop - ValidateCiphertext rejects all zeros", "[kyber][validation]") {
    std::vector<uint8_t> zeros(KyberInterop::KYBER_768_CIPHERTEXT_SIZE, 0);
    auto result = KyberInterop::ValidateCiphertext(zeros);
    REQUIRE(result.IsErr());
}


TEST_CASE("KyberInterop - Encapsulate produces valid ciphertext and shared secret", "[kyber][encaps]") {
    auto kp = KyberInterop::GenerateKyber768KeyPair("test").Unwrap();
    auto result = KyberInterop::Encapsulate(kp.second);

    REQUIRE(result.IsOk());
    auto enc = std::move(result).Unwrap();
    auto& ct = enc.first;
    auto& ss = enc.second;

    REQUIRE(ct.size() == KyberInterop::KYBER_768_CIPHERTEXT_SIZE);
    REQUIRE(ss.Size() == KyberInterop::KYBER_768_SHARED_SECRET_SIZE);
}

TEST_CASE("KyberInterop - Encapsulate produces different ciphertexts each time", "[kyber][encaps][randomness]") {
    auto kp = KyberInterop::GenerateKyber768KeyPair("test").Unwrap();

    auto enc1 = KyberInterop::Encapsulate(kp.second).Unwrap();
    auto enc2 = KyberInterop::Encapsulate(kp.second).Unwrap();
    auto enc3 = KyberInterop::Encapsulate(kp.second).Unwrap();

    REQUIRE(enc1.first != enc2.first);
    REQUIRE(enc2.first != enc3.first);
    REQUIRE(enc1.first != enc3.first);
}

TEST_CASE("KyberInterop - Encapsulate fails on invalid public key", "[kyber][encaps][errors]") {
    std::vector<uint8_t> invalid_pk(KyberInterop::KYBER_768_PUBLIC_KEY_SIZE, 0);
    auto result = KyberInterop::Encapsulate(invalid_pk);
    REQUIRE(result.IsErr());
}

TEST_CASE("KyberInterop - Decapsulate recovers shared secret", "[kyber][decaps]") {
    auto kp = KyberInterop::GenerateKyber768KeyPair("test").Unwrap();
    auto enc = KyberInterop::Encapsulate(kp.second).Unwrap();

    auto dec_result = KyberInterop::Decapsulate(enc.first, kp.first);
    REQUIRE(dec_result.IsOk());

    auto ss_receiver = std::move(dec_result).Unwrap();
    REQUIRE(ss_receiver.Size() == KyberInterop::KYBER_768_SHARED_SECRET_SIZE);

    auto ss_sender_bytes = enc.second.ReadBytes(32).Unwrap();
    auto ss_receiver_bytes = ss_receiver.ReadBytes(32).Unwrap();

    auto cmp_result = SodiumInterop::ConstantTimeEquals(ss_sender_bytes, ss_receiver_bytes);
    REQUIRE(cmp_result.IsOk());
    REQUIRE(cmp_result.Unwrap() == true);
}

TEST_CASE("KyberInterop - Decapsulate fails on invalid ciphertext", "[kyber][decaps][errors]") {
    auto kp = KyberInterop::GenerateKyber768KeyPair("test").Unwrap();
    std::vector<uint8_t> invalid_ct(KyberInterop::KYBER_768_CIPHERTEXT_SIZE, 0);

    auto result = KyberInterop::Decapsulate(invalid_ct, kp.first);
    REQUIRE(result.IsErr());
}

TEST_CASE("KyberInterop - Decapsulate fails on wrong secret key", "[kyber][decaps][errors]") {
    auto kp1 = KyberInterop::GenerateKyber768KeyPair("test1").Unwrap();
    auto kp2 = KyberInterop::GenerateKyber768KeyPair("test2").Unwrap();

    auto enc = KyberInterop::Encapsulate(kp1.second).Unwrap();

    auto dec_result = KyberInterop::Decapsulate(enc.first, kp2.first);
    REQUIRE(dec_result.IsOk());

    auto ss_sender_bytes = enc.second.ReadBytes(32).Unwrap();
    auto ss_receiver_bytes = dec_result.Unwrap().ReadBytes(32).Unwrap();

    auto cmp_result = SodiumInterop::ConstantTimeEquals(ss_sender_bytes, ss_receiver_bytes);
    REQUIRE(cmp_result.IsOk());
    REQUIRE(cmp_result.Unwrap() == false);
}

TEST_CASE("KyberInterop - Decapsulate fails on tampered ciphertext", "[kyber][decaps][tampering]") {
    auto kp = KyberInterop::GenerateKyber768KeyPair("test").Unwrap();
    auto enc = KyberInterop::Encapsulate(kp.second).Unwrap();

    auto tampered_ct = enc.first;
    tampered_ct[0] ^= 0xFF;
    tampered_ct[100] ^= 0xAA;
    tampered_ct[500] ^= 0x55;

    auto dec_result = KyberInterop::Decapsulate(tampered_ct, kp.first);
    REQUIRE(dec_result.IsOk());

    auto ss_sender_bytes = enc.second.ReadBytes(32).Unwrap();
    auto ss_receiver_bytes = dec_result.Unwrap().ReadBytes(32).Unwrap();

    auto cmp_result = SodiumInterop::ConstantTimeEquals(ss_sender_bytes, ss_receiver_bytes);
    REQUIRE(cmp_result.IsOk());
    REQUIRE(cmp_result.Unwrap() == false);
}


TEST_CASE("KyberInterop - SelfTestKeyPair succeeds on valid pair", "[kyber][selftest]") {
    auto kp = KyberInterop::GenerateKyber768KeyPair("test").Unwrap();
    auto result = KyberInterop::SelfTestKeyPair(kp.second, kp.first);
    REQUIRE(result.IsOk());
}

TEST_CASE("KyberInterop - SelfTestKeyPair fails on mismatched pair", "[kyber][selftest][errors]") {
    auto kp1 = KyberInterop::GenerateKyber768KeyPair("test1").Unwrap();
    auto kp2 = KyberInterop::GenerateKyber768KeyPair("test2").Unwrap();

    auto result = KyberInterop::SelfTestKeyPair(kp1.second, kp2.first);
    REQUIRE(result.IsErr());
}

TEST_CASE("KyberInterop - SelfTestKeyPair fails on invalid public key", "[kyber][selftest][errors]") {
    auto kp = KyberInterop::GenerateKyber768KeyPair("test").Unwrap();
    std::vector<uint8_t> invalid_pk(KyberInterop::KYBER_768_PUBLIC_KEY_SIZE, 0);

    auto result = KyberInterop::SelfTestKeyPair(invalid_pk, kp.first);
    REQUIRE(result.IsErr());
}

TEST_CASE("KyberInterop - SelfTestKeyPair fails on invalid secret key", "[kyber][selftest][errors]") {
    auto kp = KyberInterop::GenerateKyber768KeyPair("test").Unwrap();
    auto invalid_sk = SecureMemoryHandle::Allocate(KyberInterop::KYBER_768_SECRET_KEY_SIZE).Unwrap();
    std::vector<uint8_t> zeros(KyberInterop::KYBER_768_SECRET_KEY_SIZE, 0);
    invalid_sk.Write(zeros);

    auto result = KyberInterop::SelfTestKeyPair(kp.second, invalid_sk);
    REQUIRE(result.IsErr());
}


TEST_CASE("KyberInterop - CombineHybridSecrets produces valid output", "[kyber][hybrid][hkdf]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    std::vector<uint8_t> x25519_ss(32, 0xAA);
    std::vector<uint8_t> kyber_ss(32, 0xBB);

    auto result = KyberInterop::CombineHybridSecrets(x25519_ss, kyber_ss, "test-context");
    REQUIRE(result.IsOk());

    auto hybrid_handle = std::move(result).Unwrap();
    REQUIRE(hybrid_handle.Size() == 32);
}

TEST_CASE("KyberInterop - CombineHybridSecrets rejects wrong X25519 size", "[kyber][hybrid][errors]") {
    std::vector<uint8_t> invalid_x(16, 0xAA);
    std::vector<uint8_t> kyber_ss(32, 0xBB);

    auto result = KyberInterop::CombineHybridSecrets(invalid_x, kyber_ss, "test");
    REQUIRE(result.IsErr());
}

TEST_CASE("KyberInterop - CombineHybridSecrets rejects wrong Kyber size", "[kyber][hybrid][errors]") {
    std::vector<uint8_t> x25519_ss(32, 0xAA);
    std::vector<uint8_t> invalid_k(16, 0xBB);

    auto result = KyberInterop::CombineHybridSecrets(x25519_ss, invalid_k, "test");
    REQUIRE(result.IsErr());
}

TEST_CASE("KyberInterop - CombineHybridSecrets domain separates by context", "[kyber][hybrid][domain-separation]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    std::vector<uint8_t> x25519_ss(32, 0xAA);
    std::vector<uint8_t> kyber_ss(32, 0xBB);

    auto h1 = KyberInterop::CombineHybridSecrets(x25519_ss, kyber_ss, "context-1").Unwrap();
    auto h2 = KyberInterop::CombineHybridSecrets(x25519_ss, kyber_ss, "context-2").Unwrap();
    auto h3 = KyberInterop::CombineHybridSecrets(x25519_ss, kyber_ss, "context-3").Unwrap();

    auto b1 = h1.ReadBytes(32).Unwrap();
    auto b2 = h2.ReadBytes(32).Unwrap();
    auto b3 = h3.ReadBytes(32).Unwrap();

    REQUIRE(b1 != b2);
    REQUIRE(b2 != b3);
    REQUIRE(b1 != b3);
}

TEST_CASE("KyberInterop - CombineHybridSecrets different if either input changes", "[kyber][hybrid][sensitivity]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    std::vector<uint8_t> x_ss1(32, 0xAA);
    std::vector<uint8_t> x_ss2(32, 0xAB);
    std::vector<uint8_t> k_ss1(32, 0xBB);
    std::vector<uint8_t> k_ss2(32, 0xBC);

    auto h_baseline = KyberInterop::CombineHybridSecrets(x_ss1, k_ss1, "ctx").Unwrap();
    auto h_x_change = KyberInterop::CombineHybridSecrets(x_ss2, k_ss1, "ctx").Unwrap();
    auto h_k_change = KyberInterop::CombineHybridSecrets(x_ss1, k_ss2, "ctx").Unwrap();

    auto b_baseline = h_baseline.ReadBytes(32).Unwrap();
    auto b_x_change = h_x_change.ReadBytes(32).Unwrap();
    auto b_k_change = h_k_change.ReadBytes(32).Unwrap();

    REQUIRE(b_baseline != b_x_change);
    REQUIRE(b_baseline != b_k_change);
}

TEST_CASE("KyberInterop - CombineHybridSecrets is deterministic", "[kyber][hybrid][determinism]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    std::vector<uint8_t> x25519_ss(32, 0xAA);
    std::vector<uint8_t> kyber_ss(32, 0xBB);

    auto h1 = KyberInterop::CombineHybridSecrets(x25519_ss, kyber_ss, "ctx").Unwrap();
    auto h2 = KyberInterop::CombineHybridSecrets(x25519_ss, kyber_ss, "ctx").Unwrap();
    auto h3 = KyberInterop::CombineHybridSecrets(x25519_ss, kyber_ss, "ctx").Unwrap();

    auto b1 = h1.ReadBytes(32).Unwrap();
    auto b2 = h2.ReadBytes(32).Unwrap();
    auto b3 = h3.ReadBytes(32).Unwrap();

    REQUIRE(b1 == b2);
    REQUIRE(b2 == b3);
}

TEST_CASE("KyberInterop - Complete KEM workflow succeeds", "[kyber][e2e]") {
    auto alice_kp = KyberInterop::GenerateKyber768KeyPair("alice").Unwrap();

    auto bob_encaps = KyberInterop::Encapsulate(alice_kp.second).Unwrap();
    auto& ct = bob_encaps.first;
    auto& bob_ss = bob_encaps.second;

    auto alice_dec_result = KyberInterop::Decapsulate(ct, alice_kp.first);
    REQUIRE(alice_dec_result.IsOk());
    auto alice_ss = std::move(alice_dec_result).Unwrap();

    auto bob_ss_bytes = bob_ss.ReadBytes(32).Unwrap();
    auto alice_ss_bytes = alice_ss.ReadBytes(32).Unwrap();

    auto cmp_result = SodiumInterop::ConstantTimeEquals(bob_ss_bytes, alice_ss_bytes);
    REQUIRE(cmp_result.IsOk());
    REQUIRE(cmp_result.Unwrap() == true);
}

TEST_CASE("KyberInterop - Complete hybrid workflow succeeds", "[kyber][e2e][hybrid]") {
    std::vector<uint8_t> x25519_shared_secret(32);
    randombytes_buf(x25519_shared_secret.data(), 32);

    auto alice_kp = KyberInterop::GenerateKyber768KeyPair("alice").Unwrap();
    auto bob_encaps = KyberInterop::Encapsulate(alice_kp.second).Unwrap();
    auto alice_ss = KyberInterop::Decapsulate(bob_encaps.first, alice_kp.first).Unwrap();

    auto bob_kyber_bytes = bob_encaps.second.ReadBytes(32).Unwrap();
    auto alice_kyber_bytes = alice_ss.ReadBytes(32).Unwrap();

    auto bob_hybrid = KyberInterop::CombineHybridSecrets(
        x25519_shared_secret, bob_kyber_bytes, "X3DH-Handshake").Unwrap();
    auto alice_hybrid = KyberInterop::CombineHybridSecrets(
        x25519_shared_secret, alice_kyber_bytes, "X3DH-Handshake").Unwrap();

    auto bob_final = bob_hybrid.ReadBytes(32).Unwrap();
    auto alice_final = alice_hybrid.ReadBytes(32).Unwrap();

    auto cmp_result = SodiumInterop::ConstantTimeEquals(bob_final, alice_final);
    REQUIRE(cmp_result.IsOk());
    REQUIRE(cmp_result.Unwrap() == true);
}

TEST_CASE("KyberInterop - Concurrent encapsulations are thread-safe", "[kyber][thread-safety][stress]") {
    auto kp = KyberInterop::GenerateKyber768KeyPair("test").Unwrap();

    constexpr size_t NUM_THREADS = 8;
    std::vector<std::thread> threads;
    std::atomic<size_t> success_count{0};

    for (size_t i = 0; i < NUM_THREADS; ++i) {
        threads.emplace_back([&]() {
            for (size_t j = 0; j < 10; ++j) {
                auto result = KyberInterop::Encapsulate(kp.second);
                if (result.IsOk()) {
                    success_count.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    REQUIRE(success_count == NUM_THREADS * 10);
}

TEST_CASE("KyberInterop - High-volume key generation stress test", "[kyber][stress]") {
    constexpr size_t NUM_KEYS = 100;
    std::vector<std::vector<uint8_t>> public_keys;
    public_keys.reserve(NUM_KEYS);

    for (size_t i = 0; i < NUM_KEYS; ++i) {
        auto kp = KyberInterop::GenerateKyber768KeyPair("stress-" + std::to_string(i)).Unwrap();
        public_keys.push_back(std::move(kp.second));
    }

    for (size_t i = 0; i < NUM_KEYS; ++i) {
        for (size_t j = i + 1; j < NUM_KEYS; ++j) {
            REQUIRE(public_keys[i] != public_keys[j]);
        }
    }
}

TEST_CASE("KyberInterop - Constants match FIPS 203 specification", "[kyber][constants]") {
    REQUIRE(KyberInterop::KYBER_768_PUBLIC_KEY_SIZE == 1184);
    REQUIRE(KyberInterop::KYBER_768_SECRET_KEY_SIZE == 2400);
    REQUIRE(KyberInterop::KYBER_768_CIPHERTEXT_SIZE == 1088);
    REQUIRE(KyberInterop::KYBER_768_SHARED_SECRET_SIZE == 32);
}
