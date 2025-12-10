#include <catch2/catch_test_macros.hpp>
#include "ecliptix/protocol/connection/ecliptix_protocol_connection.hpp"
#include "ecliptix/crypto/aes_gcm.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include "ecliptix/utilities/envelope_builder.hpp"
#include "ecliptix/core/constants.hpp"
#include "common/secure_envelope.pb.h"
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <unordered_set>
#include <string>

using namespace ecliptix::protocol;
using namespace ecliptix::protocol::connection;
using namespace ecliptix::protocol::crypto;
using namespace ecliptix::protocol::utilities;
using namespace ecliptix::proto::common;

TEST_CASE("Concurrency - Parallel Nonce Generation", "[concurrency][envelope][nonce]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("100 threads generating 1000 nonces each - no collisions") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xAB);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        auto finalize = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize.IsOk());

        constexpr int THREAD_COUNT = 100;
        constexpr int NONCES_PER_THREAD = 1000;

        std::unordered_set<std::string> nonce_set;
        std::mutex nonce_set_mutex;
        std::atomic<bool> collision_detected{false};
        std::atomic<int> total_nonces_generated{0};

        std::vector<std::thread> threads;
        threads.reserve(THREAD_COUNT);

        for (int t = 0; t < THREAD_COUNT; ++t) {
            threads.emplace_back([&]() {
                for (int i = 0; i < NONCES_PER_THREAD; ++i) {
                    auto nonce_result = conn->GenerateNextNonce();
                    if (nonce_result.IsOk()) {
                        auto nonce = std::move(nonce_result).Unwrap();
                        const std::string nonce_str(nonce.begin(), nonce.end());

                        std::lock_guard<std::mutex> lock(nonce_set_mutex);
                        if (nonce_set.find(nonce_str) != nonce_set.end()) {
                            collision_detected.store(true);
                        }
                        nonce_set.insert(nonce_str);
                        total_nonces_generated.fetch_add(1);
                    }
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        REQUIRE_FALSE(collision_detected.load());
        REQUIRE(total_nonces_generated.load() == THREAD_COUNT * NONCES_PER_THREAD);
        REQUIRE(nonce_set.size() == THREAD_COUNT * NONCES_PER_THREAD);
    }
}

TEST_CASE("Concurrency - Parallel Message Preparation", "[concurrency][envelope][send]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("50 threads preparing 500 messages each") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xCD);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        auto finalize = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize.IsOk());

        constexpr int THREAD_COUNT = 50;
        constexpr int MESSAGES_PER_THREAD = 500;

        std::atomic<int> successful_preparations{0};
        std::atomic<int> failed_preparations{0};
        std::unordered_set<uint32_t> message_indices;
        std::mutex indices_mutex;

        std::vector<std::thread> threads;
        threads.reserve(THREAD_COUNT);

        for (int t = 0; t < THREAD_COUNT; ++t) {
            threads.emplace_back([&]() {
                for (int i = 0; i < MESSAGES_PER_THREAD; ++i) {
                    auto prepare_result = conn->PrepareNextSendMessage();
                    if (prepare_result.IsOk()) {
                        auto [chain_key, include_dh] = std::move(prepare_result).Unwrap();

                        {
                            std::lock_guard<std::mutex> lock(indices_mutex);
                            message_indices.insert(chain_key.Index());
                        }

                        successful_preparations.fetch_add(1);
                    } else {
                        failed_preparations.fetch_add(1);
                    }
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        REQUIRE(successful_preparations.load() > 0);
        REQUIRE(message_indices.size() == static_cast<size_t>(successful_preparations.load()));
    }
}

TEST_CASE("Concurrency - Parallel Metadata Encryption", "[concurrency][envelope][metadata]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("50 threads encrypting 1000 metadata blocks each") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0xEF);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        auto finalize = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize.IsOk());

        auto metadata_key_result = conn->GetMetadataEncryptionKey();
        REQUIRE(metadata_key_result.IsOk());
        auto metadata_key = std::move(metadata_key_result).Unwrap();

        constexpr int THREAD_COUNT = 50;
        constexpr int ENCRYPTIONS_PER_THREAD = 1000;

        std::atomic<int> successful_encryptions{0};
        std::atomic<int> failed_encryptions{0};

        std::vector<std::thread> threads;
        threads.reserve(THREAD_COUNT);

        for (int t = 0; t < THREAD_COUNT; ++t) {
            threads.emplace_back([&, thread_id = t]() {
                for (int i = 0; i < ENCRYPTIONS_PER_THREAD; ++i) {
                    const uint32_t msg_id = thread_id * ENCRYPTIONS_PER_THREAD + i;

                    std::vector<uint8_t> nonce(12, static_cast<uint8_t>(msg_id & 0xFF));
                    const EnvelopeMetadata metadata = EnvelopeBuilder::CreateEnvelopeMetadata(
                        msg_id,
                        nonce,
                        msg_id,
                        {},
                        static_cast<EnvelopeType>(0),
                        "concurrent-test"
                    );

                    std::vector<uint8_t> header_nonce(12, 0x42);
                    std::vector<uint8_t> aad{0xAA, 0xBB};

                    auto encrypted_result = EnvelopeBuilder::EncryptMetadata(
                        metadata,
                        metadata_key,
                        header_nonce,
                        aad
                    );

                    if (encrypted_result.IsOk()) {
                        successful_encryptions.fetch_add(1);
                    } else {
                        failed_encryptions.fetch_add(1);
                    }
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        REQUIRE(successful_encryptions.load() == THREAD_COUNT * ENCRYPTIONS_PER_THREAD);
        REQUIRE(failed_encryptions.load() == 0);
    }
}

TEST_CASE("Concurrency - Bidirectional Concurrent Communication", "[concurrency][envelope][bidirectional]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("50 threads each direction - 1000 messages per thread") {
        auto alice_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(alice_result.IsOk());
        auto alice = std::move(alice_result).Unwrap();

        auto bob_result = EcliptixProtocolConnection::Create(2, false);
        REQUIRE(bob_result.IsOk());
        auto bob = std::move(bob_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x12);

        auto alice_dh = alice->GetCurrentSenderDhPublicKey().Unwrap().value();
        auto bob_dh = bob->GetCurrentSenderDhPublicKey().Unwrap().value();

        REQUIRE(alice->FinalizeChainAndDhKeys(root_key, bob_dh).IsOk());
        REQUIRE(bob->FinalizeChainAndDhKeys(root_key, alice_dh).IsOk());

        constexpr int THREAD_COUNT = 50;
        constexpr int MESSAGES_PER_THREAD = 1000;

        std::atomic<int> alice_to_bob_success{0};
        std::atomic<int> bob_to_alice_success{0};

        std::vector<std::thread> alice_threads;
        alice_threads.reserve(THREAD_COUNT);

        for (int t = 0; t < THREAD_COUNT; ++t) {
            alice_threads.emplace_back([&]() {
                for (int i = 0; i < MESSAGES_PER_THREAD; ++i) {
                    auto prepare = alice->PrepareNextSendMessage();
                    if (prepare.IsOk()) {
                        auto nonce_result = alice->GenerateNextNonce();
                        if (nonce_result.IsOk()) {
                            alice_to_bob_success.fetch_add(1);
                        }
                    }
                }
            });
        }

        std::vector<std::thread> bob_threads;
        bob_threads.reserve(THREAD_COUNT);

        for (int t = 0; t < THREAD_COUNT; ++t) {
            bob_threads.emplace_back([&]() {
                for (int i = 0; i < MESSAGES_PER_THREAD; ++i) {
                    auto prepare = bob->PrepareNextSendMessage();
                    if (prepare.IsOk()) {
                        auto nonce_result = bob->GenerateNextNonce();
                        if (nonce_result.IsOk()) {
                            bob_to_alice_success.fetch_add(1);
                        }
                    }
                }
            });
        }

        for (auto& thread : alice_threads) {
            thread.join();
        }

        for (auto& thread : bob_threads) {
            thread.join();
        }

        REQUIRE(alice_to_bob_success.load() > 0);
        REQUIRE(bob_to_alice_success.load() > 0);
    }
}

TEST_CASE("Concurrency - Race Condition Detection", "[concurrency][envelope][race]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("Stress test with 100 threads × 500 operations") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x34);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        auto finalize = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize.IsOk());

        constexpr int THREAD_COUNT = 100;
        constexpr int OPERATIONS_PER_THREAD = 500;

        std::atomic<int> total_operations{0};
        std::atomic<int> concurrent_errors{0};

        std::vector<std::thread> threads;
        threads.reserve(THREAD_COUNT);

        for (int t = 0; t < THREAD_COUNT; ++t) {
            threads.emplace_back([&]() {
                for (int i = 0; i < OPERATIONS_PER_THREAD; ++i) {
                    auto nonce_result = conn->GenerateNextNonce();
                    auto prepare_result = conn->PrepareNextSendMessage();

                    if (nonce_result.IsOk() && prepare_result.IsOk()) {
                        total_operations.fetch_add(1);
                    } else {
                        concurrent_errors.fetch_add(1);
                    }
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        REQUIRE(total_operations.load() > 0);
    }
}

TEST_CASE("Concurrency - Concurrent Replay Protection Checks", "[concurrency][envelope][replay]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("100 threads checking replay protection for 500 unique nonces each") {
        auto conn_result = EcliptixProtocolConnection::Create(1, false);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x56);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        auto finalize = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize.IsOk());

        constexpr int THREAD_COUNT = 100;
        constexpr int CHECKS_PER_THREAD = 500;

        std::atomic<int> replay_checks_passed{0};
        std::atomic<int> replay_checks_failed{0};

        std::vector<std::thread> threads;
        threads.reserve(THREAD_COUNT);

        for (int t = 0; t < THREAD_COUNT; ++t) {
            threads.emplace_back([&, thread_id = t]() {
                for (int i = 0; i < CHECKS_PER_THREAD; ++i) {
                    const uint64_t msg_index = thread_id * CHECKS_PER_THREAD + i;

                    std::vector<uint8_t> nonce(12);
                    for (size_t j = 0; j < 8; ++j) {
                        nonce[j] = static_cast<uint8_t>((msg_index >> (j * 8)) & 0xFF);
                    }
                    nonce[8] = static_cast<uint8_t>(thread_id & 0xFF);
                    nonce[9] = static_cast<uint8_t>((thread_id >> 8) & 0xFF);
                    nonce[10] = static_cast<uint8_t>(i & 0xFF);
                    nonce[11] = static_cast<uint8_t>((i >> 8) & 0xFF);

                    auto check_result = conn->CheckReplayProtection(nonce, msg_index);
                    if (check_result.IsOk()) {
                        replay_checks_passed.fetch_add(1);
                    } else {
                        replay_checks_failed.fetch_add(1);
                    }
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }

        REQUIRE(replay_checks_passed.load() > 0);
    }
}

TEST_CASE("Concurrency - Concurrent Metadata Encryption and Decryption", "[concurrency][envelope][roundtrip]") {
    REQUIRE(SodiumInterop::Initialize().IsOk());

    SECTION("20 threads encrypting + 20 threads decrypting - 1000 envelopes each") {
        auto conn_result = EcliptixProtocolConnection::Create(1, true);
        REQUIRE(conn_result.IsOk());
        auto conn = std::move(conn_result).Unwrap();

        std::vector<uint8_t> root_key(Constants::X_25519_KEY_SIZE, 0x78);
        auto peer_keypair = SodiumInterop::GenerateX25519KeyPair("peer");
        REQUIRE(peer_keypair.IsOk());
        auto [peer_sk, peer_pk] = std::move(peer_keypair).Unwrap();

        auto finalize = conn->FinalizeChainAndDhKeys(root_key, peer_pk);
        REQUIRE(finalize.IsOk());

        auto metadata_key = conn->GetMetadataEncryptionKey().Unwrap();

        constexpr int ENCRYPTING_THREADS = 20;
        constexpr int DECRYPTING_THREADS = 20;
        constexpr int OPERATIONS_PER_THREAD = 1000;

        struct EnvelopePacket {
            std::vector<uint8_t> encrypted;
            std::vector<uint8_t> header_nonce;
            std::vector<uint8_t> aad;
        };

        std::vector<EnvelopePacket> packets;
        std::mutex packets_mutex;

        std::atomic<int> successful_encryptions{0};
        std::atomic<int> successful_decryptions{0};

        std::vector<std::thread> encrypt_threads;
        encrypt_threads.reserve(ENCRYPTING_THREADS);

        for (int t = 0; t < ENCRYPTING_THREADS; ++t) {
            encrypt_threads.emplace_back([&, thread_id = t]() {
                for (int i = 0; i < OPERATIONS_PER_THREAD; ++i) {
                    const uint32_t msg_id = thread_id * OPERATIONS_PER_THREAD + i;

                    std::vector<uint8_t> nonce(12, static_cast<uint8_t>(msg_id & 0xFF));
                    const EnvelopeMetadata metadata = EnvelopeBuilder::CreateEnvelopeMetadata(
                        msg_id, nonce, msg_id, {}, static_cast<EnvelopeType>(0), "");

                    std::vector<uint8_t> header_nonce(12, static_cast<uint8_t>((msg_id >> 8) & 0xFF));
                    std::vector<uint8_t> aad{0xCC, static_cast<uint8_t>(msg_id & 0xFF)};

                    auto encrypted_result = EnvelopeBuilder::EncryptMetadata(
                        metadata, metadata_key, header_nonce, aad);

                    if (encrypted_result.IsOk()) {
                        auto encrypted = std::move(encrypted_result).Unwrap();

                        {
                            std::lock_guard<std::mutex> lock(packets_mutex);
                            packets.push_back(EnvelopePacket{
                                encrypted,
                                header_nonce,
                                aad
                            });
                        }

                        successful_encryptions.fetch_add(1);
                    }
                }
            });
        }

        for (auto& thread : encrypt_threads) {
            thread.join();
        }

        std::vector<std::thread> decrypt_threads;
        decrypt_threads.reserve(DECRYPTING_THREADS);

        for (int t = 0; t < DECRYPTING_THREADS; ++t) {
            decrypt_threads.emplace_back([&]() {
                while (true) {
                    EnvelopePacket packet;
                    bool has_packet = false;

                    {
                        std::lock_guard<std::mutex> lock(packets_mutex);
                        if (!packets.empty()) {
                            packet = std::move(packets.back());
                            packets.pop_back();
                            has_packet = true;
                        }
                    }

                    if (!has_packet) {
                        break;
                    }

                    auto decrypted_result = EnvelopeBuilder::DecryptMetadata(
                        packet.encrypted,
                        metadata_key,
                        packet.header_nonce,
                        packet.aad
                    );

                    if (decrypted_result.IsOk()) {
                        successful_decryptions.fetch_add(1);
                    }
                }
            });
        }

        for (auto& thread : decrypt_threads) {
            thread.join();
        }

        REQUIRE(successful_encryptions.load() == ENCRYPTING_THREADS * OPERATIONS_PER_THREAD);
        REQUIRE(successful_decryptions.load() == successful_encryptions.load());
    }
}
