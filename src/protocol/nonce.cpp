#include "ecliptix/protocol/nonce.hpp"
#include "ecliptix/crypto/sodium_interop.hpp"
#include <algorithm>

namespace ecliptix::protocol {
    using crypto::SodiumInterop;

    namespace {
        constexpr size_t kNonceSize = kNoncePrefixBytes + kNonceCounterBytes + kNonceIndexBytes;
        static_assert(kNonceSize == kAesGcmNonceBytes, "Nonce layout must match AES-GCM nonce size");
    }

    NonceGenerator::NonceGenerator(State state)
        : state_(state) {
    }

    Result<NonceGenerator, ProtocolFailure> NonceGenerator::Create() {
        auto random = SodiumInterop::GetRandomBytes(kNoncePrefixBytes);
        if (random.size() != kNoncePrefixBytes) {
            return Result<NonceGenerator, ProtocolFailure>::Err(
                ProtocolFailure::Generic("Failed to generate nonce prefix"));
        }
        State state;
        std::copy(random.begin(), random.end(), state.prefix.begin());
        state.counter = 0;
        return Result<NonceGenerator, ProtocolFailure>::Ok(NonceGenerator(state));
    }

    Result<NonceGenerator, ProtocolFailure> NonceGenerator::FromState(const State& state) {
        if (state.counter > kMaxNonceCounter) {
            return Result<NonceGenerator, ProtocolFailure>::Err(
                ProtocolFailure::InvalidState("Nonce counter exceeds maximum"));
        }
        return Result<NonceGenerator, ProtocolFailure>::Ok(NonceGenerator(state));
    }

    Result<std::vector<uint8_t>, ProtocolFailure> NonceGenerator::Next(uint64_t message_index) {
        if (message_index > kMaxMessageIndex) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidInput("Message index exceeds nonce encoding limits"));
        }
        if (state_.counter > kMaxNonceCounter) {
            return Result<std::vector<uint8_t>, ProtocolFailure>::Err(
                ProtocolFailure::InvalidState("Nonce counter overflow - rotate keys"));
        }

        std::vector<uint8_t> nonce(kAesGcmNonceBytes);
        std::copy(state_.prefix.begin(), state_.prefix.end(), nonce.begin());

        const uint32_t counter32 = static_cast<uint32_t>(state_.counter);
        for (size_t i = 0; i < kNonceCounterBytes; ++i) {
            nonce[kNoncePrefixBytes + i] = static_cast<uint8_t>((counter32 >> (i * 8)) & 0xFF);
        }

        const uint32_t index32 = static_cast<uint32_t>(message_index);
        for (size_t i = 0; i < kNonceIndexBytes; ++i) {
            nonce[kNoncePrefixBytes + kNonceCounterBytes + i] =
                static_cast<uint8_t>((index32 >> (i * 8)) & 0xFF);
        }

        state_.counter += 1;
        return Result<std::vector<uint8_t>, ProtocolFailure>::Ok(std::move(nonce));
    }

    NonceGenerator::State NonceGenerator::ExportState() const {
        return state_;
    }

}
