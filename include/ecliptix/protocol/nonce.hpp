#pragma once
#include "ecliptix/core/failures.hpp"
#include "ecliptix/core/result.hpp"
#include "ecliptix/protocol/constants.hpp"
#include <array>
#include <cstdint>
#include <vector>

namespace ecliptix::protocol {

class NonceGenerator {
public:
    struct State {
        std::array<uint8_t, kNoncePrefixBytes> prefix{};
        uint64_t counter = 0;
    };

    [[nodiscard]] static Result<NonceGenerator, ProtocolFailure> Create();
    [[nodiscard]] static Result<NonceGenerator, ProtocolFailure> FromState(const State& state);

    [[nodiscard]] Result<std::vector<uint8_t>, ProtocolFailure> Next(uint64_t message_index);

    [[nodiscard]] State ExportState() const;

private:
    explicit NonceGenerator(State state);

    State state_{};
};

}  // namespace ecliptix::protocol
