#include <catch2/catch_test_macros.hpp>
#include "ecliptix/configuration/protocol_config.hpp"

using namespace ecliptix::protocol::configuration;

TEST_CASE("ProtocolConfig - Factory Methods", "[config][security]") {
    SECTION("ClassicalOnly creates Classical security level") {
        auto config = ProtocolConfig::ClassicalOnly();
        REQUIRE(config.GetSecurityLevel() == SecurityLevel::Classical);
        REQUIRE_FALSE(config.IsPqEnabled());
        REQUIRE_FALSE(config.IsPuncturableEnabled());
        REQUIRE_FALSE(config.IsZkEnabled());
    }

    SECTION("PostQuantumOnly creates PostQuantum security level") {
        auto config = ProtocolConfig::PostQuantumOnly();
        REQUIRE(config.GetSecurityLevel() == SecurityLevel::PostQuantum);
        REQUIRE(config.IsPqEnabled());
        REQUIRE_FALSE(config.IsPuncturableEnabled());
        REQUIRE_FALSE(config.IsZkEnabled());
    }

    SECTION("PuncturableOnly creates Puncturable security level") {
        auto config = ProtocolConfig::PuncturableOnly();
        REQUIRE(config.GetSecurityLevel() == SecurityLevel::Puncturable);
        REQUIRE(config.IsPqEnabled());
        REQUIRE(config.IsPuncturableEnabled());
        REQUIRE_FALSE(config.IsZkEnabled());
    }

    SECTION("MaximumSecurity creates ZeroKnowledge security level") {
        auto config = ProtocolConfig::MaximumSecurity();
        REQUIRE(config.GetSecurityLevel() == SecurityLevel::ZeroKnowledge);
        REQUIRE(config.IsPqEnabled());
        REQUIRE(config.IsPuncturableEnabled());
        REQUIRE(config.IsZkEnabled());
    }

    SECTION("Default creates Classical security level") {
        auto config = ProtocolConfig::Default();
        REQUIRE(config.GetSecurityLevel() == SecurityLevel::Classical);
        REQUIRE_FALSE(config.IsPqEnabled());
        REQUIRE_FALSE(config.IsPuncturableEnabled());
        REQUIRE_FALSE(config.IsZkEnabled());
    }
}

TEST_CASE("ProtocolConfig - Feature Flags", "[config][security]") {
    SECTION("Classical disables all advanced features") {
        auto config = ProtocolConfig::ClassicalOnly();
        REQUIRE_FALSE(config.IsPqEnabled());
        REQUIRE_FALSE(config.IsPuncturableEnabled());
        REQUIRE_FALSE(config.IsZkEnabled());
    }

    SECTION("PostQuantum enables PQ only") {
        auto config = ProtocolConfig::PostQuantumOnly();
        REQUIRE(config.IsPqEnabled());
        REQUIRE_FALSE(config.IsPuncturableEnabled());
        REQUIRE_FALSE(config.IsZkEnabled());
    }

    SECTION("Puncturable enables PQ and Puncturable, not ZK") {
        auto config = ProtocolConfig::PuncturableOnly();
        REQUIRE(config.IsPqEnabled());
        REQUIRE(config.IsPuncturableEnabled());
        REQUIRE_FALSE(config.IsZkEnabled());
    }

    SECTION("ZeroKnowledge enables all features (additive layers)") {
        auto config = ProtocolConfig::MaximumSecurity();
        REQUIRE(config.IsPqEnabled());
        REQUIRE(config.IsPuncturableEnabled());
        REQUIRE(config.IsZkEnabled());
    }
}

TEST_CASE("ProtocolConfig - Performance Estimates", "[config][performance]") {
    SECTION("Classical has zero overhead (baseline)") {
        auto config = ProtocolConfig::ClassicalOnly();
        REQUIRE(config.EstimateHandshakeOverheadUs() == 0);
        REQUIRE(config.EstimateMessageOverheadUs() == 0);
        REQUIRE(config.EstimateMemoryOverheadBytes() == 0);
    }

    SECTION("PostQuantum has measurable handshake and memory overhead") {
        auto config = ProtocolConfig::PostQuantumOnly();
        REQUIRE(config.EstimateHandshakeOverheadUs() == 140);
        REQUIRE(config.EstimateMessageOverheadUs() == 10);
        REQUIRE(config.EstimateMemoryOverheadBytes() == 2400);
    }

    SECTION("Puncturable adds GGM tree overhead") {
        auto config = ProtocolConfig::PuncturableOnly();
        REQUIRE(config.EstimateHandshakeOverheadUs() == 200);
        REQUIRE(config.EstimateMessageOverheadUs() == 70);
        REQUIRE(config.EstimateMemoryOverheadBytes() == 6400);
    }

    SECTION("ZeroKnowledge has significant message overhead (proof generation)") {
        auto config = ProtocolConfig::MaximumSecurity();
        REQUIRE(config.EstimateHandshakeOverheadUs() == 200);
        REQUIRE(config.EstimateMessageOverheadUs() == 150'070);
        REQUIRE(config.EstimateMemoryOverheadBytes() == 10'400);
    }

    SECTION("Overhead increases monotonically with security level") {
        auto classical = ProtocolConfig::ClassicalOnly();
        auto pq = ProtocolConfig::PostQuantumOnly();
        auto puncturable = ProtocolConfig::PuncturableOnly();
        auto zk = ProtocolConfig::MaximumSecurity();

        REQUIRE(classical.EstimateHandshakeOverheadUs() < pq.EstimateHandshakeOverheadUs());
        REQUIRE(pq.EstimateHandshakeOverheadUs() <= puncturable.EstimateHandshakeOverheadUs());
        REQUIRE(puncturable.EstimateHandshakeOverheadUs() <= zk.EstimateHandshakeOverheadUs());

        REQUIRE(classical.EstimateMessageOverheadUs() < pq.EstimateMessageOverheadUs());
        REQUIRE(pq.EstimateMessageOverheadUs() < puncturable.EstimateMessageOverheadUs());
        REQUIRE(puncturable.EstimateMessageOverheadUs() < zk.EstimateMessageOverheadUs());

        REQUIRE(classical.EstimateMemoryOverheadBytes() < pq.EstimateMemoryOverheadBytes());
        REQUIRE(pq.EstimateMemoryOverheadBytes() < puncturable.EstimateMemoryOverheadBytes());
        REQUIRE(puncturable.EstimateMemoryOverheadBytes() < zk.EstimateMemoryOverheadBytes());
    }
}

TEST_CASE("ProtocolConfig - Comparison Operators", "[config]") {
    auto classical = ProtocolConfig::ClassicalOnly();
    auto pq = ProtocolConfig::PostQuantumOnly();
    auto puncturable = ProtocolConfig::PuncturableOnly();
    auto zk = ProtocolConfig::MaximumSecurity();

    SECTION("Equality comparison") {
        auto pq2 = ProtocolConfig::PostQuantumOnly();
        REQUIRE(pq == pq2);
        REQUIRE_FALSE(pq == classical);
        REQUIRE_FALSE(pq == puncturable);
    }

    SECTION("Inequality comparison") {
        REQUIRE(classical != pq);
        REQUIRE(pq != puncturable);
        REQUIRE(puncturable != zk);
    }

    SECTION("Greater than comparison (security ordering)") {
        REQUIRE(pq > classical);
        REQUIRE(puncturable > pq);
        REQUIRE(zk > puncturable);
        REQUIRE(zk > classical);

        REQUIRE_FALSE(classical > pq);
        REQUIRE_FALSE(pq > puncturable);
    }

    SECTION("Less than comparison (security ordering)") {
        REQUIRE(classical < pq);
        REQUIRE(pq < puncturable);
        REQUIRE(puncturable < zk);
        REQUIRE(classical < zk);

        REQUIRE_FALSE(pq < classical);
        REQUIRE_FALSE(puncturable < pq);
    }
}

TEST_CASE("ProtocolConfig - Constexpr Compatibility", "[config][compile-time]") {
    SECTION("Factory methods are constexpr") {
        constexpr auto config = ProtocolConfig::Default();
        static_assert(config.GetSecurityLevel() == SecurityLevel::Classical);
    }

    SECTION("Feature queries are constexpr") {
        constexpr auto config = ProtocolConfig::MaximumSecurity();
        static_assert(config.IsPqEnabled());
        static_assert(config.IsPuncturableEnabled());
        static_assert(config.IsZkEnabled());
    }

    SECTION("Performance estimates are constexpr") {
        constexpr auto config = ProtocolConfig::PuncturableOnly();
        static_assert(config.EstimateHandshakeOverheadUs() == 200);
        static_assert(config.EstimateMessageOverheadUs() == 70);
        static_assert(config.EstimateMemoryOverheadBytes() == 6400);
    }

    SECTION("Comparison operators are constexpr") {
        constexpr auto classical = ProtocolConfig::ClassicalOnly();
        constexpr auto pq = ProtocolConfig::PostQuantumOnly();
        static_assert(pq > classical);
        static_assert(classical < pq);
        static_assert(pq != classical);
    }
}

TEST_CASE("ProtocolConfig - Use Cases", "[config][integration]") {
    SECTION("Desktop app with maximum security") {
        auto config = ProtocolConfig::MaximumSecurity();

        REQUIRE(config.IsPqEnabled());
        REQUIRE(config.IsPuncturableEnabled());
        REQUIRE(config.IsZkEnabled());

        REQUIRE(config.EstimateMessageOverheadUs() > 100'000);
    }

    SECTION("Mobile app with PQ only (no ZK)") {
        auto config = ProtocolConfig::PostQuantumOnly();

        REQUIRE(config.IsPqEnabled());

        REQUIRE_FALSE(config.IsPuncturableEnabled());
        REQUIRE_FALSE(config.IsZkEnabled());

        REQUIRE(config.EstimateMessageOverheadUs() < 100);
    }

    SECTION("Legacy system with Classical only") {
        auto config = ProtocolConfig::ClassicalOnly();

        REQUIRE_FALSE(config.IsPqEnabled());
        REQUIRE(config.EstimateHandshakeOverheadUs() == 0);
        REQUIRE(config.EstimateMessageOverheadUs() == 0);
        REQUIRE(config.EstimateMemoryOverheadBytes() == 0);
    }

    SECTION("Server with Puncturable FS") {
        auto config = ProtocolConfig::PuncturableOnly();

        REQUIRE(config.IsPqEnabled());
        REQUIRE(config.IsPuncturableEnabled());
        REQUIRE_FALSE(config.IsZkEnabled());

        REQUIRE(config.EstimateMessageOverheadUs() == 70);
    }
}

TEST_CASE("ProtocolConfig - Additive Layer Verification", "[config][security]") {
    SECTION("PostQuantum includes Classical") {
        auto pq = ProtocolConfig::PostQuantumOnly();
        REQUIRE(pq.IsPqEnabled());
    }

    SECTION("Puncturable includes PostQuantum and Classical") {
        auto puncturable = ProtocolConfig::PuncturableOnly();
        REQUIRE(puncturable.IsPqEnabled());
        REQUIRE(puncturable.IsPuncturableEnabled());
    }

    SECTION("ZeroKnowledge includes all layers") {
        auto zk = ProtocolConfig::MaximumSecurity();
        REQUIRE(zk.IsPqEnabled());
        REQUIRE(zk.IsPuncturableEnabled());
        REQUIRE(zk.IsZkEnabled());
    }
}
