#include <catch2/catch_test_macros.hpp>
#include "ecliptix/core/result.hpp"
using namespace ecliptix::protocol;
TEST_CASE("Result<T, E> - Basic Operations", "[result][core]") {
    SECTION("Ok construction and queries") {
        auto result = Result<int, std::string>::Ok(42);
        REQUIRE(result.IsOk());
        REQUIRE_FALSE(result.IsErr());
        REQUIRE(result.Unwrap() == 42);
    }
    SECTION("Err construction and queries") {
        auto result = Result<int, std::string>::Err("error");
        REQUIRE(result.IsErr());
        REQUIRE_FALSE(result.IsOk());
        REQUIRE(result.UnwrapErr() == "error");
    }
    SECTION("Unit type for void results") {
        auto result = Result<Unit, std::string>::Ok(unit);
        REQUIRE(result.IsOk());
    }
}
TEST_CASE("Result<T, E> - Monadic Operations", "[result][core]") {
    SECTION("Map transforms Ok value") {
        auto result = Result<int, std::string>::Ok(21);
        auto mapped = std::move(result).Map([](int x) { return x * 2; });
        REQUIRE(mapped.IsOk());
        REQUIRE(mapped.Unwrap() == 42);
    }
    SECTION("Map preserves Err") {
        auto result = Result<int, std::string>::Err("error");
        auto mapped = std::move(result).Map([](int x) { return x * 2; });
        REQUIRE(mapped.IsErr());
        REQUIRE(mapped.UnwrapErr() == "error");
    }
    SECTION("MapErr transforms Err value") {
        auto result = Result<int, std::string>::Err("error");
        auto mapped = std::move(result).MapErr([](std::string s) {
            return s + "!";
        });
        REQUIRE(mapped.IsErr());
        REQUIRE(mapped.UnwrapErr() == "error!");
    }
    SECTION("Bind chains operations") {
        auto result = Result<int, std::string>::Ok(10);
        auto bound = std::move(result).Bind([](int x) {
            if (x > 5) {
                return Result<int, std::string>::Ok(x * 2);
            }
            return Result<int, std::string>::Err("too small");
        });
        REQUIRE(bound.IsOk());
        REQUIRE(bound.Unwrap() == 20);
    }
}
TEST_CASE("Result<T, E> - UnwrapOr and UnwrapOrElse", "[result][core]") {
    SECTION("UnwrapOr returns value on Ok") {
        auto result = Result<int, std::string>::Ok(42);
        REQUIRE(std::move(result).UnwrapOr(0) == 42);
    }
    SECTION("UnwrapOr returns default on Err") {
        auto result = Result<int, std::string>::Err("error");
        REQUIRE(std::move(result).UnwrapOr(0) == 0);
    }
    SECTION("UnwrapOrElse computes default on Err") {
        auto result = Result<int, std::string>::Err("error");
        auto value = std::move(result).UnwrapOrElse([](const std::string& err) {
            return static_cast<int>(err.length());
        });
        REQUIRE(value == 5);  
    }
}
TEST_CASE("Result<T, E> - Try factory", "[result][core]") {
    SECTION("Try captures successful execution") {
        auto result = Result<int, std::string>::Try(
            []() { return 42; },
            [](const std::exception& ex) { return std::string(ex.what()); }
        );
        REQUIRE(result.IsOk());
        REQUIRE(result.Unwrap() == 42);
    }
    SECTION("Try captures exceptions") {
        auto result = Result<int, std::string>::Try(
            []() -> int { throw std::runtime_error("oops"); },
            [](const std::exception& ex) { return std::string(ex.what()); }
        );
        REQUIRE(result.IsErr());
        REQUIRE(result.UnwrapErr() == "oops");
    }
}
