#pragma once

#if __has_include(<fmt/core.h>)
    #include <fmt/core.h>
    namespace ecliptix::compat {
        using fmt::format;
    }
#elif __has_include(<format>)
    #include <format>
    namespace ecliptix::compat {
        using std::format;
    }
#else
    #error "Neither fmt nor std::format available"
#endif
