// Logging utilities
// Author: Max Schwarz <max.schwarz@online.de>

#ifndef LOG_H
#define LOG_H

#include <fmt/format.h>
#include <fmt/color.h>

template<typename ... Args>
void error(const fmt::format_string<Args...>& format, Args&& ... args)
{
    fmt::print(stderr, fmt::fg(fmt::color::red), "Error: ");
    fmt::print(stderr, format, std::forward<Args>(args)...);
    fmt::print("\n");
}

template<typename ... Args>
void fatal(const fmt::format_string<Args...>& format, Args&& ... args)
{
    fmt::print(stderr, fmt::fg(fmt::color::red), "Fatal: ");
    fmt::print(stderr, format, std::forward<Args>(args)...);
    fmt::print("\n");
    std::exit(1);
}

template<typename ... Args>
void sys_error(const fmt::format_string<Args...>& format, Args&& ... args)
{
    fmt::print(stderr, fmt::fg(fmt::color::red), "Error: ");
    fmt::print(stderr, format, std::forward<Args>(args)...);
    fmt::print(stderr, ": {}", strerror(errno));
    fmt::print("\n");
}

template<typename ... Args>
void sys_fatal(const fmt::format_string<Args...>& format, Args&& ... args)
{
    fmt::print(stderr, fmt::fg(fmt::color::red), "Fatal: ");
    fmt::print(stderr, format, std::forward<Args>(args)...);
    fmt::print(stderr, ": {}", strerror(errno));
    fmt::print("\n");
    std::exit(1);
}

template<typename ... Args>
void info(const fmt::format_string<Args...>& format, Args&& ... args)
{
    fmt::print(fmt::fg(fmt::color::green), "Info: ");
    fmt::print(format, std::forward<Args>(args)...);
    fmt::print("\n");
}

#endif
