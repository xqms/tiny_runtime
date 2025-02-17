// Logging utilities
// Author: Max Schwarz <max.schwarz@online.de>

#ifndef LOG_H
#define LOG_H

#include <fmt/format.h>
#include <fmt/color.h>

extern bool log_debug;

template<typename Level>
void log(FILE* file, Level&& level, const std::string& msg)
{
    fmt::print(file, "tiny_runtime[{}]: {}\n",
        std::forward<Level>(level), msg);
}

template<typename ... Args>
void warning(const fmt::format_string<Args...>& format, Args&& ... args)
{
    log(stderr, fmt::styled("WARNING", fmt::fg(fmt::color::yellow)), fmt::format(format, std::forward<Args>(args)...));
}

template<typename ... Args>
void error(const fmt::format_string<Args...>& format, Args&& ... args)
{
    log(stderr, fmt::styled("ERROR", fmt::fg(fmt::color::red)), fmt::format(format, std::forward<Args>(args)...));
}

template<typename ... Args>
void fatal(const fmt::format_string<Args...>& format, Args&& ... args)
{
    log(stderr, fmt::styled("FATAL", fmt::fg(fmt::color::red)), fmt::format(format, std::forward<Args>(args)...));
    std::exit(1);
}

template<typename ... Args>
void sys_error(const fmt::format_string<Args...>& format, Args&& ... args)
{
    auto savedErrno = errno;

    log(stderr, fmt::styled("ERROR", fmt::fg(fmt::color::red)),
        fmt::format("{}: {}",
            fmt::format(format, std::forward<Args>(args)...),
            strerror(savedErrno)
        )
    );
}

template<typename ... Args>
void sys_fatal(const fmt::format_string<Args...>& format, Args&& ... args)
{
    auto savedErrno = errno;

    log(stderr, fmt::styled("FATAL", fmt::fg(fmt::color::red)),
        fmt::format("{}: {}",
            fmt::format(format, std::forward<Args>(args)...),
            strerror(savedErrno)
        )
    );
    std::exit(1);
}

template<typename ... Args>
void info(const fmt::format_string<Args...>& format, Args&& ... args)
{
    log(stdout, fmt::styled("INFO", fmt::fg(fmt::color::green)), fmt::format(format, std::forward<Args>(args)...));
}

template<typename ... Args>
void debug(const fmt::format_string<Args...>& format, Args&& ... args)
{
    if(!log_debug)
        return;

    log(stderr, fmt::styled("DEBUG", fmt::fg(fmt::color::orange)), fmt::format(format, std::forward<Args>(args)...));
}

#endif
