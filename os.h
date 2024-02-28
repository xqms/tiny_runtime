// OS Utilities
// Author: Max Schwarz <max.schwarz@online.de>

#ifndef OS_H
#define OS_H

#include <array>
#include <cstdlib>
#include <concepts>
#include <cstring>

#include <unistd.h>

#include "log.h"

namespace os
{

void create_directory(const char* path);

std::size_t file_size(const char* path);

void set_ambient_caps();

[[nodiscard]]
bool is_mountpoint(const char* path);

template<std::convertible_to<const char*> ... Args>
[[nodiscard]]
pid_t fork_and_execv_with_caps(const char* cmd, Args ... args)
{
    auto pid = fork();
    if(pid == 0)
    {
        set_ambient_caps();

        auto argsCopy = std::to_array<char*>({
            strdup(cmd),
            strdup(args)...,
            static_cast<char*>(nullptr)
        });

        if(execvp(cmd, argsCopy.data()) != 0)
            sys_fatal("Could not run {}", cmd);
    }
    if(pid < 0)
        sys_fatal("Could not fork()");

    return pid;
}

template<std::convertible_to<const char*> ... Args>
[[nodiscard]]
bool run_with_caps(const char* cmd, Args&& ... args)
{
    auto pid = fork_and_execv_with_caps(cmd, std::forward<Args>(args)...);

    int wstatus = 0;
    if(waitpid(pid, &wstatus, 0) <= 0)
        sys_fatal("Could not wait for cmd {}", cmd);

    if(!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0)
        fatal("{} failed", cmd);

    return true;
}

}

#endif
