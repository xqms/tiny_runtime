// OS Utilities
// Author: Max Schwarz <max.schwarz@online.de>

#ifndef OS_H
#define OS_H

#include <array>
#include <cstdlib>
#include <concepts>
#include <cstring>
#include <filesystem>
#include <optional>
#include <span>
#include <ranges>

#include <unistd.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/wait.h>

#include "log.h"
#include "scope_guard.h"

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

        debug("Running {}", argsCopy | std::views::take(argsCopy.size()-1));

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

template<std::convertible_to<const char*> ... Args>
[[nodiscard]]
pid_t fork_and_execv(const char* cmd, Args ... args)
{
    auto pid = fork();
    if(pid == 0)
    {
        auto argsCopy = std::to_array<char*>({
            strdup(cmd),
            strdup(args)...,
            static_cast<char*>(nullptr)
        });

        debug("Running {}", argsCopy | std::views::take(argsCopy.size()-1));

        if(execvp(cmd, argsCopy.data()) != 0)
            sys_fatal("Could not run {}", cmd);
    }
    if(pid < 0)
        sys_fatal("Could not fork()");

    return pid;
}

template<std::convertible_to<const char*> ... Args>
[[nodiscard]]
bool run(const char* cmd, Args&& ... args)
{
    auto pid = fork_and_execv(cmd, std::forward<Args>(args)...);

    int wstatus = 0;
    if(waitpid(pid, &wstatus, 0) <= 0)
        sys_fatal("Could not wait for cmd {}", cmd);

    if(!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0)
        fatal("{} failed", cmd);

    return true;
}

template<std::convertible_to<const char*> ... Args>
[[nodiscard]]
std::optional<std::string> run_get_output(const char* cmd, Args&& ... args)
{
    int pipefd[2];
    if(pipe2(pipefd, O_CLOEXEC) != 0)
    {
        sys_error("Could not create pipe");
        return {};
    }

    auto pid = fork();
    if(pid == 0)
    {
        close(pipefd[0]);
        if(dup2(pipefd[1], STDOUT_FILENO) == -1)
            sys_fatal("dup2");

        auto argsCopy = std::to_array<char*>({
            strdup(cmd),
            strdup(args)...,
            static_cast<char*>(nullptr)
        });

        debug("Running {}", argsCopy | std::views::take(argsCopy.size()-1));

        if(execvp(cmd, argsCopy.data()) != 0)
            sys_fatal("Could not run {}", cmd);
    }

    close(pipefd[1]);
    auto guard = sg::make_scope_guard([&]{ close(pipefd[0]); });

    std::stringstream ss;
    char buf[1024];
    while(true)
    {
        auto ret = read(pipefd[0], buf, sizeof(buf));
        if(ret < 0)
        {
            sys_error("Could not read()");
            return {};
        }
        if(ret == 0)
            break;

        ss.write(buf, ret);
    }

    int wstatus = 0;
    if(waitpid(pid, &wstatus, 0) <= 0)
    {
        sys_error("Could not wait for cmd {}", cmd);
        return {};
    }

    if(!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0)
    {
        if(WIFEXITED(wstatus))
            error("{} failed with exit code {}", cmd, WEXITSTATUS(wstatus));
        else
            error("{} failed/crashed", cmd);
        return {};
    }

    return ss.str();
}

[[nodiscard]]
bool bind_mount(const std::filesystem::path& outside, const std::optional<std::filesystem::path>& inside = {}, int flags = MS_BIND|MS_REC);

[[nodiscard]]
std::optional<std::filesystem::path> find_binary(const std::string_view& name);

[[nodiscard]]
bool prepend_space_to_file(const std::filesystem::path& path, std::size_t amount);

[[nodiscard]]
bool remove_leading_space(const std::filesystem::path& path, std::size_t amount);

[[nodiscard]]
bool copy_from_to_fd(int srcFD, int dstFD, const std::optional<std::size_t>& maxSize = {});

[[nodiscard]]
bool write_to_fd(int fd, const std::span<char>& data);

[[nodiscard]]
bool apparmor_restricts_userns();

}

#endif
