// OS Utilities
// Author: Max Schwarz <max.schwarz@online.de>

#include "os.h"

#include <array>
#include <algorithm>
#include <fstream>
#include <ranges>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/capability.h>
#include <fcntl.h>
#include <unistd.h>

#include "log.h"
#include "scope_guard.h"
#include "config.h"

namespace fs = std::filesystem;

namespace os
{

void create_directory(const char* path)
{
    if(mkdir(path, 0777) != 0)
        sys_fatal("Could not create directory '{}'", path);
}

std::size_t file_size(const char* path)
{
    int fd = open(path, O_RDONLY);
    if(fd < 0)
        sys_fatal("Could not open myself");
    auto off = lseek64(fd, 0, SEEK_END);
    if(off == (off64_t)-1)
        sys_fatal("Could not seek");
    close(fd);

    return off;
}

void set_ambient_caps()
{
    cap_t caps = cap_get_proc();
    if(!caps)
        sys_fatal("Could not get caps");

    auto guard = sg::make_scope_guard([&]{ cap_free(caps); });

    auto cap_list = std::to_array({
        CAP_SYS_ADMIN, CAP_DAC_OVERRIDE, CAP_MKNOD, CAP_CHOWN,
        CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FOWNER,
        CAP_KILL, CAP_NET_ADMIN, CAP_SETGID, CAP_SETPCAP,
        CAP_SETUID, CAP_SYS_CHROOT, CAP_SYS_PTRACE
    });
    if(cap_set_flag(caps, CAP_INHERITABLE, cap_list.size(), cap_list.data(), CAP_SET) != 0)
        sys_fatal("Could not set cap flags");
    if(cap_set_flag(caps, CAP_PERMITTED, cap_list.size(), cap_list.data(), CAP_SET) != 0)
        sys_fatal("Could not set cap flags");

    if(cap_set_proc(caps) != 0)
        sys_fatal("Could not set capabilities");

    for(auto& cap : cap_list)
    {
        if(cap_set_ambient(cap, CAP_SET) != 0)
            sys_fatal("Could not set ambient cap {}", cap);
    }
}

bool is_mountpoint(const char* path)
{
    std::ifstream mountfile{"/proc/mounts"};
    if(!mountfile)
        sys_fatal("Could not open /proc/mounts");

    for(std::string line; std::getline(mountfile, line);)
    {
        auto begin = line.find(' ');
        if(begin == std::string::npos)
        {
            error("Could not parse mount line: '{}'", line);
            continue;
        }

        auto end = line.find(' ', begin+1);
        if(end == std::string::npos)
        {
            error("Could not parse mount line: '{}'", line);
            continue;
        }

        std::string target = line.substr(begin+1, end-(begin+1));
        std::ranges::replace(target, '\040', ' ');
        if(target == path)
            return true;
    }

    return false;
}

[[nodiscard]]
bool bind_mount(const char* path, int flags)
{
    namespace fs = std::filesystem;
    fs::path target = std::string{config::FINAL} + path;
    fs::path source = path;

    if(fs::is_directory(source))
        std::filesystem::create_directories(target);
    else
    {
        std::filesystem::create_directories(target.parent_path());
        if(!fs::exists(target))
        {
            int fd = open(target.c_str(), O_RDWR|O_CREAT, 0755);
            close(fd);
        }
    }

    if(mount(path, target.c_str(), nullptr, flags, nullptr) != 0)
    {
        sys_error("Could not bind-mount {} into container (flags={})", path, flags);
        return false;
    }
    if(mount(nullptr, target.c_str(), nullptr, (flags & MS_REC)|MS_SLAVE, nullptr) != 0)
    {
        sys_error("Could not change {} to MS_SLAVE", std::string{target});
        return false;
    }

    return true;
}

std::optional<std::filesystem::path> find_binary(const std::string_view& name)
{
    std::string_view PATH = getenv("PATH") ? getenv("PATH") : "/bin:/usr/bin";

    for(const auto dir : std::views::split(PATH, ':'))
    {
        auto path = fs::path(std::string_view(&*dir.begin(), std::ranges::distance(dir))) / fs::path(name);

        std::error_code ec;
        auto stat = fs::status(path, ec);

        if(ec)
            continue;

        if(stat.type() != fs::file_type::directory && (stat.permissions() & fs::perms::owner_exec) != fs::perms::none)
            return path;
    }

    return {};
}

}
