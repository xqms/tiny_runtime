// OS Utilities
// Author: Max Schwarz <max.schwarz@online.de>

#include "os.h"

#include <array>
#include <algorithm>
#include <fstream>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/capability.h>
#include <fcntl.h>
#include <unistd.h>

#include "log.h"
#include "scope_guard.h"

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

}
