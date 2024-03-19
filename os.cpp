// OS Utilities
// Author: Max Schwarz <max.schwarz@online.de>

#include "os.h"

#include <array>
#include <algorithm>
#include <fstream>
#include <ranges>

#include <fmt/std.h>

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
bool bind_mount(const std::filesystem::path& outside, const std::optional<std::filesystem::path>& inside, int flags)
{
    namespace fs = std::filesystem;
    fs::path source = outside;
    fs::path targetInContainer = (inside ? (*inside) : outside);
    fs::path target = fs::path{config::FINAL} / targetInContainer.relative_path();

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

    debug("Binding {} to {}", source, target);
    if(mount(source.c_str(), target.c_str(), nullptr, flags, nullptr) != 0)
    {
        sys_error("Could not bind-mount {} to {} in container (flags={})", source, targetInContainer, flags);
        return false;
    }
    if(mount(nullptr, target.c_str(), nullptr, (flags & MS_REC)|MS_SLAVE, nullptr) != 0)
    {
        sys_error("Could not change {} to MS_SLAVE", target);
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

bool prepend_space_to_file(const std::filesystem::path& path, std::size_t amount)
{
    // Try fallocate() first
    {
        int fd = open(path.c_str(), O_RDWR);
        if(fd < 0)
        {
            sys_error("Could not open '{}'", path);
            return false;
        }
        auto guard = sg::make_scope_guard([&]{ close(fd); });

        int ret = fallocate(fd, FALLOC_FL_INSERT_RANGE, 0, amount);
        if(ret == 0)
            return true;

        sys_error("Could not use fallocate() to prepend space to {}", path);
        error("Falling back to slow copy mode");
    }

    fs::path tempFile = path;
    tempFile += ".trt-temp";

    std::error_code ec;
    fs::rename(path, tempFile, ec);
    if(ec)
    {
        error("Could not rename {} to {}: {}", path, tempFile, ec);
        return false;
    }

    auto unlinkGuard = sg::make_scope_guard([&]{
        if(unlink(tempFile.c_str()) != 0)
            sys_error("Could not remove temporary file {}", tempFile);
    });

    int srcFD = open(tempFile.c_str(), O_RDONLY);
    if(srcFD < 0)
    {
        sys_error("Could not open {}", tempFile);
        return false;
    }

    struct stat statbuf{};
    if(fstat(srcFD, &statbuf) != 0)
    {
        sys_error("Could not stat() {}", tempFile);
        return false;
    }

    auto srcGuard = sg::make_scope_guard([&]{ close(srcFD); });

    int dstFD = open(path.c_str(), O_WRONLY|O_TRUNC|O_CREAT, statbuf.st_mode);
    if(dstFD < 0)
    {
        sys_error("Could not create {}", path);
        return false;
    }

    std::vector<char> data(amount, 0);
    if(write(dstFD, data.data(), data.size()) != static_cast<ssize_t>(data.size()))
    {
        sys_error("Could not write zeroes to {}", path);
        return false;
    }

    return copy_from_to_fd(srcFD, dstFD);
}

bool remove_leading_space(const std::filesystem::path& path, std::size_t amount)
{
    // Try fallocate() first
    {
        int fd = open(path.c_str(), O_RDWR);
        if(fd < 0)
        {
            sys_error("Could not open '{}'", path);
            return false;
        }
        auto guard = sg::make_scope_guard([&]{ close(fd); });

        int ret = fallocate(fd, FALLOC_FL_COLLAPSE_RANGE, 0, amount);
        if(ret == 0)
            return true;

        sys_error("Could not use fallocate() to remove leading data from {}", path);
        error("Falling back to slow copy mode");
    }

    fs::path tempFile = path;
    tempFile += ".trt-temp";

    std::error_code ec;
    fs::rename(path, tempFile, ec);
    if(ec)
    {
        error("Could not rename {} to {}: {}", path, tempFile, ec);
        return false;
    }

    int srcFD = open(tempFile.c_str(), O_RDONLY);
    if(srcFD < 0)
    {
        sys_error("Could not open {}", tempFile);
        return false;
    }

    if(lseek64(srcFD, amount, SEEK_SET) != static_cast<off64_t>(amount))
    {
        sys_error("Could not seek in {}", tempFile);
        return false;
    }

    struct stat statbuf{};
    if(fstat(srcFD, &statbuf) != 0)
    {
        sys_error("Could not stat() {}", tempFile);
        return false;
    }

    auto srcGuard = sg::make_scope_guard([&]{ close(srcFD); });

    int dstFD = open(path.c_str(), O_WRONLY|O_TRUNC|O_CREAT, statbuf.st_mode);
    if(dstFD < 0)
    {
        sys_error("Could not create {}", path);
        return false;
    }

    auto unlinkGuard = sg::make_scope_guard([&]{
        if(unlink(tempFile.c_str()) != 0)
            sys_error("Could not remove temporary file {}", tempFile);
    });

    return copy_from_to_fd(srcFD, dstFD);
}

bool copy_from_to_fd(int srcFD, int dstFD, const std::optional<std::size_t>& maxSize)
{
    std::vector<char> buf(4096 * 1024);

    std::size_t toRead = 0;
    if(maxSize)
        toRead = *maxSize;

    while(true)
    {
        std::size_t readSize = maxSize ? std::min(buf.size(), *maxSize) : buf.size();
        auto bytes = read(srcFD, buf.data(), readSize);
        if(bytes < 0)
        {
            sys_error("Could not read()");
            return false;
        }
        if(bytes == 0)
            break;

        while(bytes != 0)
        {
            auto wbytes = write(dstFD, buf.data(), bytes);
            if(wbytes <= 0)
            {
                sys_error("Could not write()");
                return false;
            }

            bytes -= wbytes;
        }

        if(maxSize)
        {
            toRead -= bytes;
            if(toRead == 0)
                break;
        }
    }

    return true;
}

bool write_to_fd(int fd, const std::span<char>& data)
{
    std::size_t toWrite = data.size();
    const char* ptr = data.data();

    while(toWrite != 0)
    {
        auto ret = write(fd, ptr, toWrite);
        if(ret <= 0)
        {
            sys_error("Could not write()");
            return false;
        }

        ptr += ret;
        toWrite -= ret;
    }

    return true;
}

}
