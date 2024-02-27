// Tiny container runtime for use with Apptainer images
// Author: Max Schwarz <max.schwarz@online.de>

#include <array>

#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <vector>
#include <ranges>
#include <algorithm>

#include <sched.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/capability.h>
#include <sys/syscall.h>

#include <fmt/format.h>
#include <fmt/color.h>
#include <fmt/compile.h>
#include <fmt/ranges.h>

#include "log.h"
#include "static_path.h"
#include "elf_size.h"
#include "scope_guard.h"

constexpr auto SESSION_PATH = StaticPath("/tmp/tinyruntime-session");
constexpr auto ROOTFS_PATH = SESSION_PATH / "root";
constexpr auto FINAL_PATH = SESSION_PATH / "final";
constexpr auto UPPER_PATH = SESSION_PATH / "upper";
constexpr auto WORK_PATH = SESSION_PATH / "work";
constexpr auto FUSE_OVERLAYFS = SESSION_PATH / "fuse-overlayfs";
constexpr auto SQUASHFUSE = SESSION_PATH / "squashfuse";

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

    auto cap_list = std::to_array({CAP_SYS_ADMIN});
    if(cap_set_flag(caps, CAP_INHERITABLE, cap_list.size(), cap_list.data(), CAP_SET) != 0)
        sys_fatal("Could not set cap flags");

    if(cap_set_proc(caps) != 0)
        sys_fatal("Could not set capabilities");

    if(cap_set_ambient(CAP_SYS_ADMIN, CAP_SET) != 0)
        sys_fatal("Could not set CAP_SYS_ADMIN cap");
}

void cap_system(const char* cmd)
{
    info("Running '{}'", cmd);

    auto pid = fork();
    if(pid == 0)
    {
        set_ambient_caps();
        system(cmd);
        std::exit(0);
    }

    waitpid(pid, nullptr, 0);
}

static int pivot_root(const char *new_root, const char *put_old)
{
    return syscall(SYS_pivot_root, new_root, put_old);
}

int main(int argc, char** argv)
{
    int euid = geteuid();
    int egid = getegid();

    mkdir(SESSION_PATH, 0777);

    // Create user namespace
    if(unshare(CLONE_NEWUSER) != 0)
        sys_fatal("Could not create user namespace");

    // Configure UID/GID mapping inside user namespace
    {
        char buf[256];
        int fd;

        snprintf(buf, sizeof(buf), "deny");
        fd = open("/proc/self/setgroups", O_WRONLY);
        if(fd < 0)
            sys_fatal("Could not open /proc/self/setgroups");
        if(write(fd, buf, strlen(buf)) < 0)
            sys_fatal("Could not write to /proc/self/setgroups");
        close(fd);

        snprintf(buf, sizeof(buf), "%d %d 1\n", euid, euid);
        fd = open("/proc/self/uid_map", O_WRONLY);
        if(fd < 0)
            sys_fatal("Could not open /proc/self/uid_map");
        if(write(fd, buf, strlen(buf)) < 0)
            sys_fatal("Could not write to /proc/self/uid_map");
        close(fd);

        snprintf(buf, sizeof(buf), "%d %d 1\n", egid, egid);
        fd = open("/proc/self/gid_map", O_WRONLY);
        if(fd < 0)
            sys_fatal("Could not open /proc/self/gid_map");
        if(write(fd, buf, strlen(buf)) < 0)
            sys_fatal("Could not write to /proc/self/gid_map");
        close(fd);
    }

    // Create mount namespace
    if(unshare(CLONE_NEWNS) != 0)
        sys_fatal("Could not create mount namespace");

    // Don't propagate anything we do here
    if(mount("none", "/", nullptr, MS_REC|MS_PRIVATE, nullptr) == -1)
        sys_fatal("Could not change to MS_PRIVATE");

    // Mount tmpfs in session dir
    if(mount("tmpfs", SESSION_PATH, "tmpfs", 0, "size=100M") != 0)
        sys_fatal("Could not mount tmpfs");

    info("tmpfs mounted.");

    // Create directories
    create_directory(ROOTFS_PATH);
    create_directory(UPPER_PATH);
    create_directory(WORK_PATH);
    create_directory(FINAL_PATH);

    // Find our executable
    auto self = []{
        char buf[1024];
        auto ret = readlink("/proc/self/exe", buf, sizeof(buf));
        if(ret < 0 || ret == sizeof(buf))
            sys_fatal("Could not read link /proc/self/exe");
        return std::string{buf};
    }();

    // Write utilities
    std::string squashfsFile = self;
    std::size_t squashfsOffset = 0;
    std::size_t squashfsSize = 0;
    {
        auto mySize = getELFSize(self.c_str(), 0);
        if(!mySize)
            fatal("Could not get own ELF size");

        info("My size: {} bytes", *mySize);

        std::size_t squashFuseOffset = *mySize;
        auto squashFuseSize = getELFSize(self.c_str(), squashFuseOffset);
        if(!squashFuseSize)
            fatal("Could not get squashfuse ELF size");

        info("squashfuse size: {} bytes", *squashFuseSize);

        std::size_t overlayfsOffset = *mySize + *squashFuseSize;
        auto overlayfsSize = getELFSize(self.c_str(), overlayfsOffset);
        if(!overlayfsSize)
            fatal("Could not get fuse-overlayfs ELF size");

        info("fuse-overlayfs size: {} bytes", *overlayfsSize);

        squashfsOffset = *mySize + *squashFuseSize + *overlayfsSize;
        squashfsSize = file_size(self.c_str()) - squashfsOffset;

        if(squashfsSize == 0)
        {
            info("No squashfs directly attached.");
            if(argc < 2)
                fatal("Need squashfs image as parameter or concatenated to the executable");
            else
                info("Using squashfs image {}", argv[1]);

            squashfsFile = argv[1];
            squashfsOffset = 0;
            squashfsSize = file_size(squashfsFile.c_str());
        }

        info("squashfs image size: {} bytes", squashfsSize);

        auto writeTool = [&](const char* dest, std::size_t offset, std::size_t size){
            int fd_src = open(self.c_str(), O_RDONLY);
            if(fd_src < 0)
                sys_fatal("Could not open {}", self);

            auto guard_src = sg::make_scope_guard([&]{ close(fd_src); });

            if(lseek64(fd_src, offset, SEEK_SET) != static_cast<off64_t>(offset))
                sys_fatal("Could not seek to tool at offset {} in {}", offset, self.c_str());

            int fd_dst = open(dest, O_RDWR | O_CREAT, 0755);
            if(fd_dst < 0)
                sys_fatal("Could not create tool file {}", dest);

            auto guard_dst = sg::make_scope_guard([&]{ close(fd_dst); });

            std::array<char, 128*1024> buf;
            while(size > 0)
            {
                ssize_t bsize = std::min(buf.size(), size);

                ssize_t ret = read(fd_src, buf.data(), bsize);
                if(ret != bsize)
                    sys_fatal("Could not read from {}", self);

                if(write(fd_dst, buf.data(), bsize) != bsize)
                    sys_fatal("Could not write to {}", dest);

                size -= bsize;
            }
        };

        writeTool(SQUASHFUSE, squashFuseOffset, *squashFuseSize);
        writeTool(FUSE_OVERLAYFS, overlayfsOffset, *overlayfsSize);
    }

    // Things that need to be unmounted later on
    std::vector<std::string> mountedFilesystems;
    auto unmountGuard = sg::make_scope_guard([&]{
        std::ifstream mountfile{"/proc/mounts"};
        if(!mountfile)
        {
            sys_error("Could not open /proc/mounts");
            return;
        }

        std::vector<std::string> mounts;

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

            if(target.starts_with(static_cast<const char*>(SESSION_PATH)))
                mounts.push_back(target);
        }

        info("Targets: {}", mounts);

        for(auto& path : mounts | std::views::reverse)
        {
            info("Unmounting '{}'", path);
            if(umount(path.c_str()) != 0)
                sys_error("Could not unmount {}", path);
        }
    });

    // Run squashfuse
    info("Mounting image...");
    {
        auto pid = fork();
        if(pid == 0)
        {
            set_ambient_caps();

            auto args = std::to_array({
                strdup(SQUASHFUSE),
                strdup("-o"), strdup(fmt::format("offset={}", squashfsOffset).c_str()),
                strdup(squashfsFile.c_str()),
                strdup(ROOTFS_PATH),
                static_cast<char*>(nullptr)
            });

            if(execv(SQUASHFUSE, args.data()) != 0)
                sys_fatal("Could not execute {}", SQUASHFUSE.data);
        }

        // Wait for mount success
        int wstatus = 0;
        if(waitpid(pid, &wstatus, 0) <= 0)
            sys_fatal("Could not wait() for child");

        if(!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0)
            fatal("Could not mount squash image");

        mountedFilesystems.push_back(ROOTFS_PATH);
    }

    // Overlay
    auto overlayArgs = fmt::format("lowerdir={},upperdir={},workdir={}", ROOTFS_PATH, UPPER_PATH, WORK_PATH);
    if(mount("none", FINAL_PATH, "overlay", 0, overlayArgs.data()) != 0)
    {
        sys_error("Could not mount overlay on {} with options '{}'", FINAL_PATH, overlayArgs);
        return 1;
    }
    mountedFilesystems.push_back(FINAL_PATH);

    // Bind mounts
    auto bindMounts = std::to_array({
        "/dev",
        "/etc/hosts",
        "/proc",
        "/sys",
    });
    for(auto& path : bindMounts)
    {
        std::string target = std::string{FINAL_PATH} + path;
        if(mount(path, target.c_str(), nullptr, MS_BIND|MS_REC, nullptr) != 0)
        {
            sys_error("Could not bind-mount {} into container", path);
            return 1;
        }
        if(mount(nullptr, target.c_str(), nullptr, MS_REC|MS_SLAVE, nullptr) != 0)
        {
            sys_error("Could not change {} to MS_PRIVATE", target);
        }

        mountedFilesystems.push_back(std::move(target));
    }

    // Execute child
    int pid = fork();
    if(pid == 0)
    {
        // Create mount namespace
        if(unshare(CLONE_NEWNS) != 0)
            sys_fatal("Could not create mount namespace");

        info("pivot_root()");
        if(pivot_root(FINAL_PATH, FINAL_PATH) != 0)
        {
            sys_error("Could not pivot_root()");
            return 1;
        }
        if(chdir("/") != 0)
        {
            sys_error("Could not chdir(/)");
            return 1;
        }
        if(umount2("/", MNT_DETACH) != 0)
        {
            sys_error("Could not detach old /");
            return 1;
        }

        system("mount");
        std::exit(0);
    }

    int wstatus = 0;
    if(waitpid(pid, &wstatus, 0) <= 0)
        sys_fatal("Could not wait() for child");

    info("Cleanup!");
    system("cat /proc/self/mountinfo");
    cap_system("mount --make-rslave /tmp/tinyruntime-session/final/sys");
    cap_system("umount -n -R /tmp/tinyruntime-session/final/sys");
    return 0;
}
