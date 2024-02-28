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
#include <concepts>

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

static int pivot_root(const char *new_root, const char *put_old)
{
    return syscall(SYS_pivot_root, new_root, put_old);
}

static bool is_mountpoint(const char* path)
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
static bool start_squashfuse(const char* file, std::size_t offset)
{
    // Run squashfuse
    info("Mounting image...");
    auto pid = fork();
    if(pid == 0)
    {
        set_ambient_caps();

        auto args = std::to_array({
            strdup(SQUASHFUSE),
            strdup("-f"),
            strdup("-o"), strdup(fmt::format("offset={},uid={},gid={}", offset, getuid(), getgid()).c_str()),
            strdup(file),
            strdup(ROOTFS_PATH),
            static_cast<char*>(nullptr)
        });

        if(execv(SQUASHFUSE, args.data()) != 0)
            sys_fatal("Could not execute {}", SQUASHFUSE);
    }

    // Wait for mount success
    for(int i = 0; i < 1000; ++i)
    {
        int wstatus = 0;
        auto ret = waitpid(pid, &wstatus, WNOHANG);
        if(ret < 0)
            sys_fatal("Could not wait() for child");
        if(ret != 0)
        {
            sys_fatal("squashfuse failed");
            return false;
        }

        if(is_mountpoint(ROOTFS_PATH))
            return true;

        usleep(10*1000);
    }

    sys_fatal("Timeout!");
    kill(pid, SIGKILL);
    return false;
}

[[nodiscard]]
static bool start_overlayfs()
{
    info("Mounting overlay...");

    auto overlayArgs = fmt::format("lowerdir={},upperdir={},workdir={},noacl", ROOTFS_PATH, UPPER_PATH, WORK_PATH);

    setenv("FUSE_OVERLAYFS_DISABLE_OVL_WHITEOUT", "y", 1);

    auto pid = fork();
    if(pid == 0)
    {
        set_ambient_caps();

        auto args = std::to_array({
            strdup(FUSE_OVERLAYFS),
            strdup("-f"),
            strdup("-o"), strdup(overlayArgs.c_str()),
            strdup(FINAL_PATH),
            static_cast<char*>(nullptr)
        });

        if(execv(FUSE_OVERLAYFS, args.data()) != 0)
            sys_fatal("Could not execute {}", FUSE_OVERLAYFS);
    }

    // Wait for mount success
    for(int i = 0; i < 1000; ++i)
    {
        int wstatus = 0;
        auto ret = waitpid(pid, &wstatus, WNOHANG);
        if(ret < 0)
            sys_fatal("Could not wait() for child");
        if(ret != 0)
        {
            sys_fatal("fuse-overlayfs failed");
            return false;
        }

        if(is_mountpoint(FINAL_PATH))
            return true;

        usleep(10*1000);
    }

    sys_fatal("Timeout!");
    kill(pid, SIGKILL);
    return false;
}

template<std::convertible_to<const char*> ... Args>
[[nodiscard]]
static bool run_with_caps(const char* cmd, Args ... args)
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

    int wstatus = 0;
    if(waitpid(pid, &wstatus, 0) <= 0)
        sys_fatal("Could not wait for cmd {}", cmd);

    if(!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0)
        fatal("{} failed", cmd);

    return true;
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

        std::size_t squashFuseOffset = *mySize;
        auto squashFuseSize = getELFSize(self.c_str(), squashFuseOffset);
        if(!squashFuseSize)
            fatal("Could not get squashfuse ELF size");

        std::size_t overlayfsOffset = *mySize + *squashFuseSize;
        auto overlayfsSize = getELFSize(self.c_str(), overlayfsOffset);
        if(!overlayfsSize)
            fatal("Could not get fuse-overlayfs ELF size");

        squashfsOffset = *mySize + *squashFuseSize + *overlayfsSize;
        squashfsSize = file_size(self.c_str()) - squashfsOffset;

        if(squashfsSize == 0)
        {
            if(argc < 2)
                fatal("Need squashfs image as parameter or concatenated to the executable");

            squashfsFile = argv[1];
            squashfsOffset = 0;
            squashfsSize = file_size(squashfsFile.c_str());
        }

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

    {
        auto pid = fork();
        if(pid == 0)
        {
            // New process group
            setpgid(0, 0);

            if(!start_squashfuse(squashfsFile.c_str(), squashfsOffset))
                std::exit(1);

            if(!start_overlayfs())
                std::exit(1);

            // Stop ourselves, so that if we get orphaned, the kernel sends
            // a SIGHUP,SIGCONT sequence to all processes in this process group
            kill(getpid(), SIGSTOP);
            std::exit(0);
        }

        int wstatus = 0;
        if(waitpid(pid, &wstatus, WUNTRACED) <= 0)
            sys_fatal("Could not wait for child process");

        if(!WIFSTOPPED(wstatus) || WSTOPSIG(wstatus) != SIGSTOP)
            sys_fatal("Invalid mount result");
    }

    // Bind mounts
    struct Mount
    {
        const char* path;
        int flags = MS_BIND|MS_REC;
    };
    auto bindMounts = std::to_array<Mount>({
        {"/dev"},
        {"/etc/hosts"},
        {"/etc/passwd"},
        {"/etc/group"},
        {"/etc/resolv.conf"},
        {"/proc"},
        {"/sys"},
        {"/tmp", MS_BIND},
        {"/var/tmp", MS_BIND}
    });
    for(auto& path : bindMounts)
    {
        std::string target = std::string{FINAL_PATH} + path.path;
        if(mount(path.path, target.c_str(), nullptr, MS_BIND|MS_REC, nullptr) != 0)
        {
            sys_error("Could not bind-mount {} into container", path.path);
            return 1;
        }
        if(mount(nullptr, target.c_str(), nullptr, MS_REC|MS_SLAVE, nullptr) != 0)
        {
            sys_error("Could not change {} to MS_PRIVATE", target);
        }
    }

    // Run nvidia-container-cli
    info("NVIDIA setup...");
    if(!run_with_caps("nvidia-container-cli", "--user", "configure", "--device=all", "--compute", "--display", "--graphics", "--utility", "--video", "--no-cgroups", FINAL_PATH))
        sys_error("Could not run nvidia-container-cli");

    // Pivot into root
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

    info("Starting user command");
    auto args = std::to_array({strdup("/bin/bash"), static_cast<char*>(nullptr)});
    if(execv("/bin/bash", args.data()) != 0)
        sys_fatal("Could not execute /bin/bash");

    return 0;
}
