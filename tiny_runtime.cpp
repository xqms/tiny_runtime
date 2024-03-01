// Tiny container runtime for use with Apptainer images
// Author: Max Schwarz <max.schwarz@online.de>

#include <array>

#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <vector>
#include <algorithm>
#include <filesystem>
#include <span>

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
#include <fmt/std.h>

#include "config.h"
#include "log.h"
#include "os.h"
#include "static_path.h"
#include "elf_size.h"
#include "scope_guard.h"
#include "nvidia.h"
#include "image.h"
#include "argparser.h"

namespace fs = std::filesystem;

static int pivot_root(const char *new_root, const char *put_old)
{
    return syscall(SYS_pivot_root, new_root, put_old);
}

[[nodiscard]]
static bool start_squashfuse(const char* file, std::size_t offset)
{
    // Run squashfuse
    info("Mounting image...");
    auto pid = os::fork_and_execv_with_caps(
        config::SQUASHFUSE,
        "-f",
        "-o", fmt::format("offset={},uid={},gid={}", offset, getuid(), getgid()).c_str(),
        file,
        config::ROOTFS
    );

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

        if(os::is_mountpoint(config::ROOTFS))
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

    setenv("FUSE_OVERLAYFS_DISABLE_OVL_WHITEOUT", "y", 1);
    auto pid = os::fork_and_execv_with_caps(
        config::FUSE_OVERLAYFS,
        "-f",
        "-o", fmt::format("lowerdir={},upperdir={},workdir={},noacl", config::ROOTFS, config::UPPER, config::WORK).c_str(),
        config::FINAL
    );

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

        if(os::is_mountpoint(config::FINAL))
            return true;

        usleep(10*1000);
    }

    sys_fatal("Timeout!");
    kill(pid, SIGKILL);
    return false;
}

struct Args
{
    bool help = false;
    std::vector<std::string> bind;
};

void usage()
{
    fmt::print(R"(EOS
Usage: tiny-runtime [options] [cmd to execute in container...]

Options:
  --help                   This help screen
  --bind PATH              Make PATH from outside available as PATH in container
  --bind OUTSIDE:INSIDE    Make OUTSIDE available as INSIDE in container
EOS)");
}

int main(int argc, char** argv)
{
    Args args;
    argparser::parse(args, std::span<char*>(argv+1, argc-1));

    // if(args.help)
    // {
    //     usage();
    //     return 0;
    // }

    int euid = geteuid();
    int egid = getegid();

    int containerArg = 1;

    mkdir(config::SESSION, 0777);

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
    if(mount("tmpfs", config::SESSION, "tmpfs", 0, "size=100M") != 0)
        sys_fatal("Could not mount tmpfs");

    // and make it unbindable so it's not available in the container later
    if(mount(nullptr, config::SESSION, nullptr, MS_UNBINDABLE, nullptr) != 0)
        sys_fatal("Could not make session dir {} unbindable", config::SESSION);

    // Create directories
    os::create_directory(config::ROOTFS);
    os::create_directory(config::UPPER);
    os::create_directory(config::WORK);
    os::create_directory(config::FINAL);

    // Find our executable
    auto self = []{
        char buf[1024];
        auto ret = readlink("/proc/self/exe", buf, sizeof(buf));
        if(ret < 0 || ret == sizeof(buf))
            sys_fatal("Could not read link /proc/self/exe");
        return std::string{buf};
    }();

    // Write utilities
    std::string imageFile = self;
    std::size_t imageOffset = 0;
    std::size_t imageSize = 0;
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

        imageOffset = *mySize + *squashFuseSize + *overlayfsSize;
        imageSize = os::file_size(self.c_str()) - imageOffset;

        if(imageSize == 0)
        {
            if(argc < 2)
                fatal("Need container image as parameter or concatenated to the executable");

            imageFile = argv[1];
            imageOffset = 0;
            imageSize = os::file_size(imageFile.c_str());
            containerArg = 2;
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

        writeTool(config::SQUASHFUSE, squashFuseOffset, *squashFuseSize);
        writeTool(config::FUSE_OVERLAYFS, overlayfsOffset, *overlayfsSize);
    }

    // Find squashfs image
    std::size_t squashFSOffset = 0;
    {
        int fd = open(imageFile.c_str(), O_RDONLY);
        if(fd < 0)
            sys_fatal("Could not open image file {}", imageFile);

        auto guard = sg::make_scope_guard([&]{ close(fd); });

        if(auto off = image::findSquashFS(fd, imageOffset))
            squashFSOffset = *off;
        else
            fatal("Could not find squashFS image inside container file");
    }

    {
        auto pid = fork();
        if(pid == 0)
        {
            // New process group
            setpgid(0, 0);

            if(!start_squashfuse(imageFile.c_str(), squashFSOffset))
                std::exit(1);

            if(!start_overlayfs())
                std::exit(1);

            // Stop ourselves, so that if we get orphaned, the kernel sends
            // a SIGHUP,SIGCONT sequence to all processes in this process group.
            // This trick is stolen from enroot.
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
        {"/tmp"},
        {"/var/tmp"},
        {"/run"},
    });
    for(auto& path : bindMounts)
    {
        if(!os::bind_mount(path.path, path.flags))
            fatal("Could not mount {}", path.path);
    }

    // Mount $HOME
    if(auto home = getenv("HOME"))
    {
        if(!os::bind_mount(home))
            fatal("Could not mount your home directory '{}'", home);
    }

    // Mount nvidia tools & libraries
    info("NVIDIA setup...");
    nvidia::configure();

    fs::path cwd = fs::current_path();

    // Pivot into root
    if(pivot_root(config::FINAL, config::FINAL) != 0)
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

    try
    {
        fs::current_path(cwd);
    }
    catch(fs::filesystem_error& e)
    {
        error("Could not cd to current directory ({}): {}", std::string{cwd}, e.what());
    }

    info("Starting user command");

    if(fs::exists("/.singularity.d/runscript"))
    {
        std::vector<char*> args;
        args.push_back(strdup("runscript"));

        for(int i = containerArg; i < argc; ++i)
            args.push_back(strdup(argv[i]));

        args.push_back(nullptr);

        if(execv("/.singularity.d/runscript", args.data()) != 0)
            sys_fatal("Could not execute /.singularity.d/runscript");
    }
    else if(fs::exists("/etc/rc"))
    {
        std::vector<char*> args;
        args.push_back(strdup("rc"));

        for(int i = containerArg; i < argc; ++i)
            args.push_back(strdup(argv[i]));

        args.push_back(nullptr);

        if(execv("/etc/rc", args.data()) != 0)
            sys_fatal("Could not execute /etc/rc");
    }
    else
    {
        auto args = std::to_array({strdup("/bin/bash"), static_cast<char*>(nullptr)});
        if(execv("/bin/bash", args.data()) != 0)
            sys_fatal("Could not execute /bin/bash");
    }

    return 0;
}
