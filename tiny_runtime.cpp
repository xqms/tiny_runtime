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
#include <spanstream>
#include <iostream>

#include <sched.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <wordexp.h>
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

#include <nlohmann/json.hpp>

#include "config.h"
#include "log.h"
#include "os.h"
#include "static_path.h"
#include "elf_size.h"
#include "scope_guard.h"
#include "nvidia.h"
#include "image.h"
#include "argparser.h"
#include "serialization.h"

namespace fs = std::filesystem;

static int pivot_root(const char *new_root, const char *put_old)
{
    return syscall(SYS_pivot_root, new_root, put_old);
}

template <std::size_t N, std::size_t ... Is>
consteval std::array<char, N - 1>
to_array(const char (&a)[N], std::index_sequence<Is...>)
{
    return {{a[Is]...}};
}

template <std::size_t N>
consteval std::array<char, N - 1> to_array(const char (&a)[N])
{
    return to_array(a, std::make_index_sequence<N - 1>());
}

struct InstallSegment
{
    static constexpr auto MAGIC = to_array("INSTALL_SEGMENT");

    std::array<char, MAGIC.size()> magic = MAGIC;
    std::size_t segmentSize = 0;

    std::vector<std::string> args;
};

struct Segment
{
    std::size_t offset = 0;
    std::size_t size = 0;
};
struct Segments
{
    Segment squashFuse;
    Segment fuseOverlay;
    Segment mksquashfs;

    std::optional<InstallSegment> install;

    Segment image;
};

static Segments findSegments(const char* file)
{
    Segments segments;

    std::size_t offset = 0;

    if(auto mySize = getELFSize(file, offset))
    {
        segments.squashFuse.offset = *mySize;
        offset += *mySize;
    }
    else
        fatal("Could not get own ELF size");

    if(auto size = getELFSize(file, offset))
    {
        segments.squashFuse.size = *size;
        offset += *size;
    }
    else
        fatal("Could not get squashfuse ELF size");

    segments.fuseOverlay.offset = offset;
    if(auto size = getELFSize(file, offset))
    {
        segments.fuseOverlay.size = *size;
        offset += *size;
    }
    else
        fatal("Could not get fuse-overlayfs ELF size");

    // mksquashFS present?
    segments.mksquashfs.offset = offset;
    if(auto size = getELFSize(file, offset))
    {
        segments.mksquashfs.size = *size;
        offset += *size;
    }

    // Install segment present?
    {
        std::ifstream input(file);
        input.seekg(offset);

        segments.install = serialization::deserialize<InstallSegment>(input);
        if(segments.install)
            offset += segments.install->segmentSize;
    }

    segments.image.offset = offset;
    segments.image.size = os::file_size(file) - segments.image.offset;

    return segments;
}

static void writeTool(const char* file, const Segment& segment, const char* dest)
{
    int fd_src = open(file, O_RDONLY);
    if(fd_src < 0)
        sys_fatal("Could not open {}", file);

    auto guard_src = sg::make_scope_guard([&]{ close(fd_src); });

    if(lseek64(fd_src, segment.offset, SEEK_SET) != static_cast<off64_t>(segment.offset))
        sys_fatal("Could not seek to tool at offset {} in {}", segment.offset, file);

    int fd_dst = open(dest, O_RDWR | O_CREAT, 0755);
    if(fd_dst < 0)
        sys_fatal("Could not create tool file {}", dest);

    auto guard_dst = sg::make_scope_guard([&]{ close(fd_dst); });

    std::array<char, 128*1024> buf;
    std::size_t size = segment.size;
    while(size > 0)
    {
        ssize_t bsize = std::min(buf.size(), size);

        ssize_t ret = read(fd_src, buf.data(), bsize);
        if(ret != bsize)
            sys_fatal("Could not read from {}", file);

        if(write(fd_dst, buf.data(), bsize) != bsize)
            sys_fatal("Could not write to {}", dest);

        size -= bsize;
    }
}

[[nodiscard]]
static bool start_squashfuse(const char* file, std::size_t offset)
{
    // Run squashfuse
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
    argparser::Option<bool, {.shortName='h'}> help = false;

    std::optional<std::string> image;
    std::vector<std::string> bind;
    std::optional<std::string> install;
    bool verbose = false;
    std::optional<std::string> docker;
    std::optional<std::string> docker_out = "docker.trt";
    std::vector<std::string> env;

    argparser::PositionalArguments remaining;
};

void usage()
{
    fmt::print(R"EOS(
Usage: tiny_runtime [options] [cmd to execute in container...]

Options:
  --help                   This help screen.
  --image IMAGE            Use image IMAGE.
  --bind PATH              Make PATH from outside available as PATH in container.
  --bind OUTSIDE:INSIDE    Make OUTSIDE available as INSIDE in container.
  --install IMAGE          Install this tiny_runtime inside IMAGE.
                           The image is renamed to extension ".trt".
  --verbose                Enable verbose messages.
  --docker IMAGE:TAG       Obtain image from local Docker daemon. The image
                           is saved as docker.trt.
  --docker-out PATH        Save Docker image as PATH instead.
  --env NAME=VALUE         Set NAME=VALUE in environment

)EOS");
}

bool install(const fs::path& self, const Segments& segments, Args& args, const fs::path& dest)
{
    info("Installing into {}", dest);

    if(isELF(dest.c_str()))
    {
        info("{} is already an ELF executable. Checking if it is a tiny_runtime...", dest);
        Segments prevSegments = findSegments(dest.c_str());

        if(!prevSegments.install)
            fatal("{} is something else.", dest);

        info("it is.");

        if(!os::remove_leading_space(dest, prevSegments.image.offset))
            fatal("Could not remove tiny_runtime from image {}", dest);
    }

    InstallSegment installSegment;

    // Serialize args (without --install or --docker)
    args.install = {};
    args.docker = {};
    args.docker_out = {};
    installSegment.args = argparser::serialize(args);

    const std::size_t serializedSize = serialization::serializedSize(installSegment);

    // Pad such that our binary + install segment ends at 4KB boundary
    const std::size_t binarySize = segments.image.offset;
    const std::size_t combinedSize = binarySize + serializedSize;
    const std::size_t paddedSize = ((combinedSize + 4096 - 1) / 4096) * 4096;
    const std::size_t paddedInstallSize = paddedSize - binarySize;

    installSegment.segmentSize = paddedInstallSize;
    std::vector<char> serializedInstall(paddedInstallSize, 0);

    {
        std::ospanstream out(serializedInstall);
        if(!serialization::serializeInto(installSegment, out))
            fatal("Could not serialize install segment");
    }

    if(!os::prepend_space_to_file(dest, paddedSize))
        fatal("Could not prepend space to file");

    // Write everything to front of file
    {
        int fd = open(dest.c_str(), O_WRONLY);
        if(fd < 0)
            sys_fatal("Could not open {}", dest);
        auto fdGuard = sg::make_scope_guard([&]{ close(fd); });

        int srcFD = open(self.c_str(), O_RDONLY);
        if(srcFD < 0)
            sys_fatal("Could not open {}", self);
        auto srcGuard = sg::make_scope_guard([&]{ close(srcFD); });

        if(!os::copy_from_to_fd(srcFD, fd, binarySize))
            fatal("Could not copy our binary to {}", dest);

        if(!os::write_to_fd(fd, serializedInstall))
            fatal("Could not write install segment to {}", dest);
    }

    // Make executable
    fs::permissions(dest, fs::perms::owner_exec | fs::perms::group_exec | fs::perms::others_exec, fs::perm_options::add);

    info("tiny_runtime installed into image.");

    return 0;
}

bool docker(const fs::path& self, const Segments& segments, Args& args)
{
    using json = nlohmann::json;

    fs::path out = fs::absolute(*args.docker_out);

    if(fs::exists(out))
        fatal("Output file '{}' already exists. Please remove it first.", out);

    // Obtain JSON
    auto jsonString = os::run_get_output("docker", "image", "inspect", args.docker->c_str());
    if(!jsonString)
        fatal("Could not query image information from docker daemon");

    json spec = json::parse(*jsonString);
    auto containerConfig = spec.at(0).at("Config");

    if(containerConfig.contains("Entrypoint"))
    {
        args.remaining.clear();

        for(auto& arg : containerConfig.at("Entrypoint"))
            args.remaining.push_back(arg.get<std::string>());
    }

    if(containerConfig.contains("Env"))
    {
        for(auto& env : containerConfig.at("Env"))
            args.env.push_back(env);
    }

    char tempDir[] = {"/tmp/tiny_runtime-XXXXXX"};
    if(!mkdtemp(tempDir))
        sys_fatal("Could not create temporary directory");

    auto guard = sg::make_scope_guard([&]{ fs::remove_all(tempDir); });

    fs::path mksquashfs = fs::path{tempDir} / "mksquashfs";
    writeTool(self.c_str(), segments.mksquashfs, mksquashfs.c_str());

    bool success = os::run(
        "docker", "run",
        "-v", fmt::format("{}:/mksquashfs", mksquashfs).c_str(),
        "-v", fmt::format("{}:/mksquashfs_out", out.parent_path()).c_str(),
        "--entrypoint", "",
        "-it", args.docker->c_str(),

        "/mksquashfs",
        "/",
        (fs::path("/mksquashfs_out") / out.filename()).c_str(),
        "-one-file-system",
        "-comp", "zstd", "-Xcompression-level", "8",
        "-e", "/mksquashfs",
        "-e", "/mksquashfs_out"
    );
    if(!success)
    {
        error("Calling mksquashfs inside docker failed (rerun with --verbose to see command)");
        return false;
    }

    success = os::run(
        "docker", "run",
        "-v", fmt::format("{}:/mksquashfs_out", out.parent_path()).c_str(),
        "-it", "alpine",
        "chown",
            fmt::format("{}:{}", getuid(), getgid()).c_str(),
            (fs::path("/mksquashfs_out") / out.filename()).c_str()
    );
    if(!success)
        error("Could not change owner of {}", out);

    // Transition to --install
    return install(self, segments, args, out);
}

int main(int argc, char** argv)
{
    // Find our executable
    auto self = fs::read_symlink("/proc/self/exe");

    Segments segments = findSegments(self.c_str());

    Args args;
    try
    {
        argparser::Parser parser{args};

        // Additional arguments from environment variable TRT_ARGS
        if(auto env = getenv("TRT_ARGS"))
        {
            wordexp_t words{};
            auto guard = sg::make_scope_guard([&]{ wordfree(&words); });

            if(auto ret = wordexp(env, &words, WRDE_SHOWERR))
            {
                switch(ret)
                {
                    case WRDE_BADCHAR: fatal("Invalid character in TRT_ARGS");
                    case WRDE_BADVAL:  fatal("Undefined env variable in TRT_ARGS");
                    case WRDE_CMDSUB:  fatal("Command substitution failed in TRT_ARGS");
                    case WRDE_NOSPACE: fatal("Out of memory");
                    case WRDE_SYNTAX:  fatal("Syntax error in TRT_ARGS");
                }
                fatal("Unknown wordexp() error");
            }

            parser.parse(std::span<char*>(words.we_wordv, words.we_wordc));
        }

        if(segments.install)
            parser.parse(segments.install->args);

        parser.parse(std::span<char*>(argv+1, argc-1));
    }
    catch(argparser::ArgumentException& e)
    {
        error("Could not parse arguments: {}", e.what());
        error("See --help for help.");
        return 1;
    }

    if(args.help)
    {
        usage();
        return 0;
    }

    // Logging
    log_debug = args.verbose;

    debug("arguments: {}", argparser::serialize(args));

    if(args.docker)
    {
        if(!docker(self, segments, args))
            return 1;

        return 0;
    }

    struct
    {
        std::string file;
        std::size_t offset;
    } image;

    if(args.install)
    {
        if(args.image)
            fatal("You supplied --install and --image, which does not make any sense.");

        fs::path dest = *args.install;
        if(!install(self, segments, args, dest))
            return 1;

        return 0;
    }

    if(args.image)
        image = {*args.image, 0};
    else
    {
        if(segments.image.size == 0)
            fatal("Either need --image or an image file concatenated to tiny_runtime");

        image = {self, segments.image.offset};
    }

    int euid = geteuid();
    int egid = getegid();

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
    if(mount("tmpfs", config::SESSION, "tmpfs", 0, "") != 0)
        sys_fatal("Could not mount tmpfs");

    // and make it unbindable so it's not available in the container later
    if(mount(nullptr, config::SESSION, nullptr, MS_UNBINDABLE, nullptr) != 0)
        sys_fatal("Could not make session dir {} unbindable", config::SESSION);

    // Create directories
    os::create_directory(config::ROOTFS);
    os::create_directory(config::UPPER);
    os::create_directory(config::WORK);
    os::create_directory(config::FINAL);

    // Write tools
    writeTool(self.c_str(), segments.squashFuse, config::SQUASHFUSE);
    writeTool(self.c_str(), segments.fuseOverlay, config::FUSE_OVERLAYFS);

    // Find squashfs image
    std::size_t squashFSOffset = 0;
    {
        std::ifstream file{image.file};
        if(!file)
            sys_fatal("Could not open image file {}", image.file);

        if(auto off = image::findSquashFS(file, image.offset))
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

            if(!start_squashfuse(image.file.c_str(), squashFSOffset))
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
    auto bindMounts = std::to_array({
        "/dev",
        "/etc/hosts",
        "/etc/passwd",
        "/etc/group",
        "/etc/resolv.conf",
        "/proc",
        "/sys",
        "/tmp",
        "/var/tmp",
        "/run"
    });
    for(auto& path : bindMounts)
    {
        if(!os::bind_mount(path))
            fatal("Could not mount {}", path);
    }

    // Mount $HOME
    if(auto home = getenv("HOME"))
    {
        if(!os::bind_mount(home))
            fatal("Could not mount your home directory '{}'", home);
    }

    // Some helpful environment variables
    {
        // Since we auto-mount $HOME, a python instance in the container might look
        // for packages in ~/.local/lib/pythonXY, which is probably not what the user
        // expects.
        setenv("PYTHONNOUSERSITE", "1", 1);

        // Set debian_chroot, which shows up in PS1 on Debian-based systems.
        setenv("debian_chroot", "container", 1);
    }

    // User/OCI-specified environment variables
    for(auto& env : args.env)
    {
        auto eq = env.find('=');
        if(eq == env.npos)
        {
            error("Ignoring invalid env spec '{}'", env);
            continue;
        }

        auto name = env.substr(0, eq);
        auto value = env.substr(eq+1);
        debug("Setting {}={}", name, value);
        setenv(name.c_str(), value.c_str(), 1);
    }

    // Custom mounts
    for(auto& path : args.bind)
    {
        auto sep = path.find(':');
        if(sep != path.npos)
        {
            auto outside = path.substr(0, sep);
            auto inside = path.substr(sep+1);
            if(!os::bind_mount(outside, inside))
                fatal("Could not bind {} to {} inside container", outside, inside);
        }
        else
            if(!os::bind_mount(path))
                fatal("Could not bind {} inside container", path);
    }

    // Mount nvidia tools & libraries
    debug("NVIDIA setup...");
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

    if(fs::exists("/.singularity.d/actions/run"))
    {
        std::vector<char*> runArgs;
        runArgs.push_back(strdup("run"));

        for(auto& arg : args.remaining)
            runArgs.push_back(strdup(arg.c_str()));

        runArgs.push_back(nullptr);

        debug("Starting user command: /.singularity.d/actions/run {}", args.remaining);
        if(execv("/.singularity.d/actions/run", runArgs.data()) != 0)
            sys_fatal("Could not execute /.singularity.d/actions/run");
    }
    else if(fs::exists("/etc/rc"))
    {
        std::vector<char*> runArgs;
        runArgs.push_back(strdup("runscript"));

        for(auto& arg : args.remaining)
            runArgs.push_back(strdup(arg.c_str()));

        runArgs.push_back(nullptr);

        debug("Starting user command: /etc/rc {}", args.remaining);
        if(execv("/etc/rc", runArgs.data()) != 0)
            sys_fatal("Could not execute /etc/rc");
    }
    else
    {
        std::vector<char*> runArgs;
        std::string cmd = "/bin/bash";

        if(args.remaining.empty())
            runArgs.push_back(strdup(cmd.c_str()));
        else
        {
            cmd = args.remaining[0];

            for(auto& arg : args.remaining)
                runArgs.push_back(strdup(arg.c_str()));
        }
        runArgs.push_back(nullptr);

        debug("Running {}", runArgs | std::views::take(runArgs.size()-1));
        if(execv(cmd.c_str(), runArgs.data()) != 0)
            sys_fatal("Could not execute {}", runArgs | std::views::take(runArgs.size()-1));
    }

    return 0;
}
