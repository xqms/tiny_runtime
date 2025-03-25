// NVIDIA support
// Author: Max Schwarz <max.schwarz@online.de>

#include "nvidia.h"

#include <array>
#include <filesystem>

#include <fmt/std.h>

#include <fcntl.h>
#include <sys/stat.h>

#include "config.h"
#include "ldcache.h"
#include "log.h"
#include "os.h"

namespace fs = std::filesystem;

namespace {
constexpr auto BINARIES = std::to_array({
    "nvidia-smi",          /* System management interface */
    "nvidia-debugdump",    /* GPU coredump utility */
    "nvidia-persistenced", /* Persistence mode utility */
    "nv-fabricmanager",    /* NVSwitch fabrimanager utility */
});

constexpr auto LIBRARIES = std::to_array({
    "libnvidia-ml.so",
    "libcuda.so",                  /* CUDA driver library */
    "libcudadebugger.so",          /* CUDA Debugger Library */
    "libnvidia-opencl.so",         /* NVIDIA OpenCL ICD */
    "libnvidia-gpucomp.so",        /* Shared Compiler Library */
    "libnvidia-ptxjitcompiler.so", /* PTX-SASS JIT compiler (used by libcuda) */
    "libnvidia-fatbinaryloader.so", /* fatbin loader (used by libcuda) */
    "libnvidia-allocator.so",       /* NVIDIA allocator runtime library */
    "libnvidia-compiler.so",        /* NVVM-PTX compiler for OpenCL (used by
                                       libnvidia-opencl) */
    "libnvidia-pkcs11.so",          /* Encrypt/Decrypt library */
    "libnvidia-pkcs11-openssl3.so", /* Encrypt/Decrypt library (OpenSSL 3
                                       support) */
    "libnvidia-nvvm.so",            /* The NVVM Compiler library */
    "libvdpau_nvidia.so",           /* NVIDIA VDPAU ICD */
    "libnvidia-encode.so",          /* Video encoder */
    "libnvidia-opticalflow.so",     /* NVIDIA Opticalflow library */
    "libnvcuvid.so",                /* Video decoder */
    "libnvidia-egl-wayland.so",     /* EGL wayland platform extension (used by
                                       libEGL_nvidia) */
    "libnvidia-eglcore.so",         /* EGL core (used by libGLES*[_nvidia] and
                                       libEGL_nvidia) */
    "libnvidia-glcore.so", /* OpenGL core (used by libGL or libGLX_nvidia) */
    "libnvidia-tls.so", /* Thread local storage (used by libGL or libGLX_nvidia)
                         */
    "libnvidia-glsi.so", /* OpenGL system interaction (used by libEGL_nvidia) */
    "libnvidia-fbc.so",  /* Framebuffer capture */
    "libnvidia-ifr.so",  /* OpenGL framebuffer capture */
    "libnvidia-rtcore.so",    /* Optix */
    "libnvoptix.so",          /* Optix */
    "libGLX_nvidia.so",       /* OpenGL/GLX ICD */
    "libEGL_nvidia.so",       /* EGL ICD */
    "libGLESv2_nvidia.so",    /* OpenGL ES v2 ICD */
    "libGLESv1_CM_nvidia.so", /* OpenGL ES v1 common profile ICD */
    "libnvidia-glvkspirv.so", /* SPIR-V Lib for Vulkan */
    "libnvidia-cbl.so",       /* VK_NV_ray_tracing */
});

constexpr auto BINDS =
    std::to_array({"/usr/share/glvnd/egl_vendor.d", "/usr/share/egl"});
} // namespace

namespace nvidia {

bool configure() {
  for (const auto &binary : BINARIES) {
    if (auto path = os::find_binary(binary)) {
      if (!os::bind_mount(path->string().c_str(), {}, MS_BIND))
        error("Could not bind mount '{}'", *path);
    }
  }

  fs::path libraryDirName = ".trt-libs";
  fs::path libraryDirInContainer = fs::path{"/"} / libraryDirName;
  fs::path libraryDir = fs::path{config::FINAL} / libraryDirName;
  fs::create_directories(libraryDir);

  LDCache cache;
  auto resolved = cache.resolve(LIBRARIES);
  for (const auto &entry : resolved) {
    fs::path target = libraryDir / entry.key;
    {
      int fd = open(target.c_str(), O_RDWR | O_CREAT, 0755);
      close(fd);
    }
    if (mount(std::string{entry.path}.c_str(), target.c_str(), nullptr, MS_BIND,
              nullptr) != 0) {
      error("Could not bind {} to {}: {}", entry.path, target, strerror(errno));
    }
  }

  for (fs::path path : BINDS) {
    if (!fs::exists(path))
      continue;

    fs::path inContainer = fs::path{config::FINAL} / path;
    if (!fs::exists(inContainer))
      fs::create_directories(inContainer);

    if (!os::bind_mount(path.c_str(), {}, MS_BIND))
      error("Could not bind mount '{}'", path);
  }

  if (auto lib_path = getenv("LD_LIBRARY_PATH")) {
    std::string_view current{lib_path};
    if (!current.empty())
      setenv("LD_LIBRARY_PATH",
             fmt::format("{}:{}", libraryDirInContainer, current).c_str(), 1);
    else
      setenv("LD_LIBRARY_PATH", libraryDirInContainer.c_str(), 1);
  } else
    setenv("LD_LIBRARY_PATH", libraryDirInContainer.c_str(), 1);

  return true;
}

} // namespace nvidia
