
cmake_minimum_required(VERSION 3.12)
project(tiny_runtime)

include(ExternalProject)
ExternalProject_Add(squashfuse
    URL https://github.com/vasi/squashfuse/releases/download/0.5.2/squashfuse-0.5.2.tar.gz
    URL_HASH SHA256=54e4baaa20796e86a214a1f62bab07c7c361fb7a598375576d585712691178f5
    DOWNLOAD_EXTRACT_TIMESTAMP true
    BUILD_IN_SOURCE ON

    CONFIGURE_COMMAND ./autogen.sh COMMAND ./configure CFLAGS=-no-pie LDFLAGS=--static --disable-shared --enable-static --prefix=${CMAKE_CURRENT_BINARY_DIR}/tools/
    BUILD_COMMAND make VERBOSE=1
)
ExternalProject_Add(fuse_overlayfs
    URL https://github.com/containers/fuse-overlayfs/releases/download/v1.13/fuse-overlayfs-x86_64
    URL_HASH SHA256=0011ad825dc0274b6e330fb9a8d3d578ea7bbf738bab08934b90be070b8d0a4a
    DOWNLOAD_NO_EXTRACT ON

    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
)
ExternalProject_Add(libnvidia-container
    DOWNLOAD_COMMAND rm -Rf $<SOURCE_DIR>
             COMMAND git clone --recursive --depth=1 -b v1.14.6 https://github.com/NVIDIA/libnvidia-container.git $<SOURCE_DIR>
             COMMAND git -C $<SOURCE_DIR> checkout d2eb0afe86f0b643e33624ee64f065dd60e952d4

    CONFIGURE_COMMAND ""
    #PATCH_COMMAND patch -p1 < ${CMAKE_CURRENT_SOURCE_DIR}/patches/fix_elftoolchain.patch
    #      COMMAND patch -p1 < ${CMAKE_CURRENT_SOURCE_DIR}/patches/fix_rpc_flags.patch

    BUILD_IN_SOURCE ON
    BUILD_COMMAND make prefix=${CMAKE_CURRENT_BINARY_DIR}/tools WITH_NVCGO=no WITH_LIBELF=yes WITH_TIRPC=yes
    INSTALL_COMMAND make install prefix=${CMAKE_CURRENT_BINARY_DIR}/tools WITH_NVCGO=no WITH_LIBELF=yes WITH_TIRPC=yes
)

add_library(nvc INTERFACE)
target_link_libraries(nvc INTERFACE
    "${CMAKE_CURRENT_BINARY_DIR}/tools/lib/libnvidia-container.a"
    elf
    seccomp
    z
)
target_include_directories(nvc INTERFACE
    "${CMAKE_CURRENT_BINARY_DIR}/tools/include"
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_FLAGS "-Wall")

add_subdirectory(fmt)

add_executable(tiny_runtime_starter
    tiny_runtime.cpp
    elf_size.cpp
    os.cpp
    nvidia.cpp
)
target_link_libraries(tiny_runtime_starter
    fmt::fmt
    cap
    nvc
)
target_link_options(tiny_runtime_starter PRIVATE
    "-static"
)

ExternalProject_Get_Property(fuse_overlayfs DOWNLOAD_DIR)
set(FUSE_OVERLAYFS_OUT "${DOWNLOAD_DIR}/fuse-overlayfs-x86_64")
add_custom_command(
    OUTPUT tiny_runtime
    DEPENDS tiny_runtime_starter squashfuse
    COMMAND strip -o tiny_runtime.stripped tiny_runtime_starter
    COMMAND strip -o squashfuse.stripped tools/bin/squashfuse_ll
    COMMAND strip -o overlayfs.stripped "${FUSE_OVERLAYFS_OUT}"
    COMMAND cat tiny_runtime.stripped squashfuse.stripped overlayfs.stripped > tiny_runtime
    COMMAND chmod a+x tiny_runtime
)

add_custom_target(build_tiny_runtime ALL
    DEPENDS tiny_runtime
)
