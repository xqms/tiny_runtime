
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

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "-Wall")

add_subdirectory(fmt)

add_executable(tiny_runtime_starter
    tiny_runtime.cpp
    elf_size.cpp
)
target_link_libraries(tiny_runtime_starter
    fmt::fmt
    cap
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
