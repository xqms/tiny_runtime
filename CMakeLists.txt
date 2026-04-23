
cmake_minimum_required(VERSION 3.12)

project(tiny_runtime)

set(VERSION_MAJOR 1)
set(VERSION_MINOR 6)
set(VERSION_PATCH 1)

include(ExternalProject)
ExternalProject_Add(squashfuse
    URL https://github.com/vasi/squashfuse/releases/download/0.5.2/squashfuse-0.5.2.tar.gz
    URL_HASH SHA256=54e4baaa20796e86a214a1f62bab07c7c361fb7a598375576d585712691178f5
    DOWNLOAD_EXTRACT_TIMESTAMP true
    BUILD_IN_SOURCE ON

    CONFIGURE_COMMAND ./autogen.sh COMMAND ./configure CFLAGS=-no-pie LDFLAGS=--static --disable-shared --enable-static --prefix=${CMAKE_CURRENT_BINARY_DIR}/tools/
    BUILD_COMMAND make VERBOSE=1
)

if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL x86_64)
    set(FUSE_OVERLAYFS_URL "https://github.com/containers/fuse-overlayfs/releases/download/v1.16/fuse-overlayfs-x86_64")
    set(FUSE_OVERLAYFS_HASH "SHA256=30c6b9e192600d6854e13397974c709d7cabd980b7d1a4d67defd8eb69677e91")
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL aarch64)
    set(FUSE_OVERLAYFS_URL "https://github.com/containers/fuse-overlayfs/releases/download/v1.16/fuse-overlayfs-aarch64")
    set(FUSE_OVERLAYFS_HASH "SHA256=6c9ee54166fe7d33ebbfb085812585441f22ebe2a24a868d0a878d3127bcb89e")
else()
    message(FATAL_ERROR "Unrecognized machine type ${CMAKE_SYSTEM_PROCESSOR}")
endif()

ExternalProject_Add(fuse_overlayfs
    URL "${FUSE_OVERLAYFS_URL}"
    URL_HASH "${FUSE_OVERLAYFS_HASH}"
    DOWNLOAD_NO_EXTRACT ON
    DOWNLOAD_NAME fuse-overlayfs

    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
)
ExternalProject_Add(squashfs-tools
    URL https://github.com/plougher/squashfs-tools/releases/download/4.7.5/squashfs-tools-4.7.5.tar.gz
    URL_HASH SHA256=547b7b7f4d2e44bf91b6fc554664850c69563701deab9fd9cd7e21f694c88ea6
    DOWNLOAD_EXTRACT_TIMESTAMP ON
    BUILD_IN_SOURCE ON

    CONFIGURE_COMMAND ""
    BUILD_COMMAND make -C squashfs-tools EXTRA_LDFLAGS=-static ZSTD_SUPPORT=1 USE_PREBUILT_MANPAGES=y "INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/tools"
    INSTALL_COMMAND make -C squashfs-tools EXTRA_LDFLAGS=-static ZSTD_SUPPORT=1 USE_PREBUILT_MANPAGES=y "INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/tools" install
)

include(cmake/CPM.cmake)

CPMAddPackage("gh:fmtlib/fmt#10.2.1")
CPMAddPackage("gh:boost-ext/reflect@1.0.8")
CPMAddPackage("gh:nlohmann/json@3.11.3")

add_library(reflect INTERFACE)
target_include_directories(reflect SYSTEM INTERFACE ${reflect_SOURCE_DIR})
add_library(reflect::reflect ALIAS reflect)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

add_executable(tiny_runtime_starter
    tiny_runtime.cpp
    elf_size.cpp
    os.cpp
    nvidia.cpp
    ldcache.cpp
    image.cpp
    log.cpp
)
target_link_libraries(tiny_runtime_starter
    fmt::fmt
    reflect::reflect
    nlohmann_json::nlohmann_json
    cap
)
target_link_options(tiny_runtime_starter PRIVATE
    "-static"
)
target_compile_definitions(tiny_runtime_starter PRIVATE
    VERSION_MAJOR=${VERSION_MAJOR}
    VERSION_MINOR=${VERSION_MINOR}
    VERSION_PATCH=${VERSION_PATCH}
)

ExternalProject_Get_Property(fuse_overlayfs DOWNLOAD_DIR)
set(FUSE_OVERLAYFS_OUT "${DOWNLOAD_DIR}/fuse-overlayfs")
add_custom_command(
    OUTPUT tiny_runtime
    DEPENDS tiny_runtime_starter squashfuse fuse_overlayfs squashfs-tools
    COMMAND strip -o tiny_runtime.stripped tiny_runtime_starter
    COMMAND strip -o squashfuse.stripped tools/bin/squashfuse_ll
    COMMAND strip -o overlayfs.stripped "${FUSE_OVERLAYFS_OUT}"
    COMMAND strip -o mksquashfs.stripped tools/bin/mksquashfs
    COMMAND cat tiny_runtime.stripped squashfuse.stripped overlayfs.stripped mksquashfs.stripped > tiny_runtime
    # COMMAND cat tiny_runtime_starter tools/bin/squashfuse_ll "${FUSE_OVERLAYFS_OUT}" > tiny_runtime
    COMMAND chmod a+x tiny_runtime
)

add_custom_target(build_tiny_runtime ALL
    DEPENDS tiny_runtime
)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/tiny_runtime DESTINATION bin)
install(FILES utils/apparmor/tiny_runtime DESTINATION /etc/apparmor.d/)

# Packaging
set(CPACK_DEBIAN_PACKAGE_NAME tiny_runtime)
set(CPACK_DEBIAN_FILE_NAME tiny_runtime.deb)
set(CPACK_DEBIAN_PACKAGE_VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")
set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "")
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "all")
set(CPACK_PACKAGE_CONTACT "Max Schwarz <max.schwarz@ais.uni-bonn.de>")
include(CPack)

