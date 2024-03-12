// Path configuration
// Author: Max Schwarz <max.schwarz@online.de>

#ifndef CONFIG_H
#define CONFIG_H

#include "static_path.h"

namespace config
{
    constexpr auto SESSION = StaticPath("/mnt");
    constexpr auto ROOTFS = SESSION / "root";
    constexpr auto FINAL = SESSION / "final";
    constexpr auto UPPER = SESSION / "upper";
    constexpr auto WORK = SESSION / "work";
    constexpr auto FUSE_OVERLAYFS = SESSION / "fuse-overlayfs";
    constexpr auto SQUASHFUSE = SESSION / "squashfuse";
}

#endif
