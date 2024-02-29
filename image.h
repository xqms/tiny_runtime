// Find squashfs image in various container formats
// Author: Max Schwarz <max.schwarz@online.de>

#ifndef IMAGE_H
#define IMAGE_H

#include <cstdlib>
#include <optional>

namespace image
{
    std::optional<std::size_t> findSquashFS(int fd, std::size_t offset);
}

#endif
