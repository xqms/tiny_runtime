// Find squashfs image in various container formats
// Author: Max Schwarz <max.schwarz@online.de>

#include "image.h"

#include <cstdlib>
#include <optional>
#include <string_view>

#include <unistd.h>

#include "log.h"

namespace image
{

std::optional<std::size_t> findSquashFS(int fd, std::size_t offset)
{
    using namespace std::literals;

    // Try 1: Is this a squashfs image already?
    {
        char magic[4];
        int ret = pread(fd, magic, sizeof(magic), offset);
        if(ret != 4)
        {
            sys_error("Could not read squashfs magic sequence");
            return {};
        }

        if(std::string_view{magic, sizeof(magic)} == "hsqs"sv)
            return offset;
    }
}

}
