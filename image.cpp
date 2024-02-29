// Find squashfs image in various container formats
// Author: Max Schwarz <max.schwarz@online.de>

#include "image.h"

#include <cstdlib>
#include <optional>
#include <string_view>
#include <vector>
#include <type_traits>

#include <reflect>

#include <unistd.h>

#include "log.h"

using namespace std::literals;

namespace image
{

namespace
{
    template<int N>
    struct SrcInfo
    {
        std::array<std::size_t, N> offsets;
        std::size_t totalSize = 0;
    };

    template<typename T>
    consteval auto getSrcOffsets()
    {
        constexpr int numFields = reflect::size<T>();
        SrcInfo<numFields> info;

        int opIdx = 0;

        reflect::for_each([&](const auto& member){
            info.offsets[opIdx] = info.totalSize;
            info.totalSize += member.size_of;
            ++opIdx;
        }, T{});

        return info;
    }

    template<class T>
    requires (std::is_trivially_copyable_v<T>)
    T* start_lifetime_as(void* p) noexcept
    {
        return std::launder(static_cast<T*>(std::memmove(p, p, sizeof(T))));
    }

    template<typename T>
    std::optional<T> deserialize(int fd, std::size_t offset)
    {
        constexpr auto srcInfo = getSrcOffsets<T>();

        std::vector<std::byte> bytes(srcInfo.totalSize);
        int ret = pread(fd, bytes.data(), srcInfo.totalSize, offset);
        if(ret != srcInfo.totalSize)
            return {};

        return [&]<auto ... Ns>(std::index_sequence<Ns...>) {
            return T{
                *start_lifetime_as<std::remove_cvref_t<decltype(reflect::get<Ns>(T{}))>>(bytes.data() + srcInfo.offsets[Ns])...
            };
        }(std::make_index_sequence<reflect::size<T>()>());
    }

    template<typename T>
    std::optional<std::vector<T>> deserializeArray(int fd, std::size_t offset, std::size_t numObjects)
    {
        constexpr auto srcInfo = getSrcOffsets<T>();

        std::vector<T> ret;
        ret.reserve(numObjects);

        for(std::size_t i = 0; i < numObjects; ++i)
        {
            if(auto obj = deserialize<T>(fd, offset))
            {
                ret.push_back(std::move(*obj));
                offset += srcInfo.totalSize;
            }
            else
                return {};
        }

        return ret;
    }
}

namespace
{
    std::optional<std::size_t> trySquashFS(int fd, std::size_t offset)
    {
        char magic[4];
        int ret = pread(fd, magic, sizeof(magic), offset);
        if(ret != 4)
            return {};

        if(std::string_view{magic, sizeof(magic)} != "hsqs"sv)
            return {};

        return offset;
    }

    struct SIFHeader
    {
        std::array<char, 32> launch;
        std::array<char, 10> magic;
        std::array<char, 3> version;
        std::array<char, 3> arch;
        std::array<std::byte, 16> id;

        std::int64_t createdAt;
        std::int64_t modifiedAt;

        std::int64_t descriptorsFree;
        std::int64_t descriptorsTotal;
        std::int64_t descriptorsOffset;
        std::int64_t descriptorsSize;

        std::int64_t dataOffset;
        std::int64_t dataSize;
    };

    enum class SIFDataType : std::int32_t
    {
        Deffile = 0x4001,
        EnvVar,
        Labels,
        Partition,
        Signature,
        GenericJSON,
        Generic,
        CryptoMessage,
        SBOM,
        OCIRootIndex,
        OCIBlob
    };

    struct SIFDescriptor
    {
        SIFDataType type;
        bool used;
        std::uint32_t id;
        std::uint32_t groupID;
        std::uint32_t linkedID;
        std::int64_t offset;
        std::int64_t size;
        std::int64_t sizeWithPadding;

        std::int64_t createdAt;
        std::int64_t modifiedAt;
        std::int64_t uid;
        std::int64_t gid;

        std::array<char, 128> name;
        std::array<std::byte, 384> extra;
    };

    std::optional<std::size_t> trySIF(int fd, std::size_t offset)
    {
        auto header = deserialize<SIFHeader>(fd, offset);
        if(!header)
            return {};

        if(std::string_view{header->magic.data(), header->magic.size()-1} != "SIF_MAGIC"sv)
            return {};

        if(header->descriptorsTotal < 0 || header->descriptorsTotal > 64)
        {
            error("Unreasonably big descriptor set: {}", header->descriptorsTotal);
            return {};
        }

        auto descriptors = deserializeArray<SIFDescriptor>(fd, offset + header->descriptorsOffset, header->descriptorsTotal);
        if(!descriptors)
        {
            error("Could not read descriptors");
            return {};
        }

        for(auto& descriptor : *descriptors)
        {
            if(!descriptor.used)
                continue;

            if(descriptor.type == SIFDataType::Partition)
            {
                std::size_t totalOffset = offset + descriptor.offset;
                if(auto off = trySquashFS(fd, totalOffset))
                    return off;
            }
        }

        error("Could not find partition in SIF image with squashfs image");

        return {};
    }
}

std::optional<std::size_t> findSquashFS(int fd, std::size_t offset)
{
    // Try 1: Is this a squashfs image already?
    if(auto ret = trySquashFS(fd, offset))
        return ret;

    // Try 2: SIF image
    if(auto ret = trySIF(fd, offset))
        return ret;

    return {};
}

}
