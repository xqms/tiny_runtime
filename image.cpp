// Find squashfs image in various container formats
// Author: Max Schwarz <max.schwarz@online.de>

#include "image.h"

#include <cstdlib>
#include <optional>
#include <string_view>
#include <type_traits>
#include <vector>

#include <reflect>

#include <unistd.h>

#include "log.h"
#include "serialization.h"

using namespace std::literals;

namespace image {

namespace {
std::optional<std::size_t> trySquashFS(std::istream &stream,
                                       std::size_t offset) {
  stream.seekg(offset);
  if (!stream)
    return {};

  char magic[4];
  stream.read(magic, sizeof(magic));
  if (!stream)
    return {};

  if (std::string_view{magic, sizeof(magic)} != "hsqs"sv)
    return {};

  return offset;
}

struct SIFHeader {
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

enum class SIFDataType : std::int32_t {
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

struct SIFDescriptor {
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

std::optional<std::size_t> trySIF(std::istream &stream, std::size_t offset) {
  stream.seekg(offset);
  if (!stream)
    return {};

  auto header = serialization::deserialize<SIFHeader>(stream);
  if (!header)
    return {};

  if (std::string_view{header->magic.data(), header->magic.size() - 1} !=
      "SIF_MAGIC"sv)
    return {};

  if (header->descriptorsTotal < 0 || header->descriptorsTotal > 64) {
    error("Unreasonably big descriptor set: {}", header->descriptorsTotal);
    return {};
  }

  stream.seekg(offset + header->descriptorsOffset);
  for (std::int64_t i = 0; i < header->descriptorsTotal; ++i) {
    auto descriptor = serialization::deserialize<SIFDescriptor>(stream);
    if (!descriptor) {
      error("Could not read SIF descriptor");
      return {};
    }

    if (!descriptor->used)
      continue;

    if (descriptor->type == SIFDataType::Partition) {
      std::size_t totalOffset = offset + descriptor->offset;
      if (auto off = trySquashFS(stream, totalOffset))
        return off;
    }
  }

  error("Could not find partition in SIF image with squashfs image");

  return {};
}
} // namespace

std::optional<std::size_t> findSquashFS(std::istream &stream,
                                        std::size_t globalOffset) {
  // Try 1: Is this a squashfs image already?
  if (auto ret = trySquashFS(stream, globalOffset))
    return ret;

  // Try 2: SIF image
  if (auto ret = trySIF(stream, globalOffset))
    return ret;

  return {};
}

} // namespace image
