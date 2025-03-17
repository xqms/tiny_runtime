// LD cache
// Author: Max Schwarz <max.schwarz@online.de>

#include "ldcache.h"

#include <filesystem>

#include <fmt/format.h>

#include <sys/mman.h>

#include <fcntl.h>
#include <limits.h>
#include <stdalign.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* See glibc dl-cache.c/h and ldconfig.c/h for the format definition. */

#define MAGIC_LIBC5 "ld.so-1.7.0"
#define MAGIC_LIBC6 "glibc-ld.so.cache"
#define MAGIC_VERSION "1.1"
#define MAGIC_LIBC5_LEN (sizeof(MAGIC_LIBC5) - 1)
#define MAGIC_LIBC6_LEN (sizeof(MAGIC_LIBC6) - 1)
#define MAGIC_VERSION_LEN (sizeof(MAGIC_VERSION) - 1)

namespace fs = std::filesystem;

namespace {

struct entry_libc5 {
  int32_t flags;
  uint32_t key;
  uint32_t value;
};

struct header_libc5 {
  char magic[MAGIC_LIBC5_LEN];
  uint32_t nlibs;
  struct entry_libc5 libs[];
};

struct entry_libc6 {
  int32_t flags;
  uint32_t key;
  uint32_t value;
  uint32_t osversion;
  uint64_t hwcap;
};

struct header_libc6 {
  char magic[MAGIC_LIBC6_LEN];
  char version[MAGIC_VERSION_LEN];
  uint32_t nlibs;
  uint32_t table_size;
  uint32_t unused[5];
  struct entry_libc6 libs[];
};

enum {
  LD_UNKNOWN = -1,

  LD_TYPE_MASK = 0x00ff,
  LD_ELF = 0x0001,
  LD_ELF_LIBC5 = 0x0002,
  LD_ELF_LIBC6 = 0x0003,

  LD_ARCH_MASK = 0xff00,
  LD_I386_LIB32 = 0x0000,
  LD_SPARC_LIB64 = 0x0100,
  LD_IA64_LIB64 = 0x0200,
  LD_X8664_LIB64 = 0x0300,
  LD_S390_LIB64 = 0x0400,
  LD_POWERPC_LIB64 = 0x0500,
  LD_MIPS64_LIBN32 = 0x0600,
  LD_MIPS64_LIBN64 = 0x0700,
  LD_X8664_LIBX32 = 0x0800,
  LD_ARM_LIBHF = 0x0900,
  LD_AARCH64_LIB64 = 0x0a00,
  LD_ARM_LIBSF = 0x0b00,
  LD_MIPS_LIB32_NAN2008 = 0x0c00,
  LD_MIPS64_LIBN32_NAN2008 = 0x0d00,
  LD_MIPS64_LIBN64_NAN2008 = 0x0e00,
};

class MappedFile {
public:
  MappedFile(const char *path) {
    m_size = std::filesystem::file_size(path);

    int fd = open(path, O_RDONLY);
    if (fd < 0)
      throw std::runtime_error{
          fmt::format("Could not open file {}: {}", path, strerror(errno))};

    void *data = mmap(nullptr, m_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) {
      close(fd);
      throw std::runtime_error{
          fmt::format("Could not mmap file {}: {}", path, strerror(errno))};
    }

    m_data = reinterpret_cast<const uint8_t *>(data);
    close(fd);
  }

  MappedFile(const MappedFile &) = delete;
  MappedFile(MappedFile &&) = delete;

  MappedFile &operator=(const MappedFile &) = delete;

  ~MappedFile() {
    if (m_data)
      munmap(reinterpret_cast<void *>(const_cast<uint8_t *>(m_data)), m_size);
  }

  const uint8_t *data() const { return m_data; }

  const auto size() const { return m_size; }

private:
  const uint8_t *m_data{};
  std::uintmax_t m_size = 0;
};
} // namespace

class LDCache::Private {
public:
  Private() {
    if (m_file.size() < sizeof(header_libc5))
      throw std::runtime_error{"Invalid ld.so.cache"};

    auto ptr = m_file.data();
    auto end = m_file.data() + m_file.size();

    auto h5 = (const header_libc5 *)m_file.data();

    if (!strncmp(h5->magic, MAGIC_LIBC5, MAGIC_LIBC5_LEN)) {
      // Do not support the old libc5 format, skip these entries.
      ptr = reinterpret_cast<const uint8_t *>(h5->libs) + h5->nlibs;
      std::size_t padding =
          (-(uintptr_t)ptr) & (__alignof__(struct header_libc6) - 1);
      ptr += padding;
    }

    if (ptr + sizeof(header_libc6) > end)
      throw std::runtime_error{"Invalid ld.so.cache"};

    auto h6 = (const header_libc6 *)ptr;
    if (strncmp(h6->magic, MAGIC_LIBC6, MAGIC_LIBC6_LEN) ||
        strncmp(h6->version, MAGIC_VERSION, MAGIC_VERSION_LEN))
      throw std::runtime_error{"Invalid ld.so.cache"};

    if (reinterpret_cast<const uint8_t *>(h6->libs + h6->nlibs) > end)
      throw std::runtime_error{"Invalid ld.so.cache"};

    m_base = ptr;
    m_end = end;
  }

  std::string_view safeReadStr(const uint8_t *ptr) const {
    const char *begin = reinterpret_cast<const char *>(ptr);
    if (reinterpret_cast<const uint8_t *>(begin) >= m_end)
      return {};

    const char *end = begin;
    while (reinterpret_cast<const uint8_t *>(end) < m_end && *end != 0)
      ++end;

    return {begin, end};
  }

  std::vector<LDCache::Entry>
  resolve(const std::span<const char *const> &libraries) const {
    std::vector<LDCache::Entry> result;
    result.reserve(libraries.size());

    auto h = (const header_libc6 *)m_base;

    for (std::uint32_t i = 0; i < h->nlibs; ++i) {
      int32_t flags = h->libs[i].flags;
      auto key = safeReadStr(m_base + h->libs[i].key);
      auto value = safeReadStr(m_base + h->libs[i].value);

      if (!(flags & LD_ELF) || (flags & LD_ARCH_MASK) != LD_X8664_LIB64)
        continue;

      for (auto &lib : libraries) {
        if (!key.starts_with(lib))
          continue;

        fs::path path{value};
        if (!fs::exists(path))
          continue;

        result.emplace_back(key, fs::canonical(path));
      }
    }

    return result;
  }

private:
  MappedFile m_file{"/etc/ld.so.cache"};
  const uint8_t *m_base{};
  const uint8_t *m_end{};
};

LDCache::LDCache() : m_d{std::make_unique<Private>()} {}

LDCache::~LDCache() = default;

std::vector<LDCache::Entry>
LDCache::resolve(const std::span<const char *const> &libraries) const {
  return m_d->resolve(libraries);
}
