// Get size of an ELF binary
// Author: Max Schwarz <max.schwarz@online.de>

#include "elf_size.h"

#include <byteswap.h>
#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "log.h"
#include "scope_guard.h"

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ELFDATANATIVE ELFDATA2LSB
#elif __BYTE_ORDER == __BIG_ENDIAN
#define ELFDATANATIVE ELFDATA2MSB
#else
#error "Unknown machine endian"
#endif

std::optional<std::size_t> getELFSize(const char *file, std::size_t offset) {
  int fd = open(file, O_RDONLY);
  if (fd < 0) {
    sys_error("Could not open file '{}'", file);
    return {};
  }

  auto guard = sg::make_scope_guard([&] { close(fd); });

  // Read header
  Elf64_Ehdr ehdr{};
  int ret =
      pread(fd, reinterpret_cast<char *>(ehdr.e_ident), EI_NIDENT, offset);
  if (ret < 0) {
    sys_error("{}: Could not read ELF header", file);
    return {};
  }
  if (ret != EI_NIDENT) {
    error("{}: Could not read ELF header: Short read ({})", file, ret);
    return {};
  }

  if (std::string_view{reinterpret_cast<char *>(&ehdr.e_ident[EI_MAG0]), 4} !=
      std::string_view{ELFMAG}) {
    error("{}: Invalid ELF magic", file);
    return {};
  }

  if ((ehdr.e_ident[EI_DATA] != ELFDATA2LSB) &&
      (ehdr.e_ident[EI_DATA] != ELFDATA2MSB)) {
    error("{}: Unknown ELF data order {}", file, ehdr.e_ident[EI_DATA]);
    return {};
  }

  if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
    error("{}: Unknown ELF class {}", file, ehdr.e_ident[EI_CLASS]);
    return {};
  }

  // Read whole header
  ret = pread(fd, &ehdr, sizeof(ehdr), offset);
  if (ret < 0) {
    sys_error("{}: Could not read ELF header", file);
    return {};
  }
  if (ret != sizeof(ehdr)) {
    error("{}: Could not read ELF header: Short read ({})", file, ret);
    return {};
  }

  if (ehdr.e_ident[EI_DATA] != ELFDATANATIVE) {
    ehdr.e_shoff = bswap_64(ehdr.e_shoff);
    ehdr.e_shentsize = bswap_64(ehdr.e_shentsize);
    ehdr.e_shnum = bswap_64(ehdr.e_shnum);
  }

  return ehdr.e_shoff + (ehdr.e_shentsize * ehdr.e_shnum);
}

bool isELF(const char *file) {
  int fd = open(file, O_RDONLY);
  if (fd < 0) {
    sys_error("Could not open file '{}'", file);
    return false;
  }
  auto guard = sg::make_scope_guard([&] { close(fd); });

  // Read header
  Elf64_Ehdr ehdr{};
  int ret = read(fd, reinterpret_cast<char *>(ehdr.e_ident), EI_NIDENT);
  if (ret < 0) {
    sys_error("{}: Could not read ELF header", file);
    return {};
  }
  if (ret != EI_NIDENT)
    return false;

  if (std::string_view{reinterpret_cast<char *>(&ehdr.e_ident[EI_MAG0]), 4} !=
      std::string_view{ELFMAG})
    return false;

  return true;
}
