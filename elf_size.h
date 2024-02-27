// Get size of an ELF binary
// Author: Max Schwarz <max.schwarz@online.de>

#ifndef ELF_SIZE_H
#define ELF_SIZE_H

#include <cstdlib>
#include <optional>

std::optional<std::size_t> getELFSize(const char* file, std::size_t offset);

#endif
