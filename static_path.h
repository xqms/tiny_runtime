// Compile-time path operations
// Author: Max Schwarz <max.schwarz@online.de>

#ifndef STATIC_PATH_H
#define STATIC_PATH_H

#include <cstdlib>
#include <filesystem>

template <std::size_t Length> struct StaticPath {
  constexpr StaticPath() = default;
  constexpr StaticPath(const char (&src)[Length + 1]) noexcept {
    for (std::size_t i = 0; i < Length; ++i)
      data[i] = src[i];
    data[Length] = 0;
  }

  operator std::filesystem::path() const { return std::filesystem::path{data}; }

  operator const char *() const { return data; }

  operator std::string_view() const { return data; }

  operator std::string() const { return data; }

  char data[Length + 1] = {};
};
template <std::size_t LengthPlusOne>
StaticPath(const char (&src)[LengthPlusOne]) -> StaticPath<LengthPlusOne - 1>;

template <std::size_t LengthA, std::size_t LengthB>
constexpr StaticPath<LengthA + 1 + LengthB>
operator/(const StaticPath<LengthA> &a, const StaticPath<LengthB> &b) {
  StaticPath<LengthA + 1 + LengthB> ret;

  for (std::size_t i = 0; i < LengthA; ++i)
    ret.data[i] = a.data[i];

  ret.data[LengthA] = '/';

  for (std::size_t i = 0; i < LengthB; ++i)
    ret.data[LengthA + 1 + i] = b.data[i];

  ret.data[LengthA + 1 + LengthB] = 0;

  return ret;
}

template <std::size_t LengthA, std::size_t LengthBPlusOne>
constexpr StaticPath<LengthA + 1 + LengthBPlusOne - 1>
operator/(const StaticPath<LengthA> &a, const char (&b)[LengthBPlusOne]) {
  StaticPath<LengthA + 1 + LengthBPlusOne - 1> ret;

  for (std::size_t i = 0; i < LengthA; ++i)
    ret.data[i] = a.data[i];

  ret.data[LengthA] = '/';

  for (std::size_t i = 0; i < LengthBPlusOne - 1; ++i)
    ret.data[LengthA + 1 + i] = b[i];

  ret.data[LengthA + 1 + LengthBPlusOne - 1] = 0;

  return ret;
}

template <std::size_t Length> auto format_as(const StaticPath<Length> &path) {
  return path.data;
}

#endif
