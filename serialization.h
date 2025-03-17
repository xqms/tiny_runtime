// Binary serialization / deserialization
// Author: Max Schwarz <max.schwarz@online.de>

#ifndef SERIALIZATION_H
#define SERIALIZATION_H

#include <array>
#include <cstring>
#include <istream>
#include <optional>
#include <type_traits>
#include <vector>

#include <reflect>

namespace serialization {
namespace detail {
template <class...> struct False : std::bool_constant<false> {};

template <typename T> constexpr bool isMemcpyCapable();

template <typename T, int N>
constexpr bool isMemberMemcpyCapable(std::size_t &offset) {
  if constexpr (std::is_aggregate_v<T>) {
    using MemberType =
        std::remove_cvref_t<decltype(reflect::get<N, T>(std::declval<T>()))>;
    if (!isMemcpyCapable<MemberType>())
      return false;
  }

  if (reflect::offset_of<N, T>() != offset)
    return false;

  offset += reflect::size_of<N, T>();
  return true;
}

template <typename T> constexpr bool isMemcpyCapable() {
  if constexpr (std::is_integral_v<T> || std::is_enum_v<T>)
    return true;
  else if constexpr (!std::is_aggregate_v<T> || !std::is_standard_layout_v<T> ||
                     !std::is_trivial_v<T>)
    return false;
  else if constexpr (requires(T x) {
                       []<typename U, std::size_t N>(const std::array<U, N> &) {
                       }(x);
                     })
    return true;
  else {
    constexpr int numFields = reflect::size<T>();

    std::size_t offset = 0;

    return [&]<auto... Ns>(std::index_sequence<Ns...>) {
      return (... && isMemberMemcpyCapable<T, Ns>(offset));
    }(std::make_index_sequence<numFields>());
  }
}

template <class T>
  requires(std::is_trivially_copyable_v<T>)
T *start_lifetime_as(void *p) noexcept {
  return std::launder(static_cast<T *>(std::memmove(p, p, sizeof(T))));
}
} // namespace detail

template <typename Stream, typename T>
[[nodiscard]]
bool deserializeInto(Stream &stream, T &dest,
                     std::size_t sizeLimit = 100 * 1024) {
  if constexpr (std::is_integral_v<T> || std::is_enum_v<T>) {
    stream.read(reinterpret_cast<char *>(&dest), sizeof(T));
    return !!stream;
  } else if constexpr (requires {
                         [&]<typename U>(std::vector<U> &) {}(dest);
                       }) {
    std::size_t numElements;
    if (!deserializeInto(stream, numElements))
      return false;
    if (numElements > sizeLimit)
      return false;

    dest.clear();
    dest.reserve(numElements);
    for (std::size_t i = 0; i < numElements; ++i) {
      if (!deserializeInto(stream, dest.emplace_back()))
        return false;
    }

    return true;
  } else if constexpr (std::is_same_v<T, std::string>) {
    std::size_t size;
    if (!deserializeInto(stream, size))
      return false;
    if (size > sizeLimit)
      return false;

    std::vector<char> data(size);
    stream.read(reinterpret_cast<char *>(data.data()), size);
    if (!stream)
      return false;

    dest = std::string{std::string_view{data.data(), size}};

    return true;
  } else if constexpr (std::is_aggregate_v<T>) {
    if constexpr (detail::isMemcpyCapable<T>()) {
      stream.read(reinterpret_cast<char *>(&dest), sizeof(T));
      return !!stream;
    } else {
      return [&]<auto... Ns>(std::index_sequence<Ns...>) {
        return (... && deserializeInto(stream, reflect::get<Ns>(dest)));
      }(std::make_index_sequence<reflect::size<T>()>());
    }
  } else {
    static_assert(detail::False<T>{}, "I do not know how to handle this type");
  }
}

template <typename T, typename Stream>
std::optional<T> deserialize(Stream &stream) {
  std::optional<T> ret;
  ret.emplace();
  if (deserializeInto(stream, *ret))
    return ret;
  else
    return {};
}

template <typename T, typename Stream>
[[nodiscard]]
bool serializeInto(const T &src, Stream &out) {
  if constexpr (std::is_integral_v<T> || std::is_enum_v<T>) {
    out.write(reinterpret_cast<const char *>(&src), sizeof(T));
    return !!out;
  } else if constexpr (detail::isMemcpyCapable<T>()) {
    out.write(reinterpret_cast<const char *>(&src), sizeof(T));
    return !!out;
  } else if constexpr (requires {
                         [&]<typename U>(const std::vector<U> &) {}(src);
                       }) {
    std::size_t size = src.size();
    if (!serializeInto(size, out))
      return false;

    for (const auto &item : src) {
      if (!serializeInto(item, out))
        return false;
    }

    return true;
  } else if constexpr (std::is_same_v<T, std::string>) {
    std::string_view view = src;
    std::size_t size = view.size();
    if (!serializeInto(size, out))
      return false;

    out.write(view.data(), view.size());
    return !!out;
  } else if constexpr (std::is_aggregate_v<T>) {
    if constexpr (detail::isMemcpyCapable<T>()) {
      out.write(reinterpret_cast<const char *>(&src), sizeof(T));
      return !!out;
    } else {
      return [&]<auto... Ns>(std::index_sequence<Ns...>) {
        return (... && serializeInto(reflect::get<Ns>(src), out));
      }(std::make_index_sequence<reflect::size<T>()>());
    }
  } else {
    static_assert(detail::False<T>{}, "I do not know how to handle this type");
  }
}

template <typename T>
[[nodiscard]]
std::size_t serializedSize(const T &src) {
  if constexpr (std::is_integral_v<T>)
    return sizeof(T);
  else if constexpr (requires {
                       [&]<typename U>(const std::vector<U> &) {}(src);
                     }) {
    std::size_t size = sizeof(std::size_t);

    for (const auto &item : src)
      size += serializedSize(item);

    return size;
  } else if constexpr (std::is_same_v<T, std::string>)
    return sizeof(std::size_t) + src.size();
  else if constexpr (std::is_aggregate_v<T>) {
    if constexpr (detail::isMemcpyCapable<T>())
      return sizeof(T);
    else {
      return [&]<auto... Ns>(std::index_sequence<Ns...>) {
        return (... + serializedSize(reflect::get<Ns>(src)));
      }(std::make_index_sequence<reflect::size<T>()>());
    }
  } else
    static_assert(detail::False<T>{}, "I do not know how to handle this type");
}
} // namespace serialization

#endif
