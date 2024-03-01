// reflect-based argument parser
// Author: Max Schwarz <max.schwarz@online.de>

#ifndef ARGPARSER_H
#define ARGPARSER_H

#include <reflect>
#include <algorithm>
#include <string_view>
#include <string>
#include <vector>
#include <optional>
#include <spanstream>

#include <fmt/format.h>

namespace argparser
{

struct Opts
{
    char shortName = 0;
};

template<class T, Opts opts = {}>
struct Option : public T
{
    using T::T;
    static constexpr Opts argparser_options = opts;

    operator T() noexcept
    { return *this; }

    operator const T() const noexcept
    { return *this; }
};

template<std::integral T, Opts opts>
struct Option<T, opts>
{
    static constexpr Opts argparser_options = opts;

    constexpr Option() = default;
    Option(T data)
     : m_data{data}
    {}

    operator T() noexcept
    { return m_data; }

    operator const T() const noexcept
    { return m_data; }
private:
    T m_data{};
};


namespace detail
{
    template<typename T>
    struct Unwrapper
    {
        using type = T;
        static constexpr Opts opts = {};
    };
    template<typename T, Opts o>
    struct Unwrapper<Option<T,o>>
    {
        using type = T;
        static constexpr Opts opts = o;
    };

    template<typename T>
    constexpr Opts GetOpts = Unwrapper<T>::opts;

    template<typename T>
    using UnwrapOption = Unwrapper<T>::type;

    template<typename ArgClass, typename T>
    struct ArgInfo
    {
        using value_type = T;

        std::string name;
        T* ptr{};
    };

    template<int N, typename T, typename ArgClass>
    auto argInfo(ArgClass& args)
    {
        using namespace std::literals;

        if(reflect::member_name<N, ArgClass>() == "remaining"sv)
            return ArgInfo<ArgClass, T>{};

        return ArgInfo<ArgClass, T>{
            std::string{reflect::member_name<N, ArgClass>()},
            &reflect::get<N>(args)
        };
    }

    template<class ArgClass, int N>
    void serializeMember(std::vector<std::string>& out, const ArgClass& args)
    {
        using namespace std::literals;

        if(reflect::member_name<N, ArgClass>() == "remaining"sv)
            return;

        const auto& value = reflect::get<N>(args);

        std::string name = std::string{reflect::member_name<N>(args)};
        std::ranges::replace(name, '_', '-');

        using ValueType = UnwrapOption<std::remove_cvref_t<decltype(value)>>;

        // Is this an std::vector?
        if constexpr(requires { []<typename U>(const std::vector<U>&){}(ValueType{}); })
        {
            for(auto& entry : value)
                out.push_back(fmt::format("--{}={}", name, entry));
        }
        // or an std::optional?
        else if constexpr(requires { []<typename U>(const std::optional<U>&){}(ValueType{}); })
        {
            if(value)
                out.push_back(fmt::format("--{}={}", name, *value));
        }
        // or a bool?
        else if constexpr(std::is_same_v<ValueType, bool>)
        {
            if(value)
                out.push_back(fmt::format("--{}", name));
        }
        // or a straight value?
        else
        {
            out.push_back(fmt::format("--{}={}", name, static_cast<const ValueType&>(value)));
        }
    };
}

class ArgumentException : public std::runtime_error
{
public:
    ArgumentException(const std::string& msg) : std::runtime_error{msg} {}
};

template<typename ArgClass, typename Container>
void parse(ArgClass& args, const Container& arguments)
{
    using namespace std::literals;

    auto infos = [&]<auto ... Ns>(std::index_sequence<Ns...>) {
        return std::make_tuple(
            detail::argInfo<Ns, std::remove_cvref_t<decltype(reflect::get<Ns>(args))>>(args)...
        );
    }(std::make_index_sequence<reflect::size<ArgClass>()>());

    for(std::size_t i = 0; i < std::size(arguments); ++i)
    {
        auto arg = std::string_view{arguments[i]};
        if(!arg.starts_with("-"sv))
        {
            if constexpr(requires (ArgClass args){ args.remaining; })
            {
                for(std::size_t j = i; j < std::size(arguments); ++j)
                    args.remaining.push_back(std::string{arguments[i]});

                return;
            }
            else
                throw ArgumentException{fmt::format("Invalid argument '{}'", arg)};

            continue;
        }

        std::string_view argName = arg.starts_with("--"sv) ? arg.substr(2) : arg.substr(1);

        // Decompose argName into key and value (for --X=Y options)
        std::string key;
        std::optional<std::string_view> value;

        auto equalsSign = argName.find('=');
        if(equalsSign != std::string_view::npos)
        {
            key = argName.substr(0, equalsSign);
            value = argName.substr(equalsSign + 1);
        }
        else
            key = argName;

        if(!arg.starts_with("--"sv) && key.length() != 1)
            throw ArgumentException{fmt::format("Invalid short option '-{}'", key)};

        std::ranges::replace(key, '-', '_');

        auto parseValue = [&]<typename T>(T& target){
            // If we don't have a value already (from --X=Y), grab the next argument.
            if(!value)
            {
                if(i+1 == std::size(arguments))
                    throw ArgumentException{fmt::format("'{}' requires an argument", arg)};

                value = arguments[i+1];
                ++i;
            }

            if constexpr(std::is_same_v<T, std::string>)
                target = std::string{*value};
            else
            {
                std::ispanstream is{*value};
                is >> target;

                if(!is)
                    throw ArgumentException{fmt::format("Could not parse argument '{}' to --{}", *value, key)};
            }
        };

        auto tryParam = [&]<typename T>(T& argInfo) -> bool {
            using ValueType = detail::UnwrapOption<typename T::value_type>;
            constexpr Opts opts = detail::GetOpts<typename T::value_type>;

            if(!argInfo.ptr)
                return false;

            if(key != argInfo.name && !(key.size() == 1 && key[0] == opts.shortName))
                return false;

            // Is this an std::vector?
            if constexpr(requires { []<typename U>(const std::vector<U>&){}(ValueType{}); })
            {
                parseValue(argInfo.ptr->emplace_back());
            }
            // or an std::optional?
            else if constexpr(requires { []<typename U>(const std::optional<U>&){}(ValueType{}); })
            {
                parseValue(argInfo.ptr->emplace());
            }
            // or a bool?
            else if constexpr(std::is_same_v<ValueType, bool>)
            {
                *argInfo.ptr = true;
            }
            // or a straight value?
            else
            {
                parseValue((ValueType&)*argInfo.ptr);
            }

            return true;
        };

        bool found = std::apply([&](auto& ... infos){ return (... || tryParam(infos)); }, infos);
        if(!found)
            throw ArgumentException{fmt::format("Unknown argument --{}", key)};
    }
}

template<class ArgClass>
std::vector<std::string> serialize(const ArgClass& args)
{
    using namespace std::literals;

    std::vector<std::string> data;

    [&]<auto ... Ns>(std::index_sequence<Ns...>) {
        (... , detail::serializeMember<ArgClass, Ns>(data, args));
    }(std::make_index_sequence<reflect::size<ArgClass>()>());

    return data;
}

}

#endif
