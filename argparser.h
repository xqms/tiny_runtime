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
    return ArgInfo<ArgClass, T>{
        std::string{reflect::member_name<N>(args)},
        &reflect::get<N>(args)
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
            argInfo<Ns, std::remove_cvref_t<decltype(reflect::get<Ns>(args))>>(args)...
        );
    }(std::make_index_sequence<reflect::size<ArgClass>()>());

    for(std::size_t i = 0; i < std::size(arguments); ++i)
    {
        auto arg = std::string_view{arguments[i]};

        if(!arg.starts_with("--"sv))
        {
            if constexpr(requires (ArgClass args){ args.extra_arguments; })
            {
                args.extra_arguments.push_back(arg);
            }
            else
                throw ArgumentException{fmt::format("Invalid argument '{}'", arg)};

            continue;
        }

        std::string key;
        std::optional<std::string_view> value;
        bool found = false;

        auto equalsSign = arg.find('=');
        if(equalsSign != std::string_view::npos)
        {
            key = arg.substr(2, equalsSign - 2);
            value = arg.substr(equalsSign+1);
        }
        else
            key = arg.substr(2);

        std::ranges::replace(key, '-', '_');

        auto ensureValue = [&](){
            if(value)
                return;

            if(i+1 == std::size(arguments))
                throw ArgumentException{fmt::format("'{}' requires an argument", arg)};

            value = arguments[i+1];
            ++i;
        };

        std::apply([&]<typename T>(T& argInfo) -> void {
            if(key != argInfo.name || found)
                return;

            found = true;

            // Is this an std::vector?
            if constexpr(requires { []<typename U>(const std::vector<U>&){}(*argInfo.ptr); })
            {
                ensureValue();

                std::ispanstream is{*value};
                is >> argInfo.ptr->emplace_back();

                if(!is)
                    throw ArgumentException{fmt::format("Could not parse argument '{}' to --{}", *value, key)};
            }
            // or an std::optional?
            else if constexpr(requires { []<typename U>(const std::optional<U>&){}(*argInfo.ptr); })
            {
                ensureValue();

                std::ispanstream is{*value};
                is >> argInfo.ptr->emplace();

                if(!is)
                    throw ArgumentException{fmt::format("Could not parse argument '{}' to --{}", *value, key)};
            }
            // or a bool?
            else if constexpr(std::is_same_v<bool, typename T::value_type>)
            {
                *argInfo.ptr = true;
            }
            // or a straight value?
            else
            {
                ensureValue();

                std::ispanstream is{*value};
                is >> *argInfo.ptr;

                if(!is)
                    throw ArgumentException{fmt::format("Could not parse argument '{}' to --{}", *value, key)};
            }
        }, infos);
    }
}

}

#endif
