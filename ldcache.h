// LD cache
// Author: Max Schwarz <max.schwarz@online.de>

#ifndef LDCACHE_H
#define LDCACHE_H

#include <memory>
#include <span>
#include <vector>
#include <filesystem>

class LDCache
{
public:
    LDCache();
    ~LDCache();

    struct Entry
    {
        std::string_view key;
        std::filesystem::path path;
    };

    std::vector<Entry> resolve(const std::span<const char* const>& libraries) const;

private:
    class Private;
    std::unique_ptr<Private> m_d;
};

#endif
