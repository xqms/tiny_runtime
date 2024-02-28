// NVIDIA support
// Author: Max Schwarz <max.schwarz@online.de>

#include "nvidia.h"

#include <vector>
#include <filesystem>
#include <memory>

#include <nvc.h>

#include "log.h"
#include "scope_guard.h"

namespace fs = std::filesystem;

namespace
{
    template<class T>
    std::unique_ptr<T, void (*)(T*)> nv_unique(T* val, void (*deleter)(T*))
    {
        return {val, deleter};
    }
}

namespace nvidia
{

bool configure()
{
    auto ctx = nv_unique(nvc_context_new(), &nvc_context_free);
    if(!ctx)
    {
        error("Could not create NVC context");
        return false;
    }

    auto config = nv_unique(nvc_config_new(), &nvc_config_free);
    if(!config)
    {
        error("Could not create NVC config");
        return false;
    }

    config->uid = geteuid();
    config->gid = getegid();

    if(int ret = nvc_init(ctx.get(), config.get(), nullptr))
    {
        error("Could not initialize libnvidia-container: {}", ret);
        return false;
    }

    return true;
}

}
