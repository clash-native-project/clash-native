#include <clash_native/platform/platform_adapter.hpp>

namespace clash_native::platform {

std::string_view name() noexcept {
#if defined(_WIN32)
    return "Windows";
#elif defined(__linux__)
    return "Linux";
#elif defined(__APPLE__)
    return "macOS";
#else
    return "Unknown";
#endif
}

}  // namespace clash_native::platform
