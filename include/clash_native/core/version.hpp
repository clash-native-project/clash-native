#pragma once

#include <string_view>

#ifndef CLASH_NATIVE_VERSION
#define CLASH_NATIVE_VERSION "0.0.0"
#endif

namespace clash_native::core {

inline constexpr std::string_view version{CLASH_NATIVE_VERSION};

} // namespace clash_native::core
