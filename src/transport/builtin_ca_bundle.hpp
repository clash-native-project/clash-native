#pragma once

#include <string_view>

namespace clash_native::transport::detail {

std::string_view builtin_ca_bundle_pem() noexcept;

} // namespace clash_native::transport::detail
