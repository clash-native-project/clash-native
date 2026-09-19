#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace clash_native::core {

// Encodes arbitrary bytes using standard padded Base64.
std::string base64_encode(std::string_view input);

// Decodes standard padded Base64. Returns no value when the input is invalid.
std::optional<std::string> base64_decode(std::string_view input);

} // namespace clash_native::core
