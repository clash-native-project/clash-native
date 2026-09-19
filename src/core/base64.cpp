#include <clash_native/core/base64.hpp>

#include <openssl/base64.h>

#include <cstddef>
#include <cstdint>
#include <stdexcept>

namespace clash_native::core {

std::string base64_encode(std::string_view input) {
    if (input.empty()) {
        return {};
    }

    std::size_t encoded_length = 0;
    if (EVP_EncodedLength(&encoded_length, input.size()) == 0) {
        throw std::length_error("Base64 input is too large to encode");
    }

    std::string encoded(encoded_length, '\0');
    const auto written =
        EVP_EncodeBlock(reinterpret_cast<std::uint8_t *>(encoded.data()),
                        reinterpret_cast<const std::uint8_t *>(input.data()), input.size());
    encoded.resize(written);
    return encoded;
}

std::optional<std::string> base64_decode(std::string_view input) {
    if (input.empty()) {
        return std::string{};
    }

    std::size_t decoded_length = 0;
    if (EVP_DecodedLength(&decoded_length, input.size()) == 0) {
        return std::nullopt;
    }

    std::string decoded(decoded_length, '\0');
    std::size_t written = 0;
    if (EVP_DecodeBase64(reinterpret_cast<std::uint8_t *>(decoded.data()), &written, decoded.size(),
                         reinterpret_cast<const std::uint8_t *>(input.data()), input.size()) == 0) {
        return std::nullopt;
    }
    decoded.resize(written);
    return decoded;
}

} // namespace clash_native::core
