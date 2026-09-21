#pragma once

#include <clash_native/core/result.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace clash_native::transport::shadowsocks {

core::Result<std::vector<std::uint8_t>>
encrypt_legacy_datagram(std::string_view method, std::string_view password,
                        std::span<const std::uint8_t> plaintext);

core::Result<std::vector<std::uint8_t>> decrypt_legacy_datagram(std::string_view method,
                                                                std::string_view password,
                                                                std::span<const std::uint8_t> wire);

std::size_t legacy_datagram_payload_limit(std::string_view method, std::size_t wire_limit,
                                          std::size_t address_limit) noexcept;

} // namespace clash_native::transport::shadowsocks
