#pragma once

#include <clash_native/core/result.hpp>

#include <openssl/aead.h>

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace clash_native::outbound::detail {

struct ShadowsocksMethod {
    const EVP_AEAD *cipher = nullptr;
    std::size_t key_size = 0;
    std::string_view name;
};

core::Result<ShadowsocksMethod> shadowsocks_method(std::string_view name);
core::Result<std::vector<std::uint8_t>>
derive_shadowsocks_subkey(std::string_view method, std::string_view password,
                          std::span<const std::uint8_t> salt);
core::Result<std::vector<std::uint8_t>>
shadowsocks_encrypt(std::string_view method, std::span<const std::uint8_t> key,
                    std::span<const std::uint8_t, 12> nonce,
                    std::span<const std::uint8_t> plaintext);
core::Result<std::vector<std::uint8_t>>
shadowsocks_decrypt(std::string_view method, std::span<const std::uint8_t> key,
                    std::span<const std::uint8_t, 12> nonce,
                    std::span<const std::uint8_t> ciphertext);
bool random_bytes(std::span<std::uint8_t> bytes) noexcept;
void increment_nonce(std::array<std::uint8_t, 12> &nonce) noexcept;

} // namespace clash_native::outbound::detail
