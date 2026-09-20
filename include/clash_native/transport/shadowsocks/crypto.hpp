#pragma once

#include <clash_native/core/result.hpp>

#include <openssl/aead.h>
#include <openssl/cipher.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace clash_native::transport::shadowsocks {

enum class CipherKind {
    aead,
    stream,
};

struct CipherMethod {
    CipherKind kind = CipherKind::aead;
    const EVP_AEAD *aead = nullptr;
    const EVP_CIPHER *stream = nullptr;
    std::size_t key_size = 0;
    std::size_t salt_size = 0;
    std::size_t nonce_size = 0;
    std::size_t overhead = 0;
    std::size_t iv_size = 0;
    bool shadowsocks_2022 = false;
    std::string name;
};

core::Result<CipherMethod> cipher_method(std::string_view name);

core::Result<std::vector<std::uint8_t>> derive_aead_subkey(
    std::string_view method, std::string_view password, std::span<const std::uint8_t> salt);

// Shadowsocks 2022 passwords are standard Base64 encoded pre-shared keys.
// The returned key is the per-session BLAKE3 derive-key output.
core::Result<std::vector<std::uint8_t>> derive_shadowsocks_2022_session_key(
    std::string_view method, std::string_view password, std::span<const std::uint8_t> salt);

// Derive a Shadowsocks 2022 subkey with the protocol's BLAKE3 context. UDP
// sessions use an eight-byte session identifier as the salt, while stream
// handshakes use a full-size random salt.
core::Result<std::vector<std::uint8_t>> derive_shadowsocks_2022_subkey(
    std::string_view method, std::string_view password, std::span<const std::uint8_t> salt);

core::Result<std::vector<std::uint8_t>> decode_shadowsocks_2022_psk(
    std::string_view method, std::string_view password);

core::Result<std::vector<std::uint8_t>> derive_legacy_key(std::string_view method,
                                                          std::string_view password,
                                                          std::span<const std::uint8_t> iv);

core::Result<std::vector<std::uint8_t>> aead_encrypt(std::string_view method,
                                                     std::span<const std::uint8_t> key,
                                                     std::span<const std::uint8_t> nonce,
                                                     std::span<const std::uint8_t> plaintext);

core::Result<std::vector<std::uint8_t>> aead_decrypt(std::string_view method,
                                                     std::span<const std::uint8_t> key,
                                                     std::span<const std::uint8_t> nonce,
                                                     std::span<const std::uint8_t> ciphertext);

core::Result<std::vector<std::uint8_t>> xchacha20_poly1305_encrypt(
    std::span<const std::uint8_t> key, std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> plaintext);

core::Result<std::vector<std::uint8_t>> xchacha20_poly1305_decrypt(
    std::span<const std::uint8_t> key, std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> ciphertext);

class LegacyStreamCipher final {
  public:
    LegacyStreamCipher() = default;
    LegacyStreamCipher(LegacyStreamCipher &&) noexcept;
    LegacyStreamCipher &operator=(LegacyStreamCipher &&) noexcept;
    LegacyStreamCipher(const LegacyStreamCipher &) = delete;
    LegacyStreamCipher &operator=(const LegacyStreamCipher &) = delete;
    ~LegacyStreamCipher();

    static core::Result<LegacyStreamCipher> create(std::string_view method,
                                                    std::span<const std::uint8_t> key,
                                                    std::span<const std::uint8_t> iv,
                                                    bool encrypt);

    core::Status update(std::span<std::uint8_t> data) noexcept;

  private:
    struct Impl;
    explicit LegacyStreamCipher(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;
};

bool random_bytes(std::span<std::uint8_t> bytes) noexcept;
void increment_nonce(std::span<std::uint8_t> nonce) noexcept;

} // namespace clash_native::transport::shadowsocks
