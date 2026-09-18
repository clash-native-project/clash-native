#include "shadowsocks_crypto.hpp"

#include <openssl/aead.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <climits>
#include <memory>
#include <string>
#include <utility>

namespace clash_native::outbound::detail {

namespace {

constexpr std::size_t kAeadTagSize = 16;

using DigestContext = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using AeadContext = std::unique_ptr<EVP_AEAD_CTX, decltype(&EVP_AEAD_CTX_free)>;

core::Error crypto_error(std::string context) {
    return {core::ErrorCode::authentication, std::move(context)};
}

core::Result<std::vector<std::uint8_t>> derive_master_key(std::string_view password,
                                                          std::size_t key_size) {
    std::vector<std::uint8_t> result;
    result.reserve(key_size);
    std::array<std::uint8_t, EVP_MAX_MD_SIZE> previous{};
    unsigned int previous_size = 0;

    while (result.size() < key_size) {
        DigestContext digest(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (!digest || EVP_DigestInit_ex(digest.get(), EVP_md5(), nullptr) != 1 ||
            (previous_size != 0 &&
             EVP_DigestUpdate(digest.get(), previous.data(), previous_size) != 1) ||
            EVP_DigestUpdate(digest.get(), password.data(), password.size()) != 1 ||
            EVP_DigestFinal_ex(digest.get(), previous.data(), &previous_size) != 1) {
            return core::fail(crypto_error("failed to derive Shadowsocks master key"));
        }
        const auto remaining = key_size - result.size();
        const auto append_size = std::min<std::size_t>(remaining, previous_size);
        result.insert(result.end(), previous.begin(), previous.begin() + append_size);
    }
    return result;
}

core::Result<std::vector<std::uint8_t>> hkdf_sha1(std::span<const std::uint8_t> input_key,
                                                  std::span<const std::uint8_t> salt,
                                                  std::string_view info, std::size_t output_size) {
    std::array<std::uint8_t, EVP_MAX_MD_SIZE> pseudorandom_key{};
    unsigned int pseudorandom_key_size = 0;
    if (!HMAC(EVP_sha1(), salt.data(), static_cast<int>(salt.size()), input_key.data(),
              input_key.size(), pseudorandom_key.data(), &pseudorandom_key_size)) {
        return core::fail(crypto_error("failed to derive Shadowsocks subkey"));
    }

    std::vector<std::uint8_t> output;
    output.reserve(output_size);
    std::vector<std::uint8_t> previous;
    for (std::uint8_t counter = 1; output.size() < output_size; ++counter) {
        std::vector<std::uint8_t> input;
        input.reserve(previous.size() + info.size() + 1);
        input.insert(input.end(), previous.begin(), previous.end());
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter);

        std::array<std::uint8_t, EVP_MAX_MD_SIZE> block{};
        unsigned int block_size = 0;
        if (!HMAC(EVP_sha1(), pseudorandom_key.data(), static_cast<int>(pseudorandom_key_size),
                  input.data(), input.size(), block.data(), &block_size)) {
            return core::fail(crypto_error("failed to derive Shadowsocks subkey"));
        }
        previous.assign(block.begin(), block.begin() + block_size);
        const auto append_size = std::min(output_size - output.size(), previous.size());
        output.insert(output.end(), previous.begin(), previous.begin() + append_size);
    }
    return output;
}

} // namespace

core::Result<ShadowsocksMethod> shadowsocks_method(std::string_view name) {
    if (name == "aes-128-gcm") {
        return ShadowsocksMethod{EVP_aead_aes_128_gcm(), 16, "aes-128-gcm"};
    }
    if (name == "aes-256-gcm") {
        return ShadowsocksMethod{EVP_aead_aes_256_gcm(), 32, "aes-256-gcm"};
    }
    if (name == "chacha20-ietf-poly1305") {
        return ShadowsocksMethod{EVP_aead_chacha20_poly1305(), 32, "chacha20-ietf-poly1305"};
    }
    return core::fail({core::ErrorCode::configuration,
                       "unsupported Shadowsocks AEAD method: " + std::string(name)});
}

core::Result<std::vector<std::uint8_t>>
derive_shadowsocks_subkey(std::string_view method, std::string_view password,
                          std::span<const std::uint8_t> salt) {
    const auto method_result = shadowsocks_method(method);
    if (!method_result) {
        return core::fail(method_result.error());
    }
    if (password.empty() || salt.size() != method_result.value().key_size) {
        return core::fail(
            {core::ErrorCode::configuration, "Shadowsocks password or salt length is invalid"});
    }
    auto master_key = derive_master_key(password, method_result.value().key_size);
    if (!master_key) {
        return core::fail(master_key.error());
    }
    return hkdf_sha1(master_key.value(), salt, "ss-subkey", method_result.value().key_size);
}

core::Result<std::vector<std::uint8_t>>
shadowsocks_encrypt(std::string_view method_name, std::span<const std::uint8_t> key,
                    std::span<const std::uint8_t, 12> nonce,
                    std::span<const std::uint8_t> plaintext) {
    const auto method = shadowsocks_method(method_name);
    if (!method) {
        return core::fail(method.error());
    }
    if (key.size() != method.value().key_size || plaintext.size() > INT_MAX) {
        return core::fail(
            {core::ErrorCode::configuration, "Shadowsocks key or plaintext length is invalid"});
    }

    AeadContext context(EVP_AEAD_CTX_new(method.value().cipher, key.data(), key.size(),
                                         EVP_AEAD_DEFAULT_TAG_LENGTH),
                        EVP_AEAD_CTX_free);
    if (!context) {
        return core::fail(crypto_error("failed to initialize Shadowsocks encryption"));
    }

    std::vector<std::uint8_t> output(plaintext.size() + kAeadTagSize);
    std::size_t written = 0;
    if (EVP_AEAD_CTX_seal(context.get(), output.data(), &written, output.size(), nonce.data(),
                          nonce.size(), plaintext.data(), plaintext.size(), nullptr, 0) != 1) {
        return core::fail(crypto_error("failed to encrypt Shadowsocks data"));
    }
    output.resize(written);
    return output;
}

core::Result<std::vector<std::uint8_t>>
shadowsocks_decrypt(std::string_view method_name, std::span<const std::uint8_t> key,
                    std::span<const std::uint8_t, 12> nonce,
                    std::span<const std::uint8_t> ciphertext) {
    const auto method = shadowsocks_method(method_name);
    if (!method) {
        return core::fail(method.error());
    }
    if (key.size() != method.value().key_size || ciphertext.size() < 16 ||
        ciphertext.size() - 16 > INT_MAX) {
        return core::fail(
            {core::ErrorCode::protocol_framing, "Shadowsocks ciphertext length is invalid"});
    }

    AeadContext context(EVP_AEAD_CTX_new(method.value().cipher, key.data(), key.size(),
                                         EVP_AEAD_DEFAULT_TAG_LENGTH),
                        EVP_AEAD_CTX_free);
    if (!context) {
        return core::fail(crypto_error("failed to initialize Shadowsocks decryption"));
    }

    const auto payload_size = ciphertext.size() - kAeadTagSize;
    std::vector<std::uint8_t> output(payload_size);
    std::size_t written = 0;
    if (EVP_AEAD_CTX_open(context.get(), output.data(), &written, output.size(), nonce.data(),
                          nonce.size(), ciphertext.data(), ciphertext.size(), nullptr, 0) != 1) {
        return core::fail(crypto_error("Shadowsocks authentication tag verification failed"));
    }
    output.resize(written);
    return output;
}

bool random_bytes(std::span<std::uint8_t> bytes) noexcept {
    return bytes.size() <= INT_MAX && RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) == 1;
}

void increment_nonce(std::array<std::uint8_t, 12> &nonce) noexcept {
    for (auto &byte : nonce) {
        if (++byte != 0) {
            break;
        }
    }
}

} // namespace clash_native::outbound::detail
