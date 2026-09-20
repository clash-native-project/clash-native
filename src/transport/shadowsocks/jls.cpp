#include <clash_native/transport/shadowsocks/jls.hpp>

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <string>
#include <utility>

namespace clash_native::transport::shadowsocks {

namespace {

constexpr std::size_t kHandshakeHeaderLength = 4;
constexpr std::size_t kHelloRandomOffset = 6;
constexpr std::size_t kHelloRandomLength = 32;
constexpr std::uint8_t kClientHelloType = 1;
constexpr std::uint8_t kServerHelloType = 2;
constexpr std::uint16_t kPresharedKeyExtension = 0x0029;

core::Error jls_error(std::string message) {
    return {core::ErrorCode::protocol_framing, std::move(message), {}};
}

bool read_u8(std::span<const std::uint8_t> data, std::size_t &offset, std::uint8_t &value) {
    if (offset >= data.size()) {
        return false;
    }
    value = data[offset++];
    return true;
}

bool read_u16(std::span<const std::uint8_t> data, std::size_t &offset, std::uint16_t &value) {
    if (data.size() - offset < 2) {
        return false;
    }
    value = static_cast<std::uint16_t>(data[offset] << 8 | data[offset + 1]);
    offset += 2;
    return true;
}

bool skip_bytes(std::span<const std::uint8_t> data, std::size_t &offset, std::size_t length) {
    if (length > data.size() - offset) {
        return false;
    }
    offset += length;
    return true;
}

bool hello_wire_is_valid(std::span<const std::uint8_t> wire, std::uint8_t type) {
    if (wire.size() < kHandshakeHeaderLength + 2 + kHelloRandomLength || wire[0] != type) {
        return false;
    }
    const auto length = (static_cast<std::size_t>(wire[1]) << 16) |
                        (static_cast<std::size_t>(wire[2]) << 8) | wire[3];
    return length == wire.size() - kHandshakeHeaderLength && length >= 2 + kHelloRandomLength;
}

void zero_random(std::vector<std::uint8_t> &wire) {
    std::fill(wire.begin() + static_cast<std::ptrdiff_t>(kHelloRandomOffset),
              wire.begin() + static_cast<std::ptrdiff_t>(kHelloRandomOffset + kHelloRandomLength),
              0);
}

core::Result<std::vector<std::uint8_t>> zero_client_hello_binders(std::vector<std::uint8_t> wire) {
    if (!hello_wire_is_valid(wire, kClientHelloType)) {
        return core::fail(jls_error("invalid JLS ClientHello wire message"));
    }
    zero_random(wire);

    std::span<const std::uint8_t> input(wire);
    std::size_t offset = kHandshakeHeaderLength + 2 + kHelloRandomLength;
    std::uint8_t session_id_length = 0;
    if (!read_u8(input, offset, session_id_length) ||
        !skip_bytes(input, offset, session_id_length)) {
        return core::fail(jls_error("invalid JLS ClientHello session ID"));
    }
    std::uint16_t cipher_suites_length = 0;
    if (!read_u16(input, offset, cipher_suites_length) || (cipher_suites_length & 1U) != 0 ||
        !skip_bytes(input, offset, cipher_suites_length)) {
        return core::fail(jls_error("invalid JLS ClientHello cipher suites"));
    }
    std::uint8_t compression_methods_length = 0;
    if (!read_u8(input, offset, compression_methods_length) ||
        !skip_bytes(input, offset, compression_methods_length)) {
        return core::fail(jls_error("invalid JLS ClientHello compression methods"));
    }
    std::uint16_t extensions_length = 0;
    if (!read_u16(input, offset, extensions_length) || extensions_length != input.size() - offset) {
        return core::fail(jls_error("invalid JLS ClientHello extensions"));
    }
    const auto extensions_end = offset + extensions_length;
    while (offset < extensions_end) {
        std::uint16_t extension_type = 0;
        std::uint16_t extension_length = 0;
        if (!read_u16(input, offset, extension_type) ||
            !read_u16(input, offset, extension_length) ||
            extension_length > extensions_end - offset) {
            return core::fail(jls_error("invalid JLS ClientHello extension"));
        }
        const auto extension_data = offset;
        if (extension_type == kPresharedKeyExtension) {
            std::size_t cursor = extension_data;
            const auto extension_end = extension_data + extension_length;
            std::uint16_t identities_length = 0;
            if (!read_u16(input, cursor, identities_length) ||
                identities_length > extension_end - cursor ||
                !skip_bytes(input, cursor, identities_length)) {
                return core::fail(jls_error("invalid JLS PSK identities"));
            }
            std::uint16_t binders_length = 0;
            if (!read_u16(input, cursor, binders_length) ||
                binders_length != extension_end - cursor) {
                return core::fail(jls_error("invalid JLS PSK binders"));
            }
            const auto binders_end = cursor + binders_length;
            while (cursor < binders_end) {
                std::uint8_t binder_length = 0;
                if (!read_u8(input, cursor, binder_length) ||
                    binder_length > binders_end - cursor) {
                    return core::fail(jls_error("invalid JLS PSK binder"));
                }
                std::fill(wire.begin() + static_cast<std::ptrdiff_t>(cursor),
                          wire.begin() + static_cast<std::ptrdiff_t>(cursor + binder_length), 0);
                cursor += binder_length;
            }
            if (cursor != binders_end) {
                return core::fail(jls_error("invalid JLS PSK binder list"));
            }
        }
        offset += extension_length;
    }
    if (offset != extensions_end) {
        return core::fail(jls_error("invalid JLS ClientHello extension list"));
    }
    return wire;
}

core::Result<std::array<std::uint8_t, 32>> sha256_parts(std::string_view first,
                                                        std::span<const std::uint8_t> second) {
    std::array<std::uint8_t, 32> digest{};
    using Context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    Context context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(context.get(), first.data(), first.size()) != 1 ||
        EVP_DigestUpdate(context.get(), second.data(), second.size()) != 1) {
        return core::fail(jls_error("failed to initialize JLS SHA-256"));
    }
    unsigned int length = 0;
    if (EVP_DigestFinal_ex(context.get(), digest.data(), &length) != 1 || length != digest.size()) {
        return core::fail(jls_error("failed to calculate JLS SHA-256"));
    }
    return digest;
}

core::Result<std::vector<std::uint8_t>> aes_gcm(bool decrypt, std::span<const std::uint8_t, 32> key,
                                                std::span<const std::uint8_t, 32> nonce,
                                                std::span<const std::uint8_t> input,
                                                std::span<const std::uint8_t> tag) {
    using Context = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
    Context context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context ||
        EVP_CipherInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr,
                          decrypt ? 0 : 1) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()),
                            nullptr) != 1 ||
        EVP_CipherInit_ex(context.get(), nullptr, nullptr, key.data(), nonce.data(), -1) != 1) {
        return core::fail(jls_error("failed to initialize JLS AES-GCM"));
    }

    std::vector<std::uint8_t> output(input.size() + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    int written = 0;
    if (EVP_CipherUpdate(context.get(), output.data(), &written, input.data(),
                         static_cast<int>(input.size())) != 1) {
        return core::fail(jls_error("failed to process JLS AES-GCM data"));
    }
    int final_written = 0;
    if (decrypt) {
        if (tag.size() != 16 ||
            EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()),
                                const_cast<std::uint8_t *>(tag.data())) != 1 ||
            EVP_CipherFinal_ex(context.get(), output.data() + written, &final_written) != 1) {
            return core::fail(jls_error("JLS fake random authentication failed"));
        }
    } else if (EVP_CipherFinal_ex(context.get(), output.data() + written, &final_written) != 1) {
        return core::fail(jls_error("failed to finalize JLS AES-GCM"));
    }
    if (!decrypt) {
        std::array<std::uint8_t, 16> auth_tag{};
        if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG,
                                static_cast<int>(auth_tag.size()), auth_tag.data()) != 1) {
            return core::fail(jls_error("failed to obtain JLS AES-GCM tag"));
        }
        output.resize(static_cast<std::size_t>(written + final_written));
        output.insert(output.end(), auth_tag.begin(), auth_tag.end());
    } else {
        output.resize(static_cast<std::size_t>(written + final_written));
    }
    return output;
}

} // namespace

core::Result<std::vector<std::uint8_t>>
build_jls_fake_random(const JlsUser &user, std::span<const std::uint8_t, 16> seed,
                      std::span<const std::uint8_t> auth_data) {
    const auto nonce = sha256_parts(user.username, auth_data);
    const auto key = sha256_parts(user.password, auth_data);
    if (!nonce || !key) {
        return core::fail(!nonce ? nonce.error() : key.error());
    }
    return aes_gcm(false, key.value(), nonce.value(), seed, {});
}

bool check_jls_fake_random(const JlsUser &user, std::span<const std::uint8_t> fake_random,
                           std::span<const std::uint8_t> auth_data) {
    if (fake_random.size() != 32) {
        return false;
    }
    const auto nonce = sha256_parts(user.username, auth_data);
    const auto key = sha256_parts(user.password, auth_data);
    if (!nonce || !key) {
        return false;
    }
    const auto ciphertext = fake_random.first(16);
    const auto tag = fake_random.subspan(16);
    const auto seed = aes_gcm(true, key.value(), nonce.value(), ciphertext, tag);
    return seed.has_value() && seed.value().size() == 16;
}

core::Result<std::vector<std::uint8_t>>
jls_client_hello_auth_data(std::span<const std::uint8_t> wire_message) {
    return zero_client_hello_binders(
        std::vector<std::uint8_t>(wire_message.begin(), wire_message.end()));
}

core::Result<std::vector<std::uint8_t>>
jls_server_hello_auth_data(std::span<const std::uint8_t> wire_message) {
    if (!hello_wire_is_valid(wire_message, kServerHelloType)) {
        return core::fail(jls_error("invalid JLS ServerHello wire message"));
    }
    std::vector<std::uint8_t> result(wire_message.begin(), wire_message.end());
    zero_random(result);
    return result;
}

} // namespace clash_native::transport::shadowsocks
