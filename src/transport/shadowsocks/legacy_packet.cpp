#include <clash_native/transport/shadowsocks/legacy_packet.hpp>

#include <clash_native/transport/proxy/crypto.hpp>

#include <algorithm>
#include <cstddef>
#include <string>
#include <utility>

namespace clash_native::transport::shadowsocks {

namespace {

core::Error packet_error(std::string context) {
    return {core::ErrorCode::protocol_framing, std::move(context)};
}

} // namespace

core::Result<std::vector<std::uint8_t>>
encrypt_legacy_datagram(std::string_view method, std::string_view password,
                        std::span<const std::uint8_t> plaintext) {
    const auto spec = transport::proxy::cipher_method(method);
    if (!spec) {
        return core::fail(spec.error());
    }
    if (spec.value().kind != transport::proxy::CipherKind::stream) {
        return core::fail({core::ErrorCode::configuration,
                           "legacy datagram encryption requires a stream cipher"});
    }
    std::vector<std::uint8_t> iv(spec.value().iv_size);
    if (!transport::proxy::random_bytes(iv)) {
        return core::fail(
            {core::ErrorCode::authentication, "failed to generate Shadowsocks datagram IV"});
    }
    auto key = transport::proxy::derive_legacy_key(method, password, iv);
    if (!key) {
        return core::fail(key.error());
    }
    auto cipher = transport::proxy::LegacyStreamCipher::create(method, key.value(), iv, true);
    if (!cipher) {
        return core::fail(cipher.error());
    }
    std::vector<std::uint8_t> encrypted(plaintext.begin(), plaintext.end());
    if (const auto result = cipher.value().update(encrypted); !result) {
        return core::fail(result.error());
    }
    iv.insert(iv.end(), encrypted.begin(), encrypted.end());
    return iv;
}

core::Result<std::vector<std::uint8_t>>
decrypt_legacy_datagram(std::string_view method, std::string_view password,
                        std::span<const std::uint8_t> wire) {
    const auto spec = transport::proxy::cipher_method(method);
    if (!spec) {
        return core::fail(spec.error());
    }
    if (spec.value().kind != transport::proxy::CipherKind::stream) {
        return core::fail({core::ErrorCode::configuration,
                           "legacy datagram decryption requires a stream cipher"});
    }
    if (wire.size() < spec.value().iv_size) {
        return core::fail(packet_error("Shadowsocks legacy datagram is shorter than its IV"));
    }
    const auto iv = wire.first(spec.value().iv_size);
    auto key = transport::proxy::derive_legacy_key(method, password, iv);
    if (!key) {
        return core::fail(key.error());
    }
    auto cipher = transport::proxy::LegacyStreamCipher::create(method, key.value(), iv, false);
    if (!cipher) {
        return core::fail(cipher.error());
    }
    std::vector<std::uint8_t> plaintext(wire.begin() + static_cast<std::ptrdiff_t>(iv.size()),
                                        wire.end());
    if (const auto result = cipher.value().update(plaintext); !result) {
        return core::fail(result.error());
    }
    return plaintext;
}

std::size_t legacy_datagram_payload_limit(std::string_view method, std::size_t wire_limit,
                                          std::size_t address_limit) noexcept {
    const auto spec = transport::proxy::cipher_method(method);
    if (!spec || spec.value().kind != transport::proxy::CipherKind::stream ||
        wire_limit < spec.value().iv_size) {
        return 0;
    }
    const auto encrypted_limit = wire_limit - spec.value().iv_size;
    return encrypted_limit > address_limit ? encrypted_limit - address_limit : 0;
}

} // namespace clash_native::transport::shadowsocks
