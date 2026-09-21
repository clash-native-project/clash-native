#include <clash_native/transport/shadowsocks/aead_packet.hpp>

#include <clash_native/transport/shadowsocks/crypto.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>

namespace clash_native::transport::shadowsocks {

namespace {
core::Error packet_error(std::string message) {
    return {core::ErrorCode::protocol_framing, std::move(message)};
}
} // namespace

core::Result<std::vector<std::uint8_t>>
encrypt_aead_datagram(std::string_view method, std::string_view password,
                      std::span<const std::uint8_t> plaintext) {
    const auto spec = cipher_method(method);
    if (!spec || spec.value().kind != CipherKind::aead || spec.value().shadowsocks_2022) {
        return core::fail(spec ? core::Error{core::ErrorCode::configuration,
                                             "classic AEAD datagram requires a classic method"}
                               : spec.error());
    }
    std::vector<std::uint8_t> salt(spec.value().key_size);
    if (!random_bytes(salt)) {
        return core::fail(
            {core::ErrorCode::authentication, "failed to generate Shadowsocks AEAD datagram salt"});
    }
    auto key = derive_aead_subkey(method, password, salt);
    if (!key) {
        return core::fail(key.error());
    }
    const std::vector<std::uint8_t> nonce(spec.value().nonce_size, 0);
    auto ciphertext = aead_encrypt(method, key.value(), nonce, plaintext);
    if (!ciphertext) {
        return core::fail(ciphertext.error());
    }
    salt.insert(salt.end(), ciphertext.value().begin(), ciphertext.value().end());
    return salt;
}

core::Result<std::vector<std::uint8_t>> decrypt_aead_datagram(std::string_view method,
                                                              std::string_view password,
                                                              std::span<const std::uint8_t> wire) {
    const auto spec = cipher_method(method);
    if (!spec || spec.value().kind != CipherKind::aead || spec.value().shadowsocks_2022) {
        return core::fail(spec ? core::Error{core::ErrorCode::configuration,
                                             "classic AEAD datagram requires a classic method"}
                               : spec.error());
    }
    if (wire.size() < spec.value().key_size + spec.value().overhead) {
        return core::fail(packet_error("Shadowsocks AEAD datagram is shorter than its salt"));
    }
    const auto salt = wire.first(spec.value().key_size);
    auto key = derive_aead_subkey(method, password, salt);
    if (!key) {
        return core::fail(key.error());
    }
    const std::vector<std::uint8_t> nonce(spec.value().nonce_size, 0);
    return aead_decrypt(method, key.value(), nonce, wire.subspan(spec.value().key_size));
}

std::size_t aead_datagram_payload_limit(std::string_view method, std::size_t wire_limit,
                                        std::size_t address_limit) noexcept {
    const auto spec = cipher_method(method);
    if (!spec || spec.value().kind != CipherKind::aead || spec.value().shadowsocks_2022 ||
        wire_limit < spec.value().key_size + spec.value().overhead + address_limit) {
        return 0;
    }
    return wire_limit - spec.value().key_size - spec.value().overhead - address_limit;
}

} // namespace clash_native::transport::shadowsocks
