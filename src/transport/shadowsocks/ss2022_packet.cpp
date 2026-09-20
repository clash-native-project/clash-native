#include <clash_native/transport/shadowsocks/ss2022_packet.hpp>

#include <clash_native/transport/shadowsocks/crypto.hpp>

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <utility>

namespace clash_native::transport::shadowsocks {

namespace {

constexpr std::size_t kAeadTagSize = 16;
constexpr std::size_t kPacketHeaderSize = 16;
constexpr std::size_t kPacketNonceSize = 24;
constexpr std::size_t kFixedBodySize = 1 + 8 + 8 + 2;
constexpr std::uint8_t kClientHeader = 0;
constexpr std::uint8_t kServerHeader = 1;

core::Error packet_error(std::string message) {
    return {core::ErrorCode::protocol_framing, std::move(message)};
}

void append_u16(std::vector<std::uint8_t> &output, std::size_t value) {
    output.push_back(static_cast<std::uint8_t>(value >> 8));
    output.push_back(static_cast<std::uint8_t>(value));
}

void append_u64(std::vector<std::uint8_t> &output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

std::uint16_t read_u16(std::span<const std::uint8_t> input, std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(input[offset]) << 8) |
                                       input[offset + 1]);
}

std::uint64_t read_u64(std::span<const std::uint8_t> input, std::size_t offset) {
    std::uint64_t result = 0;
    for (std::size_t index = 0; index < sizeof(result); ++index) {
        result = (result << 8) | input[offset + index];
    }
    return result;
}

std::uint64_t unix_seconds() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

bool is_aes_method(const CipherMethod &method) {
    return method.name == "2022-blake3-aes-128-gcm" ||
           method.name == "2022-blake3-aes-256-gcm";
}

const EVP_CIPHER *aes_ecb_cipher(std::size_t key_size) {
    if (key_size == 16) {
        return EVP_aes_128_ecb();
    }
    if (key_size == 32) {
        return EVP_aes_256_ecb();
    }
    return nullptr;
}

core::Result<std::vector<std::uint8_t>> aes_ecb_crypt(std::span<const std::uint8_t> key,
                                                       std::span<const std::uint8_t> block,
                                                       bool encrypt) {
    if (block.size() != kPacketHeaderSize) {
        return core::fail(packet_error("invalid Shadowsocks 2022 packet header size"));
    }
    const auto *cipher = aes_ecb_cipher(key.size());
    if (!cipher) {
        return core::fail(packet_error("unsupported Shadowsocks 2022 packet header key"));
    }
    using Context = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
    Context context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context || EVP_CipherInit_ex(context.get(), cipher, nullptr, key.data(), nullptr,
                                      encrypt ? 1 : 0) != 1 ||
        EVP_CIPHER_CTX_set_padding(context.get(), 0) != 1) {
        return core::fail({core::ErrorCode::authentication,
                           "failed to initialize Shadowsocks 2022 packet header cipher"});
    }
    std::vector<std::uint8_t> result(kPacketHeaderSize);
    int written = 0;
    int final_written = 0;
    if (EVP_CipherUpdate(context.get(), result.data(), &written, block.data(),
                         static_cast<int>(block.size())) != 1 ||
        EVP_CipherFinal_ex(context.get(), result.data() + written, &final_written) != 1 ||
        static_cast<std::size_t>(written + final_written) != result.size()) {
        return core::fail({core::ErrorCode::authentication,
                           "failed to process Shadowsocks 2022 packet header"});
    }
    return result;
}

bool timestamp_is_recent(std::uint64_t timestamp) {
    const auto now = unix_seconds();
    return timestamp <= now + 30 && now <= timestamp + 30;
}

core::Result<std::vector<std::uint8_t>> strip_response_header(
    std::span<const std::uint8_t> plaintext, std::uint64_t expected_session_id) {
    if (plaintext.size() < kFixedBodySize || plaintext[0] != kServerHeader ||
        !timestamp_is_recent(read_u64(plaintext, 1))) {
        return core::fail(packet_error("invalid Shadowsocks 2022 UDP response header"));
    }
    if (read_u64(plaintext, 1 + 8) != expected_session_id) {
        return core::fail(packet_error("Shadowsocks 2022 UDP response targets another session"));
    }
    const auto padding_size = read_u16(plaintext, 1 + 8 + 8);
    const auto payload_offset = kFixedBodySize + padding_size;
    if (payload_offset > plaintext.size()) {
        return core::fail(packet_error("invalid Shadowsocks 2022 UDP response padding"));
    }
    return std::vector<std::uint8_t>(plaintext.begin() + static_cast<std::ptrdiff_t>(payload_offset),
                                     plaintext.end());
}

} // namespace

Shadowsocks2022DatagramCodec::Shadowsocks2022DatagramCodec(std::string method,
                                                           std::string password)
    : method_(std::move(method)), password_(std::move(password)) {
    const auto method_info = cipher_method(method_);
    if (method_info && method_info.value().shadowsocks_2022) {
        auto psk = decode_shadowsocks_2022_psk(method_, password_);
        if (psk) {
            psk_ = std::move(psk.value());
            std::array<std::uint8_t, sizeof(session_id_)> bytes{};
            if (random_bytes(bytes)) {
                session_id_ = read_u64(bytes, 0);
            }
        }
    }
}

core::Result<std::vector<std::uint8_t>> Shadowsocks2022DatagramCodec::encrypt(
    std::span<const std::uint8_t> destination, std::span<const std::uint8_t> payload) {
    const auto method_info = cipher_method(method_);
    if (!method_info || !method_info.value().shadowsocks_2022 || psk_.empty() ||
        destination.empty()) {
        return core::fail(packet_error("invalid Shadowsocks 2022 UDP configuration"));
    }
    if (!session_id_) {
        return core::fail({core::ErrorCode::authentication,
                           "failed to initialize Shadowsocks 2022 UDP session"});
    }

    const auto packet_id = packet_id_++;
    std::vector<std::uint8_t> body;
    body.reserve(kFixedBodySize + destination.size() + payload.size());
    body.push_back(kClientHeader);
    append_u64(body, unix_seconds());
    append_u16(body, 1);
    body.push_back(0);
    body.insert(body.end(), destination.begin(), destination.end());
    body.insert(body.end(), payload.begin(), payload.end());

    if (is_aes_method(method_info.value())) {
        std::vector<std::uint8_t> packet_header;
        packet_header.reserve(kPacketHeaderSize);
        append_u64(packet_header, session_id_);
        append_u64(packet_header, packet_id);
        std::array<std::uint8_t, sizeof(session_id_)> session_salt{};
        std::copy(packet_header.begin(), packet_header.begin() + session_salt.size(),
                  session_salt.begin());
        auto session_key = derive_shadowsocks_2022_subkey(method_, password_, session_salt);
        if (!session_key) {
            return core::fail(session_key.error());
        }
        const auto nonce = std::span<const std::uint8_t>(packet_header).subspan(4, 12);
        auto ciphertext = aead_encrypt(method_, session_key.value(), nonce, body);
        if (!ciphertext) {
            return core::fail(ciphertext.error());
        }
        auto encrypted_header = aes_ecb_crypt(psk_, packet_header, true);
        if (!encrypted_header) {
            return core::fail(encrypted_header.error());
        }
        encrypted_header.value().insert(encrypted_header.value().end(), ciphertext.value().begin(),
                                        ciphertext.value().end());
        return encrypted_header;
    }

    std::array<std::uint8_t, kPacketNonceSize> nonce{};
    if (!random_bytes(nonce)) {
        return core::fail({core::ErrorCode::authentication,
                           "failed to generate Shadowsocks 2022 UDP nonce"});
    }
    std::vector<std::uint8_t> encrypted_body;
    encrypted_body.reserve(sizeof(session_id_) * 2 + body.size());
    append_u64(encrypted_body, session_id_);
    append_u64(encrypted_body, packet_id);
    encrypted_body.insert(encrypted_body.end(), body.begin(), body.end());
    auto ciphertext = xchacha20_poly1305_encrypt(psk_, nonce, encrypted_body);
    if (!ciphertext) {
        return core::fail(ciphertext.error());
    }
    std::vector<std::uint8_t> result(nonce.begin(), nonce.end());
    result.insert(result.end(), ciphertext.value().begin(), ciphertext.value().end());
    return result;
}

core::Result<std::vector<std::uint8_t>> Shadowsocks2022DatagramCodec::decrypt(
    std::span<const std::uint8_t> wire) {
    const auto method_info = cipher_method(method_);
    if (!method_info || !method_info.value().shadowsocks_2022 || psk_.empty()) {
        return core::fail(packet_error("invalid Shadowsocks 2022 UDP configuration"));
    }
    if (is_aes_method(method_info.value())) {
        if (wire.size() < kPacketHeaderSize + kAeadTagSize + kFixedBodySize) {
            return core::fail(packet_error("Shadowsocks 2022 UDP response is too short"));
        }
        auto packet_header = aes_ecb_crypt(psk_, wire.first(kPacketHeaderSize), false);
        if (!packet_header) {
            return core::fail(packet_header.error());
        }
        const auto session_salt = std::span<const std::uint8_t>(*packet_header).first(8);
        auto session_key = derive_shadowsocks_2022_subkey(method_, password_, session_salt);
        if (!session_key) {
            return core::fail(session_key.error());
        }
        const auto nonce = std::span<const std::uint8_t>(*packet_header).subspan(4, 12);
        auto plaintext = aead_decrypt(method_, session_key.value(), nonce,
                                      wire.subspan(kPacketHeaderSize));
        if (!plaintext) {
            return core::fail(plaintext.error());
        }
        return strip_response_header(plaintext.value(), session_id_);
    }
    if (wire.size() < kPacketNonceSize + kAeadTagSize + sizeof(session_id_) * 2 +
                          kFixedBodySize) {
        return core::fail(packet_error("Shadowsocks 2022 UDP response is too short"));
    }
    auto plaintext = xchacha20_poly1305_decrypt(psk_, wire.first(kPacketNonceSize),
                                                  wire.subspan(kPacketNonceSize));
    if (!plaintext) {
        return core::fail(plaintext.error());
    }
    const auto body = std::span<const std::uint8_t>(plaintext.value());
    const auto server_session_id = read_u64(body, 0);
    (void)server_session_id;
    return strip_response_header(body.subspan(sizeof(session_id_) * 2), session_id_);
}

std::size_t Shadowsocks2022DatagramCodec::max_datagram_size(
    std::size_t wire_limit, std::size_t destination_limit) const noexcept {
    const auto method_info = cipher_method(method_);
    if (!method_info || !method_info.value().shadowsocks_2022) {
        return 0;
    }
    const auto overhead = is_aes_method(method_info.value())
                              ? kPacketHeaderSize + kAeadTagSize + kFixedBodySize
                              : kPacketNonceSize + kAeadTagSize + sizeof(session_id_) * 2 +
                                    kFixedBodySize;
    if (wire_limit <= overhead + destination_limit) {
        return 0;
    }
    return wire_limit - overhead - destination_limit;
}

} // namespace clash_native::transport::shadowsocks
