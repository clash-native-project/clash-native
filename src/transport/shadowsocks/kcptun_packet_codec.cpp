#include <clash_native/transport/shadowsocks/kcptun_packet_codec.hpp>

#include <clash_native/transport/shadowsocks/crypto.hpp>

#include <botan/aead.h>
#include <botan/block_cipher.h>
#include <botan/mac.h>
#include <botan/stream_cipher.h>
#include <botan/zfec.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace clash_native::transport::shadowsocks {

namespace {

constexpr std::size_t kMaximumDatagramSize = 1500;
constexpr std::size_t kMtuLimit = 1500;
constexpr std::size_t kCryptNonceSize = 16;
constexpr std::size_t kCryptHeaderSize = 20;
constexpr std::size_t kAeadNonceSize = 12;
constexpr std::size_t kAeadTagSize = 16;
constexpr std::size_t kFecHeaderSize = 6;
constexpr std::size_t kFecHeaderSizePlusTwo = 8;
constexpr std::uint16_t kFecData = 0xf1;
constexpr std::uint16_t kFecParity = 0xf2;
constexpr std::uint32_t kFecPaws = 0xffffffffU;
constexpr std::uint32_t kMaximumRetainedFecGroups = 3;
constexpr std::uint32_t kFecEncodeLatencyMs = 500;

constexpr std::array<std::uint8_t, 16> kInitialVector{167, 115, 79,  156, 18,  172, 27,  1,
                                                      164, 21,  242, 193, 252, 120, 230, 107};
constexpr std::string_view kXorSalt = "sH3CIVoF#rWLtJo6";

void put_u16(std::uint8_t *output, std::uint16_t value) {
    output[0] = static_cast<std::uint8_t>(value);
    output[1] = static_cast<std::uint8_t>(value >> 8);
}

void put_u32(std::uint8_t *output, std::uint32_t value) {
    output[0] = static_cast<std::uint8_t>(value);
    output[1] = static_cast<std::uint8_t>(value >> 8);
    output[2] = static_cast<std::uint8_t>(value >> 16);
    output[3] = static_cast<std::uint8_t>(value >> 24);
}

std::uint16_t get_u16(const std::uint8_t *input) {
    return static_cast<std::uint16_t>(input[0] | (static_cast<std::uint16_t>(input[1]) << 8));
}

std::uint32_t get_u32(const std::uint8_t *input) {
    return static_cast<std::uint32_t>(input[0]) | (static_cast<std::uint32_t>(input[1]) << 8) |
           (static_cast<std::uint32_t>(input[2]) << 16) |
           (static_cast<std::uint32_t>(input[3]) << 24);
}

std::uint32_t crc32_ieee(std::span<const std::uint8_t> input) {
    static const auto table = [] {
        std::array<std::uint32_t, 256> result{};
        for (std::uint32_t index = 0; index < result.size(); ++index) {
            auto value = index;
            for (int bit = 0; bit < 8; ++bit) {
                value = (value & 1U) != 0 ? (value >> 1U) ^ 0xedb88320U : value >> 1U;
            }
            result[index] = value;
        }
        return result;
    }();
    auto value = 0xffffffffU;
    for (const auto byte : input) {
        value = table[(value ^ byte) & 0xffU] ^ (value >> 8U);
    }
    return value ^ 0xffffffffU;
}

std::uint32_t load_be32(const std::uint8_t *input) {
    return (static_cast<std::uint32_t>(input[0]) << 24) |
           (static_cast<std::uint32_t>(input[1]) << 16) |
           (static_cast<std::uint32_t>(input[2]) << 8) | input[3];
}

void store_be32(std::uint8_t *output, std::uint32_t value) {
    output[0] = static_cast<std::uint8_t>(value >> 24);
    output[1] = static_cast<std::uint8_t>(value >> 16);
    output[2] = static_cast<std::uint8_t>(value >> 8);
    output[3] = static_cast<std::uint8_t>(value);
}

void tea_encrypt(const std::uint8_t *input, std::uint8_t *output,
                 const std::array<std::uint32_t, 4> &key) {
    auto v0 = load_be32(input);
    auto v1 = load_be32(input + 4);
    std::uint32_t sum = 0;
    constexpr std::uint32_t delta = 0x9e3779b9U;
    for (int round = 0; round < 8; ++round) {
        sum += delta;
        v0 += ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]);
        v1 += ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]);
    }
    store_be32(output, v0);
    store_be32(output + 4, v1);
}

void tea_decrypt(const std::uint8_t *input, std::uint8_t *output,
                 const std::array<std::uint32_t, 4> &key) {
    auto v0 = load_be32(input);
    auto v1 = load_be32(input + 4);
    constexpr std::uint32_t delta = 0x9e3779b9U;
    std::uint32_t sum = delta * 8;
    for (int round = 0; round < 8; ++round) {
        v1 -= ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]);
        v0 -= ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]);
        sum -= delta;
    }
    store_be32(output, v0);
    store_be32(output + 4, v1);
}

void xtea_encrypt(const std::uint8_t *input, std::uint8_t *output,
                  const std::array<std::uint32_t, 4> &key) {
    auto v0 = load_be32(input);
    auto v1 = load_be32(input + 4);
    std::uint32_t sum = 0;
    constexpr std::uint32_t delta = 0x9e3779b9U;
    for (int round = 0; round < 32; ++round) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3U]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3U]);
    }
    store_be32(output, v0);
    store_be32(output + 4, v1);
}

void xtea_decrypt(const std::uint8_t *input, std::uint8_t *output,
                  const std::array<std::uint32_t, 4> &key) {
    auto v0 = load_be32(input);
    auto v1 = load_be32(input + 4);
    constexpr std::uint32_t delta = 0x9e3779b9U;
    std::uint32_t sum = delta * 32;
    for (int round = 0; round < 32; ++round) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3U]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3U]);
    }
    store_be32(output, v0);
    store_be32(output + 4, v1);
}

core::Error codec_error(std::string message) {
    return {core::ErrorCode::authentication, std::move(message), {}};
}

core::Result<std::vector<std::uint8_t>> pbkdf2_sha1(std::span<const std::uint8_t> password,
                                                    std::span<const std::uint8_t> salt,
                                                    std::size_t length,
                                                    std::size_t iterations = 4096) {
    try {
        auto mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-1)");
        if (!mac) {
            return core::fail(codec_error("Botan HMAC-SHA1 is unavailable"));
        }
        constexpr std::size_t kDigestSize = 20;
        std::vector<std::uint8_t> output;
        output.reserve(length);
        for (std::uint32_t block = 1; output.size() < length; ++block) {
            std::array<std::uint8_t, 4> block_number{
                static_cast<std::uint8_t>(block >> 24), static_cast<std::uint8_t>(block >> 16),
                static_cast<std::uint8_t>(block >> 8), static_cast<std::uint8_t>(block)};
            mac->set_key(password);
            mac->update(salt);
            mac->update(block_number);
            auto u = mac->final_stdvec();
            auto t = u;
            for (std::size_t iteration = 1; iteration < iterations; ++iteration) {
                mac->set_key(password);
                mac->update(u);
                u = mac->final_stdvec();
                for (std::size_t index = 0; index < kDigestSize; ++index) {
                    t[index] ^= u[index];
                }
            }
            const auto count = std::min(length - output.size(), t.size());
            output.insert(output.end(), t.begin(), t.begin() + count);
        }
        return output;
    } catch (const std::exception &error) {
        return core::fail(codec_error(std::string("failed to derive kcptun key: ") + error.what()));
    }
}

std::optional<std::array<std::uint32_t, 4>> make_word_key(std::span<const std::uint8_t> key) {
    if (key.size() != 16) {
        return std::nullopt;
    }
    std::array<std::uint32_t, 4> output{};
    for (std::size_t index = 0; index < output.size(); ++index) {
        output[index] = load_be32(key.data() + index * 4);
    }
    return output;
}

} // namespace

struct KcptunPacketCodec::Impl {
    enum class CipherKind { null_cipher, none, block, xor_cipher, salsa20, aes_gcm };

    struct FecGroup {
        std::vector<std::vector<std::uint8_t>> shares;
        std::size_t max_size = 0;
        std::chrono::steady_clock::time_point latest{};
    };

    std::vector<std::uint8_t> pass;
    std::string crypt;
    CipherKind cipher_kind = CipherKind::null_cipher;
    std::unique_ptr<Botan::BlockCipher> block;
    std::optional<std::array<std::uint32_t, 4>> word_key;
    std::vector<std::uint8_t> xor_table;
    int data_shard = 0;
    int parity_shard = 0;
    std::uint32_t next_fec_sequence = 0;
    FecGroup fec_group;
    std::optional<Botan::ZFEC> fec;
    std::map<std::uint32_t, std::map<std::size_t, std::vector<std::uint8_t>>> receive_groups;
    std::uint32_t newest_receive_group = 0;
    bool have_newest_receive_group = false;
};

KcptunPacketCodec::KcptunPacketCodec(std::vector<std::uint8_t> pass, std::string crypt,
                                     int data_shard, int parity_shard)
    : impl_(std::make_unique<Impl>()) {
    impl_->pass = std::move(pass);
    impl_->crypt = std::move(crypt);
    impl_->data_shard = data_shard;
    impl_->parity_shard = parity_shard;
}

core::Result<std::shared_ptr<KcptunPacketCodec>>
KcptunPacketCodec::create(std::string key, std::string crypt, int data_shard, int parity_shard) {
    std::vector<std::uint8_t> kcp_salt{'k', 'c', 'p', '-', 'g', 'o'};
    auto pass = pbkdf2_sha1(std::span<const std::uint8_t>(
                                reinterpret_cast<const std::uint8_t *>(key.data()), key.size()),
                            kcp_salt, 32);
    if (!pass) {
        return core::fail(pass.error());
    }
    if (data_shard < 0 || parity_shard < 0 || data_shard > 0xff || parity_shard > 0xff ||
        ((data_shard == 0) != (parity_shard == 0)) ||
        (data_shard > 0 && data_shard + parity_shard > 256)) {
        return core::fail({core::ErrorCode::configuration, "invalid kcptun FEC shard counts", {}});
    }

    auto codec = std::shared_ptr<KcptunPacketCodec>(
        new KcptunPacketCodec(std::move(pass.value()), crypt, data_shard, parity_shard));
    auto &impl = *codec->impl_;
    if (crypt == "null") {
        impl.cipher_kind = Impl::CipherKind::null_cipher;
    } else if (crypt == "none") {
        impl.cipher_kind = Impl::CipherKind::none;
    } else if (crypt == "xor") {
        auto table = pbkdf2_sha1(
            impl.pass,
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(kXorSalt.data()),
                                          kXorSalt.size()),
            kMtuLimit, 32);
        if (!table) {
            return core::fail(table.error());
        }
        impl.xor_table = std::move(table.value());
        impl.cipher_kind = Impl::CipherKind::xor_cipher;
    } else if (crypt == "salsa20") {
        impl.cipher_kind = Impl::CipherKind::salsa20;
    } else if (crypt == "aes-128-gcm") {
        impl.cipher_kind = Impl::CipherKind::aes_gcm;
    } else {
        std::string algorithm;
        std::size_t key_size = impl.pass.size();
        if (crypt == "tea") {
            impl.word_key = make_word_key(std::span<const std::uint8_t>(impl.pass).first<16>());
            if (!impl.word_key) {
                return core::fail(codec_error("invalid TEA key"));
            }
            impl.cipher_kind = Impl::CipherKind::block;
        } else if (crypt == "xtea") {
            impl.word_key = make_word_key(std::span<const std::uint8_t>(impl.pass).first<16>());
            if (!impl.word_key) {
                return core::fail(codec_error("invalid XTEA key"));
            }
            impl.cipher_kind = Impl::CipherKind::block;
        } else {
            if (crypt == "aes-128") {
                algorithm = "AES-128";
                key_size = 16;
            } else if (crypt == "aes-192") {
                algorithm = "AES-192";
                key_size = 24;
            } else if (crypt == "blowfish") {
                algorithm = "Blowfish";
            } else if (crypt == "twofish") {
                algorithm = "Twofish";
            } else if (crypt == "cast5") {
                algorithm = "CAST-128";
                key_size = 16;
            } else if (crypt == "3des") {
                algorithm = "3DES";
                key_size = 24;
            } else {
                // kcp-go intentionally falls back to AES-256 for unknown names.
                algorithm = "AES-256";
                key_size = 32;
                impl.crypt = "aes";
            }
            try {
                impl.block = Botan::BlockCipher::create(algorithm);
                if (!impl.block) {
                    return core::fail(
                        codec_error("Botan does not provide kcptun cipher " + algorithm));
                }
                impl.block->set_key(std::span<const std::uint8_t>(impl.pass).first(key_size));
                impl.cipher_kind = Impl::CipherKind::block;
            } catch (const std::exception &error) {
                return core::fail(codec_error(std::string("failed to initialize kcptun cipher: ") +
                                              error.what()));
            }
        }
    }
    if (data_shard > 0) {
        try {
            impl.fec.emplace(static_cast<std::size_t>(data_shard),
                             static_cast<std::size_t>(data_shard + parity_shard));
        } catch (const std::exception &error) {
            return core::fail(
                codec_error(std::string("failed to initialize kcptun FEC: ") + error.what()));
        }
    }
    return codec;
}

namespace {

void apply_cfb(const KcptunPacketCodec::Impl &impl, std::span<std::uint8_t> data, bool decrypt) {
    if (impl.cipher_kind == KcptunPacketCodec::Impl::CipherKind::none) {
        return;
    }
    if (impl.cipher_kind == KcptunPacketCodec::Impl::CipherKind::xor_cipher) {
        for (std::size_t index = 0; index < data.size(); ++index) {
            data[index] ^= impl.xor_table[index % impl.xor_table.size()];
        }
        return;
    }
    if (impl.cipher_kind == KcptunPacketCodec::Impl::CipherKind::salsa20) {
        if (data.size() < 8) {
            return;
        }
        try {
            auto cipher = Botan::StreamCipher::create("Salsa20");
            if (!cipher) {
                return;
            }
            cipher->set_key(impl.pass);
            cipher->set_iv(data.first<8>());
            cipher->cipher1(data.subspan(8));
        } catch (...) {
        }
        return;
    }
    const auto block_size = impl.word_key ? 8U : impl.block->block_size();
    std::array<std::uint8_t, 16> keystream{};
    std::array<std::uint8_t, 16> next{};
    auto encrypt_block = [&](const std::uint8_t *input, std::uint8_t *output) {
        if (impl.word_key) {
            if (impl.crypt == "tea") {
                tea_encrypt(input, output, *impl.word_key);
            } else {
                xtea_encrypt(input, output, *impl.word_key);
            }
        } else {
            impl.block->encrypt(input, output);
        }
    };
    encrypt_block(kInitialVector.data(), keystream.data());
    for (std::size_t offset = 0; offset < data.size(); offset += block_size) {
        const auto count = std::min<std::size_t>(block_size, data.size() - offset);
        std::copy_n(data.data() + offset, count, next.data());
        for (std::size_t index = 0; index < count; ++index) {
            data[offset + index] ^= keystream[index];
        }
        if (count == block_size) {
            encrypt_block(decrypt ? next.data() : data.data() + offset, keystream.data());
        }
    }
}

std::vector<std::uint8_t> crypt_packet(const KcptunPacketCodec::Impl &impl,
                                       std::span<const std::uint8_t> plaintext) {
    if (impl.cipher_kind == KcptunPacketCodec::Impl::CipherKind::null_cipher) {
        return {plaintext.begin(), plaintext.end()};
    }
    if (impl.cipher_kind == KcptunPacketCodec::Impl::CipherKind::aes_gcm) {
        std::vector<std::uint8_t> nonce(kAeadNonceSize);
        if (!random_bytes(nonce)) {
            return {};
        }
        try {
            // Mihomo's kcptun profile names this construction aes-128-gcm and
            // passes the first 16 bytes of the PBKDF2 output to kcp-go.
            auto aead = Botan::AEAD_Mode::create("AES-128/GCM", Botan::Cipher_Dir::Encryption);
            if (!aead) {
                return {};
            }
            aead->set_key(std::span<const std::uint8_t>(impl.pass).first<16>());
            aead->start(nonce);
            std::vector<std::uint8_t> ciphertext(plaintext.begin(), plaintext.end());
            aead->finish(ciphertext);
            nonce.insert(nonce.end(), ciphertext.begin(), ciphertext.end());
            return nonce;
        } catch (...) {
            return {};
        }
    }
    std::vector<std::uint8_t> output(kCryptHeaderSize + plaintext.size());
    if (!random_bytes(std::span<std::uint8_t>(output).first(kCryptNonceSize))) {
        return {};
    }
    put_u32(output.data() + kCryptNonceSize, crc32_ieee(plaintext));
    std::copy(plaintext.begin(), plaintext.end(), output.begin() + kCryptHeaderSize);
    apply_cfb(impl, output, false);
    return output;
}

std::vector<std::uint8_t> decrypt_packet(const KcptunPacketCodec::Impl &impl,
                                         std::span<const std::uint8_t> wire) {
    if (impl.cipher_kind == KcptunPacketCodec::Impl::CipherKind::null_cipher) {
        return {wire.begin(), wire.end()};
    }
    if (impl.cipher_kind == KcptunPacketCodec::Impl::CipherKind::aes_gcm) {
        if (wire.size() < kAeadNonceSize + kAeadTagSize) {
            return {};
        }
        try {
            auto aead = Botan::AEAD_Mode::create("AES-128/GCM", Botan::Cipher_Dir::Decryption);
            if (!aead) {
                return {};
            }
            aead->set_key(std::span<const std::uint8_t>(impl.pass).first<16>());
            aead->start(wire.first(kAeadNonceSize));
            std::vector<std::uint8_t> output(wire.begin() + kAeadNonceSize, wire.end());
            aead->finish(output);
            return output;
        } catch (...) {
            return {};
        }
    }
    if (wire.size() < kCryptHeaderSize) {
        return {};
    }
    std::vector<std::uint8_t> output(wire.begin(), wire.end());
    apply_cfb(impl, output, true);
    const auto checksum = get_u32(output.data() + kCryptNonceSize);
    const auto plaintext = std::span<const std::uint8_t>(output).subspan(kCryptHeaderSize);
    if (crc32_ieee(plaintext) != checksum) {
        return {};
    }
    return {plaintext.begin(), plaintext.end()};
}

std::vector<std::uint8_t> make_fec_packet(std::uint32_t sequence, std::uint16_t type,
                                          std::span<const std::uint8_t> payload) {
    std::vector<std::uint8_t> packet(kFecHeaderSize + payload.size());
    put_u32(packet.data(), sequence);
    put_u16(packet.data() + 4, type);
    std::copy(payload.begin(), payload.end(), packet.begin() + kFecHeaderSize);
    return packet;
}

void advance_fec_sequence(std::uint32_t &sequence) {
    sequence = sequence == kFecPaws - 1 ? 0 : sequence + 1;
}

} // namespace

std::vector<std::vector<std::uint8_t>>
KcptunPacketCodec::encode(std::span<const std::uint8_t> kcp_packet) {
    auto &impl = *impl_;
    std::vector<std::vector<std::uint8_t>> plaintext_packets;
    if (!impl.fec) {
        plaintext_packets.emplace_back(kcp_packet.begin(), kcp_packet.end());
    } else {
        if (kcp_packet.size() > 0xffffU - 2U) {
            return {};
        }
        std::vector<std::uint8_t> share(kFecHeaderSizePlusTwo + kcp_packet.size());
        put_u32(share.data(), impl.next_fec_sequence);
        put_u16(share.data() + 4, kFecData);
        put_u16(share.data() + kFecHeaderSize, static_cast<std::uint16_t>(kcp_packet.size() + 2));
        std::copy(kcp_packet.begin(), kcp_packet.end(), share.begin() + kFecHeaderSizePlusTwo);
        advance_fec_sequence(impl.next_fec_sequence);
        plaintext_packets.push_back(share);

        std::vector<std::uint8_t> fec_share(kcp_packet.size() + 2);
        put_u16(fec_share.data(), static_cast<std::uint16_t>(kcp_packet.size() + 2));
        std::copy(kcp_packet.begin(), kcp_packet.end(), fec_share.begin() + 2);
        impl.fec_group.max_size = std::max(impl.fec_group.max_size, fec_share.size());
        impl.fec_group.shares.push_back(std::move(fec_share));
        const auto now = std::chrono::steady_clock::now();
        const auto continuous =
            impl.fec_group.latest.time_since_epoch().count() != 0 &&
            std::chrono::duration_cast<std::chrono::milliseconds>(now - impl.fec_group.latest)
                    .count() < kFecEncodeLatencyMs;
        impl.fec_group.latest = now;
        if (impl.fec_group.shares.size() == static_cast<std::size_t>(impl.data_shard)) {
            if (continuous) {
                const auto share_size = impl.fec_group.max_size;
                for (auto &data : impl.fec_group.shares) {
                    data.resize(share_size);
                }
                std::vector<const std::uint8_t *> pointers;
                pointers.reserve(impl.fec_group.shares.size());
                for (const auto &data : impl.fec_group.shares) {
                    pointers.push_back(data.data());
                }
                std::vector<std::vector<std::uint8_t>> parity(
                    impl.parity_shard, std::vector<std::uint8_t>(share_size));
                impl.fec->encode_shares(
                    pointers, share_size,
                    [&](std::size_t index, const std::uint8_t *data, std::size_t size) {
                        if (index >= static_cast<std::size_t>(impl.data_shard)) {
                            auto &target = parity[index - impl.data_shard];
                            std::copy_n(data, size, target.data());
                        }
                    });
                for (auto &data : parity) {
                    plaintext_packets.push_back(
                        make_fec_packet(impl.next_fec_sequence, kFecParity, data));
                    advance_fec_sequence(impl.next_fec_sequence);
                }
            } else {
                for (int index = 0; index < impl.parity_shard; ++index) {
                    advance_fec_sequence(impl.next_fec_sequence);
                }
            }
            impl.fec_group = {};
        }
    }

    std::vector<std::vector<std::uint8_t>> output;
    output.reserve(plaintext_packets.size());
    for (const auto &packet : plaintext_packets) {
        auto encrypted = crypt_packet(impl, packet);
        if (encrypted.empty() || encrypted.size() > kMaximumDatagramSize) {
            return {};
        }
        output.push_back(std::move(encrypted));
    }
    return output;
}

std::vector<std::vector<std::uint8_t>>
KcptunPacketCodec::decode(std::span<const std::uint8_t> wire_packet) {
    auto &impl = *impl_;
    auto plaintext = decrypt_packet(impl, wire_packet);
    if (plaintext.empty()) {
        return {};
    }
    if (!impl.fec) {
        return {std::move(plaintext)};
    }
    if (plaintext.size() < kFecHeaderSizePlusTwo) {
        return {};
    }
    const auto sequence = get_u32(plaintext.data());
    const auto type = get_u16(plaintext.data() + 4);
    if (type != kFecData && type != kFecParity || sequence >= kFecPaws) {
        return {};
    }
    const auto shard_size = static_cast<std::uint32_t>(impl.data_shard + impl.parity_shard);
    const auto group_id = sequence / shard_size;
    const auto slot = sequence % shard_size;
    if ((slot < static_cast<std::uint32_t>(impl.data_shard)) != (type == kFecData)) {
        return {};
    }
    if (!impl.have_newest_receive_group || group_id > impl.newest_receive_group) {
        impl.newest_receive_group = group_id;
        impl.have_newest_receive_group = true;
    }
    for (auto iterator = impl.receive_groups.begin(); iterator != impl.receive_groups.end();) {
        if (impl.newest_receive_group > iterator->first &&
            impl.newest_receive_group - iterator->first > kMaximumRetainedFecGroups) {
            iterator = impl.receive_groups.erase(iterator);
        } else {
            ++iterator;
        }
    }
    auto &group = impl.receive_groups[group_id];
    if (group.contains(slot)) {
        return {};
    }
    group.emplace(slot,
                  std::vector<std::uint8_t>(plaintext.begin() + kFecHeaderSize, plaintext.end()));

    std::vector<std::vector<std::uint8_t>> output;
    if (type == kFecData) {
        const auto &share = group.at(slot);
        if (share.size() < 2 || get_u16(share.data()) > share.size() || get_u16(share.data()) < 2) {
            return {};
        }
        const auto size = get_u16(share.data());
        output.emplace_back(share.begin() + 2, share.begin() + size);
    }
    if (group.size() < static_cast<std::size_t>(impl.data_shard)) {
        return output;
    }

    std::size_t share_size = 0;
    for (const auto &[unused, share] : group) {
        share_size = std::max(share_size, share.size());
    }
    std::map<std::size_t, const std::uint8_t *> pointers;
    std::vector<std::vector<std::uint8_t>> padded;
    padded.reserve(group.size());
    for (const auto &[index, share] : group) {
        padded.emplace_back(share);
        padded.back().resize(share_size);
        pointers.emplace(index, padded.back().data());
    }
    std::vector<bool> present(static_cast<std::size_t>(impl.data_shard + impl.parity_shard));
    for (const auto &[index, unused] : group) {
        present[index] = true;
    }
    impl.fec->decode_shares(
        pointers, share_size, [&](std::size_t index, const std::uint8_t *data, std::size_t size) {
            if (index >= static_cast<std::size_t>(impl.data_shard) || present[index] || size < 2) {
                return;
            }
            const auto packet_size = get_u16(data);
            if (packet_size >= 2 && packet_size <= size) {
                output.emplace_back(data + 2, data + packet_size);
            }
        });
    impl.receive_groups.erase(group_id);
    return output;
}

} // namespace clash_native::transport::shadowsocks
