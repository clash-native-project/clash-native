#include <clash_native/transport/shadowsocks/crypto.hpp>
#include <clash_native/transport/shadowsocks/legacy_packet.hpp>
#include <clash_native/transport/shadowsocks/ss2022_packet.hpp>
#include <clash_native/core/base64.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace {

using clash_native::transport::shadowsocks::LegacyStreamCipher;

TEST(ShadowsocksTransportTest, RecognizesClassicCipherFamilies) {
    constexpr std::array methods{
        "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb", "aes-192-cfb",
        "aes-256-cfb", "rc4-md5",     "chacha20-ietf", "aes-128-gcm", "aes-192-gcm",
        "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "chacha20",
        "xchacha20", "chacha8-ietf-poly1305", "xchacha8-ietf-poly1305", "aes-128-ccm",
        "aes-192-ccm", "aes-256-ccm"};
    for (const auto method : methods) {
        EXPECT_TRUE(clash_native::transport::shadowsocks::cipher_method(method)) << method;
    }
}

TEST(ShadowsocksTransportTest, RecognizesAndRoundTripsShadowsocks2022) {
    constexpr std::array methods{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
                                 "2022-blake3-chacha20-poly1305"};
    const std::vector<std::uint8_t> plaintext{'s', 's', '2', '0', '2', '2'};
    for (const auto method : methods) {
        const auto spec = clash_native::transport::shadowsocks::cipher_method(method);
        ASSERT_TRUE(spec) << method;
        std::vector<std::uint8_t> psk(spec.value().key_size, 0x31);
        const auto password = clash_native::core::base64_encode(
            std::string(reinterpret_cast<const char *>(psk.data()), psk.size()));
        std::vector<std::uint8_t> salt(spec.value().salt_size, 0x52);
        const auto key = clash_native::transport::shadowsocks::
            derive_shadowsocks_2022_session_key(method, password, salt);
        ASSERT_TRUE(key) << method;
        std::vector<std::uint8_t> nonce(spec.value().nonce_size, 0x17);
        const auto ciphertext = clash_native::transport::shadowsocks::aead_encrypt(
            method, key.value(), nonce, plaintext);
        ASSERT_TRUE(ciphertext) << method;
        const auto recovered = clash_native::transport::shadowsocks::aead_decrypt(
            method, key.value(), nonce, ciphertext.value());
        ASSERT_TRUE(recovered) << method;
        EXPECT_EQ(recovered.value(), plaintext) << method;
    }
}

TEST(ShadowsocksTransportTest, EncryptsAndDecryptsAeadPayloads) {
    constexpr std::array methods{"aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
                                 "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
                                 "chacha8-ietf-poly1305", "xchacha8-ietf-poly1305", "aes-128-ccm",
                                 "aes-192-ccm", "aes-256-ccm"};
    const std::vector<std::uint8_t> plaintext{'s', 'h', 'a', 'd', 'o', 'w', 's', 'o', 'c', 'k', 's'};
    for (const auto method : methods) {
        const auto spec = clash_native::transport::shadowsocks::cipher_method(method);
        ASSERT_TRUE(spec) << method;
        std::vector<std::uint8_t> salt(spec.value().salt_size, 0x23);
        std::vector<std::uint8_t> nonce(spec.value().nonce_size, 0x42);
        const auto key = clash_native::transport::shadowsocks::derive_aead_subkey(
            method, "test-password", salt);
        ASSERT_TRUE(key) << method;
        const auto ciphertext = clash_native::transport::shadowsocks::aead_encrypt(
            method, key.value(), nonce, plaintext);
        ASSERT_TRUE(ciphertext) << method;
        const auto recovered = clash_native::transport::shadowsocks::aead_decrypt(
            method, key.value(), nonce, ciphertext.value());
        ASSERT_TRUE(recovered) << method;
        EXPECT_EQ(recovered.value(), plaintext) << method;
    }
}

TEST(ShadowsocksTransportTest, EncryptsShadowsocks2022DatagramRequests) {
    const std::vector<std::uint8_t> destination{1, 127, 0, 0, 1, 0x01, 0xbb};
    const std::vector<std::uint8_t> payload{'u', 'd', 'p'};
    constexpr std::array methods{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
                                 "2022-blake3-chacha20-poly1305"};
    for (const auto method : methods) {
        const auto spec = clash_native::transport::shadowsocks::cipher_method(method);
        ASSERT_TRUE(spec) << method;
        std::vector<std::uint8_t> psk(spec.value().key_size, 0x41);
        const auto password = clash_native::core::base64_encode(
            std::string(reinterpret_cast<const char *>(psk.data()), psk.size()));
        clash_native::transport::shadowsocks::Shadowsocks2022DatagramCodec codec(method, password);
        const auto wire = codec.encrypt(destination, payload);
        ASSERT_TRUE(wire) << method;
        EXPECT_GT(wire.value().size(), destination.size() + payload.size()) << method;
        EXPECT_LE(wire.value().size(), 1500U) << method;
        EXPECT_GT(codec.max_datagram_size(1500, 1 + 255 + 2), payload.size()) << method;
    }
}

TEST(ShadowsocksTransportTest, ReservesDestinationSpaceForShadowsocks2022Datagrams) {
    constexpr std::size_t wire_limit = 1500;
    constexpr std::size_t maximum_proxy_address = 1 + 1 + 255 + 2;
    const std::vector<std::uint8_t> psk(32, 0x31);
    const auto password = clash_native::core::base64_encode(
        std::string(reinterpret_cast<const char *>(psk.data()), psk.size()));
    clash_native::transport::shadowsocks::Shadowsocks2022DatagramCodec codec(
        "2022-blake3-chacha20-poly1305", password);

    const auto advertised = codec.max_datagram_size(wire_limit, maximum_proxy_address);
    const auto wire_without_destination = codec.max_datagram_size(wire_limit, 0);
    ASSERT_GT(wire_without_destination, advertised);
    EXPECT_EQ(wire_without_destination - advertised, maximum_proxy_address);
}

TEST(ShadowsocksTransportTest, RoundTripsXchacha20Poly1305PacketPrimitive) {
    const std::vector<std::uint8_t> key(32, 0x2a);
    std::vector<std::uint8_t> nonce(24);
    for (std::size_t index = 0; index < nonce.size(); ++index) {
        nonce[index] = static_cast<std::uint8_t>(index * 13U + 5U);
    }
    const std::vector<std::uint8_t> plaintext{'x', 'c', 'h', 'a', 'c', 'h', 'a'};
    const auto ciphertext = clash_native::transport::shadowsocks::xchacha20_poly1305_encrypt(
        key, nonce, plaintext);
    ASSERT_TRUE(ciphertext);
    const auto recovered = clash_native::transport::shadowsocks::xchacha20_poly1305_decrypt(
        key, nonce, ciphertext.value());
    ASSERT_TRUE(recovered);
    EXPECT_EQ(recovered.value(), plaintext);
}

TEST(ShadowsocksTransportTest, MatchesMihomoXchacha8Construction) {
    const std::vector<std::uint8_t> key(32, 0x2a);
    std::vector<std::uint8_t> nonce(24);
    for (std::size_t index = 0; index < nonce.size(); ++index) {
        nonce[index] = static_cast<std::uint8_t>(index * 13U + 5U);
    }
    for (const auto size : {0U, 1U, 8U, 31U, 64U, 4096U, 16384U}) {
        std::vector<std::uint8_t> plaintext(size);
        for (std::size_t index = 0; index < plaintext.size(); ++index) {
            plaintext[index] = static_cast<std::uint8_t>(index * 17U + 3U);
        }
        const auto xchacha8 = clash_native::transport::shadowsocks::aead_encrypt(
            "xchacha8-ietf-poly1305", key, nonce, plaintext);
        ASSERT_TRUE(xchacha8) << "size=" << size;
        const auto xchacha20 = clash_native::transport::shadowsocks::xchacha20_poly1305_encrypt(
            key, nonce, plaintext);
        ASSERT_TRUE(xchacha20) << "size=" << size;
        EXPECT_NE(xchacha8.value(), xchacha20.value()) << "size=" << size;
        const auto recovered = clash_native::transport::shadowsocks::aead_decrypt(
            "xchacha8-ietf-poly1305", key, nonce, xchacha8.value());
        ASSERT_TRUE(recovered) << "size=" << size;
        EXPECT_EQ(recovered.value(), plaintext) << "size=" << size;
        clash_native::transport::shadowsocks::increment_nonce(nonce);
    }

    const std::vector<std::uint8_t> vector_plaintext = [] {
        std::vector<std::uint8_t> result(31);
        for (std::size_t index = 0; index < result.size(); ++index) {
            result[index] = static_cast<std::uint8_t>(index * 17U + 3U);
        }
        return result;
    }();
    const auto vector_ciphertext = clash_native::transport::shadowsocks::aead_encrypt(
        "xchacha8-ietf-poly1305", key,
        std::vector<std::uint8_t>{5, 18, 31, 44, 57, 70, 83, 96, 109, 122, 135, 148, 161, 174,
                                  187, 200, 213, 226, 239, 252, 9, 22, 35, 48},
        vector_plaintext);
    ASSERT_TRUE(vector_ciphertext);
    const std::vector<std::uint8_t> expected{
        0xc7, 0x99, 0x06, 0x5f, 0x78, 0x17, 0x60, 0x1d, 0xc5, 0x41, 0x4d,
        0x1e, 0x27, 0x63, 0xad, 0x4b, 0x6c, 0xd5, 0x2a, 0xde, 0x92, 0x7d,
        0x10, 0xc6, 0xb4, 0x40, 0xd5, 0xc7, 0x1e, 0x77, 0x2a, 0x76, 0x33,
        0xff, 0xf3, 0x9c, 0xbb, 0xa0, 0x8c, 0xd0, 0xb2, 0xcd, 0xad, 0x62,
        0x75, 0xa7, 0xf1};
    EXPECT_EQ(vector_ciphertext.value(), expected);
}

TEST(ShadowsocksTransportTest, EncryptsAndDecryptsLegacyStreams) {
    constexpr std::array methods{"aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb",
                                 "aes-192-cfb", "aes-256-cfb", "rc4-md5", "chacha20",
                                 "chacha20-ietf", "xchacha20"};
    const std::vector<std::uint8_t> source(257, 0x7a);
    for (const auto method : methods) {
        const auto spec = clash_native::transport::shadowsocks::cipher_method(method);
        ASSERT_TRUE(spec) << method;
        std::vector<std::uint8_t> iv(spec.value().iv_size, 0x19);
        const auto key = clash_native::transport::shadowsocks::derive_legacy_key(
            method, "test-password", iv);
        ASSERT_TRUE(key) << method;
        auto encrypted = source;
        auto encryptor = LegacyStreamCipher::create(method, key.value(), iv, true);
        ASSERT_TRUE(encryptor) << method;
        ASSERT_TRUE(encryptor.value().update(encrypted)) << method;
        auto decryptor = LegacyStreamCipher::create(method, key.value(), iv, false);
        ASSERT_TRUE(decryptor) << method;
        ASSERT_TRUE(decryptor.value().update(encrypted)) << method;
        EXPECT_EQ(encrypted, source) << method;
    }
}

TEST(ShadowsocksTransportTest, EncryptsAndDecryptsLegacyDatagrams) {
    constexpr std::array methods{"aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb",
                                 "aes-192-cfb", "aes-256-cfb", "rc4-md5", "chacha20",
                                 "chacha20-ietf", "xchacha20"};
    const std::vector<std::uint8_t> source{'d', 'a', 't', 'a', 'g', 'r', 'a', 'm'};
    for (const auto method : methods) {
        const auto wire = clash_native::transport::shadowsocks::encrypt_legacy_datagram(
            method, "test-password", source);
        ASSERT_TRUE(wire) << method;
        const auto recovered = clash_native::transport::shadowsocks::decrypt_legacy_datagram(
            method, "test-password", wire.value());
        ASSERT_TRUE(recovered) << method;
        EXPECT_EQ(recovered.value(), source) << method;
    }
}

} // namespace
