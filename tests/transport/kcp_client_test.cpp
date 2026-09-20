#include <clash_native/transport/kcp_client.hpp>
#include <clash_native/transport/shadowsocks/kcptun.hpp>
#include <clash_native/transport/shadowsocks/kcptun_packet_codec.hpp>

#include <boost/asio/ip/udp.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

TEST(KcpClientTest, RejectsMissingDatagramHandle) {
    const auto result = clash_native::transport::make_kcp_client_stream(
        nullptr, boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 9000));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::configuration);
}

TEST(KcpClientTest, RejectsInvalidOptions) {
    clash_native::transport::KcpClientOptions options;
    options.conversation_id = 1;

    const auto result = clash_native::transport::make_kcp_client_stream(
        nullptr, boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 9000),
        options);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::configuration);
}

TEST(KcptunClientTest, AcceptsRawKcpSmuxProfile) {
    clash_native::transport::shadowsocks::KcptunClientOptions options;
    options.crypt = "null";
    options.data_shard = 0;
    options.parity_shard = 0;
    options.no_compression = true;
    const auto result =
        clash_native::transport::shadowsocks::validate_kcptun_client_options(options);

    EXPECT_TRUE(result);
}

TEST(KcptunClientTest, AcceptsMihomoPacketCryptMethods) {
    for (const auto crypt : {"aes", "none", "null", "tea", "xor", "aes-128", "aes-192", "blowfish",
                             "twofish", "cast5", "3des", "xtea", "salsa20", "aes-128-gcm"}) {
        clash_native::transport::shadowsocks::KcptunClientOptions options;
        options.crypt = crypt;
        options.data_shard = 0;
        options.parity_shard = 0;
        options.no_compression = true;

        const auto result =
            clash_native::transport::shadowsocks::validate_kcptun_client_options(options);

        EXPECT_TRUE(result) << crypt;
    }
}

TEST(KcptunClientTest, AcceptsFecAndCompressionProfiles) {
    clash_native::transport::shadowsocks::KcptunClientOptions options;
    options.data_shard = 10;
    options.parity_shard = 3;

    auto result = clash_native::transport::shadowsocks::validate_kcptun_client_options(options);
    ASSERT_TRUE(result);

    options.data_shard = 0;
    options.parity_shard = 0;
    options.no_compression = false;
    result = clash_native::transport::shadowsocks::validate_kcptun_client_options(options);
    EXPECT_TRUE(result);
}

TEST(KcptunPacketCodecTest, RoundTripsMihomoCryptMethods) {
    const std::array methods{"null", "none", "aes",      "aes-128",    "aes-192",
                             "tea",  "xor",  "blowfish", "twofish",    "cast5",
                             "3des", "xtea", "salsa20",  "aes-128-gcm"};
    const std::vector<std::uint8_t> packet{0x01, 0x02, 0x03, 0x04, 0x81, 0x00, 0x00,
                                           0x00, 0x10, 0x20, 0x30, 0x40, 0x50};
    for (const auto method : methods) {
        auto codec = clash_native::transport::shadowsocks::KcptunPacketCodec::create(
            "codec-test-key", method, 0, 0);
        ASSERT_TRUE(codec) << method;
        const auto encoded = codec.value()->encode(packet);
        ASSERT_EQ(encoded.size(), 1U) << method;
        const auto decoded = codec.value()->decode(encoded.front());
        ASSERT_EQ(decoded.size(), 1U) << method;
        EXPECT_EQ(decoded.front(), packet) << method;
    }
}

TEST(KcptunPacketCodecTest, RecoversOneLostFecDataShard) {
    auto codec = clash_native::transport::shadowsocks::KcptunPacketCodec::create("fec-test-key",
                                                                                 "null", 4, 2);
    ASSERT_TRUE(codec);
    std::vector<std::vector<std::uint8_t>> wire;
    std::vector<std::vector<std::uint8_t>> packets;
    for (std::uint8_t index = 0; index < 4; ++index) {
        packets.push_back({0x81, index, 0, 0, index, 0xaa, 0xbb});
        auto encoded = codec.value()->encode(packets.back());
        wire.insert(wire.end(), encoded.begin(), encoded.end());
    }
    ASSERT_EQ(wire.size(), 6U);

    std::vector<std::vector<std::uint8_t>> decoded;
    for (std::size_t index = 1; index < wire.size(); ++index) {
        auto result = codec.value()->decode(wire[index]);
        decoded.insert(decoded.end(), result.begin(), result.end());
    }
    ASSERT_EQ(decoded.size(), 4U);
    for (const auto &packet : packets) {
        EXPECT_NE(std::find(decoded.begin(), decoded.end(), packet), decoded.end());
    }
}

TEST(KcptunPacketCodecTest, RecoversEncryptedFecDataAndParityLoss) {
    auto codec = clash_native::transport::shadowsocks::KcptunPacketCodec::create("fec-aes-test-key",
                                                                                 "aes", 4, 2);
    ASSERT_TRUE(codec);
    std::vector<std::vector<std::uint8_t>> packets;
    std::vector<std::vector<std::uint8_t>> wire;
    for (std::uint8_t index = 0; index < 4; ++index) {
        packets.push_back({0x81, index, 0, 0, index, 0x10, 0x20, 0x30});
        auto encoded = codec.value()->encode(packets.back());
        wire.insert(wire.end(), encoded.begin(), encoded.end());
    }
    ASSERT_EQ(wire.size(), 6U);

    std::vector<std::vector<std::uint8_t>> decoded;
    for (std::size_t index = 0; index < wire.size(); ++index) {
        if (index == 1 || index == 5) {
            continue;
        }
        auto result = codec.value()->decode(wire[index]);
        decoded.insert(decoded.end(), result.begin(), result.end());
    }
    ASSERT_EQ(decoded.size(), packets.size());
    for (const auto &packet : packets) {
        EXPECT_NE(std::find(decoded.begin(), decoded.end(), packet), decoded.end());
    }
}
