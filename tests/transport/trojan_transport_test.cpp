#include <clash_native/core/error.hpp>
#include <clash_native/core/outbound.hpp>
#include <clash_native/io/datagram_handle.hpp>
#include <clash_native/net/tcp_stream.hpp>
#include <clash_native/outbound/trojan_outbound.hpp>
#include <clash_native/runtime/asio_runtime.hpp>
#include <clash_native/transport/proxy/crypto.hpp>
#include <clash_native/transport/trojan/packet_conn.hpp>
#include <clash_native/transport/trojan/ss_stream.hpp>

#include <gtest/gtest.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/read.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <optional>
#include <stdexec/execution.hpp>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

template <stdexec::sender S> auto sync_get(S &&sender) {
    auto result = stdexec::sync_wait(std::forward<S>(sender));
    if (!result) {
        throw std::runtime_error("sync_get: sender completed with set_stopped");
    }
    return std::get<0>(std::move(*result));
}

// Loopback TCP pair on a private context: server side wrapped as the
// TrojanPacketConn under test, peer side driven with blocking calls.
struct Loopback {
    boost::asio::io_context context;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{
        context.get_executor()};
    boost::asio::ip::tcp::socket peer{context};
    std::unique_ptr<clash_native::io::DatagramHandle> packets;

    Loopback() {
        using boost::asio::ip::tcp;
        tcp::acceptor acceptor(context, tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
        tcp::socket server(context);
        std::promise<void> accepted;
        auto accepted_future = accepted.get_future();
        acceptor.async_accept(server, [&](const boost::system::error_code &error) {
            EXPECT_FALSE(error);
            accepted.set_value();
        });
        worker_ = std::thread([this] { context.run(); });
        peer.connect(tcp::endpoint(boost::asio::ip::address_v4::loopback(),
                                   acceptor.local_endpoint().port()));
        if (accepted_future.wait_for(std::chrono::seconds(5)) != std::future_status::ready) {
            throw std::runtime_error("loopback accept timed out");
        }
        auto stream = std::make_unique<clash_native::net::TcpStream>(std::move(server));
        auto handle = clash_native::transport::trojan::make_trojan_packet_conn(std::move(stream));
        if (!handle) {
            throw std::runtime_error("make_trojan_packet_conn failed");
        }
        packets = std::move(handle.value());
    }

    ~Loopback() {
        packets.reset();
        context.stop();
        if (worker_.joinable()) {
            worker_.join();
        }
    }

  private:
    std::thread worker_;
};

std::vector<std::uint8_t> read_exactly(boost::asio::ip::tcp::socket &peer, std::size_t size) {
    std::vector<std::uint8_t> buffer(size);
    boost::asio::read(peer, boost::asio::buffer(buffer));
    return buffer;
}

} // namespace

TEST(TrojanPacketConnTest, SendEncodesSocksAddrLengthCrlfPayload) {
    Loopback loop;
    const auto destination = clash_native::io::DatagramAddress::domain("example.com", 80);
    const std::string payload = "hello";
    EXPECT_EQ(sync_get(loop.packets->async_send_to(boost::asio::buffer(payload), destination)),
              payload.size());

    // 0x03 len("example.com") "example.com" port 80
    std::vector<std::uint8_t> expected = {0x03, 11,  'e', 'x', 'a', 'm',  'p', 'l',
                                          'e',  '.', 'c', 'o', 'm', 0x00, 0x50};
    const auto header = read_exactly(loop.peer, expected.size());
    EXPECT_EQ(header, expected);
    const auto framing = read_exactly(loop.peer, 4);
    EXPECT_EQ(framing, std::vector<std::uint8_t>({0x00, 0x05, '\r', '\n'}));
    const auto body = read_exactly(loop.peer, payload.size());
    EXPECT_EQ(body, std::vector<std::uint8_t>(payload.begin(), payload.end()));
}

TEST(TrojanPacketConnTest, RoundTripsIpv4PacketWithSourceAddress) {
    Loopback loop;
    const auto destination =
        clash_native::io::DatagramAddress::address(boost::asio::ip::make_address("192.0.2.7"), 53);
    const std::string payload = "dns-ish";
    EXPECT_EQ(sync_get(loop.packets->async_send_to(boost::asio::buffer(payload), destination)),
              payload.size());

    // Echo the exact wire bytes back through the peer.
    std::vector<std::uint8_t> wire(1 + 4 + 2 + 2 + 2 + payload.size());
    boost::asio::read(loop.peer, boost::asio::buffer(wire));
    EXPECT_EQ(loop.peer.send(boost::asio::buffer(wire)), wire.size());

    std::array<std::uint8_t, 65507> receive{};
    const auto packet = sync_get(loop.packets->async_receive_from(boost::asio::buffer(receive)));
    EXPECT_EQ(packet.size, payload.size());
    EXPECT_EQ(std::string(reinterpret_cast<const char *>(receive.data()), packet.size), payload);
    EXPECT_TRUE(packet.address.is_address());
    EXPECT_EQ(packet.address.address().to_string(), "192.0.2.7");
    EXPECT_EQ(packet.address.port(), 53);
}

TEST(TrojanPacketConnTest, SplitsLargePayloadInto8192ByteFrames) {
    Loopback loop;
    const auto destination = clash_native::io::DatagramAddress::domain("example.com", 443);
    const std::string payload(9000, 'x');
    EXPECT_EQ(sync_get(loop.packets->async_send_to(boost::asio::buffer(payload), destination)),
              payload.size());

    // First frame carries 8192 payload bytes, the second the remainder.
    const std::size_t header_size = 1 + 1 + 11 + 2;
    const auto first = read_exactly(loop.peer, header_size + 4 + 8192);
    EXPECT_EQ(first[header_size], 0x20);
    EXPECT_EQ(first[header_size + 1], 0x00);
    const auto second = read_exactly(loop.peer, header_size + 4 + 808);
    EXPECT_EQ(second[header_size], 0x03);
    EXPECT_EQ(second[header_size + 1], 0x28);
}

TEST(TrojanPacketConnTest, RejectsBadCrlfAndOversizeLength) {
    {
        Loopback loop;
        // Valid domain header, length 1, but ';' instead of CRLF.
        const std::vector<std::uint8_t> bad = {0x03, 0x01, 'a', 0x00, 0x50,
                                               0x00, 0x01, ';', ';',  'z'};
        EXPECT_EQ(loop.peer.send(boost::asio::buffer(bad)), bad.size());
        std::array<std::uint8_t, 1024> receive{};
        try {
            sync_get(loop.packets->async_receive_from(boost::asio::buffer(receive)));
            FAIL() << "expected protocol error for bad CRLF";
        } catch (const clash_native::core::Error &failure) {
            EXPECT_EQ(failure.code, clash_native::core::ErrorCode::transport_io);
        }
    }
    {
        Loopback loop;
        // Length prefix above the 8192-byte packet ceiling.
        const std::vector<std::uint8_t> bad = {0x01, 127,  0,    0,    1,   0x00,
                                               0x50, 0x20, 0x01, '\r', '\n'};
        EXPECT_EQ(loop.peer.send(boost::asio::buffer(bad)), bad.size());
        std::array<std::uint8_t, 65507> receive{};
        try {
            sync_get(loop.packets->async_receive_from(boost::asio::buffer(receive)));
            FAIL() << "expected protocol error for oversize length";
        } catch (const clash_native::core::Error &failure) {
            EXPECT_EQ(failure.code, clash_native::core::ErrorCode::transport_io);
        }
    }
}

TEST(TrojanPacketConnTest, ReportsTruncationAsMessageSize) {
    Loopback loop;
    const std::vector<std::uint8_t> wire = {0x01, 127,  0,    0,   1,   0x00, 0x50, 0x00,
                                            0x04, '\r', '\n', 'a', 'b', 'c',  'd'};
    EXPECT_EQ(loop.peer.send(boost::asio::buffer(wire)), wire.size());
    // Four payload bytes do not fit a two-byte buffer.
    std::array<std::uint8_t, 2> receive{};
    try {
        sync_get(loop.packets->async_receive_from(boost::asio::buffer(receive)));
        FAIL() << "expected message_size error for truncation";
    } catch (const clash_native::core::Error &failure) {
        EXPECT_EQ(failure.code, clash_native::core::ErrorCode::transport_io);
    }
}

namespace {

using clash_native::transport::proxy::aead_decrypt;
using clash_native::transport::proxy::aead_encrypt;
using clash_native::transport::proxy::derive_aead_subkey;

// Loopback TCP pair where the client end is wrapped in the Trojan ss
// stream under test; the peer side speaks raw Shadowsocks AEAD framing.
struct SsLoopback {
    boost::asio::io_context context;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{
        context.get_executor()};
    boost::asio::ip::tcp::socket peer{context};
    std::unique_ptr<clash_native::io::StreamHandle> stream;

    SsLoopback() {
        using boost::asio::ip::tcp;
        tcp::acceptor acceptor(context, tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
        tcp::socket server(context);
        std::promise<void> accepted;
        auto accepted_future = accepted.get_future();
        acceptor.async_accept(server, [&](const boost::system::error_code &error) {
            EXPECT_FALSE(error);
            accepted.set_value();
        });
        worker_ = std::thread([this] { context.run(); });
        peer.connect(tcp::endpoint(boost::asio::ip::address_v4::loopback(),
                                   acceptor.local_endpoint().port()));
        if (accepted_future.wait_for(std::chrono::seconds(5)) != std::future_status::ready) {
            throw std::runtime_error("loopback accept timed out");
        }
        auto plain = std::make_unique<clash_native::net::TcpStream>(std::move(server));
        auto handle = clash_native::transport::trojan::make_trojan_ss_stream_handle(
            std::move(plain), "AES-128-GCM", "ss-password");
        if (!handle) {
            throw std::runtime_error("make_trojan_ss_stream_handle failed");
        }
        stream = std::move(handle.value());
    }

    ~SsLoopback() {
        stream.reset();
        context.stop();
        if (worker_.joinable()) {
            worker_.join();
        }
    }

  private:
    std::thread worker_;
};

} // namespace

TEST(TrojanSsStreamTest, SealsSaltAndChunksVerifiableWithSharedPrimitives) {
    SsLoopback loop;
    const std::string payload = "trojan-ss hello";
    EXPECT_EQ(sync_get(loop.stream->async_write(boost::asio::buffer(payload))), payload.size());

    // Salt first, then one sealed length + sealed payload chunk.
    auto salt = read_exactly(loop.peer, 16);
    auto key = derive_aead_subkey("AES-128-GCM", "ss-password", salt);
    ASSERT_TRUE(key);
    std::vector<std::uint8_t> nonce(12, 0);
    auto encrypted_length = read_exactly(loop.peer, 2 + 16);
    auto length = aead_decrypt("AES-128-GCM", key.value(), nonce, encrypted_length);
    ASSERT_TRUE(length);
    ASSERT_EQ(length.value().size(), 2U);
    const std::size_t payload_size =
        (static_cast<std::size_t>(length.value()[0]) << 8) | length.value()[1];
    EXPECT_EQ(payload_size, payload.size());
    nonce[0] = 1;
    auto encrypted_payload = read_exactly(loop.peer, payload_size + 16);
    auto plaintext = aead_decrypt("AES-128-GCM", key.value(), nonce, encrypted_payload);
    ASSERT_TRUE(plaintext);
    EXPECT_EQ(std::string(plaintext.value().begin(), plaintext.value().end()), payload);
}

TEST(TrojanSsStreamTest, DecryptsPeerChunksSealedWithPeerSalt) {
    SsLoopback loop;
    // Drain the client salt + chunk; the reply direction uses the
    // peer's own salt, like a real server.
    const std::string ping = "ping";
    EXPECT_EQ(sync_get(loop.stream->async_write(boost::asio::buffer(ping))), ping.size());
    read_exactly(loop.peer, 16);
    read_exactly(loop.peer, 2 + 16 + ping.size() + 16);

    const std::vector<std::uint8_t> server_salt{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    auto key = derive_aead_subkey("AES-128-GCM", "ss-password", server_salt);
    ASSERT_TRUE(key);
    const std::string reply = "server reply";
    std::vector<std::uint8_t> nonce(12, 0);
    const std::array<std::uint8_t, 2> length{0x00, static_cast<std::uint8_t>(reply.size())};
    auto encrypted_length =
        aead_encrypt("AES-128-GCM", key.value(), nonce,
                     std::span<const std::uint8_t>(length.data(), length.size()));
    ASSERT_TRUE(encrypted_length);
    nonce[0] = 1;
    auto encrypted_payload =
        aead_encrypt("AES-128-GCM", key.value(), nonce,
                     std::span<const std::uint8_t>(
                         reinterpret_cast<const std::uint8_t *>(reply.data()), reply.size()));
    ASSERT_TRUE(encrypted_payload);
    std::vector<std::uint8_t> wire(server_salt.begin(), server_salt.end());
    wire.insert(wire.end(), encrypted_length.value().begin(), encrypted_length.value().end());
    wire.insert(wire.end(), encrypted_payload.value().begin(), encrypted_payload.value().end());
    EXPECT_EQ(loop.peer.send(boost::asio::buffer(wire)), wire.size());

    std::array<std::uint8_t, 64> receive{};
    const auto got = sync_get(loop.stream->async_read_some(boost::asio::buffer(receive)));
    ASSERT_TRUE(got);
    EXPECT_EQ(*got, reply.size());
    EXPECT_EQ(std::string(reinterpret_cast<const char *>(receive.data()), *got), reply);
}

TEST(TrojanSsStreamTest, RejectsUnsupportedMethodsAndEmptyPassword) {
    using clash_native::transport::trojan::make_trojan_ss_stream_handle;
    boost::asio::io_context context;
    auto make_plain = [&] {
        return std::make_unique<clash_native::net::TcpStream>(
            boost::asio::ip::tcp::socket(context));
    };
    EXPECT_FALSE(make_trojan_ss_stream_handle(make_plain(), "2022-BLAKE3-AES-128-GCM", "password"));
    EXPECT_FALSE(make_trojan_ss_stream_handle(make_plain(), "rc4-md5", "password"));
    EXPECT_FALSE(make_trojan_ss_stream_handle(make_plain(), "AES-128-GCM", ""));
    EXPECT_FALSE(make_trojan_ss_stream_handle(make_plain(), "not-a-method", "password"));
    EXPECT_FALSE(make_trojan_ss_stream_handle(nullptr, "AES-128-GCM", "password"));
}

TEST(TrojanOutboundConfigTest, RejectsUnknownSecurityMode) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    runtime.start();
    clash_native::outbound::TrojanOutboundConfig config;
    config.id = "test-trojan";
    config.server_host = "127.0.0.1";
    config.server_port = 1;
    config.password = "password";
    config.security_mode = "reality";
    clash_native::outbound::TrojanOutbound outbound(runtime, config);
    EXPECT_FALSE(outbound.validate());

    auto wait = stdexec::sync_wait(outbound.connect_stream(
        {clash_native::core::Destination::domain("example.com", 80), std::nullopt, nullptr}));
    ASSERT_TRUE(wait.has_value());
    const auto result = std::move(std::get<0>(*wait));
    EXPECT_FALSE(result.succeeded());
    ASSERT_TRUE(result.error);
    EXPECT_EQ(result.error->code, clash_native::core::ErrorCode::configuration);
}

TEST(TrojanOutboundConfigTest, OverlayOpenFailurePropagatesWithoutHanging) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    runtime.start();
    // Closed loopback port: TCP connect refuses before any overlay bytes.
    clash_native::outbound::TrojanOutboundConfig config;
    config.id = "test-trojan";
    config.server_host = "127.0.0.1";
    config.server_port = 1;
    config.password = "password";
    config.security_mode = "shadow-tls";
    config.shadow_tls_options.password = "overlay-password";
    clash_native::outbound::TrojanOutbound outbound(runtime, config);
    EXPECT_TRUE(outbound.validate());

    auto wait = stdexec::sync_wait(outbound.connect_stream(
        {clash_native::core::Destination::domain("example.com", 80), std::nullopt, nullptr}));
    ASSERT_TRUE(wait.has_value());
    const auto result = std::move(std::get<0>(*wait));
    EXPECT_FALSE(result.succeeded());
    ASSERT_TRUE(result.error);
    EXPECT_EQ(result.error->code, clash_native::core::ErrorCode::endpoint_connection);
}

TEST(TrojanOutboundConfigTest, GrpcDialFailurePropagatesWithoutHanging) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    runtime.start();
    clash_native::outbound::TrojanOutboundConfig config;
    config.id = "test-trojan";
    config.server_host = "127.0.0.1";
    config.server_port = 1;
    config.password = "password";
    config.network = "grpc";
    clash_native::outbound::TrojanOutbound outbound(runtime, config);
    EXPECT_TRUE(outbound.validate());

    auto wait = stdexec::sync_wait(outbound.connect_stream(
        {clash_native::core::Destination::domain("example.com", 443), std::nullopt, nullptr}));
    ASSERT_TRUE(wait.has_value());
    const auto result = std::move(std::get<0>(*wait));
    EXPECT_FALSE(result.succeeded());
    ASSERT_TRUE(result.error);
    EXPECT_EQ(result.error->code, clash_native::core::ErrorCode::endpoint_connection);
}
