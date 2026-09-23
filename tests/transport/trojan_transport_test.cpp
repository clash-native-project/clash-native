#include <clash_native/core/error.hpp>
#include <clash_native/io/datagram_handle.hpp>
#include <clash_native/net/tcp_stream.hpp>
#include <clash_native/transport/trojan/packet_conn.hpp>

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
