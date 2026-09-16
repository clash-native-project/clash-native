#include <clash_native/dns/dns_codec.hpp>
#include <clash_native/dns/dns_server.hpp>

#include <gtest/gtest.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <semaphore>
#include <span>
#include <string_view>
#include <vector>

namespace {

void append_u16(std::vector<std::uint8_t> &bytes, std::uint16_t value) {
    bytes.push_back(static_cast<std::uint8_t>(value >> 8));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xff));
}

class TcpDnsUpstream final {
  public:
    explicit TcpDnsUpstream(boost::asio::io_context &context)
        : acceptor_(context, {boost::asio::ip::address_v4::loopback(), 0}) {}

    boost::asio::ip::tcp::endpoint endpoint() const noexcept { return acceptor_.local_endpoint(); }

    void start() { accept(); }

    void stop() {
        std::binary_semaphore completed(0);
        boost::asio::post(acceptor_.get_executor(), [this, &completed] {
            boost::system::error_code ignored;
            acceptor_.cancel(ignored);
            acceptor_.close(ignored);
            if (active_socket_) {
                active_socket_->cancel(ignored);
                active_socket_->close(ignored);
                active_socket_.reset();
            }
            completed.release();
        });
        completed.acquire();
    }

  private:
    void accept() {
        auto socket = std::make_shared<boost::asio::ip::tcp::socket>(acceptor_.get_executor());
        acceptor_.async_accept(*socket, [this, socket](const boost::system::error_code &error) {
            if (!error) {
                active_socket_ = socket;
                read_query(std::move(socket));
            }
        });
    }

    void read_query(std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
        auto length = std::make_shared<std::array<std::uint8_t, 2>>();
        boost::asio::async_read(
            *socket, boost::asio::buffer(*length),
            [this, socket, length](const boost::system::error_code &error, std::size_t) {
                if (error) {
                    return;
                }
                const auto size = static_cast<std::size_t>((*length)[0] << 8 | (*length)[1]);
                auto payload = std::make_shared<std::vector<std::uint8_t>>(size);
                boost::asio::async_read(
                    *socket, boost::asio::buffer(*payload),
                    [this, socket, payload](const boost::system::error_code &read_error,
                                            std::size_t) {
                        if (read_error) {
                            return;
                        }
                        const auto query =
                            clash_native::dns::DnsMessageCodec::decode_query(*payload);
                        if (!query) {
                            return;
                        }
                        clash_native::dns::DnsAnswer answer;
                        answer.question = query.value().question;
                        answer.addresses.push_back(boost::asio::ip::make_address("198.51.100.8"));
                        answer.ttl_seconds = 10;
                        const auto encoded = clash_native::dns::DnsMessageCodec::encode_response(
                            query.value(), answer);
                        if (!encoded || encoded.value().size() > 0xffff) {
                            return;
                        }
                        auto frame = std::make_shared<std::vector<std::uint8_t>>();
                        append_u16(*frame, static_cast<std::uint16_t>(encoded.value().size()));
                        frame->insert(frame->end(), encoded.value().begin(), encoded.value().end());
                        boost::asio::async_write(
                            *socket, boost::asio::buffer(*frame),
                            [this, socket, frame](const boost::system::error_code &error,
                                                  std::size_t) {
                                if (!error) {
                                    read_query(socket);
                                }
                            });
                    });
            });
    }

    boost::asio::ip::tcp::acceptor acceptor_;
    std::shared_ptr<boost::asio::ip::tcp::socket> active_socket_;
};

class UdpDnsUpstream final {
  public:
    explicit UdpDnsUpstream(boost::asio::io_context &context)
        : socket_(context, {boost::asio::ip::address_v4::loopback(), 0}) {}

    boost::asio::ip::udp::endpoint endpoint() const noexcept { return socket_.local_endpoint(); }

    void start() { receive_query(); }

    void stop() {
        boost::system::error_code ignored;
        socket_.cancel(ignored);
        socket_.close(ignored);
    }

  private:
    void receive_query() {
        socket_.async_receive_from(
            boost::asio::buffer(query_buffer_), sender_,
            [this](const boost::system::error_code &error, std::size_t size) {
                if (error) {
                    return;
                }
                const auto query = clash_native::dns::DnsMessageCodec::decode_packet(
                    std::span<const std::uint8_t>(query_buffer_.data(), size));
                if (!query) {
                    return;
                }
                clash_native::dns::DnsAnswer answer;
                answer.question = query.value().questions.front();
                answer.addresses.push_back(boost::asio::ip::make_address("198.51.100.9"));
                answer.ttl_seconds = 10;
                const auto response = clash_native::dns::DnsMessageCodec::encode_response(
                    {query.value().id, answer.question, query.value().recursion_desired()}, answer);
                if (!response) {
                    return;
                }
                auto payload = std::make_shared<std::vector<std::uint8_t>>(response.value());
                socket_.async_send_to(boost::asio::buffer(*payload), sender_,
                                      [payload](const boost::system::error_code &, std::size_t) {});
            });
    }

    boost::asio::ip::udp::socket socket_;
    boost::asio::ip::udp::endpoint sender_;
    std::array<std::uint8_t, 65535> query_buffer_{};
};

} // namespace

TEST(DnsServerTest, ForwardsTcpQueriesToResolverService) {
    clash_native::runtime::AsioRuntime runtime;
    TcpDnsUpstream upstream(runtime.context());
    upstream.start();
    clash_native::dns::ResolverService resolver(
        runtime, {boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 1),
                  std::chrono::milliseconds(500), upstream.endpoint(), true});
    clash_native::dns::DnsServer server(runtime, resolver);
    ASSERT_TRUE(server.start());
    runtime.start();

    boost::asio::ip::tcp::socket client(runtime.context());
    boost::system::error_code error;
    client.connect(server.tcp_endpoint(), error);
    ASSERT_FALSE(error) << error.message();

    const clash_native::dns::DnsQuestion question{"local.example",
                                                  clash_native::dns::DnsRecordType::a, 1};
    const auto query = clash_native::dns::DnsMessageCodec::encode_query(question, 0x9876);
    ASSERT_TRUE(query);
    std::vector<std::uint8_t> frame;
    append_u16(frame, static_cast<std::uint16_t>(query.value().size()));
    frame.insert(frame.end(), query.value().begin(), query.value().end());
    boost::asio::write(client, boost::asio::buffer(frame), error);
    ASSERT_FALSE(error) << error.message();

    std::array<std::uint8_t, 2> length{};
    boost::asio::read(client, boost::asio::buffer(length), error);
    ASSERT_FALSE(error) << error.message();
    const auto response_size = static_cast<std::size_t>(length[0] << 8 | length[1]);
    std::vector<std::uint8_t> response(response_size);
    boost::asio::read(client, boost::asio::buffer(response), error);
    ASSERT_FALSE(error) << error.message();
    const auto decoded = clash_native::dns::DnsMessageCodec::decode_response(response, 0x9876);
    ASSERT_TRUE(decoded);
    ASSERT_EQ(decoded.value().addresses.size(), 1U);
    EXPECT_EQ(decoded.value().addresses.front().to_string(), "198.51.100.8");

    const auto second_query = clash_native::dns::DnsMessageCodec::encode_query(
        {"second.local.example", clash_native::dns::DnsRecordType::a, 1}, 0x9877);
    ASSERT_TRUE(second_query);
    frame.clear();
    append_u16(frame, static_cast<std::uint16_t>(second_query.value().size()));
    frame.insert(frame.end(), second_query.value().begin(), second_query.value().end());
    boost::asio::write(client, boost::asio::buffer(frame), error);
    ASSERT_FALSE(error) << error.message();
    boost::asio::read(client, boost::asio::buffer(length), error);
    ASSERT_FALSE(error) << error.message();
    const auto second_response_size = static_cast<std::size_t>(length[0] << 8 | length[1]);
    response.resize(second_response_size);
    boost::asio::read(client, boost::asio::buffer(response), error);
    ASSERT_FALSE(error) << error.message();
    const auto second_decoded =
        clash_native::dns::DnsMessageCodec::decode_response(response, 0x9877);
    ASSERT_TRUE(second_decoded);
    ASSERT_EQ(second_decoded.value().addresses.size(), 1U);
    EXPECT_EQ(second_decoded.value().addresses.front().to_string(), "198.51.100.8");

    client.close(error);
    ASSERT_FALSE(error) << error.message();
    server.stop();
    upstream.stop();
    runtime.stop();
}

TEST(DnsServerTest, ForwardsUdpQueriesToResolverService) {
    clash_native::runtime::AsioRuntime runtime;
    UdpDnsUpstream upstream(runtime.context());
    upstream.start();
    clash_native::dns::ResolverService resolver(
        runtime, {upstream.endpoint(), std::chrono::milliseconds(500)});
    clash_native::dns::DnsServer server(runtime, resolver);
    ASSERT_TRUE(server.start());
    runtime.start();

    boost::asio::ip::udp::socket client(runtime.context());
    boost::system::error_code error;
    client.open(boost::asio::ip::udp::v4(), error);
    ASSERT_FALSE(error) << error.message();
    client.bind({boost::asio::ip::address_v4::loopback(), 0}, error);
    ASSERT_FALSE(error) << error.message();

    const clash_native::dns::DnsQuestion question{"udp.local.example",
                                                  clash_native::dns::DnsRecordType::a, 1};
    const auto query = clash_native::dns::DnsMessageCodec::encode_query(question, 0x2468);
    ASSERT_TRUE(query);
    client.send_to(boost::asio::buffer(query.value()), server.udp_endpoint(), 0, error);
    ASSERT_FALSE(error) << error.message();

    std::array<std::uint8_t, 65535> response{};
    boost::asio::ip::udp::endpoint sender;
    const auto size = client.receive_from(boost::asio::buffer(response), sender, 0, error);
    ASSERT_FALSE(error) << error.message();
    const auto decoded = clash_native::dns::DnsMessageCodec::decode_response(
        std::span<const std::uint8_t>(response.data(), size), 0x2468);
    ASSERT_TRUE(decoded);
    ASSERT_EQ(decoded.value().addresses.size(), 1U);
    EXPECT_EQ(decoded.value().addresses.front().to_string(), "198.51.100.9");

    client.close(error);
    ASSERT_FALSE(error) << error.message();
    server.stop();
    upstream.stop();
    runtime.stop();
}

TEST(DnsServerTest, SynthesizesFakeIpForFilteredAddressQueries) {
    clash_native::runtime::AsioRuntime runtime;
    clash_native::dns::ResolverService resolver(
        runtime, {boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 1),
                  std::chrono::milliseconds(500)});
    clash_native::dns::DnsServer server(runtime, resolver);
    auto fake_ips = std::make_shared<clash_native::dns::FakeIpStore>(
        boost::asio::ip::make_address_v4("198.18.0.0"), 24, 16);
    server.set_fake_ip_store(fake_ips,
                             [](std::string_view name) { return name == "fake.example"; });
    ASSERT_TRUE(server.start());
    runtime.start();

    boost::asio::ip::tcp::socket client(runtime.context());
    boost::system::error_code error;
    client.connect(server.tcp_endpoint(), error);
    ASSERT_FALSE(error) << error.message();

    const clash_native::dns::DnsQuestion question{"fake.example",
                                                  clash_native::dns::DnsRecordType::a, 1};
    const auto query = clash_native::dns::DnsMessageCodec::encode_query(question, 0x1234);
    ASSERT_TRUE(query);
    std::vector<std::uint8_t> frame;
    append_u16(frame, static_cast<std::uint16_t>(query.value().size()));
    frame.insert(frame.end(), query.value().begin(), query.value().end());
    boost::asio::write(client, boost::asio::buffer(frame), error);
    ASSERT_FALSE(error) << error.message();

    std::array<std::uint8_t, 2> length{};
    boost::asio::read(client, boost::asio::buffer(length), error);
    ASSERT_FALSE(error) << error.message();
    const auto response_size = static_cast<std::size_t>(length[0] << 8 | length[1]);
    std::vector<std::uint8_t> response(response_size);
    boost::asio::read(client, boost::asio::buffer(response), error);
    ASSERT_FALSE(error) << error.message();
    const auto packet = clash_native::dns::DnsMessageCodec::decode_packet(response, 0x1234);
    ASSERT_TRUE(packet);
    ASSERT_EQ(packet.value().answers.size(), 1U);
    EXPECT_EQ(packet.value().answers.front().type,
              static_cast<std::uint16_t>(clash_native::dns::DnsRecordType::a));
    EXPECT_EQ(packet.value().answers.front().rdata.size(), 4U);
    const auto decoded = clash_native::dns::DnsMessageCodec::decode_response(response, 0x1234);
    ASSERT_TRUE(decoded);
    ASSERT_EQ(decoded.value().addresses.size(), 1U);
    EXPECT_EQ(decoded.value().addresses.front().to_string(), "198.18.0.1");

    boost::system::error_code ignored;
    client.close(ignored);
    server.stop();
    runtime.stop();
}

TEST(DnsServerTest, StopsActiveTcpConnectionsDuringShutdown) {
    clash_native::runtime::AsioRuntime runtime;
    clash_native::dns::ResolverService resolver(
        runtime, {boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 1),
                  std::chrono::milliseconds(500)});
    clash_native::dns::DnsServer server(runtime, resolver);
    ASSERT_TRUE(server.start());
    runtime.start();

    boost::asio::ip::tcp::socket client(runtime.context());
    boost::system::error_code error;
    client.connect(server.tcp_endpoint(), error);
    ASSERT_FALSE(error) << error.message();

    server.stop();
    runtime.stop();
    client.close(error);
    ASSERT_FALSE(error) << error.message();
}
