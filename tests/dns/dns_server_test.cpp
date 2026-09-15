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
#include <span>
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

  private:
    void accept() {
        auto socket = std::make_shared<boost::asio::ip::tcp::socket>(acceptor_.get_executor());
        acceptor_.async_accept(*socket, [this, socket](const boost::system::error_code &error) {
            if (!error) {
                read_query(std::move(socket));
            }
        });
    }

    void read_query(std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
        auto length = std::make_shared<std::array<std::uint8_t, 2>>();
        boost::asio::async_read(
            *socket, boost::asio::buffer(*length),
            [socket, length](const boost::system::error_code &error, std::size_t) {
                if (error) {
                    return;
                }
                const auto size = static_cast<std::size_t>((*length)[0] << 8 | (*length)[1]);
                auto payload = std::make_shared<std::vector<std::uint8_t>>(size);
                boost::asio::async_read(
                    *socket, boost::asio::buffer(*payload),
                    [socket, payload](const boost::system::error_code &read_error, std::size_t) {
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
                            [socket, frame](const boost::system::error_code &, std::size_t) {});
                    });
            });
    }

    boost::asio::ip::tcp::acceptor acceptor_;
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

    server.stop();
    runtime.stop();
}
