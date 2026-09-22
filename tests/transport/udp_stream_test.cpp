#include <clash_native/net/udp_stream.hpp>
#include <clash_native/runtime/asio_runtime.hpp>

#include <gtest/gtest.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/address.hpp>

#include <array>
#include <chrono>
#include <future>
#include <string>
#include <utility>

namespace {

using UdpEndpoint = boost::asio::ip::udp::endpoint;

struct ReceivedDatagram {
    boost::system::error_code error;
    std::size_t size = 0;
    clash_native::core::DatagramAddress sender;
};

boost::asio::ip::address_v4 udp_test_address(boost::asio::io_context &context) {
    boost::asio::ip::udp::socket probe(context);
    boost::system::error_code error;
    probe.open(boost::asio::ip::udp::v4(), error);
    if (!error) {
        probe.connect({boost::asio::ip::make_address_v4("192.0.2.1"), 9}, error);
        if (!error) {
            const auto local = probe.local_endpoint(error).address();
            if (!error && local.is_v4() && !local.is_loopback() && !local.is_unspecified()) {
                return local.to_v4();
            }
        }
    }
    return boost::asio::ip::address_v4::loopback();
}

} // namespace

TEST(UdpStreamTest, SendsAndReceivesDatagramsWithPeerEndpoints) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    const auto test_address = udp_test_address(runtime.context());
    clash_native::net::UdpStream stream(runtime.context().get_executor());
    boost::system::error_code error;
    stream.open(boost::asio::ip::udp::v4(), error);
    ASSERT_FALSE(error);
    stream.bind({test_address, 0}, error);
    ASSERT_FALSE(error);

    boost::asio::ip::udp::socket peer(runtime.context(), {test_address, 0});
    const auto stream_endpoint = stream.local_endpoint(error);
    ASSERT_FALSE(error);

    runtime.start();

    std::array<char, 32> incoming_buffer{};
    auto incoming = std::make_shared<std::promise<ReceivedDatagram>>();
    auto incoming_future = incoming->get_future();
    stream.async_receive_from(boost::asio::buffer(incoming_buffer),
                              [incoming](const auto &receive_error, std::size_t size,
                                         clash_native::core::DatagramAddress sender) {
                                  incoming->set_value({receive_error, size, std::move(sender)});
                              });

    const std::string query = "dns-query";
    auto query_sent = std::make_shared<std::promise<boost::system::error_code>>();
    auto query_sent_future = query_sent->get_future();
    peer.async_send_to(
        boost::asio::buffer(query), stream_endpoint,
        [query_sent](const auto &send_error, std::size_t) { query_sent->set_value(send_error); });

    ASSERT_EQ(query_sent_future.wait_for(std::chrono::seconds(1)), std::future_status::ready);
    EXPECT_FALSE(query_sent_future.get());
    ASSERT_EQ(incoming_future.wait_for(std::chrono::seconds(1)), std::future_status::ready);
    const auto received = incoming_future.get();
    EXPECT_FALSE(received.error);
    EXPECT_EQ(received.size, query.size());
    ASSERT_TRUE(received.sender.is_address());
    EXPECT_EQ(received.sender.address(), peer.local_endpoint().address());
    EXPECT_EQ(received.sender.port(), peer.local_endpoint().port());
    EXPECT_EQ(std::string(incoming_buffer.data(), received.size), query);

    std::array<char, 32> response_buffer{};
    auto response_received = std::make_shared<std::promise<ReceivedDatagram>>();
    auto response_future = response_received->get_future();
    auto response_sender = std::make_shared<UdpEndpoint>();
    peer.async_receive_from(
        boost::asio::buffer(response_buffer), *response_sender,
        [response_received, response_sender](const auto &receive_error, std::size_t size) {
            response_received->set_value(
                {receive_error, size,
                 clash_native::core::DatagramAddress::from_endpoint(*response_sender)});
        });

    const std::string response = "dns-response";
    auto response_sent = std::make_shared<std::promise<boost::system::error_code>>();
    auto response_sent_future = response_sent->get_future();
    stream.async_send_to(boost::asio::buffer(response), received.sender,
                         [response_sent](const auto &send_error, std::size_t) {
                             response_sent->set_value(send_error);
                         });

    ASSERT_EQ(response_sent_future.wait_for(std::chrono::seconds(1)), std::future_status::ready);
    EXPECT_FALSE(response_sent_future.get());
    ASSERT_EQ(response_future.wait_for(std::chrono::seconds(1)), std::future_status::ready);
    const auto response_result = response_future.get();
    EXPECT_FALSE(response_result.error);
    EXPECT_EQ(response_result.size, response.size());
    ASSERT_TRUE(response_result.sender.is_address());
    EXPECT_EQ(response_result.sender.address(), stream_endpoint.address());
    EXPECT_EQ(response_result.sender.port(), stream_endpoint.port());
    EXPECT_EQ(std::string(response_buffer.data(), response_result.size), response);

    stream.close();
    boost::system::error_code ignored;
    peer.close(ignored);
    runtime.stop();
}
