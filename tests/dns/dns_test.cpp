#include <clash_native/dns/dns_codec.hpp>
#include <clash_native/dns/dns_policy_router.hpp>
#include <clash_native/dns/fake_ip_store.hpp>
#include <clash_native/dns/resolver_service.hpp>

#include <gtest/gtest.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

using Address = boost::asio::ip::address;

void append_u16(std::vector<std::uint8_t> &message, std::uint16_t value) {
    message.push_back(static_cast<std::uint8_t>(value >> 8));
    message.push_back(static_cast<std::uint8_t>(value & 0xff));
}

std::vector<std::uint8_t> response_for(std::span<const std::uint8_t> query, bool truncated) {
    std::vector<std::uint8_t> response(query.begin(), query.end());
    response[2] = truncated ? 0x83 : 0x81;
    response[3] = 0x80;
    response[6] = 0;
    response[7] = truncated ? 0 : 1;
    if (truncated) {
        return response;
    }

    response.insert(response.end(), {0xc0, 0x0c});
    append_u16(response, 1);
    append_u16(response, 1);
    response.insert(response.end(), {0, 0, 0, 60, 0, 4, 192, 0, 2, 1});
    return response;
}

class DnsTestServer final {
  public:
    DnsTestServer(boost::asio::io_context &context, bool truncate_udp)
        : udp_socket_(context, {boost::asio::ip::address_v4::loopback(), 0}),
          endpoint_(udp_socket_.local_endpoint()),
          tcp_acceptor_(context, {boost::asio::ip::address_v4::loopback(), 0}),
          truncate_udp_(truncate_udp) {}

    boost::asio::ip::udp::endpoint endpoint() const noexcept { return endpoint_; }
    boost::asio::ip::tcp::endpoint tcp_endpoint() const noexcept {
        return tcp_acceptor_.local_endpoint();
    }
    int udp_queries() const noexcept { return udp_queries_.load(); }
    int tcp_queries() const noexcept { return tcp_queries_.load(); }

    void start() {
        receive_udp();
        accept_tcp();
    }

  private:
    void receive_udp() {
        udp_socket_.async_receive_from(
            boost::asio::buffer(udp_buffer_), sender_,
            [this](const boost::system::error_code &error, std::size_t size) {
                if (error) {
                    return;
                }
                ++udp_queries_;
                const auto query = std::make_shared<std::vector<std::uint8_t>>(
                    udp_buffer_.begin(), udp_buffer_.begin() + size);
                auto response = std::make_shared<std::vector<std::uint8_t>>(
                    response_for(*query, truncate_udp_));
                udp_socket_.async_send_to(
                    boost::asio::buffer(*response), sender_,
                    [response](const boost::system::error_code &, std::size_t) {});
                if (!truncate_udp_) {
                    receive_udp();
                }
            });
    }

    void accept_tcp() {
        auto socket = std::make_shared<boost::asio::ip::tcp::socket>(tcp_acceptor_.get_executor());
        tcp_acceptor_.async_accept(*socket, [this, socket](const boost::system::error_code &error) {
            if (!error) {
                read_tcp_query(std::move(socket));
            }
        });
    }

    void read_tcp_query(std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
        auto length = std::make_shared<std::array<std::uint8_t, 2>>();
        boost::asio::async_read(
            *socket, boost::asio::buffer(*length),
            [this, socket, length](const boost::system::error_code &error, std::size_t) {
                if (error) {
                    return;
                }
                const auto size = static_cast<std::size_t>((*length)[0] << 8 | (*length)[1]);
                auto query = std::make_shared<std::vector<std::uint8_t>>(size);
                boost::asio::async_read(
                    *socket, boost::asio::buffer(*query),
                    [this, socket, query](const boost::system::error_code &read_error,
                                          std::size_t) {
                        if (read_error) {
                            return;
                        }
                        ++tcp_queries_;
                        auto response = std::make_shared<std::vector<std::uint8_t>>(
                            response_for(*query, false));
                        const auto response_size = response->size();
                        std::vector<std::uint8_t> framed;
                        framed.reserve(2 + response_size);
                        append_u16(framed, static_cast<std::uint16_t>(response_size));
                        framed.insert(framed.end(), response->begin(), response->end());
                        auto frame = std::make_shared<std::vector<std::uint8_t>>(std::move(framed));
                        boost::asio::async_write(
                            *socket, boost::asio::buffer(*frame),
                            [socket, frame](const boost::system::error_code &, std::size_t) {});
                    });
            });
    }

    boost::asio::ip::udp::socket udp_socket_;
    boost::asio::ip::udp::endpoint endpoint_;
    boost::asio::ip::tcp::acceptor tcp_acceptor_;
    std::array<std::uint8_t, 4096> udp_buffer_{};
    boost::asio::ip::udp::endpoint sender_;
    std::atomic_int udp_queries_{0};
    std::atomic_int tcp_queries_{0};
    bool truncate_udp_;
};

} // namespace

TEST(DnsCodecTest, EncodesAndDecodesIpv4Answers) {
    const clash_native::dns::DnsQuestion question{"Example.COM.",
                                                  clash_native::dns::DnsRecordType::a, 1};
    const auto query = clash_native::dns::DnsMessageCodec::encode_query(question, 0x1234);
    ASSERT_TRUE(query);
    ASSERT_GE(query.value().size(), 12U);
    EXPECT_EQ(query.value()[0], 0x12);
    EXPECT_EQ(query.value()[1], 0x34);

    const auto response = response_for(query.value(), false);
    const auto decoded = clash_native::dns::DnsMessageCodec::decode_response(response, 0x1234);
    ASSERT_TRUE(decoded);
    EXPECT_EQ(decoded.value().question.name, "example.com");
    ASSERT_EQ(decoded.value().addresses.size(), 1U);
    EXPECT_EQ(decoded.value().addresses.front().to_string(), "192.0.2.1");
    EXPECT_EQ(decoded.value().ttl_seconds, 60U);
}

TEST(DnsCodecTest, RejectsMalformedResponses) {
    const auto decoded = clash_native::dns::DnsMessageCodec::decode_response(
        std::array<std::uint8_t, 3>{0, 1, 2}, 1);
    ASSERT_FALSE(decoded);
    EXPECT_EQ(decoded.error().code, clash_native::core::ErrorCode::protocol_framing);
}

TEST(DnsCodecTest, DecodesQueriesAndEncodesResponses) {
    const clash_native::dns::DnsQuestion question{"local.example",
                                                  clash_native::dns::DnsRecordType::a, 1};
    const auto encoded = clash_native::dns::DnsMessageCodec::encode_query(question, 0x4321);
    ASSERT_TRUE(encoded);
    const auto query = clash_native::dns::DnsMessageCodec::decode_query(encoded.value());
    ASSERT_TRUE(query);
    EXPECT_EQ(query.value().id, 0x4321);
    EXPECT_EQ(query.value().question.name, "local.example");

    clash_native::dns::DnsAnswer answer;
    answer.question = query.value().question;
    answer.addresses.push_back(boost::asio::ip::make_address("198.51.100.7"));
    answer.ttl_seconds = 30;
    const auto response =
        clash_native::dns::DnsMessageCodec::encode_response(query.value(), answer);
    ASSERT_TRUE(response);
    const auto decoded =
        clash_native::dns::DnsMessageCodec::decode_response(response.value(), 0x4321);
    ASSERT_TRUE(decoded);
    ASSERT_EQ(decoded.value().addresses.size(), 1U);
    EXPECT_EQ(decoded.value().addresses.front().to_string(), "198.51.100.7");
}

TEST(DnsPolicyRouterTest, UsesOrderedDomainPolicyAndExplicitDefault) {
    clash_native::dns::DnsPolicyRouter router("system");
    router.add_rule(
        {"internal", clash_native::dns::DnsPolicyRuleKind::suffix, "example.test", "internal-dns"});
    router.add_rule(
        {"keyword", clash_native::dns::DnsPolicyRuleKind::keyword, "video", "video-dns"});

    const auto internal = router.select("API.Example.Test.");
    EXPECT_EQ(internal.upstream_group, "internal-dns");
    EXPECT_EQ(internal.matched_rule, "internal");
    EXPECT_FALSE(internal.used_default);

    const auto fallback = router.select("www.example.org");
    EXPECT_EQ(fallback.upstream_group, "system");
    EXPECT_TRUE(fallback.used_default);
}

TEST(ResolverServiceTest, CoalescesEquivalentQueriesAndCachesTheAnswer) {
    clash_native::runtime::AsioRuntime runtime;
    DnsTestServer server(runtime.context(), false);
    server.start();
    clash_native::dns::ResolverService resolver(
        runtime, {server.endpoint(), std::chrono::milliseconds(500), server.tcp_endpoint(), true});
    runtime.start();

    const auto callback_count = std::make_shared<std::atomic_int>(0);
    auto first_done = std::make_shared<std::promise<void>>();
    auto first_future = first_done->get_future();
    boost::asio::post(runtime.context(), [&resolver, callback_count, first_done] {
        const clash_native::dns::DnsQuestion question{"coalesced.example",
                                                      clash_native::dns::DnsRecordType::a, 1};
        const auto handler = [callback_count, first_done](
                                 clash_native::core::Result<clash_native::dns::DnsAnswer> result) {
            if (!result) {
                ADD_FAILURE() << result.error().context;
                if (++*callback_count == 2) {
                    first_done->set_value();
                }
                return;
            }
            ASSERT_EQ(result.value().addresses.front().to_string(), "192.0.2.1");
            if (++*callback_count == 2) {
                first_done->set_value();
            }
        };
        resolver.resolve(question, handler);
        resolver.resolve(question, handler);
    });
    ASSERT_EQ(first_future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_EQ(server.tcp_queries(), 1);
    EXPECT_EQ(resolver.cache_size(), 1U);

    auto cached_done = std::make_shared<std::promise<void>>();
    auto cached_future = cached_done->get_future();
    boost::asio::post(runtime.context(), [&resolver, cached_done] {
        resolver.resolve(
            {"coalesced.example", clash_native::dns::DnsRecordType::a, 1},
            [cached_done](clash_native::core::Result<clash_native::dns::DnsAnswer> result) {
                ASSERT_TRUE(result) << (result ? "" : result.error().context);
                cached_done->set_value();
            });
    });
    ASSERT_EQ(cached_future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_EQ(server.tcp_queries(), 1);

    runtime.stop();
}

TEST(ResolverServiceTest, UsesConfiguredFallbackAfterPrimaryFailure) {
    clash_native::runtime::AsioRuntime runtime;
    DnsTestServer fallback(runtime.context(), false);
    fallback.start();
    clash_native::dns::ResolverService resolver(
        runtime, {boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 1),
                  std::chrono::milliseconds(250),
                  boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 1), true,
                  fallback.endpoint(), fallback.tcp_endpoint()});
    runtime.start();

    auto done = std::make_shared<std::promise<void>>();
    auto future = done->get_future();
    boost::asio::post(runtime.context(), [&resolver, done] {
        resolver.resolve({"fallback.example", clash_native::dns::DnsRecordType::a, 1},
                         [done](clash_native::core::Result<clash_native::dns::DnsAnswer> result) {
                             ASSERT_TRUE(result) << (result ? "" : result.error().context);
                             ASSERT_EQ(result.value().addresses.size(), 1U);
                             EXPECT_EQ(result.value().addresses.front().to_string(), "192.0.2.1");
                             done->set_value();
                         });
    });
    ASSERT_EQ(future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_EQ(fallback.tcp_queries(), 1);
    runtime.stop();
}

TEST(ResolverServiceTest, CancelsTheWaiterAndSharedOperation) {
    clash_native::runtime::AsioRuntime runtime;
    clash_native::dns::ResolverService resolver(
        runtime,
        {boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 1),
         std::chrono::milliseconds(500),
         boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 1), true});
    runtime.start();

    auto done = std::make_shared<std::promise<void>>();
    auto future = done->get_future();
    boost::asio::post(runtime.context(), [&resolver, done] {
        const auto request_id = resolver.resolve(
            {"cancel.example", clash_native::dns::DnsRecordType::a, 1},
            [done](clash_native::core::Result<clash_native::dns::DnsAnswer> result) {
                ASSERT_FALSE(result);
                EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::cancelled);
                done->set_value();
            });
        resolver.cancel(request_id);
    });
    ASSERT_EQ(future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    runtime.stop();
}

TEST(ResolverServiceTest, FallsBackToTcpForTruncatedUdpResponses) {
    clash_native::runtime::AsioRuntime runtime;
    DnsTestServer server(runtime.context(), true);
    server.start();
    clash_native::dns::ResolverService resolver(
        runtime, {server.endpoint(), std::chrono::milliseconds(500), server.tcp_endpoint()});
    runtime.start();

    auto done = std::make_shared<std::promise<void>>();
    auto future = done->get_future();
    auto success = std::make_shared<std::atomic_bool>(false);
    boost::asio::post(runtime.context(), [&resolver, done, success] {
        resolver.resolve(
            {"tcp-fallback.example", clash_native::dns::DnsRecordType::a, 1},
            [done, success](clash_native::core::Result<clash_native::dns::DnsAnswer> result) {
                if (result && result.value().addresses.size() == 1 &&
                    result.value().addresses.front().to_string() == "192.0.2.1") {
                    *success = true;
                }
                done->set_value();
            });
    });
    const auto status = future.wait_for(std::chrono::seconds(2));
    if (server.udp_queries() == 0) {
        GTEST_SKIP() << "UDP loopback is unavailable in this Windows environment";
    }
    ASSERT_EQ(status, std::future_status::ready);
    EXPECT_TRUE(*success);
    EXPECT_EQ(server.udp_queries(), 1);
    EXPECT_EQ(server.tcp_queries(), 1);

    runtime.stop();
}

TEST(FakeIpStoreTest, AllocatesStableAddressesAndReversesThem) {
    clash_native::dns::FakeIpStore store(boost::asio::ip::make_address_v4("198.18.0.0"), 30, 2);
    const auto first = store.resolve("Example.COM.");
    ASSERT_TRUE(first);
    const auto same = store.resolve("example.com");
    ASSERT_TRUE(same);
    EXPECT_EQ(first.value(), same.value());
    EXPECT_EQ(store.reverse(first.value()), std::optional<std::string>("example.com"));
    EXPECT_EQ(store.size(), 1U);

    const auto second = store.resolve("second.example");
    ASSERT_TRUE(second);
    EXPECT_NE(first.value(), second.value());
    EXPECT_TRUE(store.release("EXAMPLE.COM"));
    EXPECT_FALSE(store.reverse(first.value()).has_value());
    EXPECT_EQ(store.size(), 1U);
}
