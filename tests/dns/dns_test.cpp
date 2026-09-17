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
#include <thread>
#include <utility>
#include <vector>

namespace {

using Address = boost::asio::ip::address;

void append_u16(std::vector<std::uint8_t> &message, std::uint16_t value) {
    message.push_back(static_cast<std::uint8_t>(value >> 8));
    message.push_back(static_cast<std::uint8_t>(value & 0xff));
}

std::vector<std::uint8_t> response_for(std::span<const std::uint8_t> query, bool truncated,
                                       bool mismatched_question = false) {
    if (truncated) {
        std::vector<std::uint8_t> response(query.begin(), query.end());
        response[2] = 0x83;
        response[3] = 0x80;
        response[6] = 0;
        response[7] = 0;
        return response;
    }

    const auto packet = clash_native::dns::DnsMessageCodec::decode_packet(query);
    if (!packet) {
        return {};
    }
    clash_native::dns::DnsAnswer answer;
    answer.question = packet.value().questions.front();
    answer.addresses.push_back(boost::asio::ip::make_address("192.0.2.1"));
    answer.ttl_seconds = 60;
    auto encoded = clash_native::dns::DnsMessageCodec::encode_response(packet.value(), answer);
    if (!encoded) {
        return {};
    }
    auto response = std::move(encoded.value());
    if (mismatched_question && response.size() > 13) {
        response[13] ^= 1;
    }
    return response;
}

class DnsTestServer final {
  public:
    DnsTestServer(boost::asio::io_context &context, bool truncate_udp,
                  bool wrong_udp_sender = false, bool mismatched_question = false)
        : udp_socket_(context, {boost::asio::ip::address_v4::loopback(), 0}),
          endpoint_(udp_socket_.local_endpoint()),
          wrong_udp_socket_(context, {boost::asio::ip::address_v4::loopback(), 0}),
          tcp_acceptor_(context, {boost::asio::ip::address_v4::loopback(), 0}),
          truncate_udp_(truncate_udp), wrong_udp_sender_(wrong_udp_sender),
          mismatched_question_(mismatched_question) {}

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

    void stop() {
        boost::system::error_code ignored;
        udp_socket_.cancel(ignored);
        udp_socket_.close(ignored);
        wrong_udp_socket_.cancel(ignored);
        wrong_udp_socket_.close(ignored);
        tcp_acceptor_.cancel(ignored);
        tcp_acceptor_.close(ignored);
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
                    response_for(*query, truncate_udp_, mismatched_question_));
                auto &response_socket = wrong_udp_sender_ ? wrong_udp_socket_ : udp_socket_;
                response_socket.async_send_to(
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
    boost::asio::ip::udp::socket wrong_udp_socket_;
    boost::asio::ip::tcp::acceptor tcp_acceptor_;
    std::array<std::uint8_t, 4096> udp_buffer_{};
    boost::asio::ip::udp::endpoint sender_;
    std::atomic_int udp_queries_{0};
    std::atomic_int tcp_queries_{0};
    bool truncate_udp_;
    bool wrong_udp_sender_;
    bool mismatched_question_;
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
    ASSERT_TRUE(decoded) << (decoded ? "" : decoded.error().context);
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

TEST(DnsCodecTest, RejectsResponsesWithMultipleQuestions) {
    const auto query = clash_native::dns::DnsMessageCodec::encode_query(
        {"example.test", clash_native::dns::DnsRecordType::a, 1}, 0x1234);
    ASSERT_TRUE(query);
    auto response = response_for(query.value(), false);
    response[4] = 0;
    response[5] = 2;

    const auto decoded = clash_native::dns::DnsMessageCodec::decode_response(response, 0x1234);
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
    ASSERT_TRUE(decoded) << (decoded ? "" : decoded.error().context);
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

    server.stop();
    runtime.stop();
}

TEST(ResolverServiceTest, SeparatesCacheEntriesByEdnsSemanticsButIgnoresTransactionId) {
    clash_native::runtime::AsioRuntime runtime;
    DnsTestServer server(runtime.context(), false);
    server.start();
    clash_native::dns::ResolverService resolver(
        runtime, {server.endpoint(), std::chrono::milliseconds(500)});
    runtime.start();

    const auto make_edns_query = [](std::uint16_t id, bool dnssec_ok) {
        auto wire = clash_native::dns::DnsMessageCodec::encode_query_packet(
                        {"semantic-cache.example", clash_native::dns::DnsRecordType::a, 1}, id)
                        .value();
        wire[10] = 0;
        wire[11] = 1;
        wire.push_back(0);
        append_u16(wire, static_cast<std::uint16_t>(clash_native::dns::DnsRecordType::opt));
        append_u16(wire, 1232);
        append_u16(wire, 0);
        append_u16(wire, dnssec_ok ? 0x8000 : 0);
        append_u16(wire, 0);
        return clash_native::dns::DnsMessageCodec::decode_packet(wire, id);
    };
    const auto query_without_do = make_edns_query(0x1234, false);
    const auto query_with_do = make_edns_query(0x2345, true);
    const auto query_with_do_and_new_id = make_edns_query(0x3456, true);
    ASSERT_TRUE(query_without_do);
    ASSERT_TRUE(query_with_do);
    ASSERT_TRUE(query_with_do_and_new_id);

    const auto run_query = [&resolver](clash_native::dns::DnsPacket packet) {
        auto done = std::make_shared<std::promise<void>>();
        auto future = done->get_future();
        resolver.query_service().query(
            std::move(packet),
            [done](clash_native::core::Result<clash_native::dns::DnsPacket> result) {
                EXPECT_TRUE(result) << (result ? "" : result.error().context);
                done->set_value();
            });
        EXPECT_EQ(future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    };

    run_query(query_without_do.value());
    run_query(query_with_do.value());
    EXPECT_EQ(server.udp_queries(), 2);
    run_query(query_with_do_and_new_id.value());
    EXPECT_EQ(server.udp_queries(), 2);
    EXPECT_EQ(resolver.cache_size(), 2U);

    resolver.stop();
    server.stop();
    runtime.stop();
}

TEST(ResolverServiceTest, RoutesQueriesThroughTheSelectedDnsUpstreamGroup) {
    clash_native::runtime::AsioRuntime runtime;
    DnsTestServer default_server(runtime.context(), false);
    DnsTestServer internal_server(runtime.context(), false);
    default_server.start();
    internal_server.start();

    auto policy = std::make_shared<clash_native::dns::DnsPolicyRouter>("system");
    policy->add_rule({"internal", clash_native::dns::DnsPolicyRuleKind::suffix, "internal.example",
                      "internal-dns"});

    clash_native::dns::DnsResolverConfig config{
        {default_server.endpoint(), std::chrono::milliseconds(500), default_server.tcp_endpoint(),
         true},
        {{"internal-dns",
          {internal_server.endpoint(), std::chrono::milliseconds(500),
           internal_server.tcp_endpoint(), true}}},
        policy};
    clash_native::dns::ResolverService resolver(runtime, std::move(config));
    runtime.start();

    auto completed = std::make_shared<std::atomic_int>(0);
    auto done = std::make_shared<std::promise<void>>();
    auto future = done->get_future();
    boost::asio::post(runtime.context(), [&resolver, completed, done] {
        const auto handler =
            [completed, done](clash_native::core::Result<clash_native::dns::DnsAnswer> result) {
                ASSERT_TRUE(result) << (result ? "" : result.error().context);
                if (++*completed == 2) {
                    done->set_value();
                }
            };
        resolver.resolve({"api.internal.example", clash_native::dns::DnsRecordType::a, 1}, handler);
        resolver.resolve({"www.example.org", clash_native::dns::DnsRecordType::a, 1}, handler);
    });

    ASSERT_EQ(future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_EQ(internal_server.tcp_queries(), 1);
    EXPECT_EQ(default_server.tcp_queries(), 1);

    resolver.stop();
    internal_server.stop();
    default_server.stop();
    runtime.stop();
}

TEST(ResolverServiceTest, RejectsPolicyRulesThatReferenceAnUnknownUpstreamGroup) {
    clash_native::runtime::AsioRuntime runtime;
    DnsTestServer server(runtime.context(), false);
    server.start();

    auto policy = std::make_shared<clash_native::dns::DnsPolicyRouter>("system");
    policy->add_rule(
        {"missing", clash_native::dns::DnsPolicyRuleKind::exact, "missing.example", "missing-dns"});
    clash_native::dns::ResolverService resolver(
        runtime,
        clash_native::dns::DnsResolverConfig{
            {server.endpoint(), std::chrono::milliseconds(500), server.tcp_endpoint(), true},
            {},
            policy});
    runtime.start();

    auto done = std::make_shared<std::promise<void>>();
    auto future = done->get_future();
    boost::asio::post(runtime.context(), [&resolver, done] {
        resolver.resolve({"missing.example", clash_native::dns::DnsRecordType::a, 1},
                         [done](clash_native::core::Result<clash_native::dns::DnsAnswer> result) {
                             ASSERT_FALSE(result);
                             EXPECT_EQ(result.error().code,
                                       clash_native::core::ErrorCode::configuration);
                             done->set_value();
                         });
    });

    ASSERT_EQ(future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_EQ(server.tcp_queries(), 0);

    resolver.stop();
    server.stop();
    runtime.stop();
}

TEST(ResolverServiceTest, DeliversCompletionsOnTheCallingRuntime) {
    clash_native::runtime::AsioRuntime resolver_runtime;
    DnsTestServer server(resolver_runtime.context(), false);
    server.start();
    clash_native::dns::ResolverService resolver(
        resolver_runtime,
        {server.endpoint(), std::chrono::milliseconds(500), server.tcp_endpoint(), true});
    clash_native::runtime::AsioRuntime caller_runtime;
    resolver_runtime.start();
    caller_runtime.start();

    auto caller_thread = std::make_shared<std::thread::id>();
    auto completion_thread = std::make_shared<std::thread::id>();
    auto done = std::make_shared<std::promise<void>>();
    auto future = done->get_future();
    boost::asio::post(caller_runtime.context(),
                      [&resolver, &caller_runtime, caller_thread, completion_thread, done] {
                          *caller_thread = std::this_thread::get_id();
                          resolver.resolve(
                              {"cross-runtime.example", clash_native::dns::DnsRecordType::a, 1},
                              [completion_thread, done](
                                  clash_native::core::Result<clash_native::dns::DnsAnswer> result) {
                                  if (result) {
                                      *completion_thread = std::this_thread::get_id();
                                  }
                                  done->set_value();
                              },
                              caller_runtime.scheduler());
                      });

    ASSERT_EQ(future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_EQ(*completion_thread, *caller_thread);
    EXPECT_EQ(server.tcp_queries(), 1);
    resolver.stop();
    server.stop();
    caller_runtime.stop();
    resolver_runtime.stop();
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
    fallback.stop();
    runtime.stop();
}

TEST(ResolverServiceTest, IgnoresResponsesFromUnexpectedUdpSender) {
    clash_native::runtime::AsioRuntime runtime;
    DnsTestServer unexpected(runtime.context(), false, true);
    DnsTestServer fallback(runtime.context(), false);
    unexpected.start();
    fallback.start();
    clash_native::dns::ResolverService resolver(
        runtime, {unexpected.endpoint(), std::chrono::milliseconds(100), unexpected.tcp_endpoint(),
                  false, fallback.endpoint(), fallback.tcp_endpoint()});
    runtime.start();

    auto done = std::make_shared<std::promise<void>>();
    auto future = done->get_future();
    boost::asio::post(runtime.context(), [&resolver, done] {
        resolver.resolve({"unexpected-sender.example", clash_native::dns::DnsRecordType::a, 1},
                         [done](clash_native::core::Result<clash_native::dns::DnsAnswer> result) {
                             ASSERT_TRUE(result) << (result ? "" : result.error().context);
                             ASSERT_FALSE(result.value().addresses.empty());
                             done->set_value();
                         });
    });

    ASSERT_EQ(future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_EQ(unexpected.udp_queries(), 1);
    EXPECT_EQ(fallback.udp_queries(), 1);
    unexpected.stop();
    fallback.stop();
    runtime.stop();
}

TEST(ResolverServiceTest, IgnoresResponsesWithAnUnexpectedQuestion) {
    clash_native::runtime::AsioRuntime runtime;
    DnsTestServer unexpected(runtime.context(), false, false, true);
    DnsTestServer fallback(runtime.context(), false);
    unexpected.start();
    fallback.start();
    clash_native::dns::ResolverService resolver(
        runtime, {unexpected.endpoint(), std::chrono::milliseconds(100), unexpected.tcp_endpoint(),
                  false, fallback.endpoint(), fallback.tcp_endpoint()});
    runtime.start();

    auto done = std::make_shared<std::promise<void>>();
    auto future = done->get_future();
    boost::asio::post(runtime.context(), [&resolver, done] {
        resolver.resolve({"unexpected-question.example", clash_native::dns::DnsRecordType::a, 1},
                         [done](clash_native::core::Result<clash_native::dns::DnsAnswer> result) {
                             ASSERT_TRUE(result) << (result ? "" : result.error().context);
                             ASSERT_FALSE(result.value().addresses.empty());
                             done->set_value();
                         });
    });

    ASSERT_EQ(future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_EQ(unexpected.udp_queries(), 1);
    EXPECT_EQ(fallback.udp_queries(), 1);
    unexpected.stop();
    fallback.stop();
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
    resolver.stop();
    runtime.stop();
}

TEST(ResolverServiceTest, ValidatesPolicyGroupsBeforeRuntimeSnapshotPublication) {
    clash_native::runtime::AsioRuntime runtime;
    auto policy = std::make_shared<clash_native::dns::DnsPolicyRouter>("default");
    policy->add_rule({"missing-group-rule", clash_native::dns::DnsPolicyRuleKind::exact,
                      "missing.example", "missing"});
    auto resolver = std::make_shared<clash_native::dns::ResolverService>(
        runtime, clash_native::dns::DnsResolverConfig{
                     {boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 1),
                      std::chrono::milliseconds(100)},
                     {},
                     policy});

    const auto result = resolver->validate();
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::configuration);
    EXPECT_NE(result.error().context.find("missing"), std::string::npos);
}

TEST(ResolverServiceTest, RejectsAnUnknownPolicyDefaultGroupBeforeQuerying) {
    clash_native::runtime::AsioRuntime runtime;
    auto policy = std::make_shared<clash_native::dns::DnsPolicyRouter>("missing-default");
    auto resolver = std::make_shared<clash_native::dns::ResolverService>(
        runtime, clash_native::dns::DnsResolverConfig{
                     {boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 1),
                      std::chrono::milliseconds(100)},
                     {},
                     std::move(policy)});

    const auto result = resolver->validate();
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::configuration);
    EXPECT_NE(result.error().context.find("missing-default"), std::string::npos);
}

TEST(ResolverServiceTest, ValidatesTheConfiguredResolverDependencyGraph) {
    clash_native::runtime::AsioRuntime runtime;
    auto graph = std::make_shared<clash_native::dns::ResolverDependencyGraph>();
    ASSERT_TRUE(graph->add_resolver("bootstrap", clash_native::dns::ResolverRole::bootstrap));
    ASSERT_TRUE(graph->add_resolver("default", clash_native::dns::ResolverRole::default_resolver));
    ASSERT_TRUE(graph->add_outbound("direct"));
    ASSERT_TRUE(graph->add_dependency("bootstrap", "direct"));
    ASSERT_TRUE(graph->add_dependency("direct", "default"));

    clash_native::dns::ResolverService resolver(
        runtime, clash_native::dns::DnsResolverConfig{
                     {boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 1),
                      std::chrono::milliseconds(100)},
                     {},
                     nullptr,
                     {},
                     {},
                     4096,
                     std::chrono::seconds(5),
                     0,
                     graph});

    const auto result = resolver.validate();
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::configuration);
    EXPECT_NE(result.error().context.find("bootstrap"), std::string::npos);
}

TEST(ResolverServiceTest, RejectsInvalidUpstreamConfigurationBeforeQuerying) {
    clash_native::runtime::AsioRuntime runtime;
    clash_native::dns::DnsResolverConfig config{
        {boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 1),
         std::chrono::milliseconds(1)},
        {},
        nullptr,
        {}};
    config.default_upstream.timeout = std::chrono::milliseconds(0);
    clash_native::dns::ResolverService resolver(runtime, std::move(config));

    const auto result = resolver.validate();
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::configuration);
    EXPECT_NE(result.error().context.find("timeout"), std::string::npos);
}

TEST(ResolverServiceTest, RejectsUnsupportedDnsDialPolicyBeforeQuerying) {
    clash_native::runtime::AsioRuntime runtime;
    clash_native::dns::DnsResolverConfig config{
        {boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 1),
         std::chrono::milliseconds(100)},
        {},
        nullptr,
        {}};
    config.default_upstream.dial_policy.kind = clash_native::dns::DnsDialPolicyKind::named_outbound;
    config.default_upstream.dial_policy.outbound_id = "proxy";
    clash_native::dns::ResolverService resolver(runtime, std::move(config));

    const auto result = resolver.validate();
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::configuration);
    EXPECT_NE(result.error().context.find("dialer"), std::string::npos);
}

TEST(ResolverServiceTest, RejectsInvalidDnsEnumConfigurationBeforeQuerying) {
    clash_native::runtime::AsioRuntime runtime;
    clash_native::dns::DnsResolverConfig config{
        {boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 1),
         std::chrono::milliseconds(100)},
        {},
        nullptr,
        {}};
    config.default_upstream.mode = static_cast<clash_native::dns::DnsTransportMode>(99);
    clash_native::dns::ResolverService resolver(runtime, std::move(config));

    const auto result = resolver.validate();
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::configuration);
    EXPECT_NE(result.error().context.find("transport mode"), std::string::npos);
}

TEST(ResolverServiceTest, ValidatesDoqAndDoh3ConfigurationContracts) {
    clash_native::runtime::AsioRuntime runtime;
    clash_native::dns::DnsResolverConfig config{
        {boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::loopback(), 853),
         std::chrono::milliseconds(100)},
        {},
        nullptr,
        {}};
    config.default_upstream.mode = clash_native::dns::DnsTransportMode::doq;
    clash_native::dns::ResolverService doq_resolver(runtime, config);
    EXPECT_TRUE(doq_resolver.validate());

    config.default_upstream.mode = clash_native::dns::DnsTransportMode::doh3;
    config.default_upstream.doh_path = "relative-path";
    clash_native::dns::ResolverService doh3_resolver(runtime, std::move(config));
    const auto result = doh3_resolver.validate();
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::configuration);
    EXPECT_NE(result.error().context.find("DoH3 path"), std::string::npos);
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

    server.stop();
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

TEST(FakeIpStoreTest, ExpiresMappingsAndReusesReleasedAddresses) {
    clash_native::dns::FakeIpStore store(boost::asio::ip::make_address_v4("198.18.0.0"), 30, 2,
                                         std::chrono::seconds(1));
    const auto first = store.resolve("temporary.example");
    ASSERT_TRUE(first);
    ASSERT_EQ(store.reverse(first.value()), std::optional<std::string>("temporary.example"));
    const auto second = store.resolve("temporary-second.example");
    ASSERT_TRUE(second);
    EXPECT_NE(second.value(), first.value());

    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    EXPECT_FALSE(store.reverse(first.value()).has_value());
    EXPECT_EQ(store.size(), 0U);

    const auto reused = store.resolve("replacement.example");
    ASSERT_TRUE(reused);
    EXPECT_EQ(reused.value(), first.value());
    EXPECT_EQ(store.reverse(reused.value()), std::optional<std::string>("replacement.example"));
}
