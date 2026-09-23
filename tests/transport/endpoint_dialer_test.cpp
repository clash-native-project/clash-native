#include <clash_native/dns/dns_transport.hpp>
#include <clash_native/io/sender.hpp>
#include <clash_native/outbound/outbound_registry.hpp>
#include <clash_native/router/traffic_router.hpp>
#include <clash_native/transport/endpoint_dialer.hpp>

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>

#include <stdexec/execution.hpp>

#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace {

class RecordingOutbound final : public clash_native::core::Outbound {
  public:
    explicit RecordingOutbound(std::string id) : descriptor_{std::move(id), "recording"} {}

    const clash_native::core::OutboundDescriptor &descriptor() const noexcept override {
        return descriptor_;
    }

    clash_native::core::OutboundCapabilities capabilities() const noexcept override {
        return {true, clash_native::core::DatagramSemantics::multi_destination,
                clash_native::core::TargetRequirement::domain_or_ip,
                clash_native::core::TargetRequirement::domain_or_ip};
    }

    clash_native::io::AnySender<clash_native::core::StreamOpenResult>
    connect_stream(clash_native::core::StreamRequest request) override {
        ++stream_calls;
        if (request.dial_trace) {
            stream_trace = request.dial_trace->outbound_ids;
        }
        return clash_native::io::AnySender<clash_native::core::StreamOpenResult>{
            stdexec::just(clash_native::core::StreamOpenResult::unsupported())};
    }

    clash_native::io::AnySender<clash_native::core::DatagramOpenResult>
    open_datagram(clash_native::core::DatagramRequest request) override {
        ++datagram_calls;
        if (request.dial_trace) {
            datagram_trace = request.dial_trace->outbound_ids;
        }
        return clash_native::io::AnySender<clash_native::core::DatagramOpenResult>{
            stdexec::just(clash_native::core::DatagramOpenResult::unsupported())};
    }

    int stream_calls = 0;
    int datagram_calls = 0;
    std::vector<std::string> stream_trace;
    std::vector<std::string> datagram_trace;

  private:
    clash_native::core::OutboundDescriptor descriptor_;
};

} // namespace

TEST(EndpointDialerTest, PropagatesOutboundTraceToTheSelectedTarget) {
    boost::asio::io_context context;
    auto outbound = std::make_shared<RecordingOutbound>("proxy");
    clash_native::outbound::OutboundRegistry registry;
    ASSERT_TRUE(registry.add_outbound("proxy", outbound));
    const auto plan = clash_native::transport::EndpointDialPlan::from_registry(
        registry.snapshot(), "proxy", {.stream = true});
    ASSERT_TRUE(plan);

    clash_native::transport::EndpointDialer dialer(context.get_executor(), plan.value());
    auto wait = stdexec::sync_wait(dialer.connect_stream(
        {clash_native::core::Destination::address(boost::asio::ip::make_address("192.0.2.1"), 443),
         std::nullopt}));
    ASSERT_TRUE(wait.has_value());
    auto result = std::move(std::get<0>(*wait));
    EXPECT_EQ(result.status, clash_native::core::OpenStatus::unsupported);

    EXPECT_EQ(outbound->stream_calls, 1);
    EXPECT_EQ(outbound->stream_trace, (std::vector<std::string>{"proxy"}));
}

TEST(EndpointDialerTest, RejectsRuntimeOutboundCyclesBeforeOpeningAHandle) {
    boost::asio::io_context context;
    auto outbound = std::make_shared<RecordingOutbound>("proxy");
    clash_native::outbound::OutboundRegistry registry;
    ASSERT_TRUE(registry.add_outbound("proxy", outbound));
    const auto plan = clash_native::transport::EndpointDialPlan::from_registry(
        registry.snapshot(), "proxy", {.stream = true});
    ASSERT_TRUE(plan);

    clash_native::transport::EndpointDialer dialer(context.get_executor(), plan.value());
    clash_native::core::StreamRequest request{
        clash_native::core::Destination::address(boost::asio::ip::make_address("192.0.2.1"), 443),
        std::nullopt};
    request.dial_trace = std::make_shared<const clash_native::core::EndpointDialTrace>(
        clash_native::core::EndpointDialTrace{{"proxy"}});
    auto wait = stdexec::sync_wait(dialer.connect_stream(std::move(request)));
    ASSERT_TRUE(wait.has_value());
    auto result = std::move(std::get<0>(*wait));
    ASSERT_FALSE(result.succeeded());
    ASSERT_TRUE(result.error);
    EXPECT_EQ(result.error->code, clash_native::core::ErrorCode::configuration);

    EXPECT_EQ(outbound->stream_calls, 0);
}

TEST(EndpointDialerTest, ResolvesDnsTrafficRulesBeforeOpeningDatagramCarrier) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    auto outbound = std::make_shared<RecordingOutbound>("resolver-proxy");
    clash_native::outbound::OutboundRegistry registry;
    ASSERT_TRUE(registry.add_outbound("resolver-proxy", outbound));

    clash_native::router::TrafficRouter router(clash_native::router::RouteAction::reject());
    router.add_rule({"dns-egress", clash_native::router::RuleKind::domain_suffix, "example.net", 0,
                     0, false, clash_native::router::RouteAction::named("resolver-proxy")});
    auto dialer = clash_native::dns::make_traffic_rules_dns_upstream_dialer(
        runtime, registry.snapshot(), router.snapshot(), "dns.example.net");

    auto wait = stdexec::sync_wait(dialer->open_datagram({clash_native::core::Destination::address(
        boost::asio::ip::make_address("192.0.2.53"), 853)}));
    ASSERT_TRUE(wait.has_value());
    auto result = std::move(std::get<0>(*wait));
    EXPECT_EQ(result.status, clash_native::core::OpenStatus::unsupported);

    EXPECT_EQ(outbound->datagram_calls, 1);
    EXPECT_EQ(outbound->datagram_trace, (std::vector<std::string>{"resolver-proxy"}));
    runtime.stop();
}
