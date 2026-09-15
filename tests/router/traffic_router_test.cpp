#include <clash_native/router/traffic_router.hpp>

#include <gtest/gtest.h>

TEST(TrafficRouterTest, UsesFirstMatchingRuleAndPreservesMetadata) {
    const auto destination = clash_native::core::Destination::domain("Example.COM", 443);
    const clash_native::core::ConnectionMetadata metadata{
        clash_native::core::Network::tcp, {}, destination, "control", "socks5", {}, {}};

    clash_native::router::TrafficRouter router;
    router.add_rule({"suffix", clash_native::router::RuleKind::domain_suffix, "example.com", 0, 0,
                     false, clash_native::router::RouteAction::reject()});
    router.add_rule({"fallback", clash_native::router::RuleKind::network, "tcp", 0, 0, false,
                     clash_native::router::RouteAction::named("unused")});

    const auto evaluation = router.evaluate(metadata, {});
    const auto *matched = std::get_if<clash_native::router::Matched>(&evaluation);
    ASSERT_NE(matched, nullptr);
    EXPECT_EQ(matched->decision.matched_rule, "suffix");
    EXPECT_EQ(matched->decision.action.kind, clash_native::router::RouteActionKind::reject);
    EXPECT_FALSE(matched->decision.used_default);
}

TEST(TrafficRouterTest, RequestsDestinationIpOnlyWhenRuleAllowsResolution) {
    const auto destination = clash_native::core::Destination::domain("example.test", 443);
    const clash_native::core::ConnectionMetadata metadata{
        clash_native::core::Network::tcp, {}, destination, "", "http", {}, {}};

    clash_native::router::TrafficRouter router;
    router.add_rule({"private", clash_native::router::RuleKind::destination_ip_cidr, "127.0.0.0/8",
                     0, 0, false, clash_native::router::RouteAction::reject()});

    const auto evaluation = router.evaluate(metadata, {});
    const auto *need = std::get_if<clash_native::router::NeedMetadata>(&evaluation);
    ASSERT_NE(need, nullptr);
    EXPECT_EQ(need->need, clash_native::router::MetadataNeed::destination_ip);

    clash_native::router::RoutingContext no_resolve_context;
    no_resolve_context.destination_lookup = clash_native::router::LookupState::unrequested;
    router = clash_native::router::TrafficRouter();
    router.add_rule({"private", clash_native::router::RuleKind::destination_ip_cidr, "127.0.0.0/8",
                     0, 0, true, clash_native::router::RouteAction::reject()});
    const auto no_resolve_evaluation = router.evaluate(metadata, no_resolve_context);
    const auto *default_match = std::get_if<clash_native::router::Matched>(&no_resolve_evaluation);
    ASSERT_NE(default_match, nullptr);
    EXPECT_TRUE(default_match->decision.used_default);
}
