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

TEST(TrafficRouterTest, MatchesDestinationIpCidrAndResumesAfterLookupFailure) {
    const auto destination = clash_native::core::Destination::domain("example.test", 443);
    const clash_native::core::ConnectionMetadata metadata{
        clash_native::core::Network::tcp, {}, destination, "", "socks5", {}, {}};

    clash_native::router::TrafficRouter router;
    router.add_rule({"private", clash_native::router::RuleKind::destination_ip_cidr, "192.0.2.0/24",
                     0, 0, false, clash_native::router::RouteAction::reject()});
    router.add_rule({"domain-fallback", clash_native::router::RuleKind::domain, "example.test", 0,
                     0, false, clash_native::router::RouteAction::named("direct")});

    clash_native::router::RoutingContext resolved;
    resolved.destination_lookup = clash_native::router::LookupState::resolved;
    resolved.destination_address = boost::asio::ip::make_address("192.0.2.42");
    const auto matched = router.evaluate(metadata, resolved, 0);
    const auto *private_match = std::get_if<clash_native::router::Matched>(&matched);
    ASSERT_NE(private_match, nullptr);
    EXPECT_EQ(private_match->decision.matched_rule, "private");

    clash_native::router::RoutingContext failed;
    failed.destination_lookup = clash_native::router::LookupState::failed;
    const auto resumed = router.evaluate(metadata, failed, 0);
    const auto *fallback_match = std::get_if<clash_native::router::Matched>(&resumed);
    ASSERT_NE(fallback_match, nullptr);
    EXPECT_EQ(fallback_match->decision.matched_rule, "domain-fallback");
}

TEST(TrafficRouterTest, MatchesAnyResolvedDestinationAddress) {
    const auto destination = clash_native::core::Destination::domain("example.test", 443);
    const clash_native::core::ConnectionMetadata metadata{
        clash_native::core::Network::tcp, {}, destination, "", "socks5", {}, {}};

    clash_native::router::TrafficRouter router;
    router.add_rule({"private-v6", clash_native::router::RuleKind::destination_ip_cidr,
                     "2001:db8:1::/48", 0, 0, false, clash_native::router::RouteAction::reject()});

    clash_native::router::RoutingContext context;
    context.destination_lookup = clash_native::router::LookupState::resolved;
    context.destination_addresses = {boost::asio::ip::make_address("192.0.2.42"),
                                     boost::asio::ip::make_address("2001:db8:1::42")};
    const auto evaluation = router.evaluate(metadata, context);
    const auto *matched = std::get_if<clash_native::router::Matched>(&evaluation);
    ASSERT_NE(matched, nullptr);
    EXPECT_EQ(matched->decision.matched_rule, "private-v6");
}

TEST(TrafficRouterTest, SnapshotsKeepTheOldRuleProgramImmutable) {
    clash_native::router::TrafficRouter router;
    const auto old_snapshot = router.snapshot();
    router.add_rule({"new", clash_native::router::RuleKind::domain, "example.test", 0, 0, false,
                     clash_native::router::RouteAction::reject()});
    const auto new_snapshot = router.snapshot();

    const auto destination = clash_native::core::Destination::domain("example.test", 443);
    const clash_native::core::ConnectionMetadata metadata{
        clash_native::core::Network::tcp, {}, destination, "", "socks5", {}, {}};
    const auto old_result = old_snapshot->evaluate(metadata, {});
    const auto *old_match = std::get_if<clash_native::router::Matched>(&old_result);
    ASSERT_NE(old_match, nullptr);
    EXPECT_TRUE(old_match->decision.used_default);

    const auto new_result = new_snapshot->evaluate(metadata, {});
    const auto *new_match = std::get_if<clash_native::router::Matched>(&new_result);
    ASSERT_NE(new_match, nullptr);
    EXPECT_EQ(new_match->decision.matched_rule, "new");
}

TEST(TrafficRouterTest, ValidatesNamedTargetsBeforePublishingAProgram) {
    clash_native::router::TrafficRouter router(clash_native::router::RouteAction::named("proxy"));
    router.add_rule({"named", clash_native::router::RuleKind::network, "tcp", 0, 0, false,
                     clash_native::router::RouteAction::named("proxy")});

    const std::vector<std::string> targets{"direct", "proxy"};
    EXPECT_TRUE(router.validate(targets));

    const std::vector<std::string> missing{"direct"};
    const auto result = router.validate(missing);
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::configuration);
}
