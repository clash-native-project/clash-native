#include <clash_native/dns/resolver_graph.hpp>

#include <gtest/gtest.h>

TEST(ResolverDependencyGraphTest, KeepsResolverRolesExplicit) {
    clash_native::dns::ResolverDependencyGraph graph;
    ASSERT_TRUE(graph.add_resolver("bootstrap", clash_native::dns::ResolverRole::bootstrap));
    ASSERT_TRUE(graph.add_resolver("default", clash_native::dns::ResolverRole::default_resolver));
    EXPECT_EQ(graph.role("bootstrap"), clash_native::dns::ResolverRole::bootstrap);
    EXPECT_FALSE(graph.role("missing"));
    EXPECT_TRUE(graph.validate());
}

TEST(ResolverDependencyGraphTest, RejectsTransitiveBootstrapDependenciesAndCycles) {
    clash_native::dns::ResolverDependencyGraph bootstrap;
    ASSERT_TRUE(bootstrap.add_resolver("bootstrap", clash_native::dns::ResolverRole::bootstrap));
    ASSERT_TRUE(
        bootstrap.add_resolver("default", clash_native::dns::ResolverRole::default_resolver));
    ASSERT_TRUE(bootstrap.add_outbound("direct"));
    ASSERT_TRUE(bootstrap.add_dependency("bootstrap", "direct"));
    ASSERT_TRUE(bootstrap.add_dependency("direct", "default"));
    const auto bootstrap_result = bootstrap.validate();
    ASSERT_FALSE(bootstrap_result);
    EXPECT_EQ(bootstrap_result.error().code, clash_native::core::ErrorCode::configuration);

    clash_native::dns::ResolverDependencyGraph direct_bootstrap;
    ASSERT_TRUE(
        direct_bootstrap.add_resolver("bootstrap", clash_native::dns::ResolverRole::bootstrap));
    ASSERT_TRUE(direct_bootstrap.add_outbound("direct"));
    ASSERT_TRUE(direct_bootstrap.add_dependency("bootstrap", "direct"));
    EXPECT_TRUE(direct_bootstrap.validate());

    clash_native::dns::ResolverDependencyGraph cycle;
    ASSERT_TRUE(cycle.add_resolver("default", clash_native::dns::ResolverRole::default_resolver));
    ASSERT_TRUE(cycle.add_resolver("direct", clash_native::dns::ResolverRole::direct));
    ASSERT_TRUE(cycle.add_dependency("default", "direct"));
    ASSERT_TRUE(cycle.add_dependency("direct", "default"));
    const auto cycle_result = cycle.validate();
    ASSERT_FALSE(cycle_result);
    EXPECT_EQ(cycle_result.error().code, clash_native::core::ErrorCode::configuration);
}

TEST(ResolverDependencyGraphTest, RejectsDuplicateResolverRoles) {
    clash_native::dns::ResolverDependencyGraph graph;
    ASSERT_TRUE(graph.add_resolver("bootstrap", clash_native::dns::ResolverRole::bootstrap));
    const auto result =
        graph.add_resolver("second-bootstrap", clash_native::dns::ResolverRole::bootstrap);
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::configuration);
}

TEST(ResolverDependencyGraphTest, ExposesNodeKindsAndDependencies) {
    clash_native::dns::ResolverDependencyGraph graph;
    ASSERT_TRUE(graph.add_resolver("default", clash_native::dns::ResolverRole::default_resolver));
    ASSERT_TRUE(graph.add_dns_upstream("dns"));
    ASSERT_TRUE(graph.add_dependency("default", "dns"));
    EXPECT_EQ(graph.kind("dns"), clash_native::dns::DependencyNodeKind::dns_upstream);
    const auto dependencies = graph.dependencies("default");
    ASSERT_NE(dependencies, nullptr);
    ASSERT_EQ(dependencies->size(), 1U);
    EXPECT_EQ(dependencies->front(), "dns");
    EXPECT_FALSE(graph.kind("missing"));
    EXPECT_EQ(graph.dependencies("missing"), nullptr);
}

TEST(ResolverDependencyGraphTest, ValidatesUnifiedResolverAndOutboundDependencies) {
    clash_native::dns::ResolverDependencyGraph graph;
    ASSERT_TRUE(graph.add_resolver("default", clash_native::dns::ResolverRole::default_resolver));
    ASSERT_TRUE(graph.add_dns_upstream("dns-primary"));
    ASSERT_TRUE(graph.add_outbound("direct"));
    ASSERT_TRUE(graph.add_outbound_group("proxy-group"));
    ASSERT_TRUE(graph.add_proxy_endpoint("proxy-endpoint"));
    ASSERT_TRUE(graph.add_dependency("default", "dns-primary"));
    ASSERT_TRUE(graph.add_dependency("dns-primary", "direct"));
    ASSERT_TRUE(graph.add_dependency("proxy-endpoint", "default"));
    ASSERT_TRUE(graph.add_dependency("proxy-group", "proxy-endpoint"));
    ASSERT_TRUE(graph.validate());

    ASSERT_TRUE(graph.add_dependency("direct", "proxy-group"));
    const auto cycle = graph.validate();
    ASSERT_FALSE(cycle);
    EXPECT_EQ(cycle.error().code, clash_native::core::ErrorCode::configuration);
}
