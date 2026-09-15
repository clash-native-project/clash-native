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

TEST(ResolverDependencyGraphTest, RejectsBootstrapDependenciesAndCycles) {
    clash_native::dns::ResolverDependencyGraph bootstrap;
    ASSERT_TRUE(bootstrap.add_resolver("bootstrap", clash_native::dns::ResolverRole::bootstrap));
    ASSERT_TRUE(
        bootstrap.add_resolver("default", clash_native::dns::ResolverRole::default_resolver));
    const auto bootstrap_result = bootstrap.add_dependency("bootstrap", "default");
    ASSERT_FALSE(bootstrap_result);
    EXPECT_EQ(bootstrap_result.error().code, clash_native::core::ErrorCode::configuration);

    clash_native::dns::ResolverDependencyGraph cycle;
    ASSERT_TRUE(cycle.add_resolver("default", clash_native::dns::ResolverRole::default_resolver));
    ASSERT_TRUE(cycle.add_resolver("direct", clash_native::dns::ResolverRole::direct));
    ASSERT_TRUE(cycle.add_dependency("default", "direct"));
    ASSERT_TRUE(cycle.add_dependency("direct", "default"));
    const auto cycle_result = cycle.validate();
    ASSERT_FALSE(cycle_result);
    EXPECT_EQ(cycle_result.error().code, clash_native::core::ErrorCode::configuration);
}
