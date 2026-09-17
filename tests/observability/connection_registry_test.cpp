#include <clash_native/observability/connection_registry.hpp>

#include <gtest/gtest.h>

TEST(ConnectionRegistryTest, TracksAndSnapshotsConnectionMetadata) {
    clash_native::observability::ConnectionRegistry registry;
    const auto metadata = clash_native::core::ConnectionMetadata{
        clash_native::core::Network::tcp,
        {},
        clash_native::core::Destination::domain("example.test", 443),
        "listener",
        "socks5",
        {},
        {}};

    const auto id = registry.add(metadata, "direct");
    ASSERT_EQ(registry.size(), 1U);
    const auto record = registry.find(id);
    ASSERT_TRUE(record);
    EXPECT_EQ(record->metadata.destination.domain(), "example.test");
    EXPECT_EQ(record->outbound_id, "direct");

    ASSERT_TRUE(registry.update_outbound(id, "group-a"));
    EXPECT_EQ(registry.find(id)->outbound_id, "group-a");
    ASSERT_TRUE(registry.update_stats(id, 123, 456));
    EXPECT_EQ(registry.find(id)->left_to_right_bytes, 123U);
    EXPECT_EQ(registry.find(id)->right_to_left_bytes, 456U);
    EXPECT_FALSE(registry.update_stats(id + 1, 1, 1));
    EXPECT_EQ(registry.snapshot().size(), 1U);
    EXPECT_TRUE(registry.remove(id));
    EXPECT_FALSE(registry.find(id));
}
