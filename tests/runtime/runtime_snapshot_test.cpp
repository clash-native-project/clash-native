#include <clash_native/runtime/runtime_snapshot.hpp>

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <utility>

namespace {

class StubOutbound final : public clash_native::core::Outbound {
  public:
    explicit StubOutbound(std::string id) : descriptor_{std::move(id), "stub"} {}

    const clash_native::core::OutboundDescriptor &descriptor() const noexcept override {
        return descriptor_;
    }

    clash_native::core::OutboundCapabilities capabilities() const noexcept override {
        return {false, clash_native::core::DatagramSemantics::unsupported};
    }

    void connect_stream(clash_native::core::StreamRequest,
                        clash_native::core::StreamOpenHandler handler) override {
        handler(clash_native::core::StreamOpenResult::unsupported());
    }

    void open_datagram(clash_native::core::DatagramRequest,
                       clash_native::core::DatagramOpenHandler handler) override {
        handler(clash_native::core::DatagramOpenResult::unsupported());
    }

  private:
    clash_native::core::OutboundDescriptor descriptor_;
};

clash_native::runtime::RuntimeSnapshotPtr make_snapshot(std::uint64_t generation,
                                                        std::string outbound_id) {
    clash_native::outbound::OutboundRegistry outbounds;
    EXPECT_TRUE(outbounds.add_outbound(outbound_id, std::make_shared<StubOutbound>(outbound_id)));
    EXPECT_TRUE(outbounds.validate());

    auto router = std::make_shared<clash_native::router::TrafficRouter>(
        clash_native::router::RouteAction::named(outbound_id));
    EXPECT_TRUE(router->validate(outbounds.ids()));

    return std::make_shared<const clash_native::runtime::RuntimeSnapshot>(
        clash_native::runtime::RuntimeSnapshot{generation, std::move(router), outbounds.snapshot(),
                                               nullptr, nullptr});
}

} // namespace

TEST(RuntimeSnapshotTest, PublishesValidatedImmutableSnapshots) {
    clash_native::runtime::RuntimeSnapshotStore store;
    const auto first = make_snapshot(1, "first");
    const auto second = make_snapshot(2, "second");

    EXPECT_FALSE(store.load());
    ASSERT_TRUE(store.publish(first));
    EXPECT_EQ(store.load(), first);
    ASSERT_TRUE(store.publish(second));
    EXPECT_EQ(store.load(), second);
    EXPECT_EQ(first->generation, 1);
    EXPECT_EQ(second->generation, 2);
}

TEST(RuntimeSnapshotTest, RejectsIncompleteSnapshotsWithoutReplacingCurrentValue) {
    clash_native::runtime::RuntimeSnapshotStore store;
    const auto current = make_snapshot(1, "current");
    ASSERT_TRUE(store.publish(current));

    const auto invalid = std::make_shared<const clash_native::runtime::RuntimeSnapshot>();
    const auto result = store.publish(invalid);
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::configuration);
    EXPECT_EQ(store.load(), current);
}

TEST(RuntimeSnapshotTest, RejectsStaleGenerationsWithoutReplacingCurrentValue) {
    clash_native::runtime::RuntimeSnapshotStore store;
    const auto current = make_snapshot(4, "current");
    ASSERT_TRUE(store.publish(current));

    const auto stale = make_snapshot(4, "stale");
    const auto result = store.publish(stale);
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::configuration);
    EXPECT_EQ(store.load(), current);
}
