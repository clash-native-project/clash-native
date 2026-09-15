#include <clash_native/outbound/outbound_registry.hpp>

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

} // namespace

TEST(OutboundRegistryTest, ValidatesGroupsAndSelectsMembers) {
    clash_native::outbound::OutboundRegistry registry;
    const auto first = std::make_shared<StubOutbound>("first");
    const auto second = std::make_shared<StubOutbound>("second");
    ASSERT_TRUE(registry.add_outbound("first", first));
    ASSERT_TRUE(registry.add_outbound("second", second));
    ASSERT_TRUE(registry.add_group("balanced", {"first", "second"}));
    ASSERT_TRUE(registry.validate());

    const auto selected_first = registry.select("balanced");
    const auto selected_second = registry.select("balanced");
    ASSERT_TRUE(selected_first);
    ASSERT_TRUE(selected_second);
    EXPECT_EQ(selected_first.value()->descriptor().id, "first");
    EXPECT_EQ(selected_second.value()->descriptor().id, "second");

    const auto snapshot = registry.snapshot();
    EXPECT_TRUE(snapshot->validate());
}

TEST(OutboundRegistryTest, RejectsUnknownTargetsAndCycles) {
    clash_native::outbound::OutboundRegistry unknown;
    ASSERT_TRUE(unknown.add_group("broken", {"missing"}));
    const auto unknown_result = unknown.validate();
    ASSERT_FALSE(unknown_result);
    EXPECT_EQ(unknown_result.error().code, clash_native::core::ErrorCode::configuration);

    clash_native::outbound::OutboundRegistry cycle;
    ASSERT_TRUE(cycle.add_group("first", {"second"}));
    ASSERT_TRUE(cycle.add_group("second", {"first"}));
    const auto cycle_result = cycle.validate();
    ASSERT_FALSE(cycle_result);
    EXPECT_EQ(cycle_result.error().code, clash_native::core::ErrorCode::configuration);
}
