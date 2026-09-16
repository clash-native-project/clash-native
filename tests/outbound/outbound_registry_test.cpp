#include <clash_native/outbound/builtin_outbound.hpp>
#include <clash_native/outbound/outbound_registry.hpp>
#include <clash_native/runtime/asio_runtime.hpp>

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

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

TEST(OutboundRegistryTest, SelectsASharedSnapshotConcurrently) {
    clash_native::outbound::OutboundRegistry registry;
    ASSERT_TRUE(registry.add_outbound("first", std::make_shared<StubOutbound>("first")));
    ASSERT_TRUE(registry.add_outbound("second", std::make_shared<StubOutbound>("second")));
    ASSERT_TRUE(registry.add_group("balanced", {"first", "second"}));
    ASSERT_TRUE(registry.validate());
    const auto snapshot = registry.snapshot();

    constexpr std::size_t thread_count = 4;
    constexpr std::size_t selections_per_thread = 250;
    std::atomic_bool success{true};
    std::vector<std::thread> threads;
    threads.reserve(thread_count);
    for (std::size_t index = 0; index < thread_count; ++index) {
        threads.emplace_back([snapshot, &success] {
            for (std::size_t selection = 0; selection < selections_per_thread; ++selection) {
                const auto result = snapshot->select("balanced");
                if (!result) {
                    success.store(false, std::memory_order_relaxed);
                }
            }
        });
    }
    for (auto &thread : threads) {
        thread.join();
    }
    EXPECT_TRUE(success.load(std::memory_order_relaxed));
}

TEST(DirectOutboundTest, OpensAnIpDatagramForDnsEgress) {
    clash_native::runtime::AsioRuntime runtime;
    boost::asio::ip::udp::socket receiver(runtime.context(),
                                          {boost::asio::ip::address_v4::loopback(), 0});
    const auto endpoint = receiver.local_endpoint();
    clash_native::outbound::DirectOutbound outbound(runtime);

    std::unique_ptr<clash_native::core::DatagramHandle> handle;
    clash_native::core::DatagramOpenResult result;
    outbound.open_datagram(
        {clash_native::core::Destination::address(endpoint.address(), endpoint.port())},
        [&handle, &result](clash_native::core::DatagramOpenResult opened) {
            result = std::move(opened);
            handle = std::move(result.handle);
        });
    ASSERT_EQ(result.status, clash_native::core::OpenStatus::opened);
    ASSERT_NE(handle, nullptr);
    EXPECT_EQ(result.semantics, clash_native::core::DatagramSemantics::fixed_destination);

    std::array<std::uint8_t, 32> buffer{};
    auto received = std::make_shared<std::promise<std::size_t>>();
    auto future = received->get_future();
    boost::asio::ip::udp::endpoint sender;
    receiver.async_receive_from(
        boost::asio::buffer(buffer), sender,
        [received](const boost::system::error_code &error, std::size_t size) {
            received->set_value(error ? 0 : size);
        });
    runtime.start();

    const std::string payload = "dns-egress";
    handle->async_send_to(boost::asio::buffer(payload), endpoint,
                          [](const boost::system::error_code &, std::size_t) {});
    ASSERT_EQ(future.wait_for(std::chrono::seconds(1)), std::future_status::ready);
    EXPECT_EQ(future.get(), payload.size());

    handle->close();
    boost::system::error_code ignored;
    receiver.close(ignored);
    runtime.stop();
}
