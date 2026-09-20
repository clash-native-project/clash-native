#include <clash_native/outbound/builtin_outbound.hpp>
#include <clash_native/outbound/outbound_registry.hpp>
#include <clash_native/outbound/shadowsocks_outbound.hpp>
#include <clash_native/runtime/asio_runtime.hpp>

#include <boost/asio/error.hpp>

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

boost::asio::ip::address_v4 udp_test_address(boost::asio::io_context &context) {
    boost::asio::ip::udp::socket probe(context);
    boost::system::error_code error;
    probe.open(boost::asio::ip::udp::v4(), error);
    if (!error) {
        probe.connect({boost::asio::ip::make_address_v4("192.0.2.1"), 9}, error);
        if (!error) {
            const auto local = probe.local_endpoint(error).address();
            if (!error && local.is_v4() && !local.is_loopback() && !local.is_unspecified()) {
                return local.to_v4();
            }
        }
    }
    return boost::asio::ip::address_v4::loopback();
}

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

TEST(ShadowsocksOutboundTest, RejectsEncryptedUdpDatagramsLargerThan1500Bytes) {
    struct Method {
        const char *name;
        std::size_t key_size;
    };
    constexpr std::array methods{Method{"aes-128-gcm", 16}, Method{"aes-256-gcm", 32},
                                 Method{"chacha20-ietf-poly1305", 32}};
    constexpr std::size_t encrypted_limit = 1500;
    constexpr std::size_t aead_tag_size = 16;
    constexpr std::size_t ipv4_proxy_address_size = 1 + 4 + 2;

    clash_native::runtime::AsioRuntime runtime;
    runtime.start();
    const auto test_address = udp_test_address(runtime.context());

    for (const auto &method : methods) {
        boost::asio::ip::udp::socket server(runtime.context(),
                                            {test_address, 0});
        clash_native::outbound::ShadowsocksOutbound outbound(
            runtime, {"test-shadowsocks", test_address.to_string(), server.local_endpoint().port(), method.name,
                      "test-password"});

        auto opened_promise =
            std::make_shared<std::promise<clash_native::core::DatagramOpenResult>>();
        auto opened_future = opened_promise->get_future();
        outbound.open_datagram({}, [opened_promise](clash_native::core::DatagramOpenResult result) {
            opened_promise->set_value(std::move(result));
        });
        ASSERT_EQ(opened_future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
        auto opened = opened_future.get();
        ASSERT_TRUE(opened.succeeded());
        auto handle = std::move(opened.handle);

        const auto destination =
            boost::asio::ip::udp::endpoint(test_address, 53);
        const auto payload_at_limit =
            encrypted_limit - method.key_size - ipv4_proxy_address_size - aead_tag_size;

        auto receive_promise = std::make_shared<std::promise<std::size_t>>();
        auto receive_future = receive_promise->get_future();
        std::array<std::uint8_t, encrypted_limit + 1> received{};
        boost::asio::ip::udp::endpoint sender;
        server.async_receive_from(
            boost::asio::buffer(received), sender,
            [receive_promise](const boost::system::error_code &error, std::size_t size) {
                receive_promise->set_value(error ? 0 : size);
            });

        std::vector<std::uint8_t> payload(payload_at_limit, 0x5a);
        auto send_promise =
            std::make_shared<std::promise<std::pair<boost::system::error_code, std::size_t>>>();
        auto send_future = send_promise->get_future();
        handle->async_send_to(
            boost::asio::buffer(payload), destination,
            [send_promise](const boost::system::error_code &error, std::size_t size) {
                send_promise->set_value({error, size});
            });
        ASSERT_EQ(send_future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
        const auto [send_error, sent_size] = send_future.get();
        EXPECT_FALSE(send_error);
        EXPECT_EQ(sent_size, payload.size());
        ASSERT_EQ(receive_future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
        EXPECT_EQ(receive_future.get(), encrypted_limit);

        payload.push_back(0x5a);
        auto oversized_promise =
            std::make_shared<std::promise<std::pair<boost::system::error_code, std::size_t>>>();
        auto oversized_future = oversized_promise->get_future();
        handle->async_send_to(
            boost::asio::buffer(payload), destination,
            [oversized_promise](const boost::system::error_code &error, std::size_t size) {
                oversized_promise->set_value({error, size});
            });
        ASSERT_EQ(oversized_future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
        const auto [oversized_error, oversized_sent_size] = oversized_future.get();
        EXPECT_EQ(oversized_error, boost::asio::error::message_size);
        EXPECT_EQ(oversized_sent_size, 0U);

        boost::system::error_code available_error;
        EXPECT_EQ(server.available(available_error), 0U);
        EXPECT_FALSE(available_error);
        handle->close();
    }

    runtime.stop();
}
