#include <clash_native/dns/bootstrap_resolver.hpp>

#include <boost/asio/post.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <memory>
#include <vector>

namespace {

using AddressResult = clash_native::core::Result<std::vector<boost::asio::ip::address>>;

class FixedBootstrapResolver final : public clash_native::dns::BootstrapResolver {
  public:
    FixedBootstrapResolver(clash_native::runtime::AsioRuntime &runtime,
                           boost::asio::ip::address address)
        : runtime_(runtime), address_(std::move(address)) {}

    RequestId resolve(std::string, std::chrono::steady_clock::time_point,
                      Handler handler) override {
        ++calls_;
        boost::asio::post(runtime_.context(), [handler = std::move(handler), address = address_]() {
            handler(std::vector<boost::asio::ip::address>{address});
        });
        return 1;
    }

    void cancel(RequestId) noexcept override {}
    void stop() noexcept override { stopped_ = true; }
    int calls() const noexcept { return calls_; }
    bool stopped() const noexcept { return stopped_; }

  private:
    clash_native::runtime::AsioRuntime &runtime_;
    boost::asio::ip::address address_;
    int calls_ = 0;
    bool stopped_ = false;
};

} // namespace

TEST(BootstrapResolverTest, BuiltInServersKeepTheConfiguredOrder) {
    const auto servers = clash_native::dns::default_bootstrap_dns_servers();
    ASSERT_EQ(servers.size(), 6U);
    EXPECT_EQ(servers[0].address().to_string(), "223.5.5.5");
    EXPECT_EQ(servers[1].address().to_string(), "223.6.6.6");
    EXPECT_EQ(servers[2].address().to_string(), "1.1.1.1");
    EXPECT_EQ(servers[3].address().to_string(), "1.0.0.1");
    EXPECT_EQ(servers[4].address().to_string(), "8.8.8.8");
    EXPECT_EQ(servers[5].address().to_string(), "8.8.4.4");
}

TEST(BootstrapResolverTest, FallsBackToTheSystemAdapterAfterBootstrapCandidates) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    auto system = std::make_shared<FixedBootstrapResolver>(
        runtime, boost::asio::ip::make_address("192.0.2.99"));
    const auto resolver = clash_native::dns::make_bootstrap_resolver(runtime, {}, system);
    std::promise<AddressResult> result_promise;
    auto result_future = result_promise.get_future();

    runtime.start();
    resolver->resolve(
        "bootstrap.test", std::chrono::steady_clock::now() - std::chrono::milliseconds(1),
        [&result_promise](AddressResult result) { result_promise.set_value(std::move(result)); });

    ASSERT_EQ(result_future.wait_for(std::chrono::seconds(1)), std::future_status::ready);
    const auto result = result_future.get();
    ASSERT_TRUE(result);
    ASSERT_EQ(result.value().size(), 1U);
    EXPECT_EQ(result.value().front().to_string(), "192.0.2.99");
    EXPECT_EQ(system->calls(), 1);
    resolver->stop();
    EXPECT_TRUE(system->stopped());
    runtime.stop();
}

TEST(BootstrapResolverTest, ResolvesLocalhostThroughTheSystemAdapter) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    const auto resolver = clash_native::dns::make_system_bootstrap_resolver(runtime);
    std::promise<AddressResult> result_promise;
    auto result_future = result_promise.get_future();

    runtime.start();
    resolver->resolve(
        "localhost", std::chrono::steady_clock::now() + std::chrono::seconds(2),
        [&result_promise](AddressResult result) { result_promise.set_value(std::move(result)); });

    ASSERT_EQ(result_future.wait_for(std::chrono::seconds(3)), std::future_status::ready);
    const auto result = result_future.get();
    ASSERT_TRUE(result);
    ASSERT_FALSE(result.value().empty());
    resolver->stop();
    runtime.stop();
}

TEST(BootstrapResolverTest, CancellationCompletesExactlyOnce) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    const auto resolver = clash_native::dns::make_system_bootstrap_resolver(runtime);
    std::promise<AddressResult> result_promise;
    auto result_future = result_promise.get_future();

    runtime.start();
    boost::asio::post(runtime.context(), [&resolver, &result_promise] {
        const auto request_id = resolver->resolve(
            "localhost", std::chrono::steady_clock::now() + std::chrono::minutes(1),
            [&result_promise](AddressResult result) {
                result_promise.set_value(std::move(result));
            });
        resolver->cancel(request_id);
    });

    ASSERT_EQ(result_future.wait_for(std::chrono::seconds(3)), std::future_status::ready);
    const auto result = result_future.get();
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::cancelled);
    resolver->stop();
    runtime.stop();
}
