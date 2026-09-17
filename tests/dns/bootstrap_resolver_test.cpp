#include <clash_native/dns/bootstrap_resolver.hpp>

#include <boost/asio/post.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <vector>

namespace {

using AddressResult = clash_native::core::Result<std::vector<boost::asio::ip::address>>;

} // namespace

TEST(BootstrapResolverTest, ResolvesLocalhostThroughTheSystemAdapter) {
    clash_native::runtime::AsioRuntime runtime;
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
    clash_native::runtime::AsioRuntime runtime;
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
