#include <clash_native/runtime/asio_runtime.hpp>

#include <gtest/gtest.h>

#include <boost/asio/post.hpp>

#include <chrono>
#include <future>

using namespace std::chrono_literals;

TEST(AsioRuntimeTest, RunsPostedWork) {
    clash_native::runtime::AsioRuntime runtime;
    std::promise<void> completion;
    auto future = completion.get_future();

    runtime.start();
    boost::asio::post(runtime.context(), [&completion] { completion.set_value(); });

    EXPECT_EQ(future.wait_for(1s), std::future_status::ready);
    runtime.stop();
}

TEST(AsioRuntimeTest, DrainsPostedWorkWhenStopping) {
    clash_native::runtime::AsioRuntime runtime;
    std::promise<void> completion;
    auto future = completion.get_future();

    runtime.start();
    boost::asio::post(runtime.context(), [&completion] { completion.set_value(); });

    runtime.stop();

    EXPECT_EQ(future.wait_for(0s), std::future_status::ready);
}
