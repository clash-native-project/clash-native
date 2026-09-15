#include <clash_native/runtime/runtime_set.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <stdexcept>

using namespace std::chrono_literals;

TEST(RuntimeSetTest, RejectsAnEmptySet) {
    EXPECT_THROW(clash_native::runtime::RuntimeSet(0), std::invalid_argument);
}

TEST(RuntimeSetTest, StartsEachIndependentRuntime) {
    clash_native::runtime::RuntimeSet runtimes(2);
    ASSERT_EQ(runtimes.size(), 2);

    std::promise<void> first_completion;
    std::promise<void> second_completion;
    auto first_future = first_completion.get_future();
    auto second_future = second_completion.get_future();

    runtimes.start();
    EXPECT_TRUE(runtimes.runtime(0).running());
    EXPECT_TRUE(runtimes.runtime(1).running());
    runtimes.scheduler(0).post([&first_completion] { first_completion.set_value(); });
    runtimes.scheduler(1).post([&second_completion] { second_completion.set_value(); });

    EXPECT_EQ(first_future.wait_for(1s), std::future_status::ready);
    EXPECT_EQ(second_future.wait_for(1s), std::future_status::ready);

    runtimes.stop();
    EXPECT_FALSE(runtimes.runtime(0).running());
    EXPECT_FALSE(runtimes.runtime(1).running());
}

TEST(RuntimeSetTest, ExposesSchedulerForASingleRuntime) {
    clash_native::runtime::AsioRuntime runtime;
    std::promise<void> completion;
    auto future = completion.get_future();

    runtime.start();
    runtime.scheduler().post([&completion] { completion.set_value(); });

    EXPECT_EQ(future.wait_for(1s), std::future_status::ready);
    runtime.stop();
}
