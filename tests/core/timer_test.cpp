#include <clash_native/async/timer.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <exception>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <utility>

#include <boost/asio/io_context.hpp>

#include <exec/async_scope.hpp>
#include <stdexec/execution.hpp>

#include "async_test_helpers.hpp"

namespace {

using namespace std::chrono_literals;
using namespace clash_native::async;
using clash_native::async::test::EventReceiver;
using clash_native::async::test::OpHolder;
using clash_native::async::test::StopEnv;
using clash_native::async::test::sync_wait_void;
using clash_native::async::test::wait_get;

using VoidEvent = EventReceiver<int>::Event;
using VoidOutcome = EventReceiver<int>::Outcome;

struct TimerFixture : ::testing::Test {
    boost::asio::io_context context;
    boost::asio::any_io_executor executor{context.get_executor()};
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> guard{
        context.get_executor()};
    std::thread runner{[this] { context.run(); }};

    ~TimerFixture() override {
        guard.reset();
        context.stop();
        if (runner.joinable()) {
            runner.join();
        }
    }
};

TEST_F(TimerFixture, SleepCompletesOnExpiry) {
    auto sender = sleep_after(executor, 5ms) | stdexec::then([] { return 7; });
    std::promise<VoidEvent> done;
    auto future = done.get_future();
    OpHolder parked(std::move(sender), EventReceiver<int>{{}, &done});
    parked.start();
    EXPECT_EQ(wait_get(future).value, std::optional<int>(7));
}

// Timer sender behind a scope: stopping the scope cancels the pending sleep
// through the aborter, completing stopped instead of waiting out the delay.
TEST_F(TimerFixture, StopCancelsPendingSleep) {
    exec::async_scope scope;
    stdexec::inplace_stop_source outer;
    std::promise<VoidEvent> done;
    auto future = done.get_future();
    auto sleeper = sleep_after(executor, 30s) | stdexec::then([] { return 1; });
    OpHolder parked(std::move(sleeper), EventReceiver<int>{{outer.get_token()}, &done});
    parked.start();
    EXPECT_EQ(future.wait_for(20ms), std::future_status::timeout);
    outer.request_stop();
    EXPECT_EQ(wait_get(future).outcome, VoidOutcome::kStopped);
    parked.reset();
    auto empty = stdexec::sync_wait(scope.on_empty());
    ASSERT_TRUE(empty.has_value());
}

TEST_F(TimerFixture, SleepUntilDeadline) {
    auto sender = sleep_until(executor, std::chrono::steady_clock::now() + 5ms) |
                  stdexec::then([] { return 3; });
    std::promise<VoidEvent> done;
    auto future = done.get_future();
    OpHolder parked(std::move(sender), EventReceiver<int>{{}, &done});
    parked.start();
    EXPECT_EQ(wait_get(future).value, std::optional<int>(3));
}

// with_timeout: fast work wins and the timeout branch never builds.
TEST_F(TimerFixture, WithTimeoutWorkWins) {
    auto work = stdexec::just(std::string("fast"));
    auto task = with_timeout<std::string>(executor, 5s, std::move(work),
                                          []() -> std::string { return std::string("slow"); });
    auto result = stdexec::sync_wait(std::move(task));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(std::get<0>(*result), "fast");
}

// with_timeout: expired sleep builds the timeout value in band.
TEST_F(TimerFixture, WithTimeoutExpiryBuildsValue) {
    auto work = sleep_after(executor, 30s) | stdexec::then([] { return std::string("work"); });
    auto task = with_timeout<std::string>(executor, 5ms, std::move(work),
                                          []() -> std::string { return std::string("timeout"); });
    auto result = stdexec::sync_wait(std::move(task));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(std::get<0>(*result), "timeout");
}

} // namespace
