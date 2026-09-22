#include <clash_native/async/async.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <optional>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include "async_test_helpers.hpp"

namespace {

using namespace std::chrono_literals;
using namespace clash_native::async;
using clash_native::async::test::EventReceiver;
using clash_native::async::test::OpHolder;
using clash_native::async::test::sync_get;
using clash_native::async::test::wait_get;

using IntEvent = EventReceiver<std::optional<int>>::Event;
using IntOutcome = EventReceiver<std::optional<int>>::Outcome;

template <clash_native::async::async_stream S> auto collect_all(S &&stream) {
    auto result = stdexec::sync_wait(clash_native::async::collect(std::forward<S>(stream)));
    if (!result) {
        throw std::runtime_error("collect stopped");
    }
    return std::get<0>(std::move(*result));
}

TEST(WatchTest, BorrowSeesInitialValue) {
    auto [tx, rx] = watch::channel<int>(5);
    EXPECT_EQ(tx.borrow(), std::optional<int>(5));
    EXPECT_EQ(rx.borrow(), std::optional<int>(5));
    EXPECT_FALSE(rx.has_changed());
}

TEST(WatchTest, FirstPullParksUntilUpdate) {
    auto [tx, rx] = watch::channel<int>(0);
    std::promise<IntEvent> done;
    auto future = done.get_future();
    OpHolder parked(rx.changed(), EventReceiver<std::optional<int>>{{}, &done});
    parked.start();
    EXPECT_EQ(future.wait_for(20ms), std::future_status::timeout);
    EXPECT_TRUE(tx.send(1));
    auto event = wait_get(future);
    EXPECT_EQ(event.outcome, IntOutcome::kValue);
    ASSERT_TRUE(event.value.has_value());
    EXPECT_EQ(*event.value, std::optional<int>(1));
    EXPECT_EQ(rx.borrow(), std::optional<int>(1));
}

TEST(WatchTest, CoalescesRapidUpdates) {
    auto [tx, rx] = watch::channel<int>(0);
    EXPECT_TRUE(tx.send(1));
    EXPECT_TRUE(tx.send(2));
    EXPECT_TRUE(tx.send(3));
    // Only the latest value surfaces; intermediate versions coalesce.
    EXPECT_EQ(sync_get(rx.changed()), std::optional<int>(3));
    EXPECT_FALSE(rx.has_changed());
}

TEST(WatchTest, ReceiversObserveIndependently) {
    auto [tx, rx1] = watch::channel<std::string>(std::string("init"));
    auto rx2 = rx1;
    auto rx3 = tx.subscribe();
    EXPECT_TRUE(tx.send(std::string("update")));
    EXPECT_EQ(sync_get(rx1.changed()), std::optional<std::string>("update"));
    EXPECT_EQ(sync_get(rx2.changed()), std::optional<std::string>("update"));
    EXPECT_EQ(sync_get(rx3.changed()), std::optional<std::string>("update"));
}

TEST(WatchTest, CloseEndsAfterLastUpdate) {
    auto [tx, rx] = watch::channel<int>(1);
    EXPECT_TRUE(tx.send(2));
    tx.close();
    EXPECT_TRUE(tx.is_closed());
    EXPECT_EQ(sync_get(rx.changed()), std::optional<int>(2));
    EXPECT_EQ(sync_get(rx.changed()), std::nullopt);
}

TEST(WatchTest, SendAfterCloseFails) {
    auto [tx, rx] = watch::channel<int>(1);
    tx.close();
    EXPECT_FALSE(tx.send(2));
    EXPECT_EQ(sync_get(rx.changed()), std::nullopt);
    (void)rx;
}

TEST(WatchTest, MarkChangedReobservesCurrent) {
    auto [tx, rx] = watch::channel<int>(4);
    rx.mark_changed();
    EXPECT_TRUE(rx.has_changed());
    EXPECT_EQ(sync_get(rx.changed()), std::optional<int>(4));
    EXPECT_FALSE(rx.has_changed());
    (void)tx;
}

TEST(WatchTest, StopCancelsParkedWait) {
    auto [tx, rx] = watch::channel<int>(0);
    stdexec::inplace_stop_source source;
    std::promise<IntEvent> done;
    auto future = done.get_future();
    OpHolder parked(rx.changed(), EventReceiver<std::optional<int>>{{source.get_token()}, &done});
    parked.start();
    EXPECT_EQ(future.wait_for(20ms), std::future_status::timeout);
    source.request_stop();
    EXPECT_EQ(wait_get(future).outcome, IntOutcome::kStopped);
    // Version untouched: a later pull still waits for a real update.
    EXPECT_FALSE(rx.has_changed());
    EXPECT_TRUE(tx.send(8));
    EXPECT_EQ(sync_get(rx.changed()), std::optional<int>(8));
}

TEST(WatchTest, ProducerThreadWakesWaiters) {
    auto [tx, rx] = watch::channel<int>(0);
    std::thread producer([tx = std::move(tx)]() mutable {
        std::this_thread::sleep_for(20ms);
        EXPECT_TRUE(tx.send(42));
    });
    EXPECT_EQ(sync_get(rx.changed()), std::optional<int>(42));
    producer.join();
}

TEST(WatchTest, ComposesWithStreamOperators) {
    auto [tx, rx] = watch::channel<int>(0);
    EXPECT_TRUE(tx.send(1));
    EXPECT_TRUE(tx.send(2));
    EXPECT_TRUE(tx.send(3));
    tx.close();
    using clash_native::async::async_filter;
    using clash_native::async::async_map;
    // Coalescing means only the latest (3) is ever observed here.
    auto seen = collect_all(std::move(rx) | async_filter([](int value) { return value > 0; }) |
                            async_map([](int value) { return value * 2; }));
    EXPECT_EQ(seen, (std::vector<int>{6}));
}

} // namespace
