#include <clash_native/async/async.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <stdexcept>
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

TEST(BroadcastTest, EveryReceiverSeesEveryValue) {
    auto [tx, rx1] = broadcast::channel<int>(8);
    auto rx2 = tx.subscribe();
    EXPECT_EQ(tx.receiver_count(), 2);
    EXPECT_TRUE(tx.send(1));
    EXPECT_TRUE(tx.send(2));
    tx.close();
    EXPECT_EQ(collect_all(std::move(rx1)), (std::vector<int>{1, 2}));
    EXPECT_EQ(collect_all(std::move(rx2)), (std::vector<int>{1, 2}));
}

TEST(BroadcastTest, LateSubscriberSeesOnlyNewValues) {
    auto [tx, rx1] = broadcast::channel<int>(8);
    EXPECT_TRUE(tx.send(1));
    auto rx_late = tx.subscribe();
    EXPECT_TRUE(tx.send(2));
    tx.close();
    EXPECT_EQ(collect_all(std::move(rx1)), (std::vector<int>{1, 2}));
    EXPECT_EQ(collect_all(std::move(rx_late)), (std::vector<int>{2}));
}

TEST(BroadcastTest, SlowReceiverLagsWithSkippedCount) {
    auto [tx, rx] = broadcast::channel<int>(2);
    EXPECT_TRUE(tx.send(1));
    EXPECT_TRUE(tx.send(2));
    EXPECT_TRUE(tx.send(3)); // Evicts 1; the receiver never saw it.
    try {
        (void)sync_get(rx.recv());
        FAIL() << "expected broadcast_lagged";
    } catch (const broadcast::broadcast_lagged &lagged) {
        EXPECT_EQ(lagged.skipped, 1U);
    }
    // Resumes from the oldest buffered value without another lag.
    EXPECT_EQ(sync_get(rx.recv()), std::optional<int>(2));
    EXPECT_EQ(sync_get(rx.recv()), std::optional<int>(3));
}

TEST(BroadcastTest, LaggingLoopCatchesAndContinues) {
    auto [tx, rx] = broadcast::channel<int>(2);
    for (int i = 0; i < 10; ++i) {
        EXPECT_TRUE(tx.send(i));
    }
    tx.close();
    // Lag-tolerant manual loop: catch the lag, keep pulling.
    std::vector<int> seen;
    std::size_t skipped = 0;
    while (true) {
        try {
            auto item = sync_get(rx.recv());
            if (!item) {
                break;
            }
            seen.push_back(*item);
        } catch (const broadcast::broadcast_lagged &lagged) {
            skipped += lagged.skipped;
        }
    }
    EXPECT_GT(skipped, 0U);
    EXPECT_EQ(seen, (std::vector<int>{8, 9}));
    EXPECT_EQ(skipped + seen.size(), 10U);
}

TEST(BroadcastTest, SendFailsWithNoReceivers) {
    auto [tx, rx] = broadcast::channel<int>(4);
    rx.close();
    EXPECT_FALSE(tx.send(1));
    EXPECT_EQ(tx.receiver_count(), 0);
}

TEST(BroadcastTest, LastSenderCloseDrainsThenEnds) {
    auto [tx, rx] = broadcast::channel<int>(4);
    auto second = tx;
    EXPECT_TRUE(tx.send(7));
    EXPECT_EQ(tx.receiver_count(), 1);
    tx.close();
    second.close();
    EXPECT_EQ(sync_get(rx.recv()), std::optional<int>(7));
    EXPECT_EQ(sync_get(rx.recv()), std::nullopt);
}

TEST(BroadcastTest, MultipleProducerThreads) {
    auto [tx, rx] = broadcast::channel<int>(64);
    constexpr int kThreads = 4;
    constexpr int kPerThread = 100;
    std::atomic<int> sent{0};
    std::vector<std::thread> producers;
    for (int t = 0; t < kThreads; ++t) {
        producers.emplace_back([tx, t, &sent] {
            for (int i = 0; i < kPerThread; ++i) {
                if (tx.send(t * kPerThread + i)) {
                    sent.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }
    for (auto &producer : producers) {
        producer.join();
    }
    tx.close();
    // A single receiver sees a subsequence (lag may drop some under
    // contention, which is the documented broadcast contract).
    int received = 0;
    while (true) {
        try {
            auto item = sync_get(rx.recv());
            if (!item) {
                break;
            }
            ++received;
        } catch (const broadcast::broadcast_lagged &) {
        }
    }
    EXPECT_GT(received, 0);
    EXPECT_LE(received, sent.load());
}

TEST(BroadcastTest, StopCancelsParkedReceive) {
    auto [tx, rx] = broadcast::channel<int>(4);
    stdexec::inplace_stop_source source;
    std::promise<IntEvent> done;
    auto future = done.get_future();
    OpHolder parked(rx.recv(), EventReceiver<std::optional<int>>{{source.get_token()}, &done});
    parked.start();
    EXPECT_EQ(future.wait_for(20ms), std::future_status::timeout);
    source.request_stop();
    EXPECT_EQ(wait_get(future).outcome, IntOutcome::kStopped);
    tx.close();
}

TEST(BroadcastTest, DestroyingParkedReceiveCancels) {
    auto [tx, rx] = broadcast::channel<int>(4);
    stdexec::inplace_stop_source source;
    std::promise<IntEvent> done;
    {
        OpHolder parked(rx.recv(), EventReceiver<std::optional<int>>{{source.get_token()}, &done});
        parked.start();
        EXPECT_EQ(done.get_future().wait_for(20ms), std::future_status::timeout);
    }
    // Slot released: a later pull works and the value is intact.
    EXPECT_TRUE(tx.send(9));
    EXPECT_EQ(sync_get(rx.recv()), std::optional<int>(9));
    tx.close();
    EXPECT_EQ(sync_get(rx.recv()), std::nullopt);
}

TEST(BroadcastTest, CapacityMustBePositive) {
    EXPECT_THROW((void)broadcast::channel<int>(0), std::invalid_argument);
}

TEST(BroadcastTest, ComposesWithStreamOperators) {
    auto [tx, rx] = broadcast::channel<int>(8);
    for (int i = 0; i < 6; ++i) {
        EXPECT_TRUE(tx.send(i));
    }
    tx.close();
    using clash_native::async::async_filter;
    using clash_native::async::async_map;
    auto evens =
        collect_all(std::move(rx) | async_filter([](int value) { return value % 2 == 0; }) |
                    async_map([](int value) { return value * 10; }));
    EXPECT_EQ(evens, (std::vector<int>{0, 20, 40}));
}

} // namespace
