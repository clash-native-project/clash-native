#include <clash_native/async/async.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <stdexcept>
#include <thread>
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
using BoolEvent = EventReceiver<bool>::Event;
using BoolOutcome = EventReceiver<bool>::Outcome;

TEST(OneshotTest, DeliversValueSentBeforeReceive) {
    auto [tx, rx] = oneshot::channel<int>();
    EXPECT_TRUE(tx.send(42));
    EXPECT_EQ(sync_get(std::move(rx)), std::optional<int>(42));
}

TEST(OneshotTest, SecondSendFails) {
    auto [tx, rx] = oneshot::channel<int>();
    EXPECT_TRUE(tx.send(1));
    EXPECT_FALSE(tx.send(2));
    EXPECT_EQ(sync_get(std::move(rx)), std::optional<int>(1));
}

TEST(OneshotTest, CloseDeliversEmpty) {
    auto [tx, rx] = oneshot::channel<int>();
    tx.close();
    EXPECT_EQ(sync_get(std::move(rx)), std::nullopt);
}

TEST(OneshotTest, ErrorPropagates) {
    auto [tx, rx] = oneshot::channel<int>();
    EXPECT_TRUE(tx.send_error(std::make_exception_ptr(std::runtime_error("boom"))));
    EXPECT_THROW((void)sync_get(std::move(rx)), std::runtime_error);
}

TEST(OneshotTest, PrestoppedTokenCancelsReceive) {
    auto [tx, rx] = oneshot::channel<int>();
    stdexec::inplace_stop_source source;
    source.request_stop();
    std::promise<IntEvent> done;
    auto future = done.get_future();
    auto op = stdexec::connect(std::move(rx),
                               EventReceiver<std::optional<int>>{{source.get_token()}, &done});
    stdexec::start(op);
    EXPECT_EQ(wait_get(future).outcome, IntOutcome::kStopped);
    // The value is still there for a later, unstopped receive.
    EXPECT_TRUE(tx.send(7));
}

TEST(OneshotTest, StopRequestCancelsParkedReceive) {
    auto [tx, rx] = oneshot::channel<int>();
    stdexec::inplace_stop_source source;
    std::promise<IntEvent> done;
    auto future = done.get_future();
    OpHolder parked(std::move(rx), EventReceiver<std::optional<int>>{{source.get_token()}, &done});
    parked.start();
    EXPECT_EQ(future.wait_for(20ms), std::future_status::timeout);
    std::thread stopper([&source] { source.request_stop(); });
    stopper.join();
    EXPECT_EQ(wait_get(future).outcome, IntOutcome::kStopped);
    EXPECT_TRUE(tx.receiver_detached());
    EXPECT_FALSE(tx.send(1));
}

TEST(OneshotTest, DestroyingParkedReceiveDetaches) {
    auto [tx, rx] = oneshot::channel<int>();
    stdexec::inplace_stop_source source;
    std::promise<IntEvent> done;
    {
        OpHolder parked(std::move(rx),
                        EventReceiver<std::optional<int>>{{source.get_token()}, &done});
        parked.start();
        EXPECT_EQ(done.get_future().wait_for(20ms), std::future_status::timeout);
    }
    EXPECT_TRUE(tx.receiver_detached());
    EXPECT_FALSE(tx.send(1));
}

TEST(MpscTest, UnboundedKeepsFifoOrder) {
    auto [tx, rx] = mpsc::unbounded<int>();
    EXPECT_TRUE(tx.send(1));
    EXPECT_TRUE(tx.send(2));
    EXPECT_TRUE(tx.send(3));
    EXPECT_EQ(sync_get(rx.recv()), std::optional<int>(1));
    EXPECT_EQ(sync_get(rx.recv()), std::optional<int>(2));
    EXPECT_EQ(sync_get(rx.recv()), std::optional<int>(3));
    tx.close();
    EXPECT_EQ(sync_get(rx.recv()), std::nullopt);
}

TEST(MpscTest, LastSenderClosingDrainsThenEnds) {
    auto [tx, rx] = mpsc::unbounded<int>();
    auto second = tx;
    EXPECT_TRUE(tx.send(1));
    EXPECT_TRUE(second.send(2));
    tx.close();
    second.close();
    EXPECT_EQ(sync_get(rx.recv()), std::optional<int>(1));
    EXPECT_EQ(sync_get(rx.recv()), std::optional<int>(2));
    EXPECT_EQ(sync_get(rx.recv()), std::nullopt);
}

TEST(MpscTest, MultipleProducerThreads) {
    auto [tx, rx] = mpsc::unbounded<int>();
    constexpr int kThreads = 4;
    constexpr int kPerThread = 250;
    std::vector<std::thread> producers;
    for (int t = 0; t < kThreads; ++t) {
        producers.emplace_back([tx, t] {
            for (int i = 0; i < kPerThread; ++i) {
                EXPECT_TRUE(tx.send(t * kPerThread + i));
            }
        });
    }
    for (auto &producer : producers) {
        producer.join();
    }
    tx.close();
    std::vector<bool> seen(kThreads * kPerThread, false);
    for (int i = 0; i < kThreads * kPerThread; ++i) {
        auto item = sync_get(rx.recv());
        ASSERT_TRUE(item.has_value());
        ASSERT_GE(*item, 0);
        ASSERT_LT(*item, kThreads * kPerThread);
        seen[*item] = true;
    }
    EXPECT_EQ(sync_get(rx.recv()), std::nullopt);
    for (bool got : seen) {
        EXPECT_TRUE(got);
    }
}

TEST(MpscTest, BoundedBackpressureParksAndUnparks) {
    auto [tx, rx] = mpsc::bounded<int>(1);
    EXPECT_TRUE(sync_get(tx.send(1)));
    std::promise<BoolEvent> done;
    auto future = done.get_future();
    OpHolder parked(tx.send(2), EventReceiver<bool>{{}, &done});
    parked.start();
    EXPECT_EQ(future.wait_for(20ms), std::future_status::timeout);
    EXPECT_EQ(sync_get(rx.recv()), std::optional<int>(1));
    auto parked_event = wait_get(future);
    EXPECT_EQ(parked_event.outcome, BoolOutcome::kValue);
    ASSERT_TRUE(parked_event.value.has_value());
    EXPECT_TRUE(*parked_event.value);
    EXPECT_EQ(sync_get(rx.recv()), std::optional<int>(2));
}

TEST(MpscTest, BoundedSendOnClosedCompletesFalse) {
    auto [tx, rx] = mpsc::bounded<int>(1);
    rx.close();
    EXPECT_FALSE(sync_get(tx.send(1)));
    EXPECT_EQ(tx.remaining_capacity(), std::size_t{1});
}

TEST(MpscTest, StopCancelsParkedSendAndWithdrawsValue) {
    auto [tx, rx] = mpsc::bounded<int>(1);
    EXPECT_TRUE(sync_get(tx.send(1)));
    stdexec::inplace_stop_source source;
    std::promise<BoolEvent> done;
    auto future = done.get_future();
    OpHolder parked(tx.send(2), EventReceiver<bool>{{source.get_token()}, &done});
    parked.start();
    EXPECT_EQ(future.wait_for(20ms), std::future_status::timeout);
    source.request_stop();
    EXPECT_EQ(wait_get(future).outcome, BoolOutcome::kStopped);
    // The withdrawn value never enters the channel.
    EXPECT_EQ(rx.try_recv(), std::optional<int>(1));
    tx.close();
    EXPECT_EQ(sync_get(rx.recv()), std::nullopt);
    EXPECT_EQ(tx.remaining_capacity(), std::size_t{1});
}

TEST(MpscTest, DestroyingParkedSendWithdrawsValue) {
    auto [tx, rx] = mpsc::bounded<int>(1);
    EXPECT_TRUE(sync_get(tx.send(1)));
    std::promise<BoolEvent> done;
    {
        OpHolder parked(tx.send(2), EventReceiver<bool>{{}, &done});
        parked.start();
        EXPECT_EQ(done.get_future().wait_for(20ms), std::future_status::timeout);
    }
    EXPECT_EQ(rx.try_recv(), std::optional<int>(1));
    EXPECT_EQ(tx.remaining_capacity(), std::size_t{1});
}

TEST(MpscTest, RendezvousHandsOffDirectly) {
    auto [tx, rx] = mpsc::bounded<int>(0);
    std::promise<IntEvent> done;
    auto future = done.get_future();
    OpHolder waiter(rx.recv(), EventReceiver<std::optional<int>>{{}, &done});
    waiter.start();
    EXPECT_EQ(future.wait_for(20ms), std::future_status::timeout);
    EXPECT_TRUE(sync_get(tx.send(7)));
    auto event = wait_get(future);
    EXPECT_EQ(event.outcome, IntOutcome::kValue);
    ASSERT_TRUE(event.value.has_value());
    EXPECT_EQ(*event.value, std::optional<int>(7));
}

TEST(MpscTest, RendezvousSendParksUntilReceive) {
    auto [tx, rx] = mpsc::bounded<int>(0);
    std::promise<BoolEvent> done;
    auto future = done.get_future();
    OpHolder parked(tx.send(9), EventReceiver<bool>{{}, &done});
    parked.start();
    EXPECT_EQ(future.wait_for(20ms), std::future_status::timeout);
    EXPECT_EQ(sync_get(rx.recv()), std::optional<int>(9));
    auto parked_event = wait_get(future);
    EXPECT_EQ(parked_event.outcome, BoolOutcome::kValue);
    ASSERT_TRUE(parked_event.value.has_value());
    EXPECT_TRUE(*parked_event.value);
}

TEST(MpscTest, ConcurrentReceiveFailsLoudly) {
    auto [tx, rx] = mpsc::unbounded<int>();
    stdexec::inplace_stop_source source;
    std::promise<IntEvent> done;
    auto future = done.get_future();
    auto first = rx.recv();
    auto second = rx.recv();
    OpHolder parked(std::move(first),
                    EventReceiver<std::optional<int>>{{source.get_token()}, &done});
    parked.start();
    // A second receive while one is parked reports the violation instead of
    // clobbering the parked wait.
    EXPECT_THROW((void)sync_get(std::move(second)), std::logic_error);
    // The parked wait is untouched and still delivers.
    EXPECT_TRUE(tx.send(3));
    auto event = wait_get(future);
    EXPECT_EQ(event.outcome, IntOutcome::kValue);
    ASSERT_TRUE(event.value.has_value());
    EXPECT_EQ(*event.value, std::optional<int>(3));
}

TEST(MpscTest, TryRecvIsNonBlocking) {
    auto [tx, rx] = mpsc::unbounded<int>();
    EXPECT_EQ(rx.try_recv(), std::nullopt);
    EXPECT_TRUE(tx.send(5));
    EXPECT_EQ(rx.try_recv(), std::optional<int>(5));
    EXPECT_EQ(rx.try_recv(), std::nullopt);
}

TEST(MpscTest, MoveOnlyPayloadsFlowThrough) {
    auto [tx, rx] = mpsc::unbounded<std::unique_ptr<int>>();
    tx.send(std::make_unique<int>(11));
    auto item = sync_get(rx.recv());
    ASSERT_TRUE(item.has_value());
    EXPECT_EQ(**item, 11);
}

} // namespace
