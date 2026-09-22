#include <clash_native/async/async.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include "async_test_helpers.hpp"

namespace {

using namespace std::chrono_literals;
using namespace clash_native::async;
using clash_native::async::AnyAsyncStream;
using clash_native::async::async_filter;
using clash_native::async::async_flat_map;
using clash_native::async::async_fold;
using clash_native::async::async_for_each;
using clash_native::async::async_map;
using clash_native::async::async_merge;
using clash_native::async::async_scan;
using clash_native::async::async_skip;
using clash_native::async::async_skip_while;
using clash_native::async::async_stream;
using clash_native::async::async_take;
using clash_native::async::async_take_while;
using clash_native::async::async_zip;
using clash_native::async::collect;
using clash_native::async::count;
using clash_native::async::empty;
using clash_native::async::erase_stream;
using clash_native::async::first;
using clash_native::async::from_vector;
using clash_native::async::interval_on;
using clash_native::async::merge;
using clash_native::async::merge_concurrent;
using clash_native::async::next;
using clash_native::async::once;
using clash_native::async::test::EventReceiver;
using clash_native::async::test::OpHolder;
using clash_native::async::test::sync_get;
using clash_native::async::test::sync_wait_void;
using clash_native::async::test::wait_get;

static_assert(async_stream<mpsc::Receiver<int>>);
static_assert(async_stream<decltype(from_vector<int>({}))>);

template <async_stream S> auto collect_sync(S &&stream) {
    auto result = stdexec::sync_wait(collect(std::forward<S>(stream)));
    if (!result) {
        throw std::runtime_error("collect stopped");
    }
    return std::get<0>(std::move(*result));
}

// A stream that yields `remaining` items and then fails.
struct FailSender {
    using sender_concept = stdexec::sender_tag;
    using completion_signatures =
        stdexec::completion_signatures<stdexec::set_value_t(std::optional<int>),
                                       stdexec::set_error_t(std::exception_ptr),
                                       stdexec::set_stopped_t()>;
    int *remaining_ = nullptr;

    template <stdexec::receiver Receiver> struct OpState {
        using operation_state_concept = stdexec::operation_state_tag;
        int *remaining_ = nullptr;
        Receiver receiver_;
        void start() noexcept {
            if (*remaining_ > 0) {
                --(*remaining_);
                stdexec::set_value(std::move(receiver_), std::optional<int>(42));
            } else {
                stdexec::set_error(std::move(receiver_),
                                   std::make_exception_ptr(std::runtime_error("boom")));
            }
        }
    };

    template <stdexec::receiver Receiver> OpState<Receiver> connect(Receiver receiver) && {
        return {remaining_, std::move(receiver)};
    }
};

struct FailStream {
    using value_type = int;
    int remaining_ = 0;

    FailSender next() { return FailSender{&remaining_}; }
};

static_assert(async_stream<FailStream>);

struct TestClock {
    using scheduler_concept = stdexec::scheduler_tag;
    auto schedule_after(std::chrono::milliseconds delay) const noexcept {
        return stdexec::just() | stdexec::then([delay] { std::this_thread::sleep_for(delay); });
    }
    friend bool operator==(TestClock, TestClock) = default;
};

TEST(AsyncStreamTest, Factories) {
    EXPECT_EQ(collect_sync(empty<int>()), std::vector<int>{});
    EXPECT_EQ(collect_sync(once<int>(9)), std::vector<int>{9});
    EXPECT_EQ(collect_sync(from_vector<int>({1, 2, 3})), (std::vector<int>{1, 2, 3}));
}

TEST(AsyncStreamTest, DocumentedPipelineComposes) {
    auto pipeline = from_vector<int>({1, 2, 3, 4, 5}) |
                    async_map([](int value) { return value * 2; }) |
                    async_filter([](int value) { return value > 4; }) | async_take(2);
    EXPECT_EQ(collect_sync(std::move(pipeline)), (std::vector<int>{6, 8}));
    EXPECT_EQ(sync_get(async_fold(from_vector<int>({1, 2, 3}), 0, std::plus<>{})), 6);
}

TEST(AsyncStreamTest, TakeWhileSkipSkipWhileScan) {
    EXPECT_EQ(collect_sync(from_vector<int>({1, 2, 3, 1}) |
                           async_take_while([](int value) { return value < 3; })),
              (std::vector<int>{1, 2}));
    EXPECT_EQ(collect_sync(from_vector<int>({1, 2, 3, 4}) | async_skip(2)),
              (std::vector<int>{3, 4}));
    EXPECT_EQ(collect_sync(from_vector<int>({1, 2, 3, 1}) |
                           async_skip_while([](int value) { return value < 3; })),
              (std::vector<int>{3, 1}));
    EXPECT_EQ(collect_sync(from_vector<int>({1, 2, 3}) | async_scan(0, std::plus<>{})),
              (std::vector<int>{1, 3, 6}));
    EXPECT_EQ(collect_sync(from_vector<int>({1, 2}) | async_take(0)), std::vector<int>{});
    EXPECT_EQ(collect_sync(from_vector<int>({1}) | async_take(10)), std::vector<int>{1});
}

TEST(AsyncStreamTest, FlatMapExpands) {
    auto expanded = from_vector<int>({1, 2, 3}) |
                    async_flat_map([](int value) { return from_vector<int>({value, -value}); });
    EXPECT_EQ(collect_sync(std::move(expanded)), (std::vector<int>{1, -1, 2, -2, 3, -3}));
    auto with_empty =
        from_vector<int>({1, 2}) | async_flat_map([](int value) {
            return value == 1 ? erase_stream(from_vector<int>({})) : erase_stream(once(value));
        });
    EXPECT_EQ(collect_sync(std::move(with_empty)), std::vector<int>{2});
}

TEST(AsyncStreamTest, ZipStopsAtShorter) {
    auto zipped = async_zip(from_vector<int>({1, 2, 3}), from_vector<int>({10, 20}));
    auto pairs = collect_sync(std::move(zipped));
    ASSERT_EQ(pairs.size(), 2U);
    EXPECT_EQ(pairs[0], (std::pair<int, int>{1, 10}));
    EXPECT_EQ(pairs[1], (std::pair<int, int>{2, 20}));
}

TEST(AsyncStreamTest, MergeAlternatesAndEnds) {
    auto merged = merge(from_vector<int>({1, 3}), from_vector<int>({2, 4}));
    EXPECT_EQ(collect_sync(std::move(merged)), (std::vector<int>{1, 2, 3, 4}));
    auto with_empty = merge(empty<int>(), from_vector<int>({5}));
    EXPECT_EQ(collect_sync(std::move(with_empty)), std::vector<int>{5});
}

TEST(AsyncStreamTest, MergeConcurrentCollectsAll) {
    std::vector<decltype(from_vector<int>({}))> sources;
    sources.push_back(from_vector<int>({1, 2, 3}));
    sources.push_back(from_vector<int>({4, 5}));
    sources.push_back(from_vector<int>({6}));
    auto merged = collect_sync(async_merge(std::move(sources)));
    std::sort(merged.begin(), merged.end());
    EXPECT_EQ(merged, (std::vector<int>{1, 2, 3, 4, 5, 6}));
    std::vector<decltype(from_vector<int>({}))> none;
    EXPECT_EQ(collect_sync(merge_concurrent(std::move(none))), std::vector<int>{});
}

TEST(AsyncStreamTest, MergeConcurrentOverLiveChannel) {
    auto [tx, rx] = mpsc::unbounded<int>();
    std::vector<mpsc::Receiver<int>> sources;
    sources.push_back(std::move(rx));
    std::thread feeder([tx = std::move(tx)]() mutable {
        for (int i = 0; i < 100; ++i) {
            EXPECT_TRUE(tx.send(i));
        }
    });
    feeder.join();
    auto merged = collect_sync(async_merge(std::move(sources)));
    ASSERT_EQ(merged.size(), 100U);
    std::sort(merged.begin(), merged.end());
    for (int i = 0; i < 100; ++i) {
        EXPECT_EQ(merged[i], i);
    }
}

TEST(AsyncStreamTest, DroppingMergeStopsDrivers) {
    // Dropping the merged stream requests stop on the driver scope: the
    // parked driver wakes with stopped, delivers its sentinel, and exits, so
    // destruction completes synchronously instead of hanging.
    auto [tx, rx] = mpsc::unbounded<int>();
    std::vector<mpsc::Receiver<int>> sources;
    sources.push_back(std::move(rx));
    {
        auto merged = async_merge(std::move(sources));
        EXPECT_TRUE(tx.send(1));
        EXPECT_EQ(sync_get(next(merged)), std::optional<int>(1));
    }
    SUCCEED();
}

TEST(AsyncStreamTest, MergeConcurrentPropagatesError) {
    std::vector<FailStream> sources;
    sources.push_back(FailStream{2});
    EXPECT_THROW((void)collect_sync(async_merge(std::move(sources))), std::runtime_error);
}

TEST(AsyncStreamTest, Consumers) {
    int total = 0;
    sync_wait_void(async_for_each(from_vector<int>({1, 2, 3}), [&](int value) { total += value; }));
    EXPECT_EQ(total, 6);
    total = 0;
    sync_wait_void(from_vector<int>({4, 5}) | async_for_each([&](int value) { total += value; }));
    EXPECT_EQ(total, 9);
    EXPECT_EQ(sync_get(count(from_vector<int>({1, 2, 3, 4}))), 4U);
    EXPECT_EQ(sync_get(first(from_vector<int>({8, 9}))), std::optional<int>(8));
    EXPECT_EQ(sync_get(first(empty<int>())), std::nullopt);
}

TEST(AsyncStreamTest, MpscReceiverIsNativeStream) {
    auto [tx, rx] = mpsc::bounded<int>(8);
    EXPECT_TRUE(sync_get(tx.send(1)));
    EXPECT_TRUE(sync_get(tx.send(2)));
    EXPECT_TRUE(sync_get(tx.send(3)));
    tx.close();
    auto doubled = std::move(rx) | async_map([](int value) { return value * 2; });
    EXPECT_EQ(collect_sync(std::move(doubled)), (std::vector<int>{2, 4, 6}));
}

TEST(AsyncStreamTest, ErrorsPropagateThroughOperators) {
    EXPECT_THROW((void)collect_sync(FailStream{2} | async_map([](int value) { return value + 1; })),
                 std::runtime_error);
    EXPECT_THROW((void)collect_sync(FailStream{3} | async_filter([](int) { return true; })),
                 std::runtime_error);
}

TEST(AsyncStreamTest, MapFunctionExceptionsBecomeErrors) {
    auto bad = from_vector<int>({1, 2}) |
               async_map([](int) -> int { throw std::runtime_error("mapper failed"); });
    EXPECT_THROW((void)collect_sync(std::move(bad)), std::runtime_error);
}

TEST(AsyncStreamTest, StopPropagatesThroughOperators) {
    stdexec::inplace_stop_source source;
    source.request_stop();
    std::promise<EventReceiver<std::optional<int>>::Event> done;
    auto future = done.get_future();
    auto pipeline = from_vector<int>({1, 2, 3}) | async_map([](int value) { return value + 1; }) |
                    async_filter([](int) { return true; });
    auto op = stdexec::connect(next(pipeline),
                               EventReceiver<std::optional<int>>{{source.get_token()}, &done});
    stdexec::start(op);
    auto event = wait_get(future);
    EXPECT_EQ(event.outcome, EventReceiver<std::optional<int>>::Outcome::kStopped);
}

TEST(AsyncStreamTest, StoppedChannelPullKeepsValue) {
    auto [tx, rx] = mpsc::unbounded<int>();
    EXPECT_TRUE(tx.send(11));
    stdexec::inplace_stop_source source;
    source.request_stop();
    std::promise<EventReceiver<std::optional<int>>::Event> done;
    auto future = done.get_future();
    auto op =
        stdexec::connect(rx.recv(), EventReceiver<std::optional<int>>{{source.get_token()}, &done});
    stdexec::start(op);
    auto event = wait_get(future);
    EXPECT_EQ(event.outcome, EventReceiver<std::optional<int>>::Outcome::kStopped);
    EXPECT_EQ(rx.try_recv(), std::optional<int>(11));
}

TEST(AsyncStreamTest, ConsumersComposeWithSenderAlgorithms) {
    // Task-based consumers are ordinary senders: fan two pipelines out with
    // when_all and keep composing with then.
    auto left =
        collect(from_vector<int>({1, 2, 3}) | async_map([](int value) { return value * 2; }));
    auto right = async_fold(from_vector<int>({10, 20}), 0, std::plus<>{});
    auto joined = stdexec::when_all(std::move(left), std::move(right)) |
                  stdexec::then([](std::vector<int> values, int sum) {
                      return static_cast<int>(values.size()) + sum;
                  });
    EXPECT_EQ(sync_get(std::move(joined)), 33);
    // A consumer task also runs on a scheduler like any other sender.
    auto on_inline =
        stdexec::starts_on(stdexec::inline_scheduler{}, collect(from_vector<int>({7, 8})));
    EXPECT_EQ(sync_get(std::move(on_inline)), (std::vector<int>{7, 8}));
}

TEST(AsyncStreamTest, ComplexEventProcessingPipeline) {
    // Stage 1, ingest: 4 producer threads push disjoint ranges into 4
    // channels; the merge fan-in feeds filter -> map -> (type-erased)
    // flat_map -> collect. All assertions are order-independent.
    constexpr int kProducers = 4;
    constexpr int kPerProducer = 5;
    std::vector<mpsc::Receiver<int>> fan_in;
    std::vector<std::thread> producers;
    for (int t = 0; t < kProducers; ++t) {
        auto [tx, rx] = mpsc::unbounded<int>();
        fan_in.push_back(std::move(rx));
        producers.emplace_back([tx = std::move(tx), t] {
            for (int k = 0; k < kPerProducer; ++k) {
                EXPECT_TRUE(tx.send(t * 10 + k));
            }
        });
    }
    // The erase_stream stage in the middle proves a type-erased stream keeps
    // composing downstream.
    auto erased = erase_stream(async_merge(std::move(fan_in)) |
                               async_filter([](int value) { return value % 2 == 0; }) |
                               async_map([](int value) { return value * 2 + 1; }));
    auto ingested = collect_sync(std::move(erased) | async_flat_map([](int value) {
                                     return from_vector<int>({value, value + 1000});
                                 }));
    for (auto &producer : producers) {
        producer.join();
    }
    std::vector<int> expected;
    for (int t = 0; t < kProducers; ++t) {
        for (int k = 0; k < kPerProducer; ++k) {
            const int value = t * 10 + k;
            if (value % 2 != 0) {
                continue;
            }
            const int mapped = value * 2 + 1;
            expected.push_back(mapped);
            expected.push_back(mapped + 1000);
        }
    }
    std::sort(expected.begin(), expected.end());
    std::sort(ingested.begin(), ingested.end());
    EXPECT_EQ(ingested, expected);
    EXPECT_EQ(ingested.size(), 24U);
    // 420 (mapped base values) + 420 + 12 * 1000 (expanded copies).
    EXPECT_EQ(std::accumulate(ingested.begin(), ingested.end(), 0), 12840);

    // Stage 2, reshape: re-stream the sorted output, skip a prefix, bound it
    // with take_while, zip against an index stream, and verify both the
    // zipped pairs and a running sum over them.
    auto head = collect_sync(from_vector<int>(ingested) | async_skip(2) |
                             async_take_while([](int value) { return value < 1000; }));
    std::vector<int> expected_head(expected.begin() + 2, expected.end());
    expected_head.erase(std::remove_if(expected_head.begin(), expected_head.end(),
                                       [](int value) { return value >= 1000; }),
                        expected_head.end());
    EXPECT_EQ(head, expected_head);
    ASSERT_EQ(head.size(), 10U);

    std::vector<int> indices(64);
    std::iota(indices.begin(), indices.end(), 0);
    auto zipped = collect_sync(
        async_zip(from_vector<int>(head), from_vector<int>(indices)) |
        async_map([](std::pair<int, int> entry) { return entry.first - entry.second; }));
    std::vector<int> expected_zipped;
    for (std::size_t i = 0; i < head.size(); ++i) {
        expected_zipped.push_back(head[i] - static_cast<int>(i));
    }
    EXPECT_EQ(zipped, expected_zipped);

    auto running = collect_sync(from_vector<int>(zipped) | async_scan(0, std::plus<>{}));
    ASSERT_EQ(running.size(), zipped.size());
    EXPECT_EQ(running.back(), std::accumulate(zipped.begin(), zipped.end(), 0));

    std::atomic<std::size_t> seen{0};
    sync_wait_void(from_vector<int>(zipped) |
                   async_for_each([&](int) { seen.fetch_add(1, std::memory_order_relaxed); }));
    EXPECT_EQ(seen.load(), zipped.size());
}

TEST(AsyncStreamTest, SubscribePushesValuesAndCompletes) {
    auto [tx, rx] = mpsc::unbounded<int>();
    std::vector<int> seen;
    bool done = false;
    auto sub = subscribe(
        std::move(rx) | async_map([](int value) { return value + 1; }),
        [&](int value) { seen.push_back(value); }, [&] { done = true; },
        [&](std::exception_ptr) { FAIL() << "unexpected stream error"; });
    for (int i = 0; i < 5; ++i) {
        EXPECT_TRUE(tx.send(i));
    }
    tx.close();
    sync_wait_void(sub.on_empty());
    EXPECT_EQ(seen, (std::vector<int>{1, 2, 3, 4, 5}));
    EXPECT_TRUE(done);
}

TEST(AsyncStreamTest, SubscribeReportsError) {
    std::vector<int> seen;
    std::exception_ptr failure;
    bool done = false;
    auto sub = subscribe(
        FailStream{2}, [&](int value) { seen.push_back(value); }, [&] { done = true; },
        [&](std::exception_ptr error) { failure = error; });
    sync_wait_void(sub.on_empty());
    EXPECT_EQ(seen, (std::vector<int>{42, 42}));
    EXPECT_FALSE(done);
    ASSERT_TRUE((bool)failure);
    EXPECT_THROW(std::rethrow_exception(failure), std::runtime_error);
}

TEST(AsyncStreamTest, SubscribeSurfacesErrorAtJoin) {
    auto sub = subscribe(FailStream{1}, [&](int) {});
    EXPECT_THROW(sync_wait_void(sub.on_empty()), std::runtime_error);
}

TEST(AsyncStreamTest, UnsubscribeStopsDelivery) {
    auto [tx, rx] = mpsc::unbounded<int>();
    bool called = false;
    bool done = false;
    auto sub = subscribe(
        std::move(rx), [&](int) { called = true; }, [&] { done = true; },
        [&](std::exception_ptr) { FAIL() << "no error expected"; });
    sub.unsubscribe();
    sync_wait_void(sub.on_empty());
    EXPECT_FALSE(called);
    EXPECT_FALSE(done);
}

TEST(AsyncStreamTest, StreamMapBehavesLikeTokioExample) {
    // Heterogeneous sources (a live channel, a vector, a mapped pipe) behind
    // string keys; a single next() loop surfaces whichever is ready.
    auto [tx_a, rx_a] = mpsc::unbounded<int>();
    StreamMap<int> map;
    map.insert("a", std::move(rx_a));
    map.insert("b", from_vector<int>({10, 20}));
    map.insert("c", from_vector<int>({1}) | async_map([](int value) { return value + 100; }));
    EXPECT_TRUE(map.contains("a"));
    EXPECT_EQ(map.size(), 3U);
    EXPECT_TRUE(tx_a.send(1));
    EXPECT_TRUE(tx_a.send(2));
    tx_a.close();
    std::vector<std::pair<std::string, int>> seen;
    while (auto item = sync_get(next(map))) {
        seen.push_back(std::move(*item));
    }
    std::sort(seen.begin(), seen.end());
    const std::vector<std::pair<std::string, int>> expected{
        {"a", 1}, {"a", 2}, {"b", 10}, {"b", 20}, {"c", 101}};
    EXPECT_EQ(seen, expected);
}

TEST(AsyncStreamTest, StreamMapEndsWhenAllSourcesEnd) {
    StreamMap<int> map;
    map.insert("short", once(1));
    map.insert("long", from_vector<int>({2, 3}));
    std::vector<std::pair<std::string, int>> seen;
    while (auto item = sync_get(next(map))) {
        seen.push_back(std::move(*item));
    }
    ASSERT_EQ(seen.size(), 3U);
    EXPECT_EQ(seen[0], (std::pair<std::string, int>{"short", 1}));
    // The ended source stays silent afterwards instead of repeating its end.
    EXPECT_EQ(sync_get(next(map)), std::nullopt);
}

TEST(AsyncStreamTest, StreamMapEmptyEndsImmediately) {
    StreamMap<int> map;
    EXPECT_TRUE(map.empty());
    EXPECT_EQ(sync_get(next(map)), std::nullopt);
}

TEST(AsyncStreamTest, StreamMapPropagatesError) {
    StreamMap<int> map;
    map.insert("bad", FailStream{1});
    map.insert("good", from_vector<int>({9}));
    // The failing source still yields its one value first; the failure
    // surfaces on the pull after it is exhausted.
    EXPECT_EQ(sync_get(next(map)), (std::optional<std::pair<std::string, int>>{{"bad", 42}}));
    EXPECT_THROW((void)sync_get(next(map)), std::runtime_error);
}

TEST(AsyncStreamTest, StreamMapRemove) {
    StreamMap<int> map;
    map.insert("a", once(1));
    map.insert("b", once(2));
    EXPECT_TRUE(map.remove("a"));
    EXPECT_FALSE(map.remove("a"));
    EXPECT_FALSE(map.contains("a"));
    EXPECT_EQ(collect_sync(std::move(map)), (std::vector<std::pair<std::string, int>>{{"b", 2}}));
}

TEST(AsyncStreamTest, StreamMapAbandonedPullCancelsCleanly) {
    // Both sources park, so the pull stays outstanding with no inline
    // winner. Destroying it must wake the parked children via stop without
    // delivering anything, and the map stays usable afterwards.
    auto [tx1, rx1] = mpsc::unbounded<int>();
    auto [tx2, rx2] = mpsc::unbounded<int>();
    StreamMap<int> map;
    map.insert("one", std::move(rx1));
    map.insert("two", std::move(rx2));
    using PairEvent = EventReceiver<std::optional<std::pair<std::string, int>>>::Event;
    std::promise<PairEvent> done;
    auto future = done.get_future();
    {
        OpHolder parked(next(map),
                        EventReceiver<std::optional<std::pair<std::string, int>>>{{}, &done});
        parked.start();
        EXPECT_EQ(future.wait_for(20ms), std::future_status::timeout);
    }
    EXPECT_EQ(future.wait_for(20ms), std::future_status::timeout);
    EXPECT_TRUE(tx1.send(11));
    EXPECT_TRUE(tx2.send(22));
    tx1.close();
    tx2.close();
    std::vector<std::pair<std::string, int>> seen;
    while (auto item = sync_get(next(map))) {
        seen.push_back(std::move(*item));
    }
    std::sort(seen.begin(), seen.end());
    const std::vector<std::pair<std::string, int>> expected{{"one", 11}, {"two", 22}};
    EXPECT_EQ(seen, expected);
}

TEST(AsyncStreamTest, TypeErasedStream) {
    AnyAsyncStream<int> erased =
        erase_stream(from_vector<int>({1, 2, 3}) | async_map([](int value) { return value * 10; }));
    EXPECT_EQ(collect_sync(std::move(erased)), (std::vector<int>{10, 20, 30}));
    auto [tx, rx] = mpsc::unbounded<int>();
    EXPECT_TRUE(tx.send(4));
    tx.close();
    AnyAsyncStream<int> channel_erased(std::move(rx));
    EXPECT_EQ(collect_sync(std::move(channel_erased)), std::vector<int>{4});
}

TEST(AsyncStreamTest, MoveOnlyValuesCompose) {
    auto [tx, rx] = mpsc::unbounded<std::unique_ptr<int>>();
    tx.send(std::make_unique<int>(21));
    tx.close();
    auto doubled = std::move(rx) | async_map([](std::unique_ptr<int> value) { return *value * 2; });
    EXPECT_EQ(collect_sync(std::move(doubled)), std::vector<int>{42});
}

TEST(AsyncStreamTest, IntervalTicksOnScheduler) {
    auto ticks = interval_on<int>(TestClock{}, 1ms) | async_take(3);
    EXPECT_EQ(collect_sync(std::move(ticks)), (std::vector<int>{0, 1, 2}));
}

TEST(AsyncStreamTest, LongSkipChainDoesNotRecurse) {
    // 100k consecutive re-pulls against a synchronous source must iterate,
    // not recurse through the completion handlers.
    std::vector<int> items(100000, 1);
    items.push_back(42);
    auto stream =
        from_vector<int>(std::move(items)) | async_filter([](int value) { return value == 42; });
    EXPECT_EQ(collect_sync(std::move(stream)), std::vector<int>{42});
}

} // namespace
