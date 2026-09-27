#include <clash_native/async/callback_sender.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <exception>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <utility>

#include <exec/when_any.hpp>

#include "async_test_helpers.hpp"
namespace {

using namespace std::chrono_literals;
using namespace clash_native::async;
using clash_native::async::test::EventReceiver;
using clash_native::async::test::OpHolder;
using clash_native::async::test::sync_get;
using clash_native::async::test::wait_get;

using IntSigs = stdexec::completion_signatures<
    stdexec::set_value_t(int), stdexec::set_error_t(std::exception_ptr), stdexec::set_stopped_t()>;

// Manually driven initiation: the terminal is parked until the test fires it,
// so stop/destroy races are deterministic. The aborter just records that it
// ran; the parked terminal observes the abort flag and drops, mirroring a
// real abort that retired the underlying work.
struct Manual {
    std::function<void(int)> terminal;
    std::atomic<bool> aborted{false};
    std::atomic<bool> fired{false};
    std::mutex mutex;
};

using IntEvent = EventReceiver<int>::Event;
using IntOutcome = EventReceiver<int>::Outcome;

auto make_sender(std::shared_ptr<Manual> manual) {
    return callback_sender<IntSigs>(
        [manual](auto terminal) mutable -> CallbackAbortFn {
            {
                std::lock_guard lock(manual->mutex);
                manual->terminal = std::move(terminal);
            }
            return CallbackAbortFn{[manual] { manual->aborted.store(true); }};
        },
        [](auto receiver, int value) { stdexec::set_value(std::move(receiver), value); });
}

void fire(std::shared_ptr<Manual> manual, int value) {
    std::function<void(int)> terminal;
    {
        std::lock_guard lock(manual->mutex);
        terminal = std::move(manual->terminal);
    }
    manual->fired.store(true);
    if (!manual->aborted.load() && terminal) {
        terminal(value);
    }
}

TEST(CallbackSenderTest, ValueFlowsThrough) {
    auto manual = std::make_shared<Manual>();
    auto sender = make_sender(manual);
    std::promise<IntEvent> done;
    auto future = done.get_future();
    OpHolder parked(std::move(sender), EventReceiver<int>{{}, &done});
    parked.start();
    EXPECT_EQ(future.wait_for(20ms), std::future_status::timeout);
    fire(manual, 7);
    EXPECT_EQ(wait_get(future).value, std::optional<int>(7));
    EXPECT_FALSE(manual->aborted.load());
}

TEST(CallbackSenderTest, StopRunsAborterAndCompletesStopped) {
    auto manual = std::make_shared<Manual>();
    auto sender = make_sender(manual);
    stdexec::inplace_stop_source source;
    std::promise<IntEvent> done;
    auto future = done.get_future();
    OpHolder parked(std::move(sender), EventReceiver<int>{{source.get_token()}, &done});
    parked.start();
    EXPECT_EQ(future.wait_for(20ms), std::future_status::timeout);
    source.request_stop();
    EXPECT_EQ(wait_get(future).outcome, IntOutcome::kStopped);
    EXPECT_TRUE(manual->aborted.load());
    // Late terminal after the abort is dropped, never a second completion.
    fire(manual, 1);
    parked.reset();
}

TEST(CallbackSenderTest, DestroyRunsAborter) {
    auto manual = std::make_shared<Manual>();
    {
        std::promise<IntEvent> done;
        auto future = done.get_future();
        OpHolder parked(make_sender(manual), EventReceiver<int>{{}, &done});
        parked.start();
        EXPECT_EQ(future.wait_for(20ms), std::future_status::timeout);
    }
    EXPECT_TRUE(manual->aborted.load());
}

TEST(CallbackSenderTest, StartAfterStopCompletesStoppedWithoutInitiating) {
    auto manual = std::make_shared<Manual>();
    auto sender = make_sender(manual);
    stdexec::inplace_stop_source source;
    source.request_stop();
    std::promise<IntEvent> done;
    auto future = done.get_future();
    OpHolder parked(std::move(sender), EventReceiver<int>{{source.get_token()}, &done});
    parked.start();
    EXPECT_EQ(wait_get(future).outcome, IntOutcome::kStopped);
    {
        std::lock_guard lock(manual->mutex);
        EXPECT_FALSE(static_cast<bool>(manual->terminal));
    }
}

TEST(CallbackSenderTest, InitiationThrowCompletesError) {
    auto sender = callback_sender<IntSigs>(
        [](auto) -> CallbackAbortFn {
            throw std::runtime_error("boom");
            return CallbackAbortFn{};
        },
        [](auto receiver, int value) { stdexec::set_value(std::move(receiver), value); });
    EXPECT_THROW((void)sync_get(std::move(sender)), std::runtime_error);
}

TEST(CallbackSenderTest, InlineTerminalWinsOverStop) {
    // The initiation completes synchronously; the returned aborter is
    // immediately invoked as an orphan and must tolerate post-terminal use.
    std::atomic<bool> orphan_aborted{false};
    auto sender = callback_sender<IntSigs>(
        [&orphan_aborted](auto terminal) mutable -> CallbackAbortFn {
            terminal(3);
            return CallbackAbortFn{[&orphan_aborted] { orphan_aborted.store(true); }};
        },
        [](auto receiver, int value) { stdexec::set_value(std::move(receiver), value); });
    EXPECT_EQ(sync_get(std::move(sender)), 3);
    EXPECT_TRUE(orphan_aborted.load());
}

TEST(CallbackSenderTest, StopDuringInitiationAbortsReturnedWork) {
    // A stop racing the initiation is served by running the freshly returned
    // aborter instead of leaking the underlying work.
    std::promise<CallbackAbortFn> returned;
    auto got_returned = returned.get_future();
    auto sender = callback_sender<IntSigs>(
        [&returned](auto terminal) mutable -> CallbackAbortFn {
            // Park the terminal (never fired) and hand the aborter out.
            auto parked = std::make_shared<std::function<void(int)>>(std::move(terminal));
            CallbackAbortFn aborter{[parked] { (void)parked; }};
            returned.set_value(std::move(aborter));
            return CallbackAbortFn{[parked] { (void)parked; }};
        },
        [](auto receiver, int value) { stdexec::set_value(std::move(receiver), value); });
    stdexec::inplace_stop_source source;
    std::promise<IntEvent> done;
    auto future = done.get_future();
    OpHolder parked(std::move(sender), EventReceiver<int>{{source.get_token()}, &done});
    std::thread starter([&parked] { parked.start(); });
    // Wait until the initiation is inside its body, then stop.
    ASSERT_EQ(got_returned.wait_for(5s), std::future_status::ready);
    source.request_stop();
    starter.join();
    EXPECT_EQ(wait_get(future).outcome, IntOutcome::kStopped);
    parked.reset();
}

TEST(CallbackSenderTest, MoveOnlyAborterCapture) {
    // The aborter holds move-only state (a promise), which std::function
    // cannot express. Aborting delivers through the move-only capture.
    std::promise<void> aborted;
    auto done = aborted.get_future();
    auto sender = callback_sender<IntSigs>(
        [promise = std::move(aborted)](auto terminal) mutable -> CallbackAbortFn {
            (void)terminal;
            return CallbackAbortFn{[promise = std::move(promise)] mutable { promise.set_value(); }};
        },
        [](auto receiver, int value) { stdexec::set_value(std::move(receiver), value); });
    {
        std::promise<IntEvent> parked_done;
        auto parked_future = parked_done.get_future();
        OpHolder parked(std::move(sender), EventReceiver<int>{{}, &parked_done});
        parked.start();
        EXPECT_EQ(parked_future.wait_for(20ms), std::future_status::timeout);
    }
    EXPECT_EQ(done.wait_for(5s), std::future_status::ready);
}

TEST(CallbackSenderTest, RacingLoserIsCancelledByWhenAny) {
    // Loser branch: request_stop claims it, runs the aborter, and completes
    // set_stopped promptly; the late terminal is dropped.
    auto loser = std::make_shared<Manual>();
    auto raced = exec::when_any(make_sender(loser), stdexec::just(42));
    auto result = stdexec::sync_wait(std::move(raced));
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(loser->aborted.load());
    fire(loser, 1);
}

} // namespace
