#pragma once

#include <stdexec/execution.hpp>

#include <chrono>
#include <exception>
#include <future>
#include <optional>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace clash_native::async::test {

using namespace std::chrono_literals;

// Drive a sender to completion on the calling thread and return its single
// value. Throws when the sender stops; rethrows the sender's error.
template <stdexec::sender S> auto sync_get(S &&sender) {
    auto result = stdexec::sync_wait(std::forward<S>(sender));
    if (!result) {
        throw std::runtime_error("sync_get: sender completed with set_stopped");
    }
    return std::get<0>(std::move(*result));
}

// Environment carrying a stop token, for cancellation tests.
struct StopEnv {
    stdexec::inplace_stop_token token;
    auto query(stdexec::get_stop_token_t) const noexcept { return token; }
};

// Receiver that records the terminal signal into a promise. V is the sender's
// set_value payload type (for example bool, or std::optional<int>).
template <class V> struct EventReceiver {
    using receiver_concept = stdexec::receiver_tag;
    enum class Outcome : unsigned char { kValue, kStopped, kError };
    struct Event {
        Outcome outcome;
        std::optional<V> value;
    };

    StopEnv env;
    std::promise<Event> *done = nullptr;

    auto get_env() const noexcept -> const StopEnv & { return env; }

    void set_value(V value) noexcept {
        done->set_value(Event{Outcome::kValue, std::optional<V>(std::move(value))});
    }
    void set_error(std::exception_ptr) noexcept {
        done->set_value(Event{Outcome::kError, std::nullopt});
    }
    void set_stopped() noexcept { done->set_value(Event{Outcome::kStopped, std::nullopt}); }
};

// Drives a sender with an empty (void) completion.
template <stdexec::sender S> void sync_wait_void(S &&sender) {
    auto result = stdexec::sync_wait(std::forward<S>(sender));
    if (!result) {
        throw std::runtime_error("sync_wait_void: sender completed with set_stopped");
    }
}

// Holds an operation state in place without moving it, so tests can destroy a
// parked operation (cancel by destruction). Operation states are immovable,
// so the state is connected directly into manual storage.
template <class S, class R> struct OpHolder {
    using Op = stdexec::connect_result_t<std::decay_t<S>, std::decay_t<R>>;

    OpHolder(S &&sender, R &&receiver) {
        op_ = ::new (static_cast<void *>(storage_))
            Op(stdexec::connect(std::forward<S>(sender), std::forward<R>(receiver)));
    }

    OpHolder(const OpHolder &) = delete;
    OpHolder &operator=(const OpHolder &) = delete;

    ~OpHolder() {
        if (op_ != nullptr) {
            op_->~Op();
        }
    }

    void start() { stdexec::start(*op_); }

    void reset() {
        if (op_ != nullptr) {
            op_->~Op();
            op_ = nullptr;
        }
    }

  private:
    alignas(Op) unsigned char storage_[sizeof(Op)];
    Op *op_{nullptr};
};

template <class S, class R> OpHolder(S &&, R &&) -> OpHolder<S, R>;

// Wait for the future to become ready, failing the test with a diagnostic
// instead of hanging forever when the signal never arrives.
template <class T> T wait_get(std::future<T> &future) {
    if (future.wait_for(5s) != std::future_status::ready) {
        throw std::runtime_error("timed out waiting for the async signal");
    }
    return future.get();
}

} // namespace clash_native::async::test
