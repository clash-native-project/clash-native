#pragma once

#include <stdexec/execution.hpp>

#include <atomic>
#include <concepts>
#include <exception>
#include <memory>
#include <mutex>
#include <optional>
#include <type_traits>
#include <utility>

namespace clash_native::async {

// Values that can travel through a channel. Move-only payloads are supported;
// const/volatile qualified types are rejected.
template <typename T>
concept channel_value = std::movable<T> && !std::is_const_v<T> && !std::is_volatile_v<T>;

namespace oneshot {

template <channel_value T> class Sender;

template <channel_value T> class Receiver;

template <channel_value T> struct Channel {
    Sender<T> sender;
    Receiver<T> receiver;
};

template <channel_value T> struct State {
    mutable std::mutex mutex;
    enum class Status : unsigned char { kEmpty, kValue, kError };
    Status status{Status::kEmpty};
    std::optional<T> value;
    std::exception_ptr error;
    // Waiter operation state plus completion entry point, installed by the
    // receiver operation state on start(). `waiter` is non-owning: the
    // operation state must outlive the completion signal (P2300 guarantee).
    void *waiter{nullptr};
    using DeliverFn = void (*)(void *op, std::optional<T> &&value, std::exception_ptr error,
                               bool is_error);
    DeliverFn deliver{nullptr};
    // Set (under `mutex`) when a parked waiter is destroyed or cancelled
    // before completing. settle() then fails instead of storing a value that
    // nobody will ever read.
    bool detached{false};
    std::atomic<bool> settled{false};
};

template <channel_value T> class Sender {
  public:
    Sender() = default;

    explicit Sender(std::shared_ptr<State<T>> state) : state_(std::move(state)) {}

    Sender(const Sender &) = delete;
    Sender &operator=(const Sender &) = delete;

    Sender(Sender &&other) noexcept : state_(std::move(other.state_)) {}

    Sender &operator=(Sender &&other) noexcept {
        if (this != &other) {
            close();
            state_ = std::move(other.state_);
        }
        return *this;
    }

    ~Sender() { close(); }

    explicit operator bool() const { return static_cast<bool>(state_); }

    // Non-blocking. Returns false if already sent, closed, or detached.
    bool send(T value) {
        std::optional<T> wrapped(std::move(value));
        return settle(State<T>::Status::kValue, wrapped, nullptr);
    }

    // Non-blocking. Like send(), but on failure the value is left engaged in
    // `value` so the caller can reroute it instead of losing it.
    bool send(std::optional<T> &value) { return settle(State<T>::Status::kValue, value, nullptr); }

    // Non-blocking. Completes the receiver with an error. Returns false if
    // already settled or detached.
    bool send_error(std::exception_ptr error) {
        std::optional<T> empty;
        return settle(State<T>::Status::kError, empty, std::move(error));
    }

    // Completes the receiver with an empty value when it is still waiting.
    void close() {
        std::optional<T> empty;
        (void)settle(State<T>::Status::kValue, empty, nullptr);
    }

    // True when the receiver side parked a waiter and then destroyed or
    // cancelled it without completing: a send() to this channel would deliver
    // to nobody.
    bool receiver_detached() const {
        if (!state_) {
            return true;
        }
        std::lock_guard lock(state_->mutex);
        return state_->detached;
    }

  private:
    // `value` is moved into the state only on success; on failure (already
    // settled or detached) it is left untouched so the caller keeps it.
    bool settle(typename State<T>::Status status, std::optional<T> &value,
                std::exception_ptr error) {
        if (!state_) {
            return false;
        }
        void *waiter = nullptr;
        typename State<T>::DeliverFn deliver = nullptr;
        {
            std::lock_guard lock(state_->mutex);
            if (state_->status != State<T>::Status::kEmpty) {
                return false;
            }
            if (state_->detached) {
                return false;
            }
            // Write the payload first and publish `settled` last, all under
            // `mutex`: a start() that observes settled while holding `mutex`
            // is then guaranteed to also observe the payload.
            state_->status = status;
            state_->value = std::move(value);
            state_->error = std::move(error);
            state_->settled.store(true, std::memory_order_release);
            waiter = state_->waiter;
            deliver = state_->deliver;
            state_->waiter = nullptr;
            state_->deliver = nullptr;
        }
        if (waiter != nullptr && deliver != nullptr) {
            deliver(waiter, std::move(state_->value), std::move(state_->error),
                    status == State<T>::Status::kError);
        }
        state_.reset();
        return true;
    }

    std::shared_ptr<State<T>> state_;
};

template <channel_value T> class Receiver {
  public:
    using sender_concept = stdexec::sender_tag;
    using completion_signatures =
        stdexec::completion_signatures<stdexec::set_value_t(std::optional<T>),
                                       stdexec::set_error_t(std::exception_ptr),
                                       stdexec::set_stopped_t()>;

    Receiver() = default;

    explicit Receiver(std::shared_ptr<State<T>> state) : state_(std::move(state)) {}

    Receiver(const Receiver &) = delete;
    Receiver &operator=(const Receiver &) = delete;

    Receiver(Receiver &&) noexcept = default;
    Receiver &operator=(Receiver &&) noexcept = default;

    explicit operator bool() const { return static_cast<bool>(state_); }

    bool is_ready() const {
        if (!state_) {
            return true;
        }
        return state_->settled.load(std::memory_order_acquire);
    }

    // The receiver side IS the sender; connect it to a stdexec receiver.
    template <stdexec::receiver Rcvr> struct OpState {
        using operation_state_concept = stdexec::operation_state_tag;

        struct StopFn {
            OpState *self;
            void operator()() const noexcept { self->on_stop(); }
        };

        using StopToken = stdexec::stop_token_of_t<stdexec::env_of_t<Rcvr>>;
        using StopCallback = stdexec::stop_callback_for_t<StopToken, StopFn>;

        std::shared_ptr<State<T>> state_;
        Rcvr receiver_;
        // Observed before the waiter is parked; guarded by state_->mutex.
        bool stop_requested_{false};
        // Declared last so it is destroyed first: unregistering may block
        // until an in-flight callback returns, and the callback touches the
        // members above.
        std::optional<StopCallback> stop_callback_;

        OpState(std::shared_ptr<State<T>> state, Rcvr receiver)
            : state_(std::move(state)), receiver_(std::move(receiver)) {}

        OpState(const OpState &) = delete;
        OpState &operator=(const OpState &) = delete;

        ~OpState() {
            // Unregister the waiter so a late send()/close() never touches a
            // destroyed operation state, and mark the state detached so the
            // late send() fails instead of writing a value nobody will read.
            if (state_) {
                std::lock_guard lock(state_->mutex);
                if (state_->waiter == this) {
                    state_->waiter = nullptr;
                    state_->deliver = nullptr;
                    state_->detached = true;
                }
            }
        }

        static void deliver(void *op, std::optional<T> &&value, std::exception_ptr error,
                            bool is_error) {
            auto *self = static_cast<OpState *>(op);
            // Never invoked while holding the state mutex; unregister first
            // (unregistering may block on an in-flight stop callback, which
            // itself needs the mutex).
            self->stop_callback_.reset();
            if (is_error) {
                stdexec::set_error(std::move(self->receiver_), std::move(error));
            } else {
                stdexec::set_value(std::move(self->receiver_), std::move(value));
            }
        }

        void start() noexcept {
            if (!state_) {
                stdexec::set_value(std::move(receiver_), std::optional<T>());
                return;
            }
            // Register the stop callback before any completion can be in
            // flight. A stop that was already requested fires inline here and
            // only sets stop_requested_ (the stage below is still unset).
            stop_callback_.emplace(stdexec::get_stop_token(stdexec::get_env(receiver_)),
                                   StopFn{this});
            enum class Outcome : unsigned char { kStopped, kValue, kError, kQueued };
            Outcome outcome;
            std::optional<T> value;
            std::exception_ptr error;
            {
                std::lock_guard lock(state_->mutex);
                if (stop_requested_) {
                    outcome = Outcome::kStopped;
                } else if (state_->settled.load(std::memory_order_acquire)) {
                    if (state_->status == State<T>::Status::kError) {
                        error = state_->error;
                        outcome = Outcome::kError;
                    } else {
                        value = std::move(state_->value);
                        outcome = Outcome::kValue;
                    }
                } else {
                    state_->waiter = this;
                    state_->deliver = &OpState::deliver;
                    outcome = Outcome::kQueued;
                }
            }
            // Complete outside `mutex`: continuations may re-enter the channel.
            // The parked path keeps the stop registration armed; every other
            // path unregisters before completing (never while holding `mutex`).
            if (outcome != Outcome::kQueued) {
                stop_callback_.reset();
            }
            switch (outcome) {
            case Outcome::kStopped:
                stdexec::set_stopped(std::move(receiver_));
                return;
            case Outcome::kValue:
                stdexec::set_value(std::move(receiver_), std::move(value));
                return;
            case Outcome::kError:
                stdexec::set_error(std::move(receiver_), std::move(error));
                return;
            case Outcome::kQueued:
                return;
            }
        }

      private:
        // Stop callback body (fires on the stop-requesting thread). Arbitrates
        // under `mutex`; the completion fires after `mutex` is released.
        void on_stop() noexcept {
            auto *state = state_.get();
            if (state == nullptr) {
                return;
            }
            bool fire = false;
            {
                std::lock_guard lock(state->mutex);
                if (state->waiter == this) {
                    // Withdraw the parked wait and complete with set_stopped;
                    // a late send() observes detached and fails.
                    state->waiter = nullptr;
                    state->deliver = nullptr;
                    state->detached = true;
                    fire = true;
                } else if (!state->settled.load(std::memory_order_acquire)) {
                    // Races start()'s arbitration: leave a flag; start()
                    // completes with set_stopped when it observes this under
                    // `mutex`.
                    stop_requested_ = true;
                }
                // Already settled: too late, the in-flight completion wins.
            }
            if (fire) {
                // After completing, the operation state must not be touched.
                stdexec::set_stopped(std::move(receiver_));
            }
        }
    };

    template <stdexec::receiver Rcvr> OpState<Rcvr> connect(Rcvr receiver) && {
        return OpState<Rcvr>(std::move(state_), std::move(receiver));
    }

  private:
    std::shared_ptr<State<T>> state_;
};

template <channel_value T> Channel<T> channel() {
    auto state = std::make_shared<State<T>>();
    return {Sender<T>{state}, Receiver<T>{state}};
}

} // namespace oneshot

} // namespace clash_native::async
