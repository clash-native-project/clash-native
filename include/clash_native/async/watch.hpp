#pragma once

#include <clash_native/async/oneshot.hpp>

#include <stdexec/execution.hpp>

#include <atomic>
#include <concepts>
#include <cstdint>
#include <exception>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

// Single-producer multi-consumer latest-value channel (tokio::watch style),
// sender-native: the sender overwrites one shared slot, every receiver
// observes versions newer than the one it has seen, and Receiver::next() is
// a sender, so watch receivers compose with all stream operators directly.
//
// A pull completes with exactly one of:
//   set_value(optional<T>) - a copy of the current value once it advances
//     past the receiver's seen version, or disengaged when the sender is
//     gone and there is nothing unseen left;
//   set_error(exception_ptr) - only for contract violations (concurrent pulls
//     on one receiver; watch values themselves never fail);
//   set_stopped() - the pull was cancelled.
//
// Values must be copyable: every pull and every borrow materializes a copy.
// New receivers start having seen the current version, so the first pull
// parks until the next update (use mark_changed() to re-observe the current
// value immediately). At most one next() operation may be outstanding per
// receiver at a time.

namespace clash_native::async {
namespace watch {

template <typename T>
concept watch_value = channel_value<T> && std::copyable<T>;

template <watch_value T> class Receiver;

template <watch_value T> class Sender;

template <watch_value T> struct Channel {
    Sender<T> sender;
    Receiver<T> receiver;
};

template <watch_value T> struct State {
    // Wait node of a parked change-watch, embedded in the operation state.
    struct WaitNode {
        WaitNode *prev = nullptr;
        WaitNode *next = nullptr;
        enum class Stage : unsigned char { kInit, kQueued, kDone, kStopped, kGone };
        Stage stage = Stage::kInit;
        // Identifies the receiver this wait belongs to (its seen-version
        // address): a second concurrent pull from the same receiver is a
        // single-consumer violation instead of a second wait.
        const std::uint64_t *owner = nullptr;
        // Version this waiter has seen; wakes when state version passes it.
        std::uint64_t seen = 0;
        bool closed = false;
        // mutex NOT held; runs exactly once after the node was detached.
        virtual void complete() noexcept = 0;
    };

    // Guards current, version, closed, and the parked list. Never held across
    // a completion callback.
    mutable std::mutex mutex;
    T current;
    std::uint64_t version = 1;
    bool closed = false;
    WaitNode *park_head = nullptr;
    WaitNode *park_tail = nullptr;

    explicit State(T initial) : current(std::move(initial)) {}

    void link(WaitNode *node) {
        node->prev = park_tail;
        node->next = nullptr;
        if (park_tail != nullptr) {
            park_tail->next = node;
        } else {
            park_head = node;
        }
        park_tail = node;
    }

    void unlink(WaitNode *node) {
        if (node->prev != nullptr) {
            node->prev->next = node->next;
        } else {
            park_head = node->next;
        }
        if (node->next != nullptr) {
            node->next->prev = node->prev;
        } else {
            park_tail = node->prev;
        }
        node->prev = node->next = nullptr;
    }

    // Overwrite the value, bump the version, and wake every parked waiter.
    // Returns false when closed.
    bool store(T value) {
        std::vector<WaitNode *> woken;
        {
            std::lock_guard lock(mutex);
            if (closed) {
                return false;
            }
            current = std::move(value);
            ++version;
            for (auto *node = park_head; node != nullptr;) {
                auto *next = node->next;
                unlink(node);
                node->stage = WaitNode::Stage::kDone;
                woken.push_back(node);
                node = next;
            }
        }
        for (auto *node : woken) {
            node->complete();
        }
        return true;
    }

    void close() {
        std::vector<WaitNode *> woken;
        {
            std::lock_guard lock(mutex);
            if (closed) {
                return;
            }
            closed = true;
            for (auto *node = park_head; node != nullptr;) {
                auto *next = node->next;
                unlink(node);
                node->stage = WaitNode::Stage::kDone;
                node->closed = true;
                woken.push_back(node);
                node = next;
            }
        }
        for (auto *node : woken) {
            node->complete();
        }
    }
};

// Operation state of a change-watch. Immovable: the wait node is linked by
// address. The seen version advances only when a newer value is actually
// delivered (never on stop or destroy, so a later pull retries the same
// version). Destroying a still-queued operation state releases the wait
// (cancel); a stop request completes with set_stopped.
template <watch_value T, stdexec::receiver Rcvr> class WaitOpState : public State<T>::WaitNode {
    using Node = typename State<T>::WaitNode;

    struct StopFn {
        WaitOpState *self;
        void operator()() const noexcept { self->on_stop(); }
    };

    using StopToken = stdexec::stop_token_of_t<stdexec::env_of_t<Rcvr>>;
    using StopCallback = stdexec::stop_callback_for_t<StopToken, StopFn>;

  public:
    using operation_state_concept = stdexec::operation_state_tag;

    WaitOpState(std::shared_ptr<State<T>> state, std::uint64_t *seen, Rcvr receiver)
        : state_(std::move(state)), seen_(seen), receiver_(std::move(receiver)) {
        this->owner = seen;
    }

    WaitOpState(const WaitOpState &) = delete;
    WaitOpState &operator=(const WaitOpState &) = delete;

    ~WaitOpState() {
        if (state_) {
            std::lock_guard lock(state_->mutex);
            if (this->stage == Node::Stage::kQueued) {
                state_->unlink(this);
                this->stage = Node::Stage::kGone;
            }
        }
    }

    void complete() noexcept override {
        // mutex released by the caller. Unregister first (never while holding
        // mutex): this may wait for an in-flight stop callback, which itself
        // needs mutex.
        stop_callback_.reset();
        // Re-read under mutex: complete() only means "something changed";
        // the exact outcome (new value vs. close) is resolved here so a
        // close racing the wake cannot strand the waiter.
        auto *state = state_.get();
        std::optional<T> out;
        if (state != nullptr) {
            // Wakes fire only on version bump or close, and versions only
            // move forward, so exactly one of the branches below holds.
            std::lock_guard lock(state->mutex);
            if (seen_ != nullptr && *seen_ < state->version) {
                out = state->current;
                *seen_ = state->version;
            }
        }
        stdexec::set_value(std::move(receiver_), std::move(out));
    }

    void start() noexcept {
        auto *state = state_.get();
        if (state == nullptr || seen_ == nullptr) {
            stdexec::set_value(std::move(receiver_), std::optional<T>());
            return;
        }
        stop_callback_.emplace(stdexec::get_stop_token(stdexec::get_env(receiver_)), StopFn{this});
        enum class Outcome : unsigned char { kValue, kClosed, kViolation, kQueued, kStopped };
        Outcome outcome = Outcome::kQueued;
        std::optional<T> out;
        {
            std::lock_guard lock(state->mutex);
            this->seen = *seen_;
            if (stop_requested_) {
                outcome = Outcome::kStopped;
            } else if (*seen_ < state->version) {
                out = state->current;
                *seen_ = state->version;
                outcome = Outcome::kValue;
            } else if (state->closed) {
                outcome = Outcome::kClosed;
            } else {
                // Single-consumer violation: at most one outstanding pull per
                // receiver. Nodes from one receiver share its seen address.
                bool duplicate = false;
                for (auto *node = state->park_head; node != nullptr; node = node->next) {
                    if (node != this && node->owner != nullptr && node->owner == this->owner) {
                        duplicate = true;
                        break;
                    }
                }
                if (duplicate) {
                    outcome = Outcome::kViolation;
                } else {
                    this->stage = Node::Stage::kQueued;
                    state->link(this);
                }
            }
        }
        // Complete outside mutex: continuations may re-enter the channel.
        if (outcome != Outcome::kQueued) {
            stop_callback_.reset();
        }
        switch (outcome) {
        case Outcome::kValue:
            stdexec::set_value(std::move(receiver_), std::move(out));
            return;
        case Outcome::kClosed:
            stdexec::set_value(std::move(receiver_), std::optional<T>());
            return;
        case Outcome::kViolation:
            stdexec::set_error(std::move(receiver_),
                               std::make_exception_ptr(std::logic_error(
                                   "clash_native::async::watch: concurrent wait on a "
                                   "single-consumer Receiver")));
            return;
        case Outcome::kStopped:
            stdexec::set_stopped(std::move(receiver_));
            return;
        case Outcome::kQueued:
            return;
        }
    }

  private:
    void on_stop() noexcept {
        auto *state = state_.get();
        if (state == nullptr) {
            return;
        }
        bool fire = false;
        {
            std::lock_guard lock(state->mutex);
            if (this->stage == Node::Stage::kQueued) {
                state->unlink(this);
                this->stage = Node::Stage::kStopped;
                fire = true;
            } else if (this->stage == Node::Stage::kInit) {
                stop_requested_ = true;
            }
        }
        if (fire) {
            stdexec::set_stopped(std::move(receiver_));
        }
    }

    std::shared_ptr<State<T>> state_;
    // Owning receiver's seen version (advance on delivery only). The receiver
    // outlives its pulls by contract; null means detached.
    std::uint64_t *seen_;
    Rcvr receiver_;
    bool stop_requested_ = false; // guarded by state_->mutex
    // Declared last so it is destroyed first.
    std::optional<StopCallback> stop_callback_;
};

template <watch_value T> class ChangeSender {
  public:
    using sender_concept = stdexec::sender_tag;
    using completion_signatures =
        stdexec::completion_signatures<stdexec::set_value_t(std::optional<T>),
                                       stdexec::set_error_t(std::exception_ptr),
                                       stdexec::set_stopped_t()>;

    ChangeSender(std::shared_ptr<State<T>> state, std::uint64_t *seen)
        : state_(std::move(state)), seen_(seen) {}

    template <stdexec::receiver Rcvr> WaitOpState<T, Rcvr> connect(Rcvr receiver) && {
        return WaitOpState<T, Rcvr>(std::move(state_), seen_, std::move(receiver));
    }

  private:
    std::shared_ptr<State<T>> state_;
    std::uint64_t *seen_;
};

template <watch_value T> class Sender {
  public:
    Sender() = default;

    explicit Sender(std::shared_ptr<State<T>> state) : state_(std::move(state)) {}

    Sender(const Sender &) = delete;
    Sender &operator=(const Sender &) = delete;

    Sender(Sender &&) noexcept = default;
    Sender &operator=(Sender &&other) noexcept {
        if (this != &other) {
            close();
            state_ = std::move(other.state_);
        }
        return *this;
    }

    ~Sender() { close(); }

    explicit operator bool() const { return static_cast<bool>(state_); }

    // Overwrite the current value, bump the version, and wake every parked
    // waiter. Returns false when closed.
    bool send(T value) const {
        if (!state_) {
            return false;
        }
        return state_->store(std::move(value));
    }

    // Synchronous snapshot of the current value. Disengaged when detached.
    std::optional<T> borrow() const {
        if (!state_) {
            return std::nullopt;
        }
        std::lock_guard lock(state_->mutex);
        return state_->current;
    }

    bool is_closed() const {
        if (!state_) {
            return true;
        }
        std::lock_guard lock(state_->mutex);
        return state_->closed;
    }

    void close() {
        if (state_) {
            state_->close();
            state_.reset();
        }
    }

    Receiver<T> subscribe() const { return Receiver<T>(state_); }

  private:
    std::shared_ptr<State<T>> state_;
};

template <watch_value T> class Receiver {
  public:
    using value_type = T;

    Receiver() = default;

    // New receivers start having seen the current version: the first pull
    // parks until the next update (or ends at close).
    explicit Receiver(std::shared_ptr<State<T>> state) : state_(std::move(state)) {
        if (state_) {
            std::lock_guard lock(state_->mutex);
            seen_ = state_->version;
        }
    }

    Receiver(const Receiver &other) : state_(other.state_), seen_(other.seen_) {}

    Receiver &operator=(const Receiver &other) {
        if (this != &other) {
            state_ = other.state_;
            seen_ = other.seen_;
        }
        return *this;
    }

    Receiver(Receiver &&) noexcept = default;
    Receiver &operator=(Receiver &&) noexcept = default;

    explicit operator bool() const { return static_cast<bool>(state_); }

    // Core async pull (awaitable, pipeable): waits until the version advances
    // past the seen one, then yields a copy; disengaged at end.
    // Single-consumer: at most one outstanding next() per receiver.
    ChangeSender<T> next() { return ChangeSender<T>(state_, state_ ? &seen_ : nullptr); }

    ChangeSender<T> recv() { return next(); }

    ChangeSender<T> changed() { return next(); }

    // Synchronous snapshot of the current value. Disengaged when detached.
    std::optional<T> borrow() const {
        if (!state_) {
            return std::nullopt;
        }
        std::lock_guard lock(state_->mutex);
        return state_->current;
    }

    bool has_changed() const {
        if (!state_) {
            return false;
        }
        std::lock_guard lock(state_->mutex);
        return seen_ < state_->version;
    }

    std::uint64_t version() const {
        if (!state_) {
            return 0;
        }
        std::lock_guard lock(state_->mutex);
        return state_->version;
    }

    // Re-observe the current value on the next pull even without an update.
    void mark_changed() {
        if (!state_) {
            return;
        }
        std::lock_guard lock(state_->mutex);
        if (seen_ == state_->version && state_->version > 0) {
            --seen_;
        }
    }

    bool is_closed() const {
        if (!state_) {
            return true;
        }
        std::lock_guard lock(state_->mutex);
        return state_->closed;
    }

    void close() { state_.reset(); }

  private:
    std::shared_ptr<State<T>> state_;
    // Newest version observed. Advanced only when a newer value is actually
    // delivered (never on stop/destroy, so a later pull retries the wait).
    std::uint64_t seen_ = 0;
};

template <watch_value T> Channel<T> channel(T initial) {
    auto state = std::make_shared<State<T>>(std::move(initial));
    return {Sender<T>{state}, Receiver<T>{state}};
}

} // namespace watch
} // namespace clash_native::async
