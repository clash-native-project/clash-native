#pragma once

#include <clash_native/async/oneshot.hpp>

#include <stdexec/execution.hpp>

#include <atomic>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

// Multi-producer multi-consumer broadcast channel (tokio::broadcast style),
// sender-native: every receiver observes every value through its own cursor,
// and Receiver::next() is a sender, so broadcast receivers compose with all
// stream operators directly.
//
// A pull completes with exactly one of:
//   set_value(optional<T>) - the next value at the receiver cursor, or
//     disengaged when all senders are gone and the receiver drained;
//   set_error(exception_ptr) - broadcast_lagged when the receiver fell behind
//     (the stream stays alive: the cursor jumps to the oldest buffered value,
//     so the next pull resumes without another lag; a lag-tolerant loop can
//     catch broadcast_lagged around co_await and continue);
//   set_stopped() - the pull was cancelled.
//
// Values must be copyable: each receiver materializes its own copy. The
// buffer is bounded and send() never blocks: a full buffer evicts the oldest
// values, which is what makes lagging receivers lag. At most one next()
// operation may be outstanding per receiver at a time.

namespace clash_native::async {
namespace broadcast {

template <typename T>
concept broadcast_value = channel_value<T> && std::copyable<T>;

// Delivered as set_error when a receiver fell behind the buffer. Carries the
// number of skipped values; the cursor has already jumped to the oldest
// buffered value, so the next pull resumes cleanly.
struct broadcast_lagged : std::runtime_error {
    std::size_t skipped;
    explicit broadcast_lagged(std::size_t skipped)
        : std::runtime_error("clash_native::async::broadcast: receiver lagged"), skipped(skipped) {}
};

template <broadcast_value T> class Receiver;

template <broadcast_value T> class Sender;

template <broadcast_value T> struct Channel {
    Sender<T> sender;
    Receiver<T> receiver;
};

template <broadcast_value T> struct State {
    // Wait node of a parked receive, embedded in the receive operation state.
    // Outcomes are resolved under mutex by whoever wakes the node; the
    // completion fires after mutex is released.
    struct RecvNode {
        RecvNode *prev = nullptr;
        RecvNode *next = nullptr;
        enum class Stage : unsigned char { kInit, kQueued, kDone, kStopped, kGone };
        Stage stage = Stage::kInit;
        // Owning receiver's cursor address. Identifies the receiver this wait
        // belongs to (a second concurrent pull from the same receiver is a
        // single-consumer violation instead of a second wait), and receives
        // the cursor write-back whenever a value or lag is delivered to this
        // node. The receiver outlives its pulls by contract.
        std::uint64_t *cursor = nullptr;
        // Cursor of this wait: the sequence number it wants to read.
        std::uint64_t pos = 0;
        enum class Outcome : unsigned char { kValue, kLagged, kClosed };
        Outcome outcome = Outcome::kClosed;
        std::optional<T> held;
        std::size_t lagged = 0;
        // mutex NOT held; runs exactly once after the outcome was resolved.
        virtual void complete() noexcept = 0;
    };

    // Guards buffer, sequence bookkeeping, the parked list, and closed.
    // Never held across a completion callback.
    mutable std::mutex mutex;
    std::deque<T> buffer;
    std::size_t capacity = 0;
    // Sequence number of buffer.front(); next_seq() == base_seq + size().
    std::uint64_t base_seq = 0;
    std::uint64_t next_seq() const { return base_seq + buffer.size(); }
    RecvNode *park_head = nullptr;
    RecvNode *park_tail = nullptr;
    std::atomic<int> senders{1};
    std::atomic<int> receivers{0};
    std::atomic<bool> closed{false};

    explicit State(std::size_t cap) : capacity(cap) {}

    void link(RecvNode *node) {
        node->prev = park_tail;
        node->next = nullptr;
        if (park_tail != nullptr) {
            park_tail->next = node;
        } else {
            park_head = node;
        }
        park_tail = node;
    }

    void unlink(RecvNode *node) {
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

    // Resolve one parked waiter against the current buffer: lag, value, or
    // closed. mutex held. Always resolves while open (a push just made data
    // available or evicted it past the waiter). Commits the cursor write-back
    // for value/lag outcomes; stop/destroy paths never advance the cursor.
    void resolve(RecvNode *node) {
        if (closed.load(std::memory_order_relaxed)) {
            node->stage = RecvNode::Stage::kDone;
            node->outcome = RecvNode::Outcome::kClosed;
            return;
        }
        if (node->pos < base_seq) {
            node->stage = RecvNode::Stage::kDone;
            node->outcome = RecvNode::Outcome::kLagged;
            node->lagged = static_cast<std::size_t>(base_seq - node->pos);
            node->pos = base_seq;
        } else {
            node->stage = RecvNode::Stage::kDone;
            node->outcome = RecvNode::Outcome::kValue;
            node->held = buffer[static_cast<std::size_t>(node->pos - base_seq)];
            ++node->pos;
        }
        if (node->cursor != nullptr) {
            *node->cursor = node->pos;
        }
    }

    // Non-blocking send. Returns false when closed or when nobody receives.
    bool try_send(T value) {
        if (closed.load(std::memory_order_acquire)) {
            return false;
        }
        std::vector<RecvNode *> woken;
        {
            std::lock_guard lock(mutex);
            if (closed.load(std::memory_order_relaxed)) {
                return false;
            }
            if (receivers.load(std::memory_order_relaxed) == 0) {
                return false;
            }
            buffer.push_back(std::move(value));
            while (buffer.size() > capacity) {
                buffer.pop_front();
                ++base_seq;
            }
            for (auto *node = park_head; node != nullptr;) {
                auto *next = node->next;
                unlink(node);
                resolve(node);
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
        std::vector<RecvNode *> woken;
        {
            std::lock_guard lock(mutex);
            bool expected = false;
            if (!closed.compare_exchange_strong(expected, true, std::memory_order_acq_rel,
                                                std::memory_order_relaxed)) {
                return;
            }
            for (auto *node = park_head; node != nullptr;) {
                auto *next = node->next;
                unlink(node);
                node->stage = RecvNode::Stage::kDone;
                node->outcome = RecvNode::Outcome::kClosed;
                woken.push_back(node);
                node = next;
            }
        }
        for (auto *node : woken) {
            node->complete();
        }
    }

    bool is_closed() const { return closed.load(std::memory_order_acquire); }
};

// Operation state of a broadcast receive. Immovable: the wait node is linked
// by address. The receiver cursor advances only when a value or lag is
// actually delivered (never on stop or destroy, so a later pull retries the
// same position). Destroying a still-queued operation state releases the wait
// (cancel); a stop request completes with set_stopped.
template <broadcast_value T, stdexec::receiver Rcvr> class RecvOpState : public State<T>::RecvNode {
    using Node = typename State<T>::RecvNode;

    struct StopFn {
        RecvOpState *self;
        void operator()() const noexcept { self->on_stop(); }
    };

    using StopToken = stdexec::stop_token_of_t<stdexec::env_of_t<Rcvr>>;
    using StopCallback = stdexec::stop_callback_for_t<StopToken, StopFn>;

  public:
    using operation_state_concept = stdexec::operation_state_tag;

    RecvOpState(std::shared_ptr<State<T>> state, std::uint64_t *cursor, Rcvr receiver)
        : state_(std::move(state)), cursor_(cursor), receiver_(std::move(receiver)) {
        this->cursor = cursor;
    }

    RecvOpState(const RecvOpState &) = delete;
    RecvOpState &operator=(const RecvOpState &) = delete;

    ~RecvOpState() {
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
        switch (this->outcome) {
        case Node::Outcome::kValue:
            stdexec::set_value(std::move(receiver_), std::move(this->held));
            return;
        case Node::Outcome::kLagged: {
            auto lagged = this->lagged;
            this->lagged = 0;
            this->held.reset();
            stdexec::set_error(std::move(receiver_),
                               std::make_exception_ptr(broadcast_lagged(lagged)));
            return;
        }
        case Node::Outcome::kClosed:
            stdexec::set_value(std::move(receiver_), std::optional<T>());
            return;
        }
    }

    void start() noexcept {
        auto *state = state_.get();
        if (state == nullptr || cursor_ == nullptr) {
            stdexec::set_value(std::move(receiver_), std::optional<T>());
            return;
        }
        stop_callback_.emplace(stdexec::get_stop_token(stdexec::get_env(receiver_)), StopFn{this});
        enum class Outcome : unsigned char {
            kValue,
            kLagged,
            kClosed,
            kViolation,
            kQueued,
            kStopped
        };
        Outcome outcome = Outcome::kQueued;
        std::optional<T> out;
        std::size_t lagged = 0;
        {
            std::lock_guard lock(state->mutex);
            this->pos = *cursor_;
            if (stop_requested_) {
                outcome = Outcome::kStopped;
            } else if (this->pos < state->base_seq) {
                lagged = static_cast<std::size_t>(state->base_seq - this->pos);
                this->pos = state->base_seq;
                *cursor_ = this->pos;
                outcome = Outcome::kLagged;
            } else if (this->pos < state->next_seq()) {
                out = state->buffer[static_cast<std::size_t>(this->pos - state->base_seq)];
                ++this->pos;
                *cursor_ = this->pos;
                outcome = Outcome::kValue;
            } else if (state->closed.load(std::memory_order_relaxed)) {
                outcome = Outcome::kClosed;
            } else {
                bool duplicate = false;
                for (auto *node = state->park_head; node != nullptr; node = node->next) {
                    if (node != this && node->cursor != nullptr && node->cursor == this->cursor) {
                        duplicate = true;
                        break;
                    }
                }
                if (duplicate) {
                    // Single-consumer violation: this receiver already waits.
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
        case Outcome::kLagged:
            stdexec::set_error(std::move(receiver_),
                               std::make_exception_ptr(broadcast_lagged(lagged)));
            return;
        case Outcome::kClosed:
            stdexec::set_value(std::move(receiver_), std::optional<T>());
            return;
        case Outcome::kViolation:
            stdexec::set_error(std::move(receiver_),
                               std::make_exception_ptr(std::logic_error(
                                   "clash_native::async::broadcast: concurrent receive on a "
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
    // Owning receiver's cursor (advance on delivery only). The receiver
    // outlives its pulls by contract; null means detached.
    std::uint64_t *cursor_;
    Rcvr receiver_;
    bool stop_requested_ = false; // guarded by state_->mutex
    // Declared last so it is destroyed first.
    std::optional<StopCallback> stop_callback_;
};

template <broadcast_value T> class RecvSender {
  public:
    using sender_concept = stdexec::sender_tag;
    using completion_signatures =
        stdexec::completion_signatures<stdexec::set_value_t(std::optional<T>),
                                       stdexec::set_error_t(std::exception_ptr),
                                       stdexec::set_stopped_t()>;

    RecvSender(std::shared_ptr<State<T>> state, std::uint64_t *cursor)
        : state_(std::move(state)), cursor_(cursor) {}

    template <stdexec::receiver Rcvr> RecvOpState<T, Rcvr> connect(Rcvr receiver) && {
        return RecvOpState<T, Rcvr>(std::move(state_), cursor_, std::move(receiver));
    }

  private:
    std::shared_ptr<State<T>> state_;
    std::uint64_t *cursor_;
};

template <broadcast_value T> class Sender {
  public:
    Sender() = default;

    explicit Sender(std::shared_ptr<State<T>> state) : state_(std::move(state)) {}

    Sender(const Sender &other) : state_(other.state_) {
        if (state_) {
            state_->senders.fetch_add(1, std::memory_order_relaxed);
        }
    }

    Sender &operator=(const Sender &other) {
        if (this != &other) {
            Sender copy(other);
            release();
            state_ = std::move(copy.state_);
        }
        return *this;
    }

    Sender(Sender &&) noexcept = default;
    Sender &operator=(Sender &&other) noexcept {
        if (this != &other) {
            release();
            state_ = std::move(other.state_);
        }
        return *this;
    }

    ~Sender() { release(); }

    explicit operator bool() const { return static_cast<bool>(state_); }

    // Non-blocking, never waits: buffers the value (evicting the oldest when
    // full) and wakes parked receivers. Returns false when closed or when no
    // receiver exists.
    bool send(T value) const {
        if (!state_) {
            return false;
        }
        return state_->try_send(std::move(value));
    }

    void close() const {
        if (state_) {
            state_->close();
        }
    }

    bool is_closed() const {
        if (!state_) {
            return true;
        }
        return state_->is_closed();
    }

    std::size_t capacity() const {
        if (!state_) {
            return 0;
        }
        return state_->capacity;
    }

    std::size_t len() const {
        if (!state_) {
            return 0;
        }
        std::lock_guard lock(state_->mutex);
        return state_->buffer.size();
    }

    int receiver_count() const {
        if (!state_) {
            return 0;
        }
        return state_->receivers.load(std::memory_order_acquire);
    }

    // Add another subscriber. It observes only values sent after this call
    // (positioned at the current tail), like tokio's Sender::subscribe.
    Receiver<T> subscribe() const { return Receiver<T>(state_, /*tail=*/true); }

  private:
    void release() {
        if (!state_) {
            return;
        }
        bool last_sender = (state_->senders.fetch_sub(1, std::memory_order_acq_rel) == 1);
        if (last_sender) {
            state_->close();
        }
        state_.reset();
    }

    std::shared_ptr<State<T>> state_;
};

template <broadcast_value T> class Receiver {
  public:
    using value_type = T;

    Receiver() = default;

    explicit Receiver(std::shared_ptr<State<T>> state) : Receiver(std::move(state), false) {}

    Receiver(std::shared_ptr<State<T>> state, bool tail) : state_(std::move(state)) {
        if (state_) {
            std::lock_guard lock(state_->mutex);
            if (tail) {
                pos_ = state_->next_seq();
            }
            state_->receivers.fetch_add(1, std::memory_order_relaxed);
        }
    }

    Receiver(const Receiver &) = delete;
    Receiver &operator=(const Receiver &) = delete;

    Receiver(Receiver &&other) noexcept : state_(std::move(other.state_)), pos_(other.pos_) {}

    Receiver &operator=(Receiver &&other) noexcept {
        if (this != &other) {
            release();
            state_ = std::move(other.state_);
            pos_ = other.pos_;
        }
        return *this;
    }

    ~Receiver() { release(); }

    explicit operator bool() const { return static_cast<bool>(state_); }

    // Core async pull (awaitable, pipeable): the next value at this
    // receiver's cursor, disengaged at end, broadcast_lagged on lag.
    // Single-consumer: at most one outstanding next() per receiver.
    RecvSender<T> next() { return RecvSender<T>(state_, state_ ? &pos_ : nullptr); }

    RecvSender<T> recv() { return next(); }

    RecvSender<T> recv_raw() { return next(); }

    // Non-blocking: the next value, nullopt when nothing is ready or when
    // closed and drained; throws broadcast_lagged when behind.
    std::optional<T> try_recv() {
        if (!state_) {
            return std::nullopt;
        }
        std::lock_guard lock(state_->mutex);
        if (pos_ < state_->base_seq) {
            auto skipped = static_cast<std::size_t>(state_->base_seq - pos_);
            pos_ = state_->base_seq;
            throw broadcast_lagged(skipped);
        }
        if (pos_ < state_->next_seq()) {
            std::optional<T> out =
                state_->buffer[static_cast<std::size_t>(pos_ - state_->base_seq)];
            ++pos_;
            return out;
        }
        return std::nullopt;
    }

    // Values currently available for this receiver.
    std::size_t len() const {
        if (!state_) {
            return 0;
        }
        std::lock_guard lock(state_->mutex);
        std::uint64_t base = pos_ < state_->base_seq ? state_->base_seq : pos_;
        return base >= state_->next_seq() ? 0 : static_cast<std::size_t>(state_->next_seq() - base);
    }

    bool is_empty() const { return len() == 0; }

    bool is_closed() const {
        if (!state_) {
            return true;
        }
        return state_->is_closed();
    }

    void close() { release(); }

  private:
    void release() {
        if (!state_) {
            return;
        }
        state_->receivers.fetch_sub(1, std::memory_order_acq_rel);
        state_.reset();
    }

    std::shared_ptr<State<T>> state_;
    // This receiver's cursor: the sequence number of the next value to read.
    // Advanced only when a value or lag is delivered (never on stop/destroy,
    // so a later pull retries the same position).
    std::uint64_t pos_ = 0;
};

template <broadcast_value T> Channel<T> channel(std::size_t capacity) {
    if (capacity == 0) {
        throw std::invalid_argument(
            "clash_native::async::broadcast::channel: capacity must be at least 1");
    }
    auto state = std::make_shared<State<T>>(capacity);
    return {Sender<T>{state}, Receiver<T>{state}};
}

} // namespace broadcast
} // namespace clash_native::async
