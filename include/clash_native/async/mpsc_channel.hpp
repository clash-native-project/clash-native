#pragma once

#include <clash_native/async/oneshot.hpp>

#include <stdexec/execution.hpp>

#include <atomic>
#include <cstddef>
#include <deque>
#include <exception>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <utility>

namespace clash_native::async {
namespace mpsc {

inline constexpr std::size_t kUnbounded = std::numeric_limits<std::size_t>::max();

template <channel_value T> class Receiver;

template <channel_value T> class Sender;

template <channel_value T> class BoundedSender;

template <channel_value T> struct Channel {
    Sender<T> sender;
    Receiver<T> receiver;
};

template <channel_value T> struct BoundedChannel {
    BoundedSender<T> sender;
    Receiver<T> receiver;
};

template <channel_value T> struct State {
    // Type-erased wait node of a parked bounded send, embedded in the send
    // operation state (which lives on the caller's coroutine frame: no
    // allocation). The parked value stays inside the node (the value enters
    // the channel only when a receiver claims the node) and is withdrawn
    // silently if the operation state is destroyed while queued.
    //
    // All node transitions are arbitrated under `mutex`; completion callbacks
    // (`complete`) always fire after `mutex` has been released, so only the
    // brief queue/slot bookkeeping holds the lock.
    struct SendNode {
        SendNode *prev = nullptr;
        SendNode *next = nullptr;
        // Arbitration stage (guarded by State::mutex):
        //   kInit    - start() has not enqueued the node yet
        //   kQueued  - linked in the wait list; the value is owned by the node
        //   kClaimed - a receiver took the value (take_value ran); completion owed
        //   kClosed  - close() won; completion with false is owed
        //   kStopped - a stop request won; the callback unlinked and completed
        //   kGone    - the operation state destructor consumed the node
        enum class Stage : unsigned char { kInit, kQueued, kClaimed, kClosed, kStopped, kGone };
        Stage stage = Stage::kInit;
        // `mutex` held; pre: stage == kQueued. Moves the parked value out and
        // switches to kClaimed. The caller runs complete(true) after releasing
        // `mutex`.
        virtual T take_value() = 0;
        // `mutex` NOT held; called exactly once by the claiming receiver
        // (accepted=true) or by close() (accepted=false, value dropped).
        virtual void complete(bool accepted) noexcept = 0;
    };

    // Type-erased wait node of the single parked receiver (single-consumer
    // contract), embedded in the receive operation state. Symmetric to SendNode.
    struct RecvNode {
        // Arbitration stage (guarded by State::mutex):
        //   kInit    - start() has not taken the slot yet
        //   kQueued  - holds the slot; waiting for a value or close
        //   kClaimed - a sender stored a direct-delivery value (store ran)
        //   kClosed  - close() won; complete_closed() is owed
        //   kStopped - a stop request won; the slot was released
        //   kGone    - the operation state destructor consumed the node
        enum class Stage : unsigned char { kInit, kQueued, kClaimed, kClosed, kStopped, kGone };
        Stage stage = Stage::kInit;
        // `mutex` held; pre: stage == kQueued. Moves `value` into the node's
        // storage and switches to kClaimed. The caller runs complete_value()
        // after releasing `mutex`.
        virtual void store(T &&value) = 0;
        // `mutex` NOT held; pre: store() ran. Delivers set_value(optional<T>).
        virtual void complete_value() noexcept = 0;
        // `mutex` NOT held. Delivers set_value(nullopt) for close().
        virtual void complete_closed() noexcept = 0;
    };

    // Buffered values. Unbounded channels grow without limit; bounded channels
    // hold at most `capacity` entries (capacity == 0 means rendezvous: values
    // are only handed directly to a parked receiver, never buffered).
    std::deque<T> buffer;
    std::size_t capacity{kUnbounded};
    bool bounded_mode{false};
    // Guards `buffer`, the parked-receiver slot, the closed flag, and the
    // parked-sender wait list. Never held across a completion callback.
    mutable std::mutex mutex;
    // The single parked receiver (null while none). Invariant, under `mutex`:
    // non-null means a live node in kQueued: the operation state destructor
    // clears the slot first, so a visible node is always deliverable.
    RecvNode *recv_slot = nullptr;
    // FIFO wait list of parked bounded sends (intrusive; nodes live inside
    // their operation states).
    SendNode *wait_head = nullptr;
    SendNode *wait_tail = nullptr;
    std::atomic<int> senders{1};
    std::atomic<bool> closed{false};

    State() = default;

    explicit State(std::size_t cap) : capacity(cap), bounded_mode(true) {}

    // `mutex` held.
    void queue_send(SendNode *node) {
        node->prev = wait_tail;
        node->next = nullptr;
        if (wait_tail != nullptr) {
            wait_tail->next = node;
        } else {
            wait_head = node;
        }
        wait_tail = node;
    }

    // `mutex` held.
    void unlink_send(SendNode *node) {
        if (node->prev != nullptr) {
            node->prev->next = node->next;
        } else {
            wait_head = node->next;
        }
        if (node->next != nullptr) {
            node->next->prev = node->prev;
        } else {
            wait_tail = node->prev;
        }
        node->prev = node->next = nullptr;
    }

    // Synchronous send path. Directly hands the value to a parked receiver
    // when one exists, otherwise buffers it. Returns false when the channel
    // is closed, or when a bounded channel is full (the caller must park).
    bool try_send(T value) {
        if (closed.load(std::memory_order_acquire)) {
            return false;
        }
        RecvNode *slot = nullptr;
        {
            std::lock_guard lock(mutex);
            if (closed.load(std::memory_order_relaxed)) {
                return false;
            }
            if (recv_slot != nullptr) {
                slot = recv_slot;
                recv_slot = nullptr;
                slot->store(std::move(value));
            } else if (!bounded_mode) {
                buffer.push_back(std::move(value));
            } else if (buffer.size() < capacity) {
                buffer.push_back(std::move(value));
            } else {
                return false;
            }
        }
        if (slot != nullptr) {
            slot->complete_value();
        }
        return true;
    }

    void close() {
        RecvNode *slot = nullptr;
        SendNode *pending = nullptr;
        {
            std::lock_guard lock(mutex);
            bool expected = false;
            if (!closed.compare_exchange_strong(expected, true, std::memory_order_acq_rel,
                                                std::memory_order_relaxed)) {
                return;
            }
            slot = recv_slot;
            recv_slot = nullptr;
            if (slot != nullptr) {
                slot->stage = RecvNode::Stage::kClosed;
            }
            // Detach the whole wait list; parked sends complete with false
            // (their values are still owned by the nodes and die with them).
            pending = wait_head;
            wait_head = wait_tail = nullptr;
            for (auto *node = pending; node != nullptr; node = node->next) {
                node->stage = SendNode::Stage::kClosed;
            }
        }
        if (slot != nullptr) {
            slot->complete_closed();
        }
        while (pending != nullptr) {
            auto *node = pending;
            pending = pending->next;
            node->prev = node->next = nullptr;
            node->complete(false);
        }
    }

    std::optional<T> try_recv() {
        std::optional<T> out;
        SendNode *claimed = nullptr;
        {
            std::lock_guard lock(mutex);
            if (!buffer.empty()) {
                out = std::move(buffer.front());
                buffer.pop_front();
                if (bounded_mode && wait_head != nullptr) {
                    // Freed slot: accept the oldest parked value into the
                    // buffer and wake its sender (outside the lock).
                    claimed = wait_head;
                    unlink_send(claimed);
                    buffer.push_back(claimed->take_value());
                }
            } else if (bounded_mode && wait_head != nullptr) {
                // Rendezvous (capacity == 0) or transient empty: deliver the
                // parked value directly, bypassing the buffer.
                claimed = wait_head;
                unlink_send(claimed);
                out = claimed->take_value();
            }
        }
        if (claimed != nullptr) {
            claimed->complete(true);
        }
        return out;
    }

    bool is_closed() const { return closed.load(std::memory_order_acquire); }
};

// Operation state of a bounded send. Immovable: the wait node is linked by
// address. The value stays in `value_` until a receiver claims it: cancelling
// the wait withdraws the value from the channel, either via a stop request on
// the receiver's token (completion: set_stopped) or by destroying the
// operation state while queued (no completion).
template <channel_value T, stdexec::receiver Rcvr> class SendOpState : public State<T>::SendNode {
    using Node = typename State<T>::SendNode;

    struct StopFn {
        SendOpState *self;
        void operator()() const noexcept { self->on_stop(); }
    };

    using StopToken = stdexec::stop_token_of_t<stdexec::env_of_t<Rcvr>>;
    using StopCallback = stdexec::stop_callback_for_t<StopToken, StopFn>;

  public:
    using operation_state_concept = stdexec::operation_state_tag;

    SendOpState(std::shared_ptr<State<T>> state, T value, Rcvr receiver)
        : state_(std::move(state)), value_(std::move(value)), receiver_(std::move(receiver)) {}

    SendOpState(const SendOpState &) = delete;
    SendOpState &operator=(const SendOpState &) = delete;

    ~SendOpState() {
        // Destroying a still-queued operation state cancels the wait: unlink
        // so a late claim or close never touches the node; the value dies
        // with the operation state (withdrawn). Destroying a kClaimed node
        // before its completion fires is a P2300 contract violation.
        if (state_) {
            std::lock_guard lock(state_->mutex);
            if (this->stage == Node::Stage::kQueued) {
                state_->unlink_send(this);
                this->stage = Node::Stage::kGone;
            }
        }
    }

    T take_value() override {
        // `mutex` held by the caller; pre: kQueued.
        this->stage = Node::Stage::kClaimed;
        T out = std::move(*value_);
        value_.reset();
        return out;
    }

    void complete(bool accepted) noexcept override {
        // `mutex` released by the caller. Unregister first (never while
        // holding `mutex`): this may wait for an in-flight stop callback,
        // which itself needs `mutex`.
        stop_callback_.reset();
        stdexec::set_value(std::move(receiver_), accepted);
    }

    void start() noexcept {
        auto *state = state_.get();
        if (state == nullptr) {
            stdexec::set_value(std::move(receiver_), false);
            return;
        }
        // Register the stop callback before any completion can be in flight.
        stop_callback_.emplace(stdexec::get_stop_token(stdexec::get_env(receiver_)), StopFn{this});
        typename State<T>::RecvNode *direct = nullptr;
        enum class Outcome : unsigned char { kClosed, kDirect, kAccepted, kQueued, kStopped };
        Outcome outcome;
        {
            std::lock_guard lock(state->mutex);
            if (stop_requested_) {
                outcome = Outcome::kStopped;
            } else if (state->closed.load(std::memory_order_relaxed)) {
                outcome = Outcome::kClosed;
            } else if (state->recv_slot != nullptr) {
                direct = state->recv_slot;
                state->recv_slot = nullptr;
                direct->store(std::move(*value_));
                outcome = Outcome::kDirect;
            } else if (state->bounded_mode && state->buffer.size() < state->capacity) {
                state->buffer.push_back(std::move(*value_));
                value_.reset();
                outcome = Outcome::kAccepted;
            } else if (!state->bounded_mode) {
                state->buffer.push_back(std::move(*value_));
                value_.reset();
                outcome = Outcome::kAccepted;
            } else {
                // Full (or rendezvous): park until a receiver frees a slot.
                this->stage = Node::Stage::kQueued;
                state->queue_send(this);
                outcome = Outcome::kQueued;
            }
        }
        // Complete outside `mutex`: continuations may re-enter the channel.
        // The parked path keeps the stop registration armed; every other path
        // unregisters before completing (never while holding `mutex`).
        if (outcome != Outcome::kQueued) {
            stop_callback_.reset();
        }
        switch (outcome) {
        case Outcome::kClosed:
            stdexec::set_value(std::move(receiver_), false);
            return;
        case Outcome::kAccepted:
            stdexec::set_value(std::move(receiver_), true);
            return;
        case Outcome::kStopped:
            stdexec::set_stopped(std::move(receiver_));
            return;
        case Outcome::kQueued:
            return;
        case Outcome::kDirect:
            direct->complete_value();
            stdexec::set_value(std::move(receiver_), true);
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
                state->unlink_send(this);
                this->stage = Node::Stage::kStopped;
                fire = true;
            } else if (this->stage == Node::Stage::kInit) {
                stop_requested_ = true;
            }
            // kClaimed/kClosed/kStopped/kGone: too late, in-flight wins.
        }
        if (fire) {
            stdexec::set_stopped(std::move(receiver_));
        }
    }

    std::shared_ptr<State<T>> state_;
    std::optional<T> value_;
    Rcvr receiver_;
    bool stop_requested_{false}; // guarded by state_->mutex
    // Declared last so it is destroyed first: unregistering may block until
    // an in-flight callback returns, and the callback touches the members.
    std::optional<StopCallback> stop_callback_;
};

// Sender form of a bounded send. Carries the value until connect() moves it
// into the operation state. Completes with bool: true once accepted, false
// when the channel is closed (value dropped).
template <channel_value T> class SendSender {
  public:
    using sender_concept = stdexec::sender_tag;
    using completion_signatures =
        stdexec::completion_signatures<stdexec::set_value_t(bool), stdexec::set_stopped_t()>;

    SendSender(std::shared_ptr<State<T>> state, T value)
        : state_(std::move(state)), value_(std::move(value)) {}

    template <stdexec::receiver Rcvr> SendOpState<T, Rcvr> connect(Rcvr receiver) && {
        return SendOpState<T, Rcvr>(std::move(state_), std::move(value_), std::move(receiver));
    }

  private:
    std::shared_ptr<State<T>> state_;
    T value_;
};

// Operation state of a channel receive. Immovable: the wait node is linked by
// address. Parks by taking the state's single receive slot; destroying a
// still-queued operation state releases the slot (cancel).
template <channel_value T, stdexec::receiver Rcvr> class RecvOpState : public State<T>::RecvNode {
    using Node = typename State<T>::RecvNode;

    struct StopFn {
        RecvOpState *self;
        void operator()() const noexcept { self->on_stop(); }
    };

    using StopToken = stdexec::stop_token_of_t<stdexec::env_of_t<Rcvr>>;
    using StopCallback = stdexec::stop_callback_for_t<StopToken, StopFn>;

  public:
    using operation_state_concept = stdexec::operation_state_tag;

    RecvOpState(std::shared_ptr<State<T>> state, Rcvr receiver)
        : state_(std::move(state)), receiver_(std::move(receiver)) {}

    RecvOpState(const RecvOpState &) = delete;
    RecvOpState &operator=(const RecvOpState &) = delete;

    ~RecvOpState() {
        // Destroying a still-queued operation state cancels the wait: release
        // the slot so a late send/close never touches the node and a later
        // receive may park normally.
        if (state_) {
            std::lock_guard lock(state_->mutex);
            if (this->stage == Node::Stage::kQueued) {
                state_->recv_slot = nullptr;
                this->stage = Node::Stage::kGone;
            }
        }
    }

    void store(T &&value) override {
        // `mutex` held by the caller; pre: kQueued.
        held_ = std::move(value);
        this->stage = Node::Stage::kClaimed;
    }

    void complete_value() noexcept override {
        // `mutex` released by the caller; pre: store() ran.
        stop_callback_.reset();
        stdexec::set_value(std::move(receiver_), std::move(held_));
    }

    void complete_closed() noexcept override {
        // `mutex` released by the caller.
        stop_callback_.reset();
        stdexec::set_value(std::move(receiver_), std::optional<T>());
    }

    void start() noexcept {
        auto *state = state_.get();
        if (state == nullptr) {
            stdexec::set_value(std::move(receiver_), std::optional<T>());
            return;
        }
        stop_callback_.emplace(stdexec::get_stop_token(stdexec::get_env(receiver_)), StopFn{this});
        std::optional<T> out;
        typename State<T>::SendNode *claimed = nullptr;
        enum class Outcome : unsigned char { kValue, kClosed, kViolation, kQueued, kStopped };
        Outcome outcome;
        {
            std::lock_guard lock(state->mutex);
            if (stop_requested_) {
                outcome = Outcome::kStopped;
            } else {
                if (!state->buffer.empty()) {
                    out = std::move(state->buffer.front());
                    state->buffer.pop_front();
                    if (state->bounded_mode && state->wait_head != nullptr) {
                        claimed = state->wait_head;
                        state->unlink_send(claimed);
                        state->buffer.push_back(claimed->take_value());
                    }
                } else if (state->bounded_mode && state->wait_head != nullptr) {
                    claimed = state->wait_head;
                    state->unlink_send(claimed);
                    out = claimed->take_value();
                }
                if (out) {
                    outcome = Outcome::kValue;
                } else if (state->closed.load(std::memory_order_relaxed)) {
                    outcome = Outcome::kClosed;
                } else if (state->recv_slot != nullptr) {
                    // Single-consumer violation: a previous receive is still
                    // parked. Fail the new call so the bug surfaces at the
                    // offending call site instead of clobbering the wait.
                    outcome = Outcome::kViolation;
                } else {
                    this->stage = Node::Stage::kQueued;
                    state->recv_slot = this;
                    outcome = Outcome::kQueued;
                }
            }
        }
        // Complete outside `mutex`: continuations may re-enter the channel.
        if (claimed != nullptr) {
            claimed->complete(true);
        }
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
                                   "clash_native::async::mpsc: concurrent receive on a "
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
                state->recv_slot = nullptr;
                this->stage = Node::Stage::kStopped;
                fire = true;
            } else if (this->stage == Node::Stage::kInit) {
                stop_requested_ = true;
            }
            // kClaimed/kClosed/kStopped/kGone: too late, in-flight wins.
        }
        if (fire) {
            stdexec::set_stopped(std::move(receiver_));
        }
    }

    std::shared_ptr<State<T>> state_;
    Rcvr receiver_;
    std::optional<T> held_;
    bool stop_requested_{false}; // guarded by state_->mutex
    // Declared last so it is destroyed first: unregistering may block until
    // an in-flight callback returns, and the callback touches the members.
    std::optional<StopCallback> stop_callback_;
};

// Sender form of a channel receive. Completes with std::optional<T>
// (disengaged means closed and drained), set_error(logic_error) on a
// single-consumer violation, or set_stopped on cancellation.
template <channel_value T> class RecvSender {
  public:
    using sender_concept = stdexec::sender_tag;
    using completion_signatures =
        stdexec::completion_signatures<stdexec::set_value_t(std::optional<T>),
                                       stdexec::set_error_t(std::exception_ptr),
                                       stdexec::set_stopped_t()>;

    explicit RecvSender(std::shared_ptr<State<T>> state) : state_(std::move(state)) {}

    template <stdexec::receiver Rcvr> RecvOpState<T, Rcvr> connect(Rcvr receiver) && {
        return RecvOpState<T, Rcvr>(std::move(state_), std::move(receiver));
    }

  private:
    std::shared_ptr<State<T>> state_;
};

template <channel_value T> class Sender {
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

    // Non-blocking. Returns false when the channel is closed.
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

// Bounded (backpressure) sender: send() never blocks a thread. When the
// channel is full the returned sender parks until a receiver frees a slot.
// Completion: true once accepted, false when the channel is closed (value
// dropped). Cancel-safe: the value stays inside the operation state until a
// receiver claims it, so destroying the operation state while parked
// withdraws the value.
template <channel_value T> class BoundedSender {
  public:
    BoundedSender() = default;

    explicit BoundedSender(std::shared_ptr<State<T>> state) : state_(std::move(state)) {}

    BoundedSender(const BoundedSender &other) : state_(other.state_) {
        if (state_) {
            state_->senders.fetch_add(1, std::memory_order_relaxed);
        }
    }

    BoundedSender &operator=(const BoundedSender &other) {
        if (this != &other) {
            BoundedSender copy(other);
            release();
            state_ = std::move(copy.state_);
        }
        return *this;
    }

    BoundedSender(BoundedSender &&) noexcept = default;
    BoundedSender &operator=(BoundedSender &&other) noexcept {
        if (this != &other) {
            release();
            state_ = std::move(other.state_);
        }
        return *this;
    }

    ~BoundedSender() { release(); }

    explicit operator bool() const { return static_cast<bool>(state_); }

    SendSender<T> send(T value) const {
        // A detached sender (state_ == null) completes with false on start().
        return SendSender<T>(state_, std::move(value));
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

    // Configured capacity (0 means rendezvous); 0 when detached.
    std::size_t capacity() const {
        if (!state_) {
            return 0;
        }
        return state_->capacity;
    }

    // Free slots right now. This is a point-in-time snapshot; concurrent
    // activity may change it immediately.
    std::size_t remaining_capacity() const {
        if (!state_) {
            return 0;
        }
        std::lock_guard lock(state_->mutex);
        return state_->buffer.size() >= state_->capacity ? 0
                                                         : state_->capacity - state_->buffer.size();
    }

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

template <channel_value T> class Receiver {
  public:
    using value_type = T;

    Receiver() = default;

    explicit Receiver(std::shared_ptr<State<T>> state) : state_(std::move(state)) {}

    Receiver(const Receiver &) = delete;
    Receiver &operator=(const Receiver &) = delete;

    Receiver(Receiver &&) noexcept = default;
    Receiver &operator=(Receiver &&other) noexcept {
        if (this != &other) {
            close();
            state_ = std::move(other.state_);
        }
        return *this;
    }

    ~Receiver() { close(); }

    explicit operator bool() const { return static_cast<bool>(state_); }

    // Core async pull. Returns a sender (awaitable in a coroutine, pipeable
    // with sender adaptors) that completes with std::optional<T>: an engaged
    // value, or disengaged when the channel is closed and drained.
    // Single-consumer: at most one outstanding next() operation; a concurrent
    // second pull fails with std::logic_error instead of clobbering the wait.
    RecvSender<T> next() { return RecvSender<T>(state_); }

    // Alias of next() for channel-style call sites.
    RecvSender<T> recv() { return RecvSender<T>(state_); }

    // Alias of next() for advanced call sites that connect a custom receiver
    // (for example one whose environment carries a stop token).
    RecvSender<T> recv_raw() { return RecvSender<T>(state_); }

    std::optional<T> try_recv() {
        if (!state_) {
            return std::nullopt;
        }
        return state_->try_recv();
    }

    bool is_closed() const {
        if (!state_) {
            return true;
        }
        return state_->is_closed();
    }

    void close() {
        if (state_) {
            state_->close();
            state_.reset();
        }
    }

  private:
    std::shared_ptr<State<T>> state_;
};

template <channel_value T> Channel<T> unbounded() {
    auto state = std::make_shared<State<T>>();
    return {Sender<T>{state}, Receiver<T>{state}};
}

template <channel_value T> BoundedChannel<T> bounded(std::size_t capacity) {
    auto state = std::make_shared<State<T>>(capacity);
    return {BoundedSender<T>{state}, Receiver<T>{state}};
}

} // namespace mpsc
} // namespace clash_native::async
