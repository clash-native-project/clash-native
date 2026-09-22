#pragma once

#include <clash_native/async/mpsc_channel.hpp>

#include <stdexec/execution.hpp>

#include <exec/any_sender_of.hpp>
#include <exec/async_scope.hpp>
#include <exec/task.hpp>

#include <chrono>
#include <concepts>
#include <cstddef>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

// Sender-native asynchronous streams.
//
// A stream is any move-only object with a `value_type` member whose `next()`
// member returns a *sender* (not a coroutine task wrapper around one). Every
// pull completes with exactly one of:
//   set_value(std::optional<value_type>) - engaged item, or disengaged at end
//   set_error(std::exception_ptr)        - the stream failed
//   set_stopped()                        - the pull was cancelled
//
// Because `next()` returns a real sender, operators compose statically (no
// virtual dispatch, no heap allocation per stage) and stop tokens propagate
// through the whole pipeline: cancelling the outermost pull cancels the
// outstanding upstream pull. Only one `next()` operation may be outstanding
// per stream at a time (single-consumer contract, enforced at runtime by the
// mpsc receiver and assumed by operators).
//
// Pipelines read left to right, either nested or piped:
//
//   auto total = co_await (from_vector<int>({1, 2, 3})
//                         | async_map([](int v) { return v * 2; })
//                         | async_filter([](int v) { return v > 2; })
//                         | async_fold(0, std::plus<>{}));
//
//   stdexec::sync_wait(std::move(pipeline));  // outside a coroutine

namespace clash_native::async {

template <class S> using stream_value_t = typename std::remove_cvref_t<S>::value_type;

namespace detail {

struct NextFn {
    template <class S>
    constexpr auto operator()(S &stream) const noexcept(noexcept(stream.next()))
        -> decltype(stream.next()) {
        return stream.next();
    }
};

} // namespace detail

inline constexpr detail::NextFn next{};

template <class S>
concept async_stream = channel_value<stream_value_t<S>> && std::movable<std::remove_cvref_t<S>> &&
                       requires(std::remove_cvref_t<S> &stream) {
                           { next(stream) } -> stdexec::sender;
                       };

template <class A>
concept stream_adaptor = requires { typename std::remove_cvref_t<A>::stream_adaptor_tag; };

// Pipe a stream through a unary adaptor: `s | async_map(f)`.
template <async_stream S, stream_adaptor A> auto operator|(S &&stream, A &&adaptor) {
    return std::forward<A>(adaptor)(std::forward<S>(stream));
}

namespace detail {

// Environment that forwards only the stop token, resolved eagerly. Returning
// the outer environment by value is impossible in general (type-erased
// receiver envs are immovable) and returning it by reference would dangle
// whenever the outer get_env() returns a prvalue, so operator adapters
// snapshot the token instead. Tokens are cheap views, so liveness is
// unaffected. No other query is forwarded: no sender in this library queries
// schedulers or domains from its receiver's environment.
template <class Rcvr> struct ForwardStopEnv {
    stdexec::stop_token_of_t<stdexec::env_of_t<Rcvr>> token;
    auto query(stdexec::get_stop_token_t) const noexcept { return token; }
};

// In-place slot for a nested operation state. Operation states are immovable
// in general (channel wait nodes are linked by address), and
// `std::optional<Op>::emplace(connect(...))` would move the prvalue through
// forwarding, so the operation is connected directly into manual storage
// (guaranteed elision into placement new) instead.
template <class Op> struct OpSlot {
    OpSlot() = default;
    OpSlot(const OpSlot &) = delete;
    OpSlot &operator=(const OpSlot &) = delete;

    ~OpSlot() { reset(); }

    template <class Sender, class Receiver> void emplace(Sender &&sender, Receiver &&receiver) {
        reset();
        slot_ = ::new (static_cast<void *>(storage_))
            Op(stdexec::connect(std::forward<Sender>(sender), std::forward<Receiver>(receiver)));
    }

    void reset() {
        if (slot_ != nullptr) {
            slot_->~Op();
            slot_ = nullptr;
        }
    }

    Op &operator*() { return *slot_; }
    const Op &operator*() const { return *slot_; }
    explicit operator bool() const { return slot_ != nullptr; }

  private:
    alignas(Op) unsigned char storage_[sizeof(Op)];
    Op *slot_{nullptr};
};

// Single upstream pull with a pure transform. Func is
// `std::optional<U>(T&&)`; end-of-stream bypasses it. A disengaged
// `upstream_` completes with end-of-stream without pulling (used by take and
// take_while once they are exhausted).
template <class UpSender, class T, class U, class Func> struct TransformSender {
    using sender_concept = stdexec::sender_tag;
    using completion_signatures =
        stdexec::completion_signatures<stdexec::set_value_t(std::optional<U>),
                                       stdexec::set_error_t(std::exception_ptr),
                                       stdexec::set_stopped_t()>;

    std::optional<UpSender> upstream_;
    Func func_;

    template <stdexec::receiver Rcvr> struct OpState {
        using operation_state_concept = stdexec::operation_state_tag;

        struct Inner {
            // NOTE: no ref-qualifiers on the completions below. The erased
            // pull sender invokes the wrapped receiver as an lvalue, while
            // plain senders invoke it as an rvalue; only unqualified
            // overloads accept both. Do not add ref-qualifiers here.
            using receiver_concept = stdexec::receiver_tag;
            OpState *self_;
            auto get_env() const noexcept {
                return detail::ForwardStopEnv<Rcvr>{
                    stdexec::get_stop_token(stdexec::get_env(self_->receiver_))};
            }
            void set_value(std::optional<T> value) noexcept {
                if (!value) {
                    stdexec::set_value(std::move(self_->receiver_), std::optional<U>());
                    return;
                }
                try {
                    stdexec::set_value(std::move(self_->receiver_),
                                       self_->func_(std::move(*value)));
                } catch (...) {
                    stdexec::set_error(std::move(self_->receiver_), std::current_exception());
                }
            }
            void set_error(std::exception_ptr error) noexcept {
                stdexec::set_error(std::move(self_->receiver_), std::move(error));
            }
            void set_stopped() noexcept { stdexec::set_stopped(std::move(self_->receiver_)); }
        };

        std::optional<UpSender> upstream_;
        Func func_;
        Rcvr receiver_;
        OpSlot<stdexec::connect_result_t<UpSender, Inner>> inner_op_;

        void start() noexcept {
            if (stdexec::get_stop_token(stdexec::get_env(receiver_)).stop_requested()) {
                stdexec::set_stopped(std::move(receiver_));
                return;
            }
            if (!upstream_) {
                stdexec::set_value(std::move(receiver_), std::optional<U>());
                return;
            }
            inner_op_.emplace(std::move(*upstream_), Inner{this});
            upstream_.reset();
            stdexec::start(*inner_op_);
        }
    };

    template <stdexec::receiver Rcvr> OpState<Rcvr> connect(Rcvr receiver) && {
        return OpState<Rcvr>{std::move(upstream_), std::move(func_), std::move(receiver)};
    }
};

// Repeated upstream pulls until a step delivers. Step is
// `std::optional<std::optional<U>>(T&&)`: disengaged means "pull again",
// engaged means "deliver" (an item or end-of-stream). End-of-stream from
// upstream always delivers end-of-stream. The stream is re-polled through the
// borrowed `Stream*`, so no upstream sender is ever reused after being moved
// from. The stream must outlive the pull (single-outstanding-pull contract).
template <class Stream, class T, class U, class Step> struct RepeatSender {
    using sender_concept = stdexec::sender_tag;
    using completion_signatures =
        stdexec::completion_signatures<stdexec::set_value_t(std::optional<U>),
                                       stdexec::set_error_t(std::exception_ptr),
                                       stdexec::set_stopped_t()>;

    Stream *stream_;
    Step step_;

    template <stdexec::receiver Rcvr> struct OpState {
        using operation_state_concept = stdexec::operation_state_tag;
        using UpSender = decltype(next(std::declval<Stream &>()));

        struct Inner {
            // NOTE: no ref-qualifiers on the completions below. The erased
            // pull sender invokes the wrapped receiver as an lvalue, while
            // plain senders invoke it as an rvalue; only unqualified
            // overloads accept both. Do not add ref-qualifiers here.
            using receiver_concept = stdexec::receiver_tag;
            OpState *self_;
            auto get_env() const noexcept {
                return detail::ForwardStopEnv<Rcvr>{
                    stdexec::get_stop_token(stdexec::get_env(self_->receiver_))};
            }
            void set_value(std::optional<T> value) noexcept {
                if (!value) {
                    stdexec::set_value(std::move(self_->receiver_), std::optional<U>());
                    return;
                }
                std::optional<std::optional<U>> next;
                try {
                    next = self_->step_(std::move(*value));
                } catch (...) {
                    stdexec::set_error(std::move(self_->receiver_), std::current_exception());
                    return;
                }
                if (next) {
                    stdexec::set_value(std::move(self_->receiver_), std::move(*next));
                } else {
                    // Ask for another pull without recursing: when the
                    // upstream completes inline (synchronous sources), the
                    // pull loop in pull() iterates instead of growing the
                    // stack; otherwise restart the wait from here.
                    self_->inner_op_.reset();
                    if (self_->in_frame_) {
                        self_->repeat_ = true;
                    } else {
                        self_->pull();
                    }
                }
            }
            void set_error(std::exception_ptr error) noexcept {
                stdexec::set_error(std::move(self_->receiver_), std::move(error));
            }
            void set_stopped() noexcept { stdexec::set_stopped(std::move(self_->receiver_)); }
        };

        Stream *stream_;
        Step step_;
        Rcvr receiver_;
        OpSlot<stdexec::connect_result_t<UpSender, Inner>> inner_op_;
        // Trampoline state for inline-completing upstreams (see pull()).
        bool in_frame_{false};
        bool repeat_{false};

        void pull_raw() noexcept {
            inner_op_.emplace(next(*stream_), Inner{this});
            in_frame_ = true;
            stdexec::start(*inner_op_);
            in_frame_ = false;
        }

        void pull() noexcept {
            do {
                repeat_ = false;
                pull_raw();
            } while (repeat_);
        }

        void start() noexcept {
            if (stdexec::get_stop_token(stdexec::get_env(receiver_)).stop_requested()) {
                stdexec::set_stopped(std::move(receiver_));
                return;
            }
            pull();
        }
    };

    template <stdexec::receiver Rcvr> OpState<Rcvr> connect(Rcvr receiver) && {
        return OpState<Rcvr>{stream_, std::move(step_), std::move(receiver)};
    }
};

} // namespace detail

// ---------------------------------------------------------------------------
// Factories
// ---------------------------------------------------------------------------

template <channel_value T> class EmptyStream {
  public:
    using value_type = T;
    auto next() { return stdexec::just(std::optional<T>()); }
};

template <channel_value T> EmptyStream<T> empty() { return {}; }

template <channel_value T> class OnceStream {
  public:
    using value_type = T;
    explicit OnceStream(T value) : payload_(std::move(value)) {}
    auto next() {
        std::optional<T> out = std::move(payload_);
        payload_.reset();
        return stdexec::just(std::move(out));
    }

  private:
    std::optional<T> payload_;
};

template <channel_value T> OnceStream<T> once(T value) { return OnceStream<T>(std::move(value)); }

template <channel_value T> class FromVectorStream {
  public:
    using value_type = T;
    explicit FromVectorStream(std::vector<T> values) : items_(std::move(values)) {}
    auto next() {
        std::optional<T> out;
        if (index_ < items_.size()) {
            out = std::move(items_[index_++]);
        }
        return stdexec::just(std::move(out));
    }

  private:
    std::vector<T> items_;
    std::size_t index_{0};
};

template <channel_value T> FromVectorStream<T> from_vector(std::vector<T> values) {
    return FromVectorStream<T>(std::move(values));
}

// Ticks 0, 1, 2, ... on any timed scheduler (anything providing
// `schedule_after(duration)`). The completion of each pull arrives on the
// scheduler; cancelling the pull cancels the pending sleep.
template <channel_value T, class Sched> class IntervalStream {
    static_assert(std::is_integral_v<T>, "interval requires an integral value type");

  public:
    using value_type = T;
    IntervalStream(Sched scheduler, std::chrono::milliseconds period)
        : scheduler_(std::move(scheduler)), period_(period), counter_(std::make_shared<T>(0)) {}
    auto next() {
        return scheduler_.schedule_after(period_) | stdexec::then([counter = counter_]() {
                   std::optional<T> out((*counter)++);
                   return out;
               });
    }

  private:
    Sched scheduler_;
    std::chrono::milliseconds period_;
    std::shared_ptr<T> counter_;
};

template <channel_value T, class Sched>
IntervalStream<T, std::decay_t<Sched>> interval_on(Sched &&scheduler,
                                                   std::chrono::milliseconds period) {
    return IntervalStream<T, std::decay_t<Sched>>(std::forward<Sched>(scheduler), period);
}

// ---------------------------------------------------------------------------
// map
// ---------------------------------------------------------------------------

template <async_stream Up, class F> class MapStream {
  public:
    using UpValue = stream_value_t<Up>;
    using value_type = std::decay_t<std::invoke_result_t<F, UpValue>>;

    MapStream(Up upstream, F func) : upstream_(std::move(upstream)), func_(std::move(func)) {}

    auto next() {
        using UpSender = decltype(async::next(upstream_));
        struct Step {
            F *func_;
            std::optional<value_type> operator()(UpValue &&item) {
                return std::optional<value_type>(std::invoke(*func_, std::move(item)));
            }
        };
        return detail::TransformSender<UpSender, UpValue, value_type, Step>{
            std::optional<UpSender>(async::next(upstream_)), Step{&func_}};
    }

  private:
    Up upstream_;
    F func_;
};

template <class F> struct MapAdaptor {
    using stream_adaptor_tag = void;
    F func_;
    template <async_stream S> auto operator()(S &&stream) && {
        return MapStream<std::remove_cvref_t<S>, F>(std::forward<S>(stream), std::move(func_));
    }
};

struct AsyncMapFn {
    template <class F> auto operator()(F &&func) const {
        return MapAdaptor<std::decay_t<F>>{std::forward<F>(func)};
    }
    template <async_stream S, class F> auto operator()(S &&stream, F &&func) const {
        return MapStream<std::remove_cvref_t<S>, std::decay_t<F>>(std::forward<S>(stream),
                                                                  std::forward<F>(func));
    }
};

inline constexpr AsyncMapFn async_map{};

// ---------------------------------------------------------------------------
// filter
// ---------------------------------------------------------------------------

template <async_stream Up, class F> class FilterStream {
  public:
    using value_type = stream_value_t<Up>;

    FilterStream(Up upstream, F func) : upstream_(std::move(upstream)), func_(std::move(func)) {}

    auto next() {
        struct Step {
            F *func_;
            std::optional<std::optional<value_type>> operator()(value_type &&item) {
                if (std::invoke(*func_, item)) {
                    return std::optional<std::optional<value_type>>(
                        std::optional<value_type>(std::move(item)));
                }
                return std::nullopt;
            }
        };
        return detail::RepeatSender<Up, value_type, value_type, Step>{&upstream_, Step{&func_}};
    }

  private:
    Up upstream_;
    F func_;
};

template <class F> struct FilterAdaptor {
    using stream_adaptor_tag = void;
    F func_;
    template <async_stream S> auto operator()(S &&stream) && {
        return FilterStream<std::remove_cvref_t<S>, F>(std::forward<S>(stream), std::move(func_));
    }
};

struct AsyncFilterFn {
    template <class F> auto operator()(F &&func) const {
        return FilterAdaptor<std::decay_t<F>>{std::forward<F>(func)};
    }
    template <async_stream S, class F> auto operator()(S &&stream, F &&func) const {
        return FilterStream<std::remove_cvref_t<S>, std::decay_t<F>>(std::forward<S>(stream),
                                                                     std::forward<F>(func));
    }
};

inline constexpr AsyncFilterFn async_filter{};

// ---------------------------------------------------------------------------
// take
// ---------------------------------------------------------------------------

template <async_stream Up> class TakeStream {
  public:
    using value_type = stream_value_t<Up>;

    TakeStream(Up upstream, std::size_t count)
        : upstream_(std::move(upstream)), remaining_(count) {}

    auto next() {
        using UpSender = decltype(async::next(upstream_));
        struct Step {
            std::optional<value_type> operator()(value_type &&item) {
                return std::optional<value_type>(std::move(item));
            }
        };
        std::optional<UpSender> pull;
        if (remaining_ > 0) {
            --remaining_;
            pull.emplace(async::next(upstream_));
        }
        return detail::TransformSender<UpSender, value_type, value_type, Step>{std::move(pull),
                                                                               Step{}};
    }

  private:
    Up upstream_;
    std::size_t remaining_;
};

struct TakeAdaptor {
    using stream_adaptor_tag = void;
    std::size_t count_;
    template <async_stream S> auto operator()(S &&stream) && {
        return TakeStream<std::remove_cvref_t<S>>(std::forward<S>(stream), count_);
    }
};

struct AsyncTakeFn {
    auto operator()(std::size_t count) const { return TakeAdaptor{count}; }
    template <async_stream S> auto operator()(S &&stream, std::size_t count) const {
        return TakeStream<std::remove_cvref_t<S>>(std::forward<S>(stream), count);
    }
};

inline constexpr AsyncTakeFn async_take{};

// ---------------------------------------------------------------------------
// take_while
// ---------------------------------------------------------------------------

template <async_stream Up, class F> class TakeWhileStream {
  public:
    using value_type = stream_value_t<Up>;

    TakeWhileStream(Up upstream, F func) : upstream_(std::move(upstream)), func_(std::move(func)) {}

    auto next() {
        using UpSender = decltype(async::next(upstream_));
        struct Step {
            F *func_;
            bool *done_;
            std::optional<value_type> operator()(value_type &&item) {
                if (*done_) {
                    return std::nullopt;
                }
                if (!std::invoke(*func_, item)) {
                    *done_ = true;
                    return std::nullopt;
                }
                return std::optional<value_type>(std::move(item));
            }
        };
        std::optional<UpSender> pull;
        if (!done_) {
            pull.emplace(async::next(upstream_));
        }
        return detail::TransformSender<UpSender, value_type, value_type, Step>{
            std::move(pull), Step{&func_, &done_}};
    }

  private:
    Up upstream_;
    F func_;
    bool done_{false};
};

template <class F> struct TakeWhileAdaptor {
    using stream_adaptor_tag = void;
    F func_;
    template <async_stream S> auto operator()(S &&stream) && {
        return TakeWhileStream<std::remove_cvref_t<S>, F>(std::forward<S>(stream),
                                                          std::move(func_));
    }
};

struct AsyncTakeWhileFn {
    template <class F> auto operator()(F &&func) const {
        return TakeWhileAdaptor<std::decay_t<F>>{std::forward<F>(func)};
    }
    template <async_stream S, class F> auto operator()(S &&stream, F &&func) const {
        return TakeWhileStream<std::remove_cvref_t<S>, std::decay_t<F>>(std::forward<S>(stream),
                                                                        std::forward<F>(func));
    }
};

inline constexpr AsyncTakeWhileFn async_take_while{};

// ---------------------------------------------------------------------------
// skip
// ---------------------------------------------------------------------------

template <async_stream Up> class SkipStream {
  public:
    using value_type = stream_value_t<Up>;

    SkipStream(Up upstream, std::size_t count)
        : upstream_(std::move(upstream)), remaining_(count) {}

    auto next() {
        struct Step {
            std::size_t *remaining_;
            std::optional<std::optional<value_type>> operator()(value_type &&item) {
                if (*remaining_ > 0) {
                    --(*remaining_);
                    return std::nullopt;
                }
                return std::optional<std::optional<value_type>>(
                    std::optional<value_type>(std::move(item)));
            }
        };
        return detail::RepeatSender<Up, value_type, value_type, Step>{&upstream_, {&remaining_}};
    }

  private:
    Up upstream_;
    std::size_t remaining_;
};

struct SkipAdaptor {
    using stream_adaptor_tag = void;
    std::size_t count_;
    template <async_stream S> auto operator()(S &&stream) && {
        return SkipStream<std::remove_cvref_t<S>>(std::forward<S>(stream), count_);
    }
};

struct AsyncSkipFn {
    auto operator()(std::size_t count) const { return SkipAdaptor{count}; }
    template <async_stream S> auto operator()(S &&stream, std::size_t count) const {
        return SkipStream<std::remove_cvref_t<S>>(std::forward<S>(stream), count);
    }
};

inline constexpr AsyncSkipFn async_skip{};

// ---------------------------------------------------------------------------
// skip_while
// ---------------------------------------------------------------------------

template <async_stream Up, class F> class SkipWhileStream {
  public:
    using value_type = stream_value_t<Up>;

    SkipWhileStream(Up upstream, F func) : upstream_(std::move(upstream)), func_(std::move(func)) {}

    auto next() {
        struct Step {
            F *func_;
            bool *skipping_;
            std::optional<std::optional<value_type>> operator()(value_type &&item) {
                if (*skipping_) {
                    if (std::invoke(*func_, item)) {
                        return std::nullopt;
                    }
                    *skipping_ = false;
                }
                return std::optional<std::optional<value_type>>(
                    std::optional<value_type>(std::move(item)));
            }
        };
        return detail::RepeatSender<Up, value_type, value_type, Step>{&upstream_,
                                                                      {&func_, &skipping_}};
    }

  private:
    Up upstream_;
    F func_;
    bool skipping_{true};
};

template <class F> struct SkipWhileAdaptor {
    using stream_adaptor_tag = void;
    F func_;
    template <async_stream S> auto operator()(S &&stream) && {
        return SkipWhileStream<std::remove_cvref_t<S>, F>(std::forward<S>(stream),
                                                          std::move(func_));
    }
};

struct AsyncSkipWhileFn {
    template <class F> auto operator()(F &&func) const {
        return SkipWhileAdaptor<std::decay_t<F>>{std::forward<F>(func)};
    }
    template <async_stream S, class F> auto operator()(S &&stream, F &&func) const {
        return SkipWhileStream<std::remove_cvref_t<S>, std::decay_t<F>>(std::forward<S>(stream),
                                                                        std::forward<F>(func));
    }
};

inline constexpr AsyncSkipWhileFn async_skip_while{};

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

template <async_stream Up, class Acc, class F> class ScanStream {
  public:
    using value_type = Acc;

    ScanStream(Up upstream, Acc init, F func)
        : upstream_(std::move(upstream)), acc_(std::move(init)), func_(std::move(func)) {}

    auto next() {
        using UpSender = decltype(async::next(upstream_));
        using UpValue = stream_value_t<Up>;
        struct Step {
            Acc *acc_;
            F *func_;
            std::optional<Acc> operator()(UpValue &&item) {
                *acc_ = std::invoke(*func_, std::move(*acc_), std::move(item));
                return std::optional<Acc>(*acc_);
            }
        };
        return detail::TransformSender<UpSender, UpValue, Acc, Step>{
            std::optional<UpSender>(async::next(upstream_)), {&acc_, &func_}};
    }

  private:
    Up upstream_;
    Acc acc_;
    F func_;
};

template <class Acc, class F> struct ScanAdaptor {
    using stream_adaptor_tag = void;
    Acc init_;
    F func_;
    template <async_stream S> auto operator()(S &&stream) && {
        return ScanStream<std::remove_cvref_t<S>, Acc, F>(std::forward<S>(stream), std::move(init_),
                                                          std::move(func_));
    }
};

struct AsyncScanFn {
    template <class Acc, class F> auto operator()(Acc init, F &&func) const {
        return ScanAdaptor<Acc, std::decay_t<F>>{std::move(init), std::forward<F>(func)};
    }
    template <async_stream S, class Acc, class F>
    auto operator()(S &&stream, Acc init, F &&func) const {
        return ScanStream<std::remove_cvref_t<S>, Acc, std::decay_t<F>>(
            std::forward<S>(stream), std::move(init), std::forward<F>(func));
    }
};

inline constexpr AsyncScanFn async_scan{};

// ---------------------------------------------------------------------------
// flat_map
// ---------------------------------------------------------------------------

template <async_stream Up, class F> class FlatMapStream {
  public:
    using UpValue = stream_value_t<Up>;
    using InnerStream = std::invoke_result_t<F, UpValue>;
    using value_type = stream_value_t<InnerStream>;

    static_assert(async_stream<InnerStream>, "flat_map function must return an async_stream");

    FlatMapStream(Up upstream, F func) : upstream_(std::move(upstream)), func_(std::move(func)) {}

    auto next() { return FlatSender{this}; }

  private:
    struct FlatSender {
        using sender_concept = stdexec::sender_tag;
        using completion_signatures =
            stdexec::completion_signatures<stdexec::set_value_t(std::optional<value_type>),
                                           stdexec::set_error_t(std::exception_ptr),
                                           stdexec::set_stopped_t()>;

        FlatMapStream *self_;

        template <stdexec::receiver Rcvr> struct OpState {
            using operation_state_concept = stdexec::operation_state_tag;
            using OuterSender = decltype(clash_native::async::next(std::declval<Up &>()));
            using InnerNextSender =
                decltype(clash_native::async::next(std::declval<InnerStream &>()));

            struct OuterInner {
                // NOTE: no ref-qualifiers on the completions below. The erased
                // pull sender invokes the wrapped receiver as an lvalue, while
                // plain senders invoke it as an rvalue; only unqualified
                // overloads accept both. Do not add ref-qualifiers here.
                using receiver_concept = stdexec::receiver_tag;
                OpState *self_;
                auto get_env() const noexcept {
                    return detail::ForwardStopEnv<Rcvr>{
                        stdexec::get_stop_token(stdexec::get_env(self_->receiver_))};
                }
                void set_value(std::optional<UpValue> value) noexcept {
                    self_->on_outer(std::move(value));
                }
                void set_error(std::exception_ptr error) noexcept {
                    stdexec::set_error(std::move(self_->receiver_), std::move(error));
                }
                void set_stopped() noexcept { stdexec::set_stopped(std::move(self_->receiver_)); }
            };

            struct InnerInner {
                // NOTE: no ref-qualifiers on the completions below. The erased
                // pull sender invokes the wrapped receiver as an lvalue, while
                // plain senders invoke it as an rvalue; only unqualified
                // overloads accept both. Do not add ref-qualifiers here.
                using receiver_concept = stdexec::receiver_tag;
                OpState *self_;
                auto get_env() const noexcept {
                    return detail::ForwardStopEnv<Rcvr>{
                        stdexec::get_stop_token(stdexec::get_env(self_->receiver_))};
                }
                void set_value(std::optional<value_type> value) noexcept {
                    self_->on_inner(std::move(value));
                }
                void set_error(std::exception_ptr error) noexcept {
                    stdexec::set_error(std::move(self_->receiver_), std::move(error));
                }
                void set_stopped() noexcept { stdexec::set_stopped(std::move(self_->receiver_)); }
            };

            FlatMapStream *self_;
            Rcvr receiver_;
            detail::OpSlot<stdexec::connect_result_t<OuterSender, OuterInner>> outer_op_;
            detail::OpSlot<stdexec::connect_result_t<InnerNextSender, InnerInner>> inner_op_;
            // Trampoline: inline-completing upstreams iterate in run()
            // instead of recursing through the completion handlers.
            enum class Next : unsigned char { kNone, kOuter, kInner };
            Next pending_{Next::kNone};
            bool in_frame_{false};

            void pull_outer_raw() noexcept {
                inner_op_.reset();
                outer_op_.emplace(clash_native::async::next(self_->upstream_), OuterInner{this});
                in_frame_ = true;
                stdexec::start(*outer_op_);
                in_frame_ = false;
            }

            void pull_inner_raw() noexcept {
                outer_op_.reset();
                inner_op_.emplace(clash_native::async::next(*self_->current_), InnerInner{this});
                in_frame_ = true;
                stdexec::start(*inner_op_);
                in_frame_ = false;
            }

            void run() noexcept {
                do {
                    Next step = pending_;
                    pending_ = Next::kNone;
                    if (step == Next::kOuter) {
                        pull_outer_raw();
                    } else if (step == Next::kInner) {
                        pull_inner_raw();
                    }
                } while (pending_ != Next::kNone);
            }

            void request(Next step) noexcept {
                pending_ = step;
                if (!in_frame_) {
                    run();
                }
            }

            void on_outer(std::optional<UpValue> value) noexcept {
                if (!value) {
                    self_->current_.reset();
                    stdexec::set_value(std::move(receiver_), std::optional<value_type>());
                    return;
                }
                try {
                    self_->current_.emplace(std::invoke(self_->func_, std::move(*value)));
                } catch (...) {
                    stdexec::set_error(std::move(receiver_), std::current_exception());
                    return;
                }
                request(Next::kInner);
            }

            void on_inner(std::optional<value_type> value) noexcept {
                if (value) {
                    stdexec::set_value(std::move(receiver_), std::move(value));
                } else {
                    self_->current_.reset();
                    request(Next::kOuter);
                }
            }

            void start() noexcept {
                if (stdexec::get_stop_token(stdexec::get_env(receiver_)).stop_requested()) {
                    stdexec::set_stopped(std::move(receiver_));
                    return;
                }
                request(self_->current_ ? Next::kInner : Next::kOuter);
            }
        };

        template <stdexec::receiver Rcvr> OpState<Rcvr> connect(Rcvr receiver) && {
            return OpState<Rcvr>{self_, std::move(receiver)};
        }
    };

    Up upstream_;
    F func_;
    std::optional<InnerStream> current_;
};

template <class F> struct FlatMapAdaptor {
    using stream_adaptor_tag = void;
    F func_;
    template <async_stream S> auto operator()(S &&stream) && {
        return FlatMapStream<std::remove_cvref_t<S>, F>(std::forward<S>(stream), std::move(func_));
    }
};

struct AsyncFlatMapFn {
    template <class F> auto operator()(F &&func) const {
        return FlatMapAdaptor<std::decay_t<F>>{std::forward<F>(func)};
    }
    template <async_stream S, class F> auto operator()(S &&stream, F &&func) const {
        return FlatMapStream<std::remove_cvref_t<S>, std::decay_t<F>>(std::forward<S>(stream),
                                                                      std::forward<F>(func));
    }
};

inline constexpr AsyncFlatMapFn async_flat_map{};

// ---------------------------------------------------------------------------
// zip
// ---------------------------------------------------------------------------

template <async_stream A, async_stream B> class ZipStream {
  public:
    using AValue = stream_value_t<A>;
    using BValue = stream_value_t<B>;
    using value_type = std::pair<AValue, BValue>;

    ZipStream(A first, B second) : first_(std::move(first)), second_(std::move(second)) {}

    auto next() { return ZipSender{this}; }

  private:
    struct ZipSender {
        using sender_concept = stdexec::sender_tag;
        using completion_signatures =
            stdexec::completion_signatures<stdexec::set_value_t(std::optional<value_type>),
                                           stdexec::set_error_t(std::exception_ptr),
                                           stdexec::set_stopped_t()>;

        ZipStream *self_;

        template <stdexec::receiver Rcvr> struct OpState {
            using operation_state_concept = stdexec::operation_state_tag;
            using FirstSender = decltype(clash_native::async::next(std::declval<A &>()));
            using SecondSender = decltype(clash_native::async::next(std::declval<B &>()));

            struct FirstInner {
                // NOTE: no ref-qualifiers on the completions below. The erased
                // pull sender invokes the wrapped receiver as an lvalue, while
                // plain senders invoke it as an rvalue; only unqualified
                // overloads accept both. Do not add ref-qualifiers here.
                using receiver_concept = stdexec::receiver_tag;
                OpState *self_;
                auto get_env() const noexcept {
                    return detail::ForwardStopEnv<Rcvr>{
                        stdexec::get_stop_token(stdexec::get_env(self_->receiver_))};
                }
                void set_value(std::optional<AValue> value) noexcept {
                    if (!value) {
                        stdexec::set_value(std::move(self_->receiver_),
                                           std::optional<value_type>());
                        return;
                    }
                    self_->held_.emplace(std::move(*value));
                    self_->first_op_.reset();
                    self_->second_op_.emplace(clash_native::async::next(self_->self_->second_),
                                              SecondInner{self_});
                    stdexec::start(*self_->second_op_);
                }
                void set_error(std::exception_ptr error) noexcept {
                    stdexec::set_error(std::move(self_->receiver_), std::move(error));
                }
                void set_stopped() noexcept { stdexec::set_stopped(std::move(self_->receiver_)); }
            };

            struct SecondInner {
                // NOTE: no ref-qualifiers on the completions below. The erased
                // pull sender invokes the wrapped receiver as an lvalue, while
                // plain senders invoke it as an rvalue; only unqualified
                // overloads accept both. Do not add ref-qualifiers here.
                using receiver_concept = stdexec::receiver_tag;
                OpState *self_;
                auto get_env() const noexcept {
                    return detail::ForwardStopEnv<Rcvr>{
                        stdexec::get_stop_token(stdexec::get_env(self_->receiver_))};
                }
                void set_value(std::optional<BValue> value) noexcept {
                    if (!value) {
                        stdexec::set_value(std::move(self_->receiver_),
                                           std::optional<value_type>());
                        return;
                    }
                    stdexec::set_value(std::move(self_->receiver_),
                                       std::optional<value_type>(value_type(
                                           std::move(*self_->held_), std::move(*value))));
                }
                void set_error(std::exception_ptr error) noexcept {
                    stdexec::set_error(std::move(self_->receiver_), std::move(error));
                }
                void set_stopped() noexcept { stdexec::set_stopped(std::move(self_->receiver_)); }
            };

            ZipStream *self_;
            Rcvr receiver_;
            std::optional<AValue> held_;
            detail::OpSlot<stdexec::connect_result_t<FirstSender, FirstInner>> first_op_;
            detail::OpSlot<stdexec::connect_result_t<SecondSender, SecondInner>> second_op_;

            void start() noexcept {
                if (stdexec::get_stop_token(stdexec::get_env(receiver_)).stop_requested()) {
                    stdexec::set_stopped(std::move(receiver_));
                    return;
                }
                first_op_.emplace(clash_native::async::next(self_->first_), FirstInner{this});
                stdexec::start(*first_op_);
            }
        };

        template <stdexec::receiver Rcvr> OpState<Rcvr> connect(Rcvr receiver) && {
            return OpState<Rcvr>{self_, std::move(receiver)};
        }
    };

    A first_;
    B second_;
};

struct AsyncZipFn {
    template <async_stream A, async_stream B> auto operator()(A &&first, B &&second) const {
        return ZipStream<std::remove_cvref_t<A>, std::remove_cvref_t<B>>(std::forward<A>(first),
                                                                         std::forward<B>(second));
    }
};

inline constexpr AsyncZipFn async_zip{};

// ---------------------------------------------------------------------------
// merge (sequential round-robin) and async_merge (concurrent)
// ---------------------------------------------------------------------------

template <async_stream A, async_stream B>
    requires std::same_as<stream_value_t<A>, stream_value_t<B>>
class MergeStream {
  public:
    using value_type = stream_value_t<A>;

    MergeStream(A first, B second) : first_(std::move(first)), second_(std::move(second)) {}

    auto next() {
        // Alternate the starting side per pull so a lone hot stream cannot
        // starve the other one forever.
        pull_first_ = !pull_first_;
        return MergeSender{this, pull_first_};
    }

  private:
    struct MergeSender {
        using sender_concept = stdexec::sender_tag;
        using completion_signatures =
            stdexec::completion_signatures<stdexec::set_value_t(std::optional<value_type>),
                                           stdexec::set_error_t(std::exception_ptr),
                                           stdexec::set_stopped_t()>;

        MergeStream *self_;
        bool primary_is_first_;

        template <stdexec::receiver Rcvr> struct OpState {
            using operation_state_concept = stdexec::operation_state_tag;
            using FirstSender = decltype(clash_native::async::next(std::declval<A &>()));
            using SecondSender = decltype(clash_native::async::next(std::declval<B &>()));

            struct PrimaryInner {
                // NOTE: no ref-qualifiers on the completions below. The erased
                // pull sender invokes the wrapped receiver as an lvalue, while
                // plain senders invoke it as an rvalue; only unqualified
                // overloads accept both. Do not add ref-qualifiers here.
                using receiver_concept = stdexec::receiver_tag;
                OpState *self_;
                auto get_env() const noexcept {
                    return detail::ForwardStopEnv<Rcvr>{
                        stdexec::get_stop_token(stdexec::get_env(self_->receiver_))};
                }
                void set_value(std::optional<value_type> value) noexcept {
                    if (value) {
                        stdexec::set_value(std::move(self_->receiver_), std::move(value));
                        return;
                    }
                    // Primary ended: fall through to the other side. Only one
                    // of the two primary slots can be engaged; reset both.
                    self_->first_as_primary_.reset();
                    self_->second_as_primary_.reset();
                    self_->pull_fallback();
                }
                void set_error(std::exception_ptr error) noexcept {
                    stdexec::set_error(std::move(self_->receiver_), std::move(error));
                }
                void set_stopped() noexcept { stdexec::set_stopped(std::move(self_->receiver_)); }
            };

            struct FallbackInner {
                // NOTE: no ref-qualifiers on the completions below. The erased
                // pull sender invokes the wrapped receiver as an lvalue, while
                // plain senders invoke it as an rvalue; only unqualified
                // overloads accept both. Do not add ref-qualifiers here.
                using receiver_concept = stdexec::receiver_tag;
                OpState *self_;
                auto get_env() const noexcept {
                    return detail::ForwardStopEnv<Rcvr>{
                        stdexec::get_stop_token(stdexec::get_env(self_->receiver_))};
                }
                void set_value(std::optional<value_type> value) noexcept {
                    stdexec::set_value(std::move(self_->receiver_), std::move(value));
                }
                void set_error(std::exception_ptr error) noexcept {
                    stdexec::set_error(std::move(self_->receiver_), std::move(error));
                }
                void set_stopped() noexcept { stdexec::set_stopped(std::move(self_->receiver_)); }
            };

            // Type-erased pull of either side: both sides share value_type, so
            // a single optional operation state slot per side kind suffices.
            // Only one pull is outstanding at a time.
            MergeStream *self_;
            bool primary_is_first_;
            Rcvr receiver_;
            detail::OpSlot<stdexec::connect_result_t<FirstSender, PrimaryInner>> first_as_primary_;
            detail::OpSlot<stdexec::connect_result_t<SecondSender, PrimaryInner>>
                second_as_primary_;
            detail::OpSlot<stdexec::connect_result_t<FirstSender, FallbackInner>>
                first_as_fallback_;
            detail::OpSlot<stdexec::connect_result_t<SecondSender, FallbackInner>>
                second_as_fallback_;

            void pull_fallback() noexcept {
                if (primary_is_first_) {
                    second_as_fallback_.emplace(clash_native::async::next(self_->second_),
                                                FallbackInner{this});
                    stdexec::start(*second_as_fallback_);
                } else {
                    first_as_fallback_.emplace(clash_native::async::next(self_->first_),
                                               FallbackInner{this});
                    stdexec::start(*first_as_fallback_);
                }
            }

            void start() noexcept {
                if (stdexec::get_stop_token(stdexec::get_env(receiver_)).stop_requested()) {
                    stdexec::set_stopped(std::move(receiver_));
                    return;
                }
                if (primary_is_first_) {
                    first_as_primary_.emplace(clash_native::async::next(self_->first_),
                                              PrimaryInner{this});
                    stdexec::start(*first_as_primary_);
                } else {
                    second_as_primary_.emplace(clash_native::async::next(self_->second_),
                                               PrimaryInner{this});
                    stdexec::start(*second_as_primary_);
                }
            }
        };

        template <stdexec::receiver Rcvr> OpState<Rcvr> connect(Rcvr receiver) && {
            return OpState<Rcvr>{self_, primary_is_first_, std::move(receiver)};
        }
    };

    A first_;
    B second_;
    // next() toggles before pulling, so starting false makes the first pull
    // start from the first side.
    bool pull_first_{false};
};

struct MergeFn {
    template <async_stream A, async_stream B>
        requires std::same_as<stream_value_t<A>, stream_value_t<B>>
    auto operator()(A &&first, B &&second) const {
        return MergeStream<std::remove_cvref_t<A>, std::remove_cvref_t<B>>(std::forward<A>(first),
                                                                           std::forward<B>(second));
    }
};

inline constexpr MergeFn merge{};

namespace detail {

template <channel_value T> struct MergeShared {
    mpsc::Channel<std::optional<T>> channel = mpsc::unbounded<std::optional<T>>();
    std::mutex mutex;
    std::exception_ptr error;
    std::size_t total{0};
    std::atomic<std::size_t> consumed{0};
    // Structured concurrency for the drivers: each driver is a coroutine task
    // spawned here, so no thread is ever blocked or created per source. A
    // parked driver suspends (its operation state stays queued in the source)
    // and resumes inline wherever the source completes. Dropping the merged
    // stream requests stop, which wakes parked drivers so they can deliver
    // their sentinel and exit; the shared state lives until the last driver
    // is done.
    exec::async_scope scope;
};

// One driver per source. Cancellation (a stopped pull, e.g. from
// scope.request_stop()) is converted into end-of-stream so the driver always
// delivers exactly one sentinel and the merge accounting stays exact.
template <channel_value T, async_stream S>
    requires std::same_as<stream_value_t<S>, T>
exec::task<void> merge_driver_task(S source, std::shared_ptr<MergeShared<T>> shared) {
    using Item = std::optional<T>;
    try {
        while (true) {
            auto item = co_await (clash_native::async::next(source) |
                                  stdexec::let_stopped([] { return stdexec::just(Item()); }));
            if (!item) {
                break;
            }
            shared->channel.sender.send(Item(std::move(*item)));
        }
    } catch (...) {
        std::lock_guard lock(shared->mutex);
        if (!shared->error) {
            shared->error = std::current_exception();
        }
    }
    // Exactly one end sentinel per driver, on every exit path.
    shared->channel.sender.send(Item());
}

} // namespace detail

// Concurrent merge: every source stream is pulled by its own driver coroutine
// (spawned into a shared async_scope; no threads are created or blocked) and
// items surface in arrival order. Ends after every source has ended; the first
// source error wins and is delivered as set_error. Sources start being
// consumed at creation (not lazily). Dropping the merged stream requests stop
// on the scope so parked drivers finish promptly; a source that ignores stop
// tokens and never ends still pins its driver (and the shared state) until it
// does, so prefer cancellable sources.
template <async_stream S> class MergeConcurrentStream {
  public:
    using value_type = stream_value_t<S>;

    explicit MergeConcurrentStream(std::vector<S> sources) : shared_(std::make_shared<Shared>()) {
        shared_->total = sources.size();
        if (sources.empty()) {
            // No drivers will ever produce: close the internal channel so the
            // first pull completes with end-of-stream instead of parking.
            shared_->channel.sender.close();
            return;
        }
        for (auto &source : sources) {
            shared_->scope.spawn(
                detail::merge_driver_task<value_type, S>(std::move(source), shared_));
        }
    }

    ~MergeConcurrentStream() {
        if (shared_) {
            shared_->scope.request_stop();
        }
    }

    MergeConcurrentStream(const MergeConcurrentStream &) = delete;
    MergeConcurrentStream &operator=(const MergeConcurrentStream &) = delete;
    MergeConcurrentStream(MergeConcurrentStream &&) noexcept = default;
    MergeConcurrentStream &operator=(MergeConcurrentStream &&) noexcept = default;

    auto next() { return MergeNextSender{shared_}; }

  private:
    using Shared = detail::MergeShared<value_type>;

    struct MergeNextSender {
        using sender_concept = stdexec::sender_tag;
        using completion_signatures =
            stdexec::completion_signatures<stdexec::set_value_t(std::optional<value_type>),
                                           stdexec::set_error_t(std::exception_ptr),
                                           stdexec::set_stopped_t()>;

        std::shared_ptr<Shared> shared_;

        template <stdexec::receiver Rcvr> struct OpState {
            using operation_state_concept = stdexec::operation_state_tag;
            using PullSender = mpsc::RecvSender<std::optional<value_type>>;

            struct Inner {
                // NOTE: no ref-qualifiers on the completions below. The erased
                // pull sender invokes the wrapped receiver as an lvalue, while
                // plain senders invoke it as an rvalue; only unqualified
                // overloads accept both. Do not add ref-qualifiers here.
                using receiver_concept = stdexec::receiver_tag;
                OpState *self_;
                auto get_env() const noexcept {
                    return detail::ForwardStopEnv<Rcvr>{
                        stdexec::get_stop_token(stdexec::get_env(self_->receiver_))};
                }
                void set_value(std::optional<std::optional<value_type>> slot) noexcept {
                    self_->on_pulled(std::move(slot));
                }
                void set_error(std::exception_ptr error) noexcept {
                    stdexec::set_error(std::move(self_->receiver_), std::move(error));
                }
                void set_stopped() noexcept { stdexec::set_stopped(std::move(self_->receiver_)); }
            };

            std::shared_ptr<Shared> shared_;
            Rcvr receiver_;
            detail::OpSlot<stdexec::connect_result_t<PullSender, Inner>> pull_op_;
            // Trampoline: buffered sentinels complete inline, so consecutive
            // sentinels iterate here instead of recursing.
            bool in_frame_{false};
            bool repeat_{false};

            void pull_raw() noexcept {
                pull_op_.reset();
                {
                    std::lock_guard lock(shared_->mutex);
                    if (shared_->error) {
                        std::exception_ptr error = shared_->error;
                        stdexec::set_error(std::move(receiver_), std::move(error));
                        return;
                    }
                }
                pull_op_.emplace(shared_->channel.receiver.recv(), Inner{this});
                in_frame_ = true;
                stdexec::start(*pull_op_);
                in_frame_ = false;
            }

            void pull() noexcept {
                do {
                    repeat_ = false;
                    pull_raw();
                } while (repeat_);
            }

            void on_pulled(std::optional<std::optional<value_type>> slot) noexcept {
                if (!slot) {
                    // Internal channel closed unexpectedly; surface end.
                    stdexec::set_value(std::move(receiver_), std::optional<value_type>());
                    return;
                }
                if (*slot) {
                    stdexec::set_value(std::move(receiver_), std::move(*slot));
                    return;
                }
                // An end sentinel only ends the merge when no source failed:
                // the driver stores the error before sending its sentinel,
                // and the channel hands the sentinel over after that store,
                // so the error (if any) is visible here.
                {
                    std::lock_guard lock(shared_->mutex);
                    if (shared_->error) {
                        std::exception_ptr error = shared_->error;
                        stdexec::set_error(std::move(receiver_), std::move(error));
                        return;
                    }
                }
                std::size_t done = shared_->consumed.fetch_add(1, std::memory_order_acq_rel) + 1;
                if (done >= shared_->total) {
                    stdexec::set_value(std::move(receiver_), std::optional<value_type>());
                } else if (in_frame_) {
                    repeat_ = true;
                } else {
                    pull();
                }
            }

            void start() noexcept {
                if (stdexec::get_stop_token(stdexec::get_env(receiver_)).stop_requested()) {
                    stdexec::set_stopped(std::move(receiver_));
                    return;
                }
                pull();
            }
        };

        template <stdexec::receiver Rcvr> OpState<Rcvr> connect(Rcvr receiver) && {
            return OpState<Rcvr>{std::move(shared_), std::move(receiver)};
        }
    };

    std::shared_ptr<Shared> shared_;
};

struct AsyncMergeFn {
    template <async_stream S> auto operator()(std::vector<S> sources) const {
        return MergeConcurrentStream<S>(std::move(sources));
    }
};

inline constexpr AsyncMergeFn async_merge{};
inline constexpr AsyncMergeFn merge_concurrent{};

// ---------------------------------------------------------------------------
// Consumers (each returns a sender)
// ---------------------------------------------------------------------------

namespace detail {

template <async_stream S, class F> exec::task<void> for_each_task(S stream, F func) {
    while (auto item = co_await next(stream)) {
        std::invoke(func, std::move(*item));
    }
}

} // namespace detail

template <class F> struct ForEachAdaptor {
    using stream_adaptor_tag = void;
    F func_;
    template <async_stream S> auto operator()(S &&stream) && {
        return detail::for_each_task(std::forward<S>(stream), std::move(func_));
    }
};

struct AsyncForEachFn {
    template <class F> auto operator()(F &&func) const {
        return ForEachAdaptor<std::decay_t<F>>{std::forward<F>(func)};
    }
    template <async_stream S, class F> auto operator()(S &&stream, F &&func) const {
        return detail::for_each_task(std::forward<S>(stream), std::forward<F>(func));
    }
};

inline constexpr AsyncForEachFn async_for_each{};

template <async_stream S, class Acc, class F>
exec::task<Acc> async_fold(S stream, Acc init, F func) {
    Acc acc = std::move(init);
    while (auto item = co_await next(stream)) {
        acc = std::invoke(func, std::move(acc), std::move(*item));
    }
    co_return acc;
}

template <async_stream S> exec::task<std::vector<stream_value_t<S>>> collect(S stream) {
    std::vector<stream_value_t<S>> out;
    while (auto item = co_await next(stream)) {
        out.push_back(std::move(*item));
    }
    co_return out;
}

template <async_stream S> exec::task<std::size_t> count(S stream) {
    std::size_t total = 0;
    while (auto item = co_await next(stream)) {
        (void)item;
        ++total;
    }
    co_return total;
}

template <async_stream S> exec::task<std::optional<stream_value_t<S>>> first(S stream) {
    co_return co_await next(stream);
}

// ---------------------------------------------------------------------------
// subscribe: push-style consumption
// ---------------------------------------------------------------------------

namespace detail {

struct SubscribeShared {
    // Structured concurrency for the background loop: the loop task is
    // spawned here, so a parked subscription suspends without consuming any
    // thread. The task holds a shared_ptr to this state, which keeps the
    // scope alive exactly until the last loop exits; destroying a scope with
    // outstanding operations would be undefined, and this ownership makes
    // that unreachable.
    exec::async_scope scope;
    std::mutex mutex;
    // Errors nobody handled: the default on_error stores them here so they
    // surface at on_empty() instead of terminating (this stdexec version
    // terminates on failing async_scope children, so the loop must never
    // complete with an error itself).
    std::exception_ptr background_error;
};

// Tag for the default error policy: store the failure for on_empty().
struct StoreForJoin {};

struct SubscribeNoop {
    void operator()() const noexcept {}
};

template <async_stream S, class OnNext, class OnDone, class OnError>
exec::task<void> subscribe_loop(S stream, std::shared_ptr<SubscribeShared> alive, OnNext on_next,
                                OnDone on_done, OnError on_error) {
    // Route a failure either to the explicit handler or, for the default
    // policy, to the join point. Never throws: the spawned task must complete
    // with a value (see SubscribeShared).
    auto report = [&](std::exception_ptr error) noexcept {
        if constexpr (std::same_as<OnError, StoreForJoin>) {
            std::lock_guard lock(alive->mutex);
            if (!alive->background_error) {
                alive->background_error = error;
            }
        } else {
            try {
                on_error(error);
            } catch (...) {
                std::lock_guard lock(alive->mutex);
                if (!alive->background_error) {
                    alive->background_error = std::current_exception();
                }
            }
        }
    };
    try {
        while (auto item = co_await clash_native::async::next(stream)) {
            try {
                on_next(std::move(*item));
            } catch (...) {
                report(std::current_exception());
                co_return;
            }
        }
        try {
            on_done();
        } catch (...) {
            report(std::current_exception());
        }
    } catch (...) {
        report(std::current_exception());
    }
    co_return;
}

} // namespace detail

// A live push subscription: values are delivered to on_next as they arrive
// (pulled one at a time in the background, so a slow callback naturally
// back-pressures bounded sources), on_done fires at normal end, and on_error
// fires once on the first failure. Callbacks run on whatever thread completes
// each pull, so they must be thread-safe when sources complete on several
// threads (for example behind async_merge).
//
// Dropping the subscription (or unsubscribe()) requests stop: the outstanding
// pull completes with set_stopped, no further callback fires, and the
// background loop exits. Await on_empty() for join semantics; with the
// default error policy it rethrows the stored failure there.
template <class OnNext, class OnDone, class OnError> class Subscription {
  public:
    template <async_stream S>
    Subscription(S &&stream, OnNext on_next, OnDone on_done, OnError on_error)
        : shared_(std::make_shared<detail::SubscribeShared>()) {
        shared_->scope.spawn(detail::subscribe_loop(std::forward<S>(stream), shared_,
                                                    std::move(on_next), std::move(on_done),
                                                    std::move(on_error)));
    }

    Subscription(const Subscription &) = delete;
    Subscription &operator=(const Subscription &) = delete;
    Subscription(Subscription &&) noexcept = default;
    Subscription &operator=(Subscription &&) noexcept = default;

    // Never blocks. After this returns, no further callback will fire; the
    // background loop exits once its outstanding pull observes the stop.
    // Destroying the subscription unsubscribes implicitly.
    ~Subscription() { unsubscribe(); }

    void unsubscribe() noexcept {
        if (shared_) {
            shared_->scope.request_stop();
        }
    }

    // Sender that completes once the background loop has exited (and, with
    // the default error policy, rethrows the stored failure). Do not call on
    // a moved-from subscription.
    auto on_empty() {
        return shared_->scope.on_empty() | stdexec::then([shared = shared_] {
                   std::exception_ptr error;
                   {
                       std::lock_guard lock(shared->mutex);
                       error = shared->background_error;
                   }
                   if (error) {
                       std::rethrow_exception(error);
                   }
               });
    }

  private:
    std::shared_ptr<detail::SubscribeShared> shared_;
};

template <async_stream S, class OnNext, class OnDone, class OnError>
auto subscribe(S &&stream, OnNext &&on_next, OnDone &&on_done, OnError &&on_error) {
    return Subscription<std::decay_t<OnNext>, std::decay_t<OnDone>, std::decay_t<OnError>>(
        std::forward<S>(stream), std::forward<OnNext>(on_next), std::forward<OnDone>(on_done),
        std::forward<OnError>(on_error));
}

template <async_stream S, class OnNext, class OnDone>
auto subscribe(S &&stream, OnNext &&on_next, OnDone &&on_done) {
    return subscribe(std::forward<S>(stream), std::forward<OnNext>(on_next),
                     std::forward<OnDone>(on_done), detail::StoreForJoin{});
}

template <async_stream S, class OnNext> auto subscribe(S &&stream, OnNext &&on_next) {
    return subscribe(std::forward<S>(stream), std::forward<OnNext>(on_next),
                     detail::SubscribeNoop{}, detail::StoreForJoin{});
}

// ---------------------------------------------------------------------------
// Type-erased stream (compilation firewall / heterogeneous storage)
// ---------------------------------------------------------------------------

namespace detail {

// Type-erased pull sender: completes with an item, end-of-stream, an error,
// or stopped, like every stream pull. A coroutine task cannot serve here:
// this stdexec version's exec::task has no connect() member and only links
// through coroutine await machinery, so fan-in children could never connect
// it to their custom receivers. The type-erased sender connects directly to
// any receiver instead. The stop-token query is declared so cancellation
// propagates through the erasure to the concrete operation (without it the
// inner operation would observe never_stop_token and parked pulls could
// never be cancelled).
template <channel_value T>
using AnyPullSender = exec::any_sender<
    exec::any_receiver<
        stdexec::completion_signatures<stdexec::set_value_t(std::optional<T>),
                                       stdexec::set_error_t(std::exception_ptr),
                                       stdexec::set_stopped_t()>,
        exec::queries<stdexec::inplace_stop_token(stdexec::get_stop_token_t) noexcept>>,
    exec::queries<>>;

} // namespace detail

template <channel_value T> class AnyAsyncStream {
    struct Concept {
        virtual ~Concept() = default;
        virtual detail::AnyPullSender<T> pull() = 0;
    };

    template <async_stream S>
        requires std::same_as<stream_value_t<S>, T>
    struct Model : Concept {
        S stream_;
        explicit Model(S stream) : stream_(std::move(stream)) {}
        detail::AnyPullSender<T> pull() override {
            return detail::AnyPullSender<T>{clash_native::async::next(stream_)};
        }
    };

  public:
    using value_type = T;

    template <async_stream S>
        requires std::same_as<stream_value_t<S>, T>
    AnyAsyncStream(S stream)
        : impl_(std::make_shared<Model<std::remove_cvref_t<S>>>(std::move(stream))) {}

    AnyAsyncStream(const AnyAsyncStream &) = delete;
    AnyAsyncStream &operator=(const AnyAsyncStream &) = delete;
    AnyAsyncStream(AnyAsyncStream &&) noexcept = default;
    AnyAsyncStream &operator=(AnyAsyncStream &&) noexcept = default;

    detail::AnyPullSender<T> next() { return impl_->pull(); }

  private:
    std::shared_ptr<Concept> impl_;
};

template <async_stream S> AnyAsyncStream<stream_value_t<S>> erase_stream(S &&stream) {
    return AnyAsyncStream<stream_value_t<S>>(std::forward<S>(stream));
}

template <channel_value T> AnyAsyncStream<T> erase_stream(AnyAsyncStream<T> &&stream) {
    return std::move(stream);
}

// ---------------------------------------------------------------------------
// StreamMap: readiness-based fan-in over named streams
// ---------------------------------------------------------------------------
//
// tokio::StreamMap style multiplexing without threads, channels, or a
// scheduler: one next() call starts one pull on every registered source at
// once, and the first source to resolve wins. A value or an error from any
// source completes the pull immediately (the outstanding pulls on the other
// sources are cancelled via stop tokens); an end-of-stream from one source
// only counts toward the end, which is delivered once every source has ended
// (ended sources simply resolve inline on later rounds).
//
// Only one next() may be outstanding per map at a time, and the map must not
// be mutated (insert/remove) while a pull is outstanding.

template <channel_value T> class StreamMap {
  public:
    using value_type = std::pair<std::string, T>;

    StreamMap() = default;
    StreamMap(const StreamMap &) = delete;
    StreamMap &operator=(const StreamMap &) = delete;
    StreamMap(StreamMap &&) noexcept = default;
    StreamMap &operator=(StreamMap &&) noexcept = default;

    // Insert or replace the stream registered under key. Streams of any
    // (single) value type are accepted; they are type-erased on insert.
    template <async_stream S>
        requires std::same_as<stream_value_t<S>, T>
    void insert(std::string key, S stream) {
        remove(key);
        entries_.push_back(Entry{std::move(key), AnyAsyncStream<T>(std::move(stream))});
    }

    // Remove the stream registered under key. Returns whether one existed.
    bool remove(const std::string &key) {
        const auto end = entries_.end();
        const auto found = std::find_if(entries_.begin(), end,
                                        [&](const Entry &entry) { return entry.key == key; });
        if (found == end) {
            return false;
        }
        entries_.erase(found);
        return true;
    }

    bool contains(const std::string &key) const {
        return std::any_of(entries_.begin(), entries_.end(),
                           [&](const Entry &entry) { return entry.key == key; });
    }

    std::size_t size() const { return entries_.size(); }

    bool empty() const { return entries_.empty(); }

    auto next() { return MapNextSender{this}; }

  private:
    struct Entry {
        std::string key;
        AnyAsyncStream<T> stream;
    };

    std::vector<Entry> entries_;

    struct MapNextSender {
        using sender_concept = stdexec::sender_tag;
        using completion_signatures =
            stdexec::completion_signatures<stdexec::set_value_t(std::optional<value_type>),
                                           stdexec::set_error_t(std::exception_ptr),
                                           stdexec::set_stopped_t()>;

        StreamMap *map_;

        template <stdexec::receiver Rcvr> struct OpState {
            using operation_state_concept = stdexec::operation_state_tag;

            // Per-pull shared state. Owned by reference count: the map
            // operation holds one reference and every outstanding child pull
            // holds one. Children never touch the map operation (it may be
            // destroyed by the downstream right after the winning delivery);
            // they only touch this state and delete themselves.
            struct Shared {
                std::mutex mutex;
                enum class Outcome : unsigned char { kRacing, kValue, kEnd, kError, kCancelled };
                Outcome outcome{Outcome::kRacing};
                // Moved out exactly once by whoever transitions out of
                // kRacing: the winner delivers it, the abandon path drops it.
                // Only ever move-constructed, never move-assigned: stdexec
                // receivers are not required to be move-assignable.
                std::optional<Rcvr> receiver;
                std::size_t total{0};
                std::size_t finished{0};
                // Cancels the losing pulls once decided (or abandoned).
                // Requested only after releasing mutex: callbacks fire inline
                // and re-enter through this same mutex.
                stdexec::inplace_stop_source stop;
            };

            struct ChildEnv {
                stdexec::inplace_stop_token token;
                auto query(stdexec::get_stop_token_t) const noexcept { return token; }
            };

            // One outstanding pull on one source. Heap-allocated and
            // self-deleting: after the map operation is gone, an in-flight
            // loser completion must still run on valid memory, so children
            // cannot live inside the map operation state.
            struct ChildOp {
                using UpSender = detail::AnyPullSender<T>;

                struct Inner {
                    // NOTE: no ref-qualifiers here. The erased pull sender
                    // invokes the wrapped receiver as an lvalue, while plain
                    // senders invoke it as an rvalue; unqualified completions
                    // accept both.
                    using receiver_concept = stdexec::receiver_tag;
                    ChildOp *self_;
                    auto get_env() const noexcept {
                        return ChildEnv{self_->shared_->stop.get_token()};
                    }
                    void set_value(std::optional<T> item) noexcept {
                        self_->on_value(std::move(item));
                    }
                    void set_error(std::exception_ptr error) noexcept {
                        self_->on_error(std::move(error));
                    }
                    void set_stopped() noexcept { self_->on_stopped(); }
                };

                std::shared_ptr<Shared> shared_;
                std::string key_;
                detail::OpSlot<stdexec::connect_result_t<UpSender, Inner>> op_;

                void start_pull(UpSender sender) {
                    op_.emplace(std::move(sender), Inner{this});
                    stdexec::start(*op_);
                }

                void on_value(std::optional<T> item) noexcept {
                    // Claiming the single delivery is exclusive: exactly one
                    // path observes kRacing, so moving the receiver out after
                    // the claim (without holding the mutex) races with
                    // nothing. The receiver is only move-constructed, never
                    // move-assigned (see Shared).
                    bool claimed = false;
                    std::optional<value_type> result;
                    {
                        std::lock_guard lock(shared_->mutex);
                        if (shared_->outcome == Shared::Outcome::kRacing) {
                            if (!item) {
                                // One source ended: the map ends only once
                                // every source has ended; the rest keep
                                // racing, this child is done.
                                if (++shared_->finished >= shared_->total) {
                                    shared_->outcome = Shared::Outcome::kEnd;
                                    claimed = true;
                                }
                            } else {
                                shared_->outcome = Shared::Outcome::kValue;
                                result.emplace(std::move(key_), std::move(*item));
                                claimed = true;
                            }
                        }
                    }
                    if (!claimed) {
                        delete this;
                        return;
                    }
                    std::optional<Rcvr> receiver(std::move(shared_->receiver));
                    shared_->stop.request_stop();
                    if (result) {
                        stdexec::set_value(std::move(*receiver), std::move(result));
                    } else {
                        stdexec::set_value(std::move(*receiver), std::optional<value_type>());
                    }
                    delete this;
                }

                void on_error(std::exception_ptr error) noexcept {
                    bool claimed = false;
                    {
                        std::lock_guard lock(shared_->mutex);
                        if (shared_->outcome == Shared::Outcome::kRacing) {
                            shared_->outcome = Shared::Outcome::kError;
                            claimed = true;
                        }
                    }
                    if (!claimed) {
                        delete this;
                        return;
                    }
                    std::optional<Rcvr> receiver(std::move(shared_->receiver));
                    shared_->stop.request_stop();
                    stdexec::set_error(std::move(*receiver), std::move(error));
                    delete this;
                }

                void on_stopped() noexcept {
                    // Shared stop is requested only together with leaving
                    // kRacing (under the same mutex), so a stopped child is
                    // always a loser: stay quiet.
                    delete this;
                }
            };

            struct StopFn {
                OpState *self_;
                void operator()() const noexcept { self_->on_stop(); }
            };

            using StopToken = stdexec::stop_token_of_t<stdexec::env_of_t<Rcvr>>;
            using StopCallback = stdexec::stop_callback_for_t<StopToken, StopFn>;

            StreamMap *map_;
            Rcvr receiver_;
            std::shared_ptr<Shared> shared_;
            // Declared last so it is destroyed first: unregistering may block
            // until an in-flight callback returns, and the callback touches
            // the members above. Destroying it from inside its own executing
            // callback is safe: request_stop detaches callbacks before
            // running them.
            std::optional<StopCallback> stop_callback_;

            OpState(StreamMap *map, Rcvr receiver) : map_(map), receiver_(std::move(receiver)) {}

            OpState(const OpState &) = delete;
            OpState &operator=(const OpState &) = delete;

            ~OpState() {
                // Abandoning a racing pull: withdraw the receiver (the
                // downstream is gone, so nothing may be delivered to it) and
                // wake the parked children so they self-delete. The shared
                // state itself dies with the last outstanding child.
                if (shared_) {
                    bool cancel = false;
                    {
                        std::lock_guard lock(shared_->mutex);
                        if (shared_->outcome == Shared::Outcome::kRacing) {
                            shared_->outcome = Shared::Outcome::kCancelled;
                            shared_->receiver.reset();
                            cancel = true;
                        }
                    }
                    if (cancel) {
                        shared_->stop.request_stop();
                    }
                }
            }

            void start() noexcept {
                auto token = stdexec::get_stop_token(stdexec::get_env(receiver_));
                if (token.stop_requested()) {
                    stdexec::set_stopped(std::move(receiver_));
                    return;
                }
                shared_ = std::make_shared<Shared>();
                shared_->receiver.emplace(std::move(receiver_));
                stop_callback_.emplace(token, StopFn{this});
                // Local anchor: a synchronous source may win inline and let
                // the downstream destroy this operation state inside the
                // delivery. The heap state below stays alive through this
                // local reference, and the map object itself outlives the
                // pull by contract, so the loop below never touches dead
                // memory (returning from a member function is safe).
                auto shared = shared_;
                {
                    std::lock_guard abandon_check(shared->mutex);
                    if (shared->outcome != Shared::Outcome::kRacing) {
                        // Stop won before any child was started.
                        return;
                    }
                }
                if (map_->entries_.empty()) {
                    finish_empty();
                    return;
                }
                shared->total = map_->entries_.size();
                for (auto &entry : map_->entries_) {
                    {
                        std::lock_guard won_check(shared->mutex);
                        if (shared->outcome != Shared::Outcome::kRacing) {
                            // An inline winner already delivered.
                            return;
                        }
                    }
                    auto *child = new ChildOp{shared, entry.key};
                    // entry.stream.next() borrows the entry stream; the map
                    // must outlive the pull (single-outstanding-pull
                    // contract).
                    child->start_pull(entry.stream.next());
                }
            }

          private:
            void finish_empty() noexcept {
                bool claimed = false;
                {
                    std::lock_guard lock(shared_->mutex);
                    if (shared_->outcome == Shared::Outcome::kRacing) {
                        shared_->outcome = Shared::Outcome::kEnd;
                        claimed = true;
                    }
                }
                stop_callback_.reset();
                if (!claimed) {
                    return;
                }
                std::optional<Rcvr> receiver(std::move(shared_->receiver));
                stdexec::set_value(std::move(*receiver), std::optional<value_type>());
            }

            void on_stop() noexcept {
                if (!shared_) {
                    return;
                }
                bool claimed = false;
                {
                    std::lock_guard lock(shared_->mutex);
                    if (shared_->outcome == Shared::Outcome::kRacing) {
                        shared_->outcome = Shared::Outcome::kCancelled;
                        claimed = true;
                    }
                }
                shared_->stop.request_stop();
                if (!claimed) {
                    return;
                }
                std::optional<Rcvr> receiver(std::move(shared_->receiver));
                stdexec::set_stopped(std::move(*receiver));
            }
        };

        template <stdexec::receiver Rcvr> OpState<Rcvr> connect(Rcvr receiver) && {
            return OpState<Rcvr>(map_, std::move(receiver));
        }
    };
};

} // namespace clash_native::async
