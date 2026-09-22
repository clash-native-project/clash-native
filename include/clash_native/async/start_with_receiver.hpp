#pragma once

#include <stdexec/execution.hpp>

#include <exception>
#include <type_traits>
#include <utility>

namespace clash_native::async {

// start_with_receiver -- connect+start helper with a user-controlled receiver.
//
// Eagerly connects sndr to rcvr, heap-allocates the resulting operation
// state, and starts it. The operation state deletes itself when a completion
// signal fires. This mirrors the lifetime pattern used by
// exec::start_detached, but forwards *all* three completion channels
// (set_value, set_error, set_stopped) to the caller's receiver and propagates
// the receiver's environment.
//
// Use this for fire-and-forget sender work whose errors must be observed
// (exec::start_detached terminates on set_error), e.g. bridging a sender back
// into a callback-style API: the custom receiver translates the terminal
// signal and the heap state needs no further management.
template <stdexec::sender S, typename Rcvr> void start_with_receiver(S &&sndr, Rcvr rcvr);

namespace detail {

template <typename Rcvr> struct StartWithReceiverOpBase {
    virtual ~StartWithReceiverOpBase() = default;

    Rcvr rcvr_;

    explicit StartWithReceiverOpBase(Rcvr rcvr) : rcvr_(std::move(rcvr)) {}
};

template <typename Rcvr> struct StartWithReceiverReceiver {
    using receiver_concept = stdexec::receiver_tag;

    StartWithReceiverOpBase<Rcvr> *op_;

    // NOTE: deliberately unqualified. The erased sender invokes the wrapped
    // receiver as an lvalue; only unqualified overloads accept both that and
    // plain rvalue invocation. The user's receiver is still invoked through
    // std::move below.
    template <class... As> void set_value(As &&...as) noexcept {
        std::move(op_->rcvr_).set_value(std::forward<As>(as)...);
        delete op_;
    }

    void set_error(std::exception_ptr error) noexcept {
        std::move(op_->rcvr_).set_error(std::move(error));
        delete op_;
    }

    void set_stopped() noexcept {
        std::move(op_->rcvr_).set_stopped();
        delete op_;
    }

    auto get_env() const noexcept {
        if constexpr (requires { op_->rcvr_.get_env(); }) {
            return op_->rcvr_.get_env();
        } else {
            return stdexec::env<>{};
        }
    }
};

template <stdexec::sender S, typename Rcvr>
struct StartWithReceiverOp : StartWithReceiverOpBase<Rcvr> {
    using Receiver = StartWithReceiverReceiver<Rcvr>;
    using OpState = decltype(stdexec::connect(std::declval<S>(), std::declval<Receiver>()));

    OpState op_;

    StartWithReceiverOp(S sndr, Rcvr rcvr)
        : StartWithReceiverOpBase<Rcvr>(std::move(rcvr)),
          op_(stdexec::connect(std::move(sndr), Receiver{this})) {}

    StartWithReceiverOp(const StartWithReceiverOp &) = delete;
    StartWithReceiverOp(StartWithReceiverOp &&) = delete;
    StartWithReceiverOp &operator=(const StartWithReceiverOp &) = delete;
    StartWithReceiverOp &operator=(StartWithReceiverOp &&) = delete;
};

} // namespace detail

template <stdexec::sender S, typename Rcvr> void start_with_receiver(S &&sndr, Rcvr rcvr) {
    using Op = detail::StartWithReceiverOp<std::decay_t<S>, std::decay_t<Rcvr>>;
    auto *state = new Op(std::forward<S>(sndr), std::move(rcvr));
    stdexec::start(state->op_);
}

} // namespace clash_native::async
