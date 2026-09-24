#pragma once

#include <stdexec/execution.hpp>

#include <memory>
#include <utility>

namespace clash_native::async {

// Holds a connected sender operation on the heap. Destroying the holder
// destroys the operation state, which aborts the in-flight work (subject
// to the sender's own abort semantics); late terminals must drop by
// themselves, e.g. by map lookup or a delivered flag, because the
// holder may die before or after the terminal.
//
// Sender operation states are immovable, so the holder constructs the
// operation in place (guaranteed prvalue elision into the member) and
// is itself heap-held and never moved after construction. Receivers
// connected to type-erased senders must not ref-qualify their
// completion handlers: the erased sender may invoke them as lvalues.
template <typename Sender, typename Receiver> struct HeldOperation {
    using Op = decltype(stdexec::connect(std::declval<Sender>(), std::declval<Receiver>()));

    template <typename S, typename R>
    HeldOperation(S &&sender, R &&receiver)
        : op(stdexec::connect(std::forward<S>(sender), std::forward<R>(receiver))) {}

    void start() noexcept { stdexec::start(op); }

    Op op;
};

template <typename Sender, typename Receiver>
std::shared_ptr<HeldOperation<std::decay_t<Sender>, std::decay_t<Receiver>>>
hold_operation(Sender &&sender, Receiver &&receiver) {
    using Held = HeldOperation<std::decay_t<Sender>, std::decay_t<Receiver>>;
    return std::make_shared<Held>(std::forward<Sender>(sender), std::forward<Receiver>(receiver));
}

} // namespace clash_native::async
