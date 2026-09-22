#pragma once

#include <exec/any_sender_of.hpp>

#include <stdexec/execution.hpp>

#include <exception>

namespace clash_native::io {

// Type-erased sender for handle operations: completes with set_value(T) on
// success, set_error(exception_ptr) carrying a core::Error on failure, or
// set_stopped() on cancellation. Movable, connected directly to any receiver
// (unlike coroutine tasks in this stdexec version, which cannot be
// connected). The stop-token query is declared so cancellation propagates
// through the erasure instead of degrading to never_stop_token.
template <typename T>
using AnySender = exec::any_sender<
    exec::any_receiver<
        stdexec::completion_signatures<stdexec::set_value_t(T),
                                       stdexec::set_error_t(std::exception_ptr),
                                       stdexec::set_stopped_t()>,
        exec::queries<stdexec::inplace_stop_token(stdexec::get_stop_token_t) noexcept>>,
    exec::queries<>>;

} // namespace clash_native::io
