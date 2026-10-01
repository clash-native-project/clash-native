#pragma once

#include <clash_native/async/callback_sender.hpp>

#include <exec/when_any.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/steady_timer.hpp>

#include <stdexec/execution.hpp>

#include <chrono>
#include <exception>
#include <memory>
#include <utility>

namespace clash_native::async {

// sleep_after / sleep_until -- timer as a sender, composable with
// stop/when_any/timeout instead of a steady_timer.async_wait callback leaf.
//
// - Completes set_value() on expiry, set_stopped() on stop (the aborter
//   cancels the timer; expiry races follow the callback_sender first-wins
//   settlement), set_error(system_error) on any other timer failure.
// - The timer is heap-owned by the initiation: the aborter keeps it alive
//   across stop/destroy, and the terminal drops late after settlement.
// - Cancellation is prompt only because the aborter really cancels the
//   timer; a caller that only ignores the result would wait out the full
//   duration (see callback_sender's cooperative caveat).
inline auto sleep_after(boost::asio::any_io_executor executor,
                        std::chrono::steady_clock::duration duration) {
    using Signatures = stdexec::completion_signatures<
        stdexec::set_value_t(), stdexec::set_error_t(std::exception_ptr), stdexec::set_stopped_t()>;
    return callback_sender<Signatures>(
        [executor = std::move(executor), duration](auto terminal) mutable -> CallbackAbortFn {
            auto timer = std::make_shared<boost::asio::steady_timer>(executor);
            timer->expires_after(duration);
            timer->async_wait(
                [terminal = std::move(terminal),
                 timer](const boost::system::error_code &error) mutable { terminal(error); });
            return CallbackAbortFn{[timer = std::move(timer)] { (void)timer->cancel(); }};
        },
        [](stdexec::receiver auto &&receiver, const boost::system::error_code &error) {
            if (!error) {
                stdexec::set_value(std::forward<decltype(receiver)>(receiver));
            } else if (error == boost::asio::error::operation_aborted) {
                stdexec::set_stopped(std::forward<decltype(receiver)>(receiver));
            } else {
                stdexec::set_error(std::forward<decltype(receiver)>(receiver),
                                   std::make_exception_ptr(boost::system::system_error(error)));
            }
        });
}

inline auto sleep_until(boost::asio::any_io_executor executor,
                        std::chrono::steady_clock::time_point deadline) {
    using Signatures = stdexec::completion_signatures<
        stdexec::set_value_t(), stdexec::set_error_t(std::exception_ptr), stdexec::set_stopped_t()>;
    return callback_sender<Signatures>(
        [executor = std::move(executor), deadline](auto terminal) mutable -> CallbackAbortFn {
            auto timer = std::make_shared<boost::asio::steady_timer>(executor);
            timer->expires_at(deadline);
            timer->async_wait(
                [terminal = std::move(terminal),
                 timer](const boost::system::error_code &error) mutable { terminal(error); });
            return CallbackAbortFn{[timer = std::move(timer)] { (void)timer->cancel(); }};
        },
        [](stdexec::receiver auto &&receiver, const boost::system::error_code &error) {
            if (!error) {
                stdexec::set_value(std::forward<decltype(receiver)>(receiver));
            } else if (error == boost::asio::error::operation_aborted) {
                stdexec::set_stopped(std::forward<decltype(receiver)>(receiver));
            } else {
                stdexec::set_error(std::forward<decltype(receiver)>(receiver),
                                   std::make_exception_ptr(boost::system::system_error(error)));
            }
        });
}

// with_timeout -- races Work against a sleep. The winner's completion is
// the result: work's value on success, a timeout value built on demand by
// the factory on expiry. Timeout is an in-band value, not an exception:
// pass a copyable factory (stored in a then() functor) that builds the
// timeout Result, e.g. [] { return core::fail<Handle>(timeout_error()); }.
//
// Requirements: Work and the timeout branch complete with set_value(Result)
// (single value, bridge-style; machinery set_error propagates as an
// exception, outer stop cancels both branches). Implemented as a coroutine
// instead of returning when_any directly: when_any's variant storage
// requires its value types to be decay-copyable (verified against this
// stdexec version's __results_storage), so move-only Results cross the
// race as shared_ptr<Result> built inside each winning branch only.
template <typename Result, stdexec::sender Work, typename TimeoutFactory>
    requires std::is_invocable_r_v<Result, TimeoutFactory &>
stdexec::task<Result> with_timeout(boost::asio::any_io_executor executor,
                                   std::chrono::steady_clock::duration timeout, Work work,
                                   TimeoutFactory timeout_factory) {
    auto pointer_race =
        exec::when_any(std::move(work) | stdexec::then([](Result result) {
                           return std::make_shared<Result>(std::move(result));
                       }),
                       sleep_after(std::move(executor), timeout) |
                           stdexec::then([factory = std::move(timeout_factory)]() mutable {
                               return std::make_shared<Result>(factory());
                           }));
    auto winner = co_await std::move(pointer_race);
    co_return std::move(*winner);
}

} // namespace clash_native::async
