#pragma once

#include <stdexec/execution.hpp>

#include <atomic>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <utility>

namespace clash_native::async {

// Bridges handler-style async work into a sender. Used when migrating an
// implementation whose internals still run on callbacks: the internals keep
// their own lifetime (typically shared_from_this chains) and their terminal
// handler, and this bridge only translates that terminal into the sender
// completion contract plus stop/destroy handling.
//
// - Starter: AbortFn(Handler). Launches the internal work and returns an
//   aborter. Handler: void(Result), invoked exactly once by the internals.
// - AbortFn: void(). Aborts the internal work (cancel timers, close sockets,
//   cancel sub-requests). Must tolerate being called after terminal delivery
//   (backed by the implementation's completed_ guard) and may be empty.
// - The result always completes set_value(result): tri-state results
//   (opened/failed/unsupported) stay in band, exactly like the old handler
//   contract. set_error is reserved for sender-machinery failures.
// - Stop or destroy before terminal: marks settled, runs the aborter, and the
//   late terminal drops its value (closing a delivered handle, if any) so
//   nothing leaks and nothing touches the dead operation state.
// - Stop after terminal, or destroy after terminal: no-ops.
template <typename Result> class BridgeSender {
  public:
    using sender_concept = stdexec::sender_tag;
    using completion_signatures =
        stdexec::completion_signatures<stdexec::set_value_t(Result),
                                       stdexec::set_error_t(std::exception_ptr),
                                       stdexec::set_stopped_t()>;

    using Handler = std::function<void(Result)>;
    using AbortFn = std::function<void()>;
    using Starter = std::function<AbortFn(Handler)>;

    explicit BridgeSender(Starter starter) : starter_(std::move(starter)) {}

    template <stdexec::receiver Rcvr> class OpState {
        struct StopFn {
            OpState *self;
            void operator()() const noexcept { self->on_stop(); }
        };

        using StopToken = stdexec::stop_token_of_t<stdexec::env_of_t<Rcvr>>;
        using StopCallback = stdexec::stop_callback_for_t<StopToken, StopFn>;

      public:
        using operation_state_concept = stdexec::operation_state_tag;

        OpState(Starter starter, Rcvr receiver)
            : starter_(std::move(starter)), receiver_(std::move(receiver)),
              shared_(std::make_shared<Shared>()) {}

        OpState(const OpState &) = delete;
        OpState &operator=(const OpState &) = delete;

        ~OpState() {
            // Cancel-by-destroy: settle so the late terminal drops, and abort
            // the internal work. Never blocks; the terminal checks the flag.
            if (!shared_->done.exchange(true, std::memory_order_acq_rel)) {
                if (aborter_) {
                    aborter_();
                }
            }
        }

        void start() noexcept {
            auto token = stdexec::get_stop_token(stdexec::get_env(receiver_));
            if (token.stop_requested()) {
                stdexec::set_stopped(std::move(receiver_));
                return;
            }
            stop_callback_.emplace(token, StopFn{this});
            auto shared = shared_;
            OpState *self = this;
            try {
                aborter_ = starter_([shared, self](Result result) {
                    // Terminal from the internal work. First claimer wins; the
                    // flag lives on the heap so this stays sound even if the
                    // operation state is already gone (settle first, touch the
                    // operation only when still alive).
                    if (shared->done.exchange(true, std::memory_order_acq_rel)) {
                        close_handle(result);
                        return;
                    }
                    self->complete(std::move(result));
                });
            } catch (...) {
                stop_callback_.reset();
                // Settle first: internal work launched before the throw still
                // terminates later and must observe done.
                shared->done.exchange(true, std::memory_order_acq_rel);
                stdexec::set_error(std::move(receiver_), std::current_exception());
            }
            // A stop that arrived during starter_ already ran on_stop above
            // (through the registered callback); nothing more to do here.
        }

      private:
        void complete(Result result) noexcept {
            stop_callback_.reset();
            aborter_ = nullptr;
            stdexec::set_value(std::move(receiver_), std::move(result));
        }

        void on_stop() noexcept {
            if (!shared_->done.exchange(true, std::memory_order_acq_rel)) {
                if (aborter_) {
                    aborter_();
                }
                stop_callback_.reset();
                stdexec::set_stopped(std::move(receiver_));
            }
        }

        // Late value cleanup: close a delivered handle instead of leaking it.
        static void close_handle(Result &result) noexcept {
            if constexpr (requires { result.handle; }) {
                if (result.handle) {
                    result.handle->close();
                }
            }
        }

        struct Shared {
            std::atomic<bool> done{false};
        };

        Starter starter_;
        Rcvr receiver_;
        std::shared_ptr<Shared> shared_;
        AbortFn aborter_;
        // Declared last so it is destroyed first.
        std::optional<StopCallback> stop_callback_;
    };

    template <stdexec::receiver Rcvr> OpState<Rcvr> connect(Rcvr receiver) && {
        return OpState<Rcvr>(std::move(starter_), std::move(receiver));
    }

  private:
    Starter starter_;
};

template <typename Result, typename Starter> BridgeSender<Result> bridge_sender(Starter &&starter) {
    return BridgeSender<Result>(std::forward<Starter>(starter));
}

} // namespace clash_native::async
