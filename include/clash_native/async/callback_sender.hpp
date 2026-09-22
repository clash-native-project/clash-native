#pragma once

#include <stdexec/execution.hpp>

#include <atomic>
#include <exception>
#include <memory>
#include <optional>
#include <utility>

namespace clash_native::async {
namespace detail {

struct CallbackShared {
    std::atomic<bool> done{false};
};

} // namespace detail

// Turns a handler-style initiation into a sender, for wrapping callback-based
// internals behind sender-based interfaces without rewriting their state
// machines:
//
// - Initiate: void(Handler). Starts the internal work; Handler is invoked
//   exactly once with the implementation's native completion arguments.
// - Translate: void(Rcvr&&, Args...). Delivers exactly one terminal signal
//   (set_value, set_error, or set_stopped at its discretion) into the moved
//   receiver. Runs on the terminal thread with the operation state known
//   alive (see below).
// - Sigs: the completion_signatures the sender advertises.
//
// Settlement is first-wins through a heap flag: stop or destroy before the
// terminal marks done (stop additionally completes set_stopped); a late
// terminal observes done and drops without touching the operation state.
// Teardown races across threads follow the same contract as the channel
// operation states. Initiation throwing out of start() completes set_error.
template <class Sigs, class Initiate, class Translate> class CallbackSender {
  public:
    using sender_concept = stdexec::sender_tag;
    using completion_signatures = Sigs;

    CallbackSender(Initiate initiate, Translate translate)
        : initiate_(std::move(initiate)), translate_(std::move(translate)) {}

    template <stdexec::receiver Rcvr> class OpState {
        struct StopFn {
            OpState *self;
            void operator()() const noexcept { self->on_stop(); }
        };

        using StopToken = stdexec::stop_token_of_t<stdexec::env_of_t<Rcvr>>;
        using StopCallback = stdexec::stop_callback_for_t<StopToken, StopFn>;

      public:
        using operation_state_concept = stdexec::operation_state_tag;

        OpState(Initiate initiate, Translate translate, Rcvr receiver)
            : initiate_(std::move(initiate)), translate_(std::move(translate)),
              receiver_(std::move(receiver)), shared_(std::make_shared<detail::CallbackShared>()) {}

        OpState(const OpState &) = delete;
        OpState &operator=(const OpState &) = delete;

        ~OpState() {
            // Cancel-by-destroy: settle so the late terminal drops. Never
            // blocks; teardown races follow the channel contract.
            shared_->done.exchange(true, std::memory_order_acq_rel);
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
                initiate_([shared, self](auto &&...args) {
                    if (shared->done.exchange(true, std::memory_order_acq_rel)) {
                        return;
                    }
                    self->stop_callback_.reset();
                    self->translate_(std::move(self->receiver_),
                                     std::forward<decltype(args)>(args)...);
                });
            } catch (...) {
                stop_callback_.reset();
                shared->done.exchange(true, std::memory_order_acq_rel);
                stdexec::set_error(std::move(receiver_), std::current_exception());
            }
        }

      private:
        void on_stop() noexcept {
            if (!shared_->done.exchange(true, std::memory_order_acq_rel)) {
                stop_callback_.reset();
                stdexec::set_stopped(std::move(receiver_));
            }
        }

        Initiate initiate_;
        Translate translate_;
        Rcvr receiver_;
        std::shared_ptr<detail::CallbackShared> shared_;
        // Declared last so it is destroyed first.
        std::optional<StopCallback> stop_callback_;
    };

    template <stdexec::receiver Rcvr> OpState<Rcvr> connect(Rcvr receiver) && {
        return OpState<Rcvr>(std::move(initiate_), std::move(translate_), std::move(receiver));
    }

  private:
    Initiate initiate_;
    Translate translate_;
};

template <class Sigs, class Initiate, class Translate>
CallbackSender<Sigs, Initiate, Translate> callback_sender(Initiate &&initiate,
                                                          Translate &&translate) {
    return CallbackSender<Sigs, std::decay_t<Initiate>, std::decay_t<Translate>>(
        std::forward<Initiate>(initiate), std::forward<Translate>(translate));
}

} // namespace clash_native::async
