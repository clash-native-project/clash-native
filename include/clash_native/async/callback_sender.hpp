#pragma once

#include <clash_native/async/move_only_function.hpp>

#include <stdexec/execution.hpp>

#include <exception>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>

namespace clash_native::async {

// Turns a handler-style initiation into a sender, for wrapping callback-based
// internals behind sender-based interfaces without rewriting their state
// machines:
//
// - Initiate: CallbackAbortFn(Handler). Starts the internal work and returns
//   an aborter for it. Handler is invoked exactly once with the
//   implementation's native completion arguments. Even an empty aborter must
//   be returned explicitly; omitting the return is a compile error.
// - Aborter: void(). Aborts the internal work (cancel the Asio operation,
//   retire the parked handler, close the stream). Requirements:
//   - Idempotent and callable from any thread, because stop, destroy, and the
//     start() tail can each invoke it, and a stop racing the initiation is
//     served by invoking the freshly returned aborter.
//   - Never blocks: it runs on the stop/destroy path.
//   - Tolerates invocation after the terminal already fired (for example an
//     inline terminal that won before the initiation returned). Back the
//     implementation with its own completed guard when needed.
//   - Must not throw; a throwing aborter is swallowed on the teardown path.
//   - Must own everything it touches (typically shared_ptr state): it can run
//     after the operation state and its initiating frame are gone.
//   An empty aborter is an explicit opt-out for work that cannot be aborted
//   (already-completed stubs, pure inline completions); say why in a comment.
// - Translate: void(Rcvr&&, Args...). Delivers exactly one terminal signal
//   (set_value, set_error, or set_stopped at its discretion) into the moved
//   receiver. Runs on the terminal thread with the operation state known
//   alive (see below). It receives a moved-from receiver on failure paths,
//   so it must not throw.
// - Sigs: the completion_signatures the sender advertises.
//
// Settlement is first-wins under a heap mutex shared with the terminal: the
// terminal, a stop request, or operation-state destruction each claim
// settlement at most once. The winner either delivers the translated terminal
// (terminal path) or runs the aborter and completes set_stopped (stop path)
// or just runs the aborter (destroy path); a late terminal observes the claim
// and drops without touching the operation state.
//
// This makes the sender composable with racing adaptors such as
// exec::when_any: a losing branch is claimed by request_stop, runs its
// aborter, and completes set_stopped promptly without waiting for the
// underlying work; the late underlying completion is dropped. Cooperative
// caveat: prompt completion still depends on the aborter actually aborting
// the work, not merely ignoring its result.
//
// Initiation throwing out of start() completes set_error; work launched
// before the throw still terminates later and its terminal is dropped.
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

        struct Shared {
            std::mutex mutex;
            bool done = false;
            CallbackAbortFn aborter;
        };

      public:
        using operation_state_concept = stdexec::operation_state_tag;

        OpState(Initiate initiate, Translate translate, Rcvr receiver)
            : initiate_(std::move(initiate)), translate_(std::move(translate)),
              receiver_(std::move(receiver)), shared_(std::make_shared<Shared>()) {}

        OpState(const OpState &) = delete;
        OpState &operator=(const OpState &) = delete;

        ~OpState() {
            // Cancel-by-destroy: claim settlement so the late terminal drops,
            // and abort the internal work. Never blocks; the aborter runs
            // without the lock.
            CallbackAbortFn aborter;
            if (claim(aborter) && aborter) {
                invoke_aborter(aborter);
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
            // Hoist the initiation off the operation state: an inline
            // terminal destroys the chain (and this state) through the
            // receiver, so `initiate_` must not be on the call stack.
            auto initiate = std::move(initiate_);
            try {
                CallbackAbortFn aborter = initiate([shared, self](auto &&...args) {
                    // Terminal from the internal work. First claimer wins;
                    // the flag lives on the heap so this stays sound even if
                    // the operation state is already gone (claim first, touch
                    // the operation only when still alive).
                    CallbackAbortFn dropped;
                    {
                        std::lock_guard lock(shared->mutex);
                        if (shared->done) {
                            return;
                        }
                        shared->done = true;
                        dropped = std::move(shared->aborter);
                    }
                    dropped.reset();
                    self->stop_callback_.reset();
                    self->translate_(std::move(self->receiver_),
                                     std::forward<decltype(args)>(args)...);
                });
                // A stop (or an inline terminal) may have settled the
                // operation while the initiation was still running. When the
                // initiation returns, the operation state (`this`) may
                // already be gone: an inline terminal delivers through the
                // receiver, which can destroy the whole chain (e.g. an erased
                // any_sender opstate owning this OpState). So the returned
                // aborter must be dispatched without touching any member:
                // claim settlement on the heap flag and run the freshly
                // returned aborter instead of leaking the underlying work.
                // When a stop won instead, the stop path already ran the
                // stored aborter, and this fresh one still needs invoking.
                CallbackAbortFn orphan;
                CallbackAbortFn stored;
                {
                    std::lock_guard lock(shared->mutex);
                    if (shared->done) {
                        // Stop (or an inline terminal) already settled while
                        // the initiation was running; the operation state may
                        // already be gone, so only touch the heap flag here.
                        orphan = std::move(aborter);
                        stored = std::move(shared->aborter);
                    } else {
                        shared->aborter = std::move(aborter);
                    }
                }
                if (stored) {
                    invoke_aborter(stored);
                }
                if (orphan) {
                    invoke_aborter(orphan);
                }
            } catch (...) {
                stop_callback_.reset();
                {
                    std::lock_guard lock(shared->mutex);
                    shared->done = true;
                    shared->aborter.reset();
                }
                stdexec::set_error(std::move(receiver_), std::current_exception());
            }
        }

      private:
        // Claims settlement; true means this call won. The stored aborter is
        // moved out regardless so it is destroyed exactly once.
        bool claim(CallbackAbortFn &out) {
            std::lock_guard lock(shared_->mutex);
            if (shared_->done) {
                return false;
            }
            shared_->done = true;
            out = std::move(shared_->aborter);
            return true;
        }

        static void invoke_aborter(CallbackAbortFn &aborter) noexcept {
            try {
                aborter();
            } catch (...) {
                // Aborter contract violation; teardown must not throw.
            }
        }

        void on_stop() noexcept {
            CallbackAbortFn aborter;
            if (!claim(aborter)) {
                return;
            }
            if (aborter) {
                invoke_aborter(aborter);
            }
            stop_callback_.reset();
            stdexec::set_stopped(std::move(receiver_));
        }

        Initiate initiate_;
        Translate translate_;
        Rcvr receiver_;
        std::shared_ptr<Shared> shared_;
        // Declared last so it is destroyed first.
        std::optional<StopCallback> stop_callback_;
    };

    // The sender must be connected as an rvalue: the initiation and the
    // translation are moved into the operation state, so an inline terminal
    // can never observe a moved-from sender member through `initiate_`.
    // The deleted lvalue overload keeps a const/mutable lvalue sender from
    // silently compiling through the member connect below.
    template <stdexec::receiver Rcvr>
    OpState<Rcvr> connect(CallbackSender &self, Rcvr receiver) = delete;

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

// Bridge vocabulary: callback_sender subsumes the old bridge_sender. A
// bridge starter launches handler-style work returning an aborter, and the
// native result always completes set_value(result) (tri-state results stay
// in band; set_error is reserved for sender-machinery failures). Handler is
// std::function so registry-style internals can store it; the translate
// below closes a late delivered handle (StreamOpenResult/DatagramOpenResult
// shape) instead of leaking it.
template <typename Result> using BridgeHandler = std::function<void(Result)>;

template <typename Result> struct BridgeTranslate {
    // Live terminal: forward the result untouched; the receiver owns it.
    // A late terminal never reaches this translate (the shared settlement
    // drops it), so unlike the old bridge there is no late-handle cleanup
    // here: closing a stale handle belongs to the aborter, which runs on
    // the stop/destroy path while it still owns the operation.
    void operator()(stdexec::receiver auto &&receiver, Result result) const {
        stdexec::set_value(std::forward<decltype(receiver)>(receiver), std::move(result));
    }
};

template <typename Result>
using BridgeSignatures = stdexec::completion_signatures<stdexec::set_value_t(Result),
                                                        stdexec::set_error_t(std::exception_ptr),
                                                        stdexec::set_stopped_t()>;

} // namespace clash_native::async
