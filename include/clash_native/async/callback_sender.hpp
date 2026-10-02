#pragma once

#include <clash_native/async/move_only_function.hpp>

#include <stdexec/execution.hpp>

#include <atomic>
#include <exception>
#include <memory>
#include <optional>
#include <thread>
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
// Settlement is first-wins through a small late-shared control block: the
// terminal, a stop request, or operation-state destruction each claim
// settlement at most once. The winner either delivers the translated terminal
// (terminal path) or runs the aborter and completes set_stopped (stop path)
// or just runs the aborter (destroy path); a late terminal observes the claim
// and drops without touching the operation state. The claim and the parked
// aborter are guarded by a spinlock (critical sections only flip a flag and
// move the aborter, so they never contend; no 40-byte mutex in the block),
// and the block itself is intrusively refcounted, so there is no separate
// control block on top of the allocation.
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

        // Late-shared settlement block: the terminal captures one reference
        // at start() and drops it after settling (or immediately when the
        // initiation throws before the terminal escapes); the operation
        // state drops its reference on stop/destroy. The last reference
        // deletes the block, so a late terminal never touches a dead
        // operation state and no separate control block is allocated.
        struct Shared {
            std::atomic_flag spin = ATOMIC_FLAG_INIT;
            bool done = false;
            CallbackAbortFn aborter;
            // Intrusive refs: 1 at construction (state ref). start()
            // adds terminal + frame refs; see start() for the full
            // ownership map. Last release deletes.
            std::atomic<int> refs{1};
        };

        static void lock(Shared *shared) noexcept {
            // Bounded spin: critical sections only flip the flag and move
            // the aborter (a few stores), so the wait is ns-scale; the
            // aborter itself always runs after unlocking. Borrowed from
            // stdexec's own __spin_wait shape (pause, then yield).
            unsigned spins = 0;
            while (shared->spin.test_and_set(std::memory_order_acquire)) {
                if (++spins < 16) {
#if defined(__x86_64__) || defined(_M_X64)
                    __builtin_ia32_pause();
#elif defined(__aarch64__) || defined(_M_ARM64)
                    __asm__ volatile("yield" ::: "memory");
#endif
                } else {
                    std::this_thread::yield();
                }
            }
        }

        static void unlock(Shared *shared) noexcept {
            shared->spin.clear(std::memory_order_release);
        }

        // RAII spin guard: every claim path returns early, so scoped
        // unlock keeps the pairing review-proof.
        struct SpinGuard {
            Shared *shared;
            explicit SpinGuard(Shared *s) noexcept : shared(s) { lock(shared); }
            SpinGuard(const SpinGuard &) = delete;
            SpinGuard &operator=(const SpinGuard &) = delete;
            ~SpinGuard() { unlock(shared); }
        };

        static void release(Shared *shared) noexcept {
            // Last reference deletes. Three references exist per started
            // op: state (dtor), terminal (settle win/lose, or the throw
            // catch), and start-frame (tail, or the throw catch). The block
            // therefore outlives the final claim and aborter handoff.
            if (shared->refs.fetch_sub(1, std::memory_order_acq_rel) == 1) {
                delete shared;
            }
        }

      public:
        OpState(Initiate initiate, Translate translate, Rcvr receiver)
            : initiate_(std::move(initiate)), translate_(std::move(translate)),
              receiver_(std::move(receiver)), shared_(new Shared()) {}

        OpState(const OpState &) = delete;
        OpState &operator=(const OpState &) = delete;

        ~OpState() {
            // Cancel-by-destroy: claim settlement so the late terminal drops,
            // and abort the internal work. Never blocks; the aborter runs
            // without the spin. Consumes the state reference; the terminal
            // (or the catch above) consumes its own, so the last release
            // frees the block. Runs on the live state, so member access
            // here is safe.
            CallbackAbortFn aborter;
            if (claim(aborter) && aborter) {
                invoke_aborter(aborter);
            }
            release(shared_);
        }

        void start() noexcept {
            auto token = stdexec::get_stop_token(stdexec::get_env(receiver_));
            if (token.stop_requested()) {
                // Never took the extra refs (fetch_add is below): the
                // initial state ref is consumed by the dtor.
                stdexec::set_stopped(std::move(receiver_));
                return;
            }
            stop_callback_.emplace(token, StopFn{this});
            Shared *shared = shared_;
            OpState *self = this;
            // consumes its ref when it settles (win or lose) or when the
            // initiation throws before it escapes (catch below); the tail
            // consumes the frame ref on every return path. The state ref
            // is consumed by the dtor. Total 3, matching the 3 releases.
            // The frame ref keeps this block alive across an inline
            // terminal that destroys the chain (and this state) through
            // the receiver, so the tail below may use ONLY locals and the
            // shared block -- never a member.
            shared->refs.fetch_add(2, std::memory_order_relaxed);
            // Hoist the initiation off the operation state: an inline
            // terminal destroys the chain (and this state) through the
            // receiver, so `initiate_` must not be on the call stack.
            auto initiate = std::move(initiate_);
            try {
                CallbackAbortFn aborter = initiate([shared, self](auto &&...args) {
                    // Terminal from the internal work. First claimer wins;
                    // the block is last-reference deleted so this stays
                    // sound even if the operation state is already gone
                    // (claim first, touch the operation only when still
                    // alive). Consumes the terminal reference either way.
                    CallbackAbortFn dropped;
                    bool won = false;
                    {
                        SpinGuard guard(shared);
                        if (!shared->done) {
                            shared->done = true;
                            won = true;
                            dropped = std::move(shared->aborter);
                        }
                    }
                    if (!won) {
                        release(shared);
                        return;
                    }
                    dropped.reset();
                    self->stop_callback_.reset();
                    self->translate_(std::move(self->receiver_),
                                     std::forward<decltype(args)>(args)...);
                    release(shared);
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
                    SpinGuard guard(shared);
                    if (shared->done) {
                        // Stop (or an inline terminal) already settled while
                        // the initiation was running; the operation state may
                        // already be gone, so only touch the shared block
                        // here -- no members.
                        orphan = std::move(aborter);
                        stored = std::move(shared->aborter);
                    } else {
                        shared->aborter = std::move(aborter);
                    }
                }
                // Consume the start-frame reference (see the fetch_add
                // above). Before running any aborter: the aborter may
                // synchronously fire the terminal, which consumes the last
                // other reference and frees the block -- the aborter locals
                // below are already moved out, so they stay valid.
                // Unconditional: parked, stop-raced, and inline-win paths
                // all hold it here. The state may already be gone, so this
                // must not touch any member.
                release(shared);
                if (stored) {
                    invoke_aborter(stored);
                }
                if (orphan) {
                    invoke_aborter(orphan);
                }
            } catch (...) {
                stop_callback_.reset();
                {
                    // The terminal never escaped (initiation threw before it
                    // could be captured), so consume its reference plus the
                    // frame reference here, and retire the parked aborter
                    // under the spin. The state ref is left for the dtor.
                    // NOTE: releases run after the guard drops: the terminal
                    // ref may be the last one, and the guard's unlock would
                    // touch a freed block.
                    CallbackAbortFn retired;
                    {
                        SpinGuard guard(shared);
                        shared->done = true;
                        retired = std::move(shared->aborter);
                    }
                    release(shared);
                    release(shared);
                }
                stdexec::set_error(std::move(receiver_), std::current_exception());
            }
        }

      private:
        // Claims settlement; true means this call won. The stored aborter is
        // moved out regardless so it is destroyed exactly once. Does NOT
        // touch the refcount: reference ownership is handled by the
        // callers (start() tail and terminal for the terminal ref, dtor
        // for the state ref), because claim() itself also runs from the
        // destructor where the state is already half-gone.
        bool claim(CallbackAbortFn &out) {
            SpinGuard guard(shared_);
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
        // Raw late-shared block (see Shared): owned jointly with the
        // terminal through refs, never dereferenced after claim().
        Shared *shared_;
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

// Bridge vocabulary: the unary bridge_sender factory below builds the
// callback_sender subsuming the old bridge_sender. A bridge starter launches
// handler-style work returning an aborter, and the native result always
// completes set_value(result) (tri-state results stay in band; set_error is
// reserved for sender-machinery failures). Handler is std::function so
// registry-style internals can store it; the translate below closes a late
// delivered handle (StreamOpenResult/DatagramOpenResult shape) instead of
// leaking it.
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

// Unary bridge factory: handler-style work whose native completion is
// already the final Result. Same CallbackSender type (Sigs/Translate built
// in); the initiation takes a BridgeHandler<Result> and returns the aborter.
template <typename Result, typename Initiate> auto bridge_sender(Initiate &&initiate) {
    return CallbackSender<BridgeSignatures<Result>, std::decay_t<Initiate>,
                          BridgeTranslate<Result>>(std::forward<Initiate>(initiate),
                                                   BridgeTranslate<Result>{});
}

} // namespace clash_native::async
