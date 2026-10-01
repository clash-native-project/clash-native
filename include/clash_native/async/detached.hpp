#pragma once

// Detached fire-and-forget tasks: run one stdexec::task<void> without an
// owning async_scope.
//
// Why not scope_.spawn(): a spawned task self-deletes inside __complete
// while holding the scope mutex. When two tasks share one scope (worker +
// deadline timer) and the owner -- hence its scope_ -- is destroyed during
// teardown (e.g. the test thread in runtime.stop()'s join), the loser's
// __complete locks a dead mutex (mtx_do_lock AV). The faulting origin is
// always the sleep_until timer: it outlives the exchange it was racing.
// Timer-only tasks that merely post back must not share the owner scope.
//
// Ownership (ASan #194, heap-use-after-free at async_scope.hpp:162):
// async_scope's __complete touches scope->__active_ as its first access on
// memory the task frame may already have freed (frame destroy runs inside
// await_resume's scope_guard, before __complete). Owner-tied scope variants
// all die the same way: owner's scope_, frame-held scope, sentinel second
// spawn (its own __complete races the same teardown).
//
// Fix: detached tasks share one process-lifetime heap async_scope that is
// intentionally never deleted (a single 104-byte allocation, reclaimed at
// process exit). The scope outlives every owner by construction, so
// __complete always touches live memory: no UAF. Sharing is safe -- spawn
// only touches the atomic active count plus the never-fired stop source;
// detached tasks never request_stop and are never drained via on_empty,
// so no join ordering exists to violate.
//
// Why a scope at all (rather than exec::start_detached): stdexec::task is only
// a sender where a spawn-like environment is present -- sender_in<root_env>
// is false for stdexec::task, while true under an env
// carrying a stop token plus start scheduler. So start_detached rejects bare
// tasks at compile time ("no matching function ... sender_in<root_env>
// evaluated to false"), and async_scope::spawn's internal submit path is the
// only public driver. The shared scope is that driver's minimal vehicle:
// upstream examples (e.g. server_theme/then_upon.cpp) always join() before
// destroying the scope, a shape that cannot fit owners which die from inside
// their own task completions -- hence one immortal scope instead of one per
// owner.

#include <exec/async_scope.hpp>
#include <stdexec/execution.hpp>

#include <exception>
#include <utility>

namespace clash_native::async {

// Process-lifetime scope shared by all detached tasks. Intentionally
// leaked (one allocation, reclaimed at exit): outlives every owner, so
// __complete always touches live memory. See ownership note above.
inline exec::async_scope &detached_scope() {
    static auto *scope = new exec::async_scope{};
    return *scope;
}

// Value-only wrapper: async_scope::spawn terminates on set_error, so swallow
// everything like the deadline tasks always did.
inline stdexec::task<void> detach_wrap(stdexec::task<void> inner) {
    try {
        co_await std::move(inner);
    } catch (...) {
    }
    co_return;
}

// Fire-and-forget for stdexec::task<void> with no owning scope. The task runs
// on the shared process-lifetime scope; completion destroys only the heap
// opstate, never owner memory.
inline void spawn_detached(stdexec::task<void> task) {
    detached_scope().spawn(detach_wrap(std::move(task)));
}

} // namespace clash_native::async
