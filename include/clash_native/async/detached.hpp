#pragma once

// Detached fire-and-forget tasks: run one exec::task<void> without an
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
// await_resume's scope_guard, before __complete). Four ASan rounds proved
// every owner-tied scope variant dies the same way: owner's scope_,
// frame-held DetachedScope (direct or via wrapper frame), sentinel second
// spawn (its own __complete races the same teardown).
//
// Fix: detached tasks share one process-lifetime heap async_scope that is
// intentionally never deleted (a single 104-byte allocation, reclaimed at
// process exit). The scope outlives every owner by construction, so
// __complete always touches live memory: no UAF. Sharing is safe -- spawn
// only touches the atomic active count plus the never-fired stop source;
// detached tasks never request_stop and are never drained via on_empty,
// so no join ordering exists to violate. exec::task drives through
// async_scope::spawn's internal submit path (tasks are awaitable, not
// directly connectable -- five rounds of connect/submit/start_detached
// attempts confirmed no public sender path exists for bare tasks).

#include <exec/async_scope.hpp>
#include <exec/task.hpp>

#include <concepts>
#include <exception>
#include <memory>
#include <type_traits>
#include <utility>

namespace clash_native::async {

// Surviving handle for exactly one detached task. Create only via
// spawn_detached. The int is API ballast (factories take the handle as
// first coroutine parameter); lifetime comes from the shared_ptr.
struct DetachedScope {
    int unused = 0;
};

template <typename MakeTask>
    requires std::invocable<MakeTask &, std::shared_ptr<DetachedScope>> &&
             std::same_as<std::invoke_result_t<MakeTask &, std::shared_ptr<DetachedScope>>,
                          exec::task<void>>
exec::task<void> detach_wrap(std::shared_ptr<DetachedScope> scope, MakeTask make_task) {
    try {
        co_await std::forward<MakeTask>(make_task)(scope);
    } catch (...) {
        // Detached tasks must complete with a value (async_scope spawn
        // terminates on set_error); swallow like the deadline tasks do.
    }
    co_return;
}

// Process-lifetime scope shared by all detached tasks. Intentionally
// leaked (one allocation, reclaimed at exit): outlives every owner, so
// __complete always touches live memory. See ownership note above.
inline exec::async_scope &detached_scope() {
    static auto *scope = new exec::async_scope{};
    return *scope;
}

template <typename MakeTask>
    requires std::invocable<MakeTask &, std::shared_ptr<DetachedScope>> &&
             std::same_as<std::invoke_result_t<MakeTask &, std::shared_ptr<DetachedScope>>,
                          exec::task<void>>
void spawn_detached(MakeTask &&make_task) {
    auto scope = std::make_shared<DetachedScope>();
    detached_scope().spawn(detach_wrap(scope, std::forward<MakeTask>(make_task)));
}

} // namespace clash_native::async
