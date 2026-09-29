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
// How this fixes it: each detached task gets a private scope that holds
// exactly one task, and the task's own coroutine frame keeps that scope
// alive (via the DetachedScope parameter) until after __complete runs.
// Single task per scope means no sibling race by construction; frame-held
// ownership means the scope cannot die first. No leak: the last frame
// reference drops right after completion.
//
// Contract on the task factory:
// - Must capture the DetachedScope parameter into the returned task
//   (pass it as the first coroutine parameter; parameters live in the
//   coroutine frame). A task that drops it reintroduces the use-after-free.
// - The task must always complete with a value (catch-all inside, like
//   the deadline tasks do): async_scope spawn terminates on set_error.

#include <exec/async_scope.hpp>
#include <exec/task.hpp>

#include <concepts>
#include <memory>
#include <type_traits>
#include <utility>

namespace clash_native::async {

// Self-kept-alive scope for exactly one detached task. Create only via
// spawn_detached.
struct DetachedScope {
    exec::async_scope scope;
};

template <typename MakeTask>
    requires std::invocable<MakeTask &, std::shared_ptr<DetachedScope>> &&
             std::same_as<std::invoke_result_t<MakeTask &, std::shared_ptr<DetachedScope>>,
                          exec::task<void>>
void spawn_detached(MakeTask &&make_task) {
    auto scope = std::make_shared<DetachedScope>();
    scope->scope.spawn(std::forward<MakeTask>(make_task)(scope));
}

} // namespace clash_native::async
