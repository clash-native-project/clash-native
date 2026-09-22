# C++26 Executor Model (`std::execution` / P2300) Usage Guide

> This document explains the C++26 standard executor model (P2300 `std::execution`, senders/receivers) and
> **how to use it**: how to launch tasks, how to use it in coroutine environments and in plain functions, fire-and-forget, switching executors,
> cancellation, composition, structured concurrency, and how to wrap callback-style C APIs as senders.
>
> All examples are based on the reference implementation cloned in this repository at `third_party/stdexec`. It covers P2300 and
> follow-up proposals such as task, scope, and environment utilities, but it also contains `exec::` extensions that are not yet standardized.
> **Version pin: commit `f0e8ae6f` (approximately v0.11.0,
> nvhpc-26.05 baseline)** -- the stdexec API drifts quickly across versions; after updating the clone, please re-check the examples.
>
> **No C++26 toolchain is required**: stdexec only requires C++20 (see [Section 1](#1-toolchain-and-integration)).
> The core patterns in this article were verified against this clone and the actual code of this project in strict C++20. When switching to the standard library in the future, you must
> **check item by item** namespaces, header files, constraints, and return types; you cannot mechanically replace
> `stdexec::` with `std::execution::`; `exec::` extensions usually have no direct standard counterpart (see
> [1.4](#14-mapping-to-the-standard-library)).

## Table of Contents

- [0. The Model in One Sentence](#0-the-model-in-one-sentence)
- [1. Toolchain and Integration](#1-toolchain-and-integration)
- [2. Core Concepts](#2-core-concepts)
- [3. Headers and Namespaces](#3-headers-and-namespaces)
- [4. How to Launch: Overview](#4-how-to-launch-overview)
- [5. Launching in Plain Functions](#5-launching-in-plain-functions)
- [6. Launching in Coroutine Environments](#6-launching-in-coroutine-environments)
- [7. Switching Executors](#7-switching-executors)
- [8. Cancellation](#8-cancellation)
- [9. Composition (Combinators)](#9-composition-combinators)
- [10. Structured Concurrency](#10-structured-concurrency)
- [11. Lifetimes and RAII](#11-lifetimes-and-raii)
- [12. Advanced Facilities](#12-advanced-facilities)
- [13. Interoperating with Callback-style APIs](#13-interoperating-with-callback-style-apis)
- [14. Common Compile-Error Quick Reference](#14-common-compile-error-quick-reference)
- [15. Appendix: Cheat Sheet](#15-appendix-cheat-sheet)

---

## 0. The Model in One Sentence

A **Sender** is a "recipe for an asynchronous computation" -- it describes _what to do_, but does not execute by itself.
A **Receiver** is the sink for the execution result -- it agrees on three completion channels: `set_value` / `set_error` / `set_stopped`.
A **Scheduler** denotes an execution context (thread pool, event loop, etc.); `schedule(sched)` produces a sender that
runs "once on this context".
Connecting a sender to a receiver with **connect** yields an **operation state**, and only **start**-ing it actually begins execution.

```text
sender (recipe) --connect--> operation state (living object) --start--> execute --> receiver (one of three completion channels)
```

Key points:

- Senders are **lazy**: merely constructing a sender produces no side effects; side effects happen only after `start`.
- Senders have **value semantics and are composable**: combine them into larger senders with adaptors (`then`, `when_all`, `upon_error`, ...).
- The completion channel is **unique**: one operation completes exactly once (value or error or stopped), and immediately after the completion function is invoked
  the operation state becomes invalid and the implementation may reclaim it immediately -- therefore **you must not use the receiver/opstate inside the completion callback anymore**.
- Combinators are responsible for re-routing child-sender completions to the upper-level receiver; business code does not need to write callback boilerplate itself.

---

## 1. Toolchain and Integration

### 1.1 Only C++20 Is Required

stdexec back-ports P2300 to C++20 -- **no C++26 toolchain is required**:

- Language standard: **C++20** (the library requires it via `target_compile_features(... cxx_std_20)`;
  C++23 is only needed when the experimental `STDEXEC_BUILD_MODULES` is enabled, which is off by default).
- Compilers: recent mainstream compilers are required (recent versions of GCC / Clang / MSVC). The exact support matrix changes with versions;
  use `third_party/stdexec/README.md` and its CI configuration as the source of truth; it is not copied here.
  Tested note (Windows + this clone): MSYS2 UCRT64 **GCC 16.1** silently crashes cc1plus when compiling stdexec
  (exits with no error output at all); **Clang 22** in the same environment compiles and runs everything normally,
  and the examples in this article were verified with Clang 22. If you hit the GCC crash on Windows, switch to Clang or MSVC.
- When integrating via a CMake target, the necessary compile options are brought in automatically:
  - MSVC: `/Zc:__cplusplus /Zc:preprocessor /Zc:externConstexpr /bigobj`
  - GCC: `-fcoroutines`
- Thread library: the CMake target transitively links `Threads::Threads` (pthread on Linux/macOS;
  no extra dependency on Windows).

### 1.2 CMake Integration

```cmake
# When pulled in as a subproject, turn off the parts you do not need
set(STDEXEC_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(STDEXEC_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(STDEXEC_INSTALL OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/stdexec)

target_link_libraries(your_target PRIVATE STDEXEC::stdexec)
```

- `stdexec` is a **header-only** `INTERFACE` library by default (`STDEXEC::stdexec` is its alias target),
  and compiles no source files. CMake >= 3.28 is required.
- You can also use it without CMake: `-I third_party/stdexec/include` is enough to use the headers directly.
  But going through the CMake target is officially recommended, because the compile options in 1.1 are set automatically by the target.
- Optional components (all OFF by default, see `third_party/stdexec/CMakeLists.txt` for details):
  `STDEXEC_BUILD_PARALLEL_SCHEDULER` (system-wide parallel scheduler, see [12.4](#124-system-parallel-scheduler-get-parallel-scheduler)),
  `STDEXEC_ENABLE_ASIO` (Asio adaptor `exec::asio`, see 12.6.6),
  `STDEXEC_BUILD_MODULES`, `STDEXEC_ENABLE_CUDA`, `STDEXEC_ENABLE_IO_URING`, etc.
  On Windows, `STDEXEC_ENABLE_WINDOWS_THREAD_POOL` is automatically enabled based on `windows.h` detection (see [12.5](#125-windows-thread-pool-backend-windows-thread-pool)).

### 1.3 Version Pin and API Drift

stdexec evolves continuously with the standard draft, and old names keep being renamed (with `[[deprecated]]` aliases kept).
Old-to-new name mapping in this clone (`f0e8ae6f`):

| Old name (deprecated)                                  | Current name                                                    |
| ------------------------------------------------------ | --------------------------------------------------------------- |
| `start_on`                                             | `stdexec::starts_on`                                            |
| `transfer`                                             | `stdexec::continues_on`                                         |
| `stdexec::read`                                        | `stdexec::read_env`                                             |
| `exec::write` / `exec::write_env`                      | `stdexec::write_env`                                            |
| `exec::on`                                             | `stdexec::on`                                                   |
| `exec::inline_scheduler`                               | `stdexec::inline_scheduler`                                     |
| `stdexec::split` / `ensure_started` / `start_detached` | `exec::split` / `exec::ensure_started` / `exec::start_detached` |
| Header `exec/repeat_effect_until.hpp`                  | `exec/repeat_until.hpp`                                         |
| `exec/system_context.hpp` / `get_system_scheduler`     | `stdexec::get_parallel_scheduler` (see 12.4)                    |

This article always uses the "current names". Note that **`exec::reschedule` is not deprecated** -- it is a proper extension algorithm.

### 1.4 Mapping to the Standard Library

- `stdexec::` is the namespace implementing the standard proposals, mainly covering P2300, P3149, P3325, and P3552.
  It is **not character-for-character identical** to the current C++ working draft: for example, `sync_wait` in the draft lives in
  `std::this_thread`, while this clone provides `stdexec::sync_wait`; header splits, constraints, and implementation extensions
  may also differ. When migrating, you must check the current working draft and the target standard library API by API.
- `exec::` is NVIDIA's experimental extension namespace (= `experimental::execution`) and **has no standard counterpart**:
  `async_scope`, `static_thread_pool`, `single_thread_context`, `task` (old extension version), `when_any`,
  `split`, `ensure_started`, `start_detached`, `timed_thread_context`, `at_coroutine_exit`,
  `create`, etc. The idea of `async_scope` has been standardized as `counting_scope` (with a different API, see
  [10.3](#103-stdexeccounting-scope-simple-counting-scope-standard)); concrete thread pools may in the future be covered by
  the "system context / parallel scheduler" proposal series (see [12.4](#124-system-parallel-scheduler-get-parallel-scheduler)).
- `stdexec::task` corresponds to the P3552 scheduler-affine coroutine task, not to P2300 itself.
  The async C++ style uniformly used in this project is this task; `exec::task` only appears when introducing the historical extensions of this clone.

---

## 2. Core Concepts

| Concept               | Description                                                                                                                            | Concept check / facility     |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------- |
| `sender`              | Describes an async operation; declares in which ways it can complete (completion signatures)                                           | `stdexec::sender`            |
| `receiver`            | Sink for completion signals: `set_value(vs...)` / `set_error(e)` / `set_stopped()`                                                     | `stdexec::receiver`          |
| `scheduler`           | Execution context; `schedule(s)` returns a sender for "execute once on that context"                                                   | `stdexec::scheduler`         |
| operation state       | Result of `connect(s, r)`; `start(op)` launches it; `op` is immovable                                                                  | `connect_result_t`           |
| environment           | Environment attached to a receiver, queried with CPOs: `get_scheduler`, `get_start_scheduler`, `get_stop_token`, `get_allocator`...    | `env_of_t`                   |
| completion signatures | Compile-time set of completion signatures, e.g. `completion_signatures<set_value_t(int), set_error_t(std::exception_ptr)>`             | `completion_signatures_of_t` |
| sender adaptor        | Combinator taking senders and returning a new sender (`then`, `upon_error`, `when_all`, ...), supporting pipe syntax `sndr \| then(f)` | --                           |

Conventions of the three completion channels:

- `set_value(vs...)`: success, carrying result values.
- `set_error(e)`: failure, carrying an error (usually `std::exception_ptr`).
- `set_stopped()`: cancelled / voluntarily abandoned, **with no value**.
- Before invoking a completion function, the sender must have switched all resource state to "ready"; immediately after completion it discards its internal state.

### 2.1 `sender` vs `sender_in`: the Environment Is Also Part of the Type System

`stdexec::sender<S>` only says that `S` is a sender; it does not guarantee that `S` can have its completion signatures computed and be successfully connected in an arbitrary receiver environment. The concept that really checks "whether this sender is valid in this environment" is:

```cpp
template <class S>
  requires stdexec::sender_in<S, my_env_t>
void launch(S&& sndr);
```

- `sender_in<S, Env>` queries `completion_signatures_of_t<S, Env>` under `Env`; senders depending on a
  scheduler, stop token, or allocator may change completion signatures in a different env, or even become
  invalid.
- `sender` is suitable for referring to "recipes" generically; when writing launchers, scope wrappers, or custom receivers, prefer the `sender_in` constraint matching the actual
  receiver environment, so errors surface closer to the call site.
- Do not assume a sender is usable everywhere just because it was verified under the empty environment `env<>`. `on()`, the home
  scheduler of tasks, cancellable callbacks, etc. all depend on the real environment.

---

## 3. Headers and Namespaces

There are two layers of namespaces in stdexec:

```cpp
#include <stdexec/execution.hpp>       // Core + P2300 standard algorithms (stdexec:: namespace)
#include <exec/static_thread_pool.hpp>  // stdexec extensions (exec:: namespace)
```

| Namespace                            | Contents                                                                                                                                                                                                                                                                                                               | Corresponding standard                                               |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `stdexec` (internal macro `STDEXEC`) | Standard-proposal APIs: `schedule`, `then`, `when_all`, `sync_wait`, `just`, `on`, `starts_on`, `continues_on`, `get_scheduler`, `get_stop_token`, `task`, `run_loop`, `spawn`, `spawn_future`, `counting_scope`, `read_env`, `write_env`, `prop`, `inline_scheduler`...                                               | Snapshot of P2300 + P3149 + P3325 + P3552, etc. in this clone        |
| `exec` (=`experimental::execution`)  | Reference-implementation extensions: `static_thread_pool`, `single_thread_context`, `async_scope`, `start_detached`, `split`, `ensure_started`, `when_any`, `finally`, `repeat_until`, `unless_stop_requested`, `reschedule`, `task` (old extension version), `timed_thread_context`, `create`, `at_coroutine_exit`... | Non-standard extensions; some ideas have separate standard proposals |

Commonly used headers:

```cpp
#include <stdexec/execution.hpp>          // All core: sender/receiver/CPO/sync_wait/stdexec::task/run_loop
                                          //   /spawn/spawn_future/counting_scope/read_env/write_env/prop
#include <exec/static_thread_pool.hpp>    // exec::static_thread_pool (multi-threaded pool)
#include <exec/single_thread_context.hpp> // exec::single_thread_context (single thread)
#include <exec/start_detached.hpp>        // exec::start_detached (fire-and-forget)
#include <exec/async_scope.hpp>           // exec::async_scope (structured concurrency)
#include <exec/task.hpp>                  // Old extension exec::task; not used by business code in this project
#include <exec/reschedule.hpp>            // exec::reschedule (migrate to the environment's start scheduler)
#include <exec/when_any.hpp>              // exec::when_any (racing)
#include <exec/finally.hpp>               // exec::finally (cleanup sender)
#include <exec/split.hpp>                 // exec::split (broadcast, subscribable multiple times)
#include <exec/ensure_started.hpp>        // exec::ensure_started (start immediately + cache, single subscription)
#include <exec/repeat_until.hpp>          // exec::repeat_until / repeat_effect_until (loops)
#include <exec/unless_stop_requested.hpp> // exec::unless_stop_requested (stop check)
#include <exec/just_from.hpp>             // exec::just_from (lazy just)
#include <exec/timed_thread_scheduler.hpp>// exec::timed_thread_context / timed_thread_scheduler
#include <exec/timed_scheduler.hpp>       // exec::now / exec::schedule_at / exec::schedule_after (CPOs)
#include <exec/at_coroutine_exit.hpp>     // exec::at_coroutine_exit (coroutine cleanup)
#include <exec/on_coro_disposition.hpp>   // exec::on_coroutine_succeeded / stopped / failed
#include <exec/create.hpp>                // exec::create (wrap callbacks as senders)
#include <exec/materialize.hpp>           // exec::materialize / dematerialize
#include <exec/trampoline_scheduler.hpp>  // exec::trampoline_scheduler (protect against recursive stack overflow)
#include <exec/asio/use_sender.hpp>       // exec::asio::use_sender (Asio completion token -> sender)
#include <exec/asio/asio_thread_pool.hpp> // exec::asio::asio_thread_pool (Asio-based thread pool)
                                          //   ^ exec::asio requires STDEXEC_ENABLE_ASIO=ON (see 12.6.6)
#include <stdexec/stop_token.hpp>         // inplace_stop_source / inplace_stop_token / inplace_stop_callback
```

> Note: `stdexec/coroutine.hpp` only contains internal coroutine facilities and does not need to be included directly;
> `stdexec::task` is provided by `<stdexec/execution.hpp>`.
>
> For renames and deprecated aliases, see [1.3](#13-version-pin-and-api-drift). Special reminder: `exec::on` is a
> deprecated alias (use `stdexec::on`); `exec::reschedule` is **not** deprecated.

---

## 4. How to Launch: Overview

"Launching" in the senders world has five typical styles; choose by scenario:

| Scenario                                                       | Method                                                            | Header                                           | Lifetime                                     |
| -------------------------------------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------ | -------------------------------------------- |
| Synchronously block and wait for the result                    | `stdexec::sync_wait(sndr)`                                        | `stdexec/execution.hpp`                          | On the stack; ends when the function returns |
| Fire-and-forget (untracked)                                    | `exec::start_detached(sndr)`                                      | `exec/start_detached.hpp`                        | On the heap; deletes itself                  |
| Fire-and-forget (standard version, must be adopted by a scope) | `stdexec::spawn(sndr, token)`                                     | `stdexec/execution.hpp`                          | Held by the scope                            |
| Launch into a scope and want the result                        | `scope.spawn_future(sndr)` / `stdexec::spawn_future(sndr, token)` | `exec/async_scope.hpp` / `stdexec/execution.hpp` | Held by the scope                            |
| Fully manual lifetime control                                  | `connect(sndr, rcvr)` + `start(op)`                               | `stdexec/execution.hpp`                          | You decide                                   |

In addition, **inside a coroutine**, a sender can be `co_await`-ed directly (see [Section 6](#6-launching-in-coroutine-environments)),
and the coroutine itself is then launched via one of the five methods above.

---

## 5. Launching in Plain Functions

### 5.1 sync_wait: Block and Wait for the Result

`sync_wait(sndr)` runs the sender to completion in place and blocks the current thread until it finishes:

```cpp
#include <stdexec/execution.hpp>
#include <exec/static_thread_pool.hpp>

using namespace stdexec;

int main()
{
  exec::static_thread_pool pool{8};          // Pool with 8 threads
  scheduler auto sch = pool.get_scheduler(); // Get the scheduler

  sender auto work = schedule(sch)                       // Run once on the pool
    | then([] { return 13; })                            // Return 13
    | then([](int x) { return x + 42; });                // 55

  auto [result] = sync_wait(std::move(work)).value();    // std::optional<std::tuple<int>>
  std::cout << result << '\n';                           // 55
}
```

Semantics:

- The return value is `std::optional<std::tuple<Ts...>>`: the **values** are the `set_value` arguments;
- sender finishes with `set_stopped()` -> returns `std::nullopt`;
- sender finishes with `set_error(e)` -> **throws** `e` (`std::exception_ptr` is rethrown with `std::rethrow_exception`).
- `sync_wait` internally owns a `stdexec::run_loop`. Its environment answers
  `get_scheduler` / `get_start_scheduler` / `get_delegation_scheduler` at the same time (all pointing to this
  run_loop's scheduler), so `on()`, scheduler-affine tasks, and senders that actively query the delegation
  scheduler can throw work back to the waiting thread. **But this does not guarantee that the final completion callback of an arbitrary sender
  will run on the waiting thread**: for example, `schedule(pool) | then(...)` may complete the receiver directly from a pool thread;
  `sync_wait` only drives the run_loop from the waiting thread and blocks until the completion signal arrives.

```cpp
// Zero-argument get_scheduler() is a sender (equivalent to read_env(get_scheduler)):
auto [sch2] = sync_wait(get_scheduler()).value();   // Get the scheduler provided by sync_wait (run_loop)
```

> Limitations:
>
> - The sender must have **exactly one `set_value` completion signature** (compile-time static assert).
>   A flattened `set_value(x, y)` produced by `when_all(a, b)` also counts as "one kind" and is legal.
>   For senders with multiple success shapes, use `stdexec::sync_wait_with_variant()` instead (returns a variant-of-tuples).
> - Not cancellable: the environment provides no stop token (queries fall back to `never_stop_token`).
> - `sync_wait` is a blocking API. Technically it can be written in any ordinary C++ call site, but **do not call it inside a coroutine,
>   a single-threaded event loop, or on that loop's scheduler thread**; if the awaited operation still needs that thread to make progress,
>   it will self-deadlock. Inside a coroutine, `co_await` directly.
>
> Multi-runner schedulers do not make such calls safe. `sync_wait` keeps occupying the
> runner that calls it, and does not release this thread back to the scheduler while waiting. When only one runner calls the original
> `stdexec::sync_wait`, and there are still idle runners executing the awaited task, the wait can complete,
> and the original thread then returns to the scheduler; if every runner is waiting on tasks on the same scheduler, all
> runners are occupied and the scheduler deadlocks. Therefore this repository's `dcb::sync_wait` refuses to be called on an io scheduler runner no matter how many
> io runners are configured.

### 5.2 start_detached: Fire-and-Forget

```cpp
#include <exec/start_detached.hpp>

exec::static_thread_pool pool{4};

void kick_off_logging(std::string msg)
{
  exec::start_detached(
    schedule(pool.get_scheduler())
    | then([msg = std::move(msg)]() noexcept {
        // Do background work on the thread pool; nobody waits for the result
        write_log(msg);
      }));
}
```

Key points:

- It does `connect + start` immediately; the operation state is allocated **on the heap** (customizable with the allocator in the environment),
  and **deletes itself** on completion; the caller needs no management.
- `set_error` is not allowed, but **not intercepted at compile time**: the header comment claims a static assert, but there is actually
  none in the code -- a sender that can fail still compiles, and on error the built-in receiver's `set_error` directly
  calls `std::terminate()` (see `exec/start_detached.hpp`). For **compile-time** rejection, use
  `stdexec::spawn` (see 5.3). When the business logic may fail, first add `| upon_error(...)` to swallow or log the error.
- **No scope adoption**: when the program exits, such work may still be in flight. If you need "wait until all background tasks finish before exiting",
  use `async_scope` (see [Section 10](#10-structured-concurrency)) or `stdexec::spawn`.

> Tip: adaptors such as `then` / `upon_error` decide whether to append a `set_error_t(std::exception_ptr)` completion signature based on whether the lambda is **`noexcept`**. For any chain ultimately fed to `start_detached` / `stdexec::spawn`,
> mark the trailing lambda `noexcept` (and make sure earlier errors are already handled), otherwise `spawn` will reject it at compile time, while
> `start_detached` leaves a terminate hole.

### 5.3 stdexec::spawn / spawn_future: Standardized Fire-and-Forget

The C++26 standard (P3149) `stdexec::spawn` also does "fire-and-forget", but it **requires the operation to be adopted by an async
scope** (associated via the scope's token), so that scope close/join can guarantee they finish:

```cpp
#include <stdexec/execution.hpp>
#include <exec/static_thread_pool.hpp>
#include <exec/async_scope.hpp>

int main()
{
  exec::static_thread_pool pool{2};

  // Option A: standard API -- adopt with a scope token (stdexec::counting_scope provides get_token())
  stdexec::counting_scope scope;
  stdexec::spawn(
    schedule(pool.get_scheduler()) | then([]() noexcept { /* ... */ }),
    scope.get_token());
  // Note noexcept: if the then lambda can throw, a set_error_t(exception_ptr) signature is attached,
  // while spawn rejects failing senders at compile time

  scope.close();                       // No longer accept new tasks
  sync_wait(scope.join());             // Wait until all tasks in the scope finish

  // Option B: exec::async_scope (stdexec extension, more commonly used)
  exec::async_scope scope2;
  scope2.spawn(schedule(pool.get_scheduler()) | then([] { /* ... */ }));
  sync_wait(scope2.on_empty());        // Or scope2.request_stop(); sync_wait(scope2.on_empty());
}
```

Signatures and constraints:

- `stdexec::spawn(sndr, token)` / `stdexec::spawn(sndr, token, env)`: env can inject an
  extra environment (allocator, etc.) into the child operation. At **compile time** it requires the sender to be unable to `set_error`
  (`requires __never_sends<set_error_t, ...>`; when not satisfied it falls to a diagnostic overload reporting
  `static_assert: "spawn expects a sender that cannot fail"`).
  Internally it executes `token.wrap(sndr)` + associates it with the scope.
- `stdexec::spawn_future(sndr, token)` / `(sndr, token, env)`: returns a **sender that can wait for the result**
  (like the future of `std::async`).
- In everyday code, calling `async_scope.spawn(...)` / `spawn_future(...)` directly is simpler; but note that
  `exec::async_scope::spawn` has **no** compile-time interception for failures (terminate on error, see 10.2).

```cpp
exec::async_scope scope;

sender auto fut = scope.spawn_future(
  schedule(pool.get_scheduler()) | then([] { return 42; }));

// Can co_await / sync_wait this sender elsewhere:
auto [n] = sync_wait(std::move(fut) | stopped_as_optional()).value();
// Note: fut can only be connected once; when nobody connects it, the result is discarded (no leak)
```

### 5.4 connect + start: Fully Manual Control

When you want no heap allocation, no waiting, and precise control over the opstate lifetime yourself, connect + start directly:

```cpp
#include <stdexec/execution.hpp>
#include <exec/static_thread_pool.hpp>
#include <latch>

using namespace stdexec;

struct my_receiver
{
  using receiver_concept = receiver_tag;

  std::latch& done;                              // Used to signal "operation completed"

  void set_value(int v) noexcept
  {
    std::cout << "got " << v << '\n';
    done.count_down();
  }

  void set_error(std::exception_ptr e) noexcept
  {
    try { std::rethrow_exception(e); }
    catch (std::exception const& ex) { std::cerr << "err: " << ex.what() << '\n'; }
    done.count_down();
  }

  void set_stopped() noexcept
  {
    std::cout << "stopped\n";
    done.count_down();
  }

  auto get_env() const noexcept
  {
    return prop{get_stop_token, never_stop_token{}};   // Environment: not cancellable
  }
};

int main()
{
  exec::static_thread_pool pool{1};
  std::latch done{1};

  auto op = connect(schedule(pool.get_scheduler()) | then([] { return 7; }),
                    my_receiver{done});
  start(op);      // Returns immediately; the operation runs asynchronously on a pool thread
  done.wait();    // op is a stack object and must not be destroyed until after the completion callback!
}
```

Rules:

- **The opstate is immovable and non-copyable**, and must be stored in a storage in the `connect` context that outlives the operation.
- `start(op)` is called exactly once; once a completion function is invoked, the opstate is immediately invalid.
- Senders like `schedule(pool...)` are enqueued **asynchronously**: when `start()` returns, the operation has not finished yet,
  and the opstate must live until after the completion callback (the example above guarantees this with a latch). Forgetting to wait is the most typical
  opstate-lifetime UB.
- This path is the foundation of all other launching methods, but business code **almost never** needs to use it directly,
  unless you are writing a custom receiver (e.g. an adaptor for C callbacks, see [Section 13](#13-interoperating-with-callback-style-apis)).

### 5.5 run_loop: Drive the Event Loop Yourself

`stdexec::run_loop` is a "loop you run manually": the scheduler submits tasks into a queue, and `run()` consumes them:

```cpp
#include <stdexec/execution.hpp>
#include <exec/start_detached.hpp>
using namespace stdexec;

int main()
{
  run_loop loop;

  exec::start_detached(     // Throw into run_loop (fire-and-forget, needs <exec/start_detached.hpp>)
    schedule(loop.get_scheduler()) | then([&loop]() noexcept {
      std::cout << "tick\n";
      loop.finish();        // Close the loop inside the task: run() will then return
    }));

  loop.run();               // Block and process the queue until finish() is called and the queue is drained
}
```

Key points:

- The exit condition of `run()` is: **`finish()` has been called, the queue is drained, and in-flight tasks have dropped to zero**.
  It does not return just because tasks have finished -- someone must call `finish()`.
- `finish()` can be called from any thread, or from a task in the queue (this is how `sync_wait` exits its internal
  run_loop); repeated calls are safe.
- So writing `loop.finish()` after `loop.run()` in program order deadlocks -- `run()` never returns,
  and `finish()` is never reached.

Typical uses: stuffing the event loop into your own thread (`exec::single_thread_context` is implemented this way),
integrating with a GUI/game main loop, implementing manual blocking waits like `sync_wait`.

---

## 6. Launching in Coroutine Environments

### 6.1 This Project Uniformly Uses `stdexec::task`

`stdexec::task<T, TaskEnv = env<>>` is this clone's implementation of the P3552 scheduler-affine task.
It is a lazy coroutine and also a sender; business code, the runtime, and code generators in this project all uniformly return
`stdexec::task<T>`. Do not switch to the old extension `exec::task<T>` for "affinity" anymore: the current
`stdexec::task` already automatically returns to its own **home/start scheduler** after every `co_await`.

```cpp
#include <stdexec/execution.hpp>
#include <exec/static_thread_pool.hpp>

using namespace stdexec;

auto fetch_and_add(exec::static_thread_pool& pool) -> stdexec::task<int>
{
  // schedule(pool) completes on a pool thread; the task then automatically returns to the home scheduler that launched it.
  int a = co_await (schedule(pool.get_scheduler())
                  | then([] { return 20; }));
  int b = co_await (schedule(pool.get_scheduler())
                  | then([] { return 22; }));
  co_return a + b;
}

int main()
{
  exec::static_thread_pool pool{2};
  auto [ans] = sync_wait(fetch_and_add(pool)).value();
  std::cout << ans << '\n';                       // 42
}
```

Here the task's home scheduler comes from `get_start_scheduler` in the receiver environment that launches it;
`sync_wait` provides its own run_loop scheduler. The task's promise environment then exposes this scheduler as the query result of both
`get_scheduler` / `get_start_scheduler`, and propagates the
allocator and stop token to the awaited sender.

### 6.2 Value, Error, and Stopped Semantics of `co_await`

When `co_await sndr` inside a `stdexec::task`:

| Upstream completion                        | Behavior of the `co_await` expression                                |
| ------------------------------------------ | -------------------------------------------------------------------- |
| `set_value()`                              | `void`                                                               |
| `set_value(v)` (exactly one value)         | **`v` itself (bare value, not a tuple)**                             |
| `set_value(v1, v2, ...)` (multiple values) | `std::tuple<...>` (decayed)                                          |
| `set_error(e)`                             | **throws** `e`                                                       |
| `set_stopped()`                            | Does not resume the current statement; stop propagates to the parent |

> Comparison: `sync_wait` always returns `std::optional<std::tuple<...>>`, so
> `auto [v] = sync_wait(...).value()` also holds for a single value; while `co_await` gives a bare value for a single value,
> written as `int a = co_await ...`.
>
> `co_await` binds **tighter** than `|`. `co_await a | then(f)` parses as
> `(co_await a) | then(f)`; an awaited pipeline must be written as `co_await (a | then(f))`.

When the awaited object completes with `set_stopped()`, the task does not execute statements after the `co_await`; the stop propagates outward through
the promise's `unhandled_stopped()`, finally making the task sender invoke
`set_stopped()` downstream. The default completion signatures of `stdexec::task<T>` are `set_value_t(T)` (no argument when `void`),
`set_error_t(std::exception_ptr)`, and `set_stopped_t()`, so it can directly participate in `when_all`,
`then`, `sync_wait`, and other compositions.

### 6.3 Querying the Execution Environment Inside Coroutines

A zero-argument call of a query CPO produces a `read_env(query)` sender, which can be `co_await`-ed directly:

```cpp
auto query_env() -> stdexec::task<void>
{
  scheduler auto sch = co_await get_scheduler();
  auto tok = co_await get_stop_token();
  (void) sch;
  (void) tok;
  co_return;
}
```

- `get_scheduler()` is the task's current home scheduler; `get_start_scheduler()` returns the
  same scheduler here.
- `get_stop_token()` is a token linked with the parent environment. After the parent requests stop, the task and the sender it awaits
  share the same cooperative cancellation chain.
- Zero-argument queries also hold in ordinary sender chains, e.g. `sync_wait(get_scheduler())`.

### 6.4 Do Work on Another Scheduler, Then Automatically Come Home

`stdexec::task` does not have, nor does it need, `exec::reschedule_coroutine_on`. To put a piece of work on a thread pool,
`co_await` a sender launched on the target scheduler; after the wait ends, the task's `affine` machinery throws the
coroutine resumption back to the home scheduler:

```cpp
auto handle_request(exec::static_thread_pool& workers) -> stdexec::task<result>
{
  auto value = co_await stdexec::starts_on(
    workers.get_scheduler(),
    stdexec::just() | stdexec::then([] { return blocking_compute(); }));

  // Here we are already back on the home scheduler that launched this task.
  co_return finish_on_home(std::move(value));
}
```

If you want to change the **home scheduler of the whole task**, write
`starts_on(home, task())` at the outermost launch. Do not expect `continues_on(target)` to permanently change the task's home; it only changes
the completion location of the awaited sender, and the task still performs the affinity hop-back before resuming.

### 6.5 `TaskEnv` and the Hard Constraints of the Home Scheduler

The second template parameter `TaskEnv` can customize the task's allocator, `start_scheduler_type`,
`stop_source_type`, `error_types`, and extra environment; the defaults are a byte allocator,
`stdexec::task_scheduler`, `inplace_stop_source`, `std::exception_ptr`, and an empty extra environment, respectively.
The vast majority of business code should keep using the defaults.

The default `task_scheduler` type-erases the home scheduler. There are two implementation constraints that are easy to trip over with custom schedulers:

1. `schedule(home)` must be a sender that **never fails**. Merely satisfying the `stdexec::scheduler` concept is not enough;
   if the completion signatures still declare `set_error`, task construction with that home scheduler fails to compile.
2. The type-erased schedule operation state must fit into a fixed-size inline buffer. The default macro
   `STDEXEC_TASK_SCHEDULE_OPSTATE_SIZE` is 72 bytes; when a custom scheduler's opstate is larger,
   this macro must be raised consistently in all relevant translation units (this project sets it to 256, see 12.6.2/12.6.6).

These two requirements are implementation constraints of this clone's `task_scheduler`, not general rules for judging whether an ordinary scheduler is well-formed.

### 6.6 Launching Tasks: Specify the Home First, Then Add Uniform Fallbacks

```cpp
// 1) Ordinary thread blocking wait: sync_wait's run_loop is the home.
auto [v] = sync_wait(my_task()).value();

// 2) Launch on a specified event loop and use it as home; handle all non-value channels before detaching.
exec::start_detached(
  starts_on(io_scheduler, my_void_task())
  | upon_error([](std::exception_ptr e) noexcept { log_error(e); })
  | upon_stopped([]() noexcept { log_stopped(); }));

// 3) Have a scope track the lifetime.
exec::async_scope scope;
scope.spawn(my_void_task()
  | upon_error([](std::exception_ptr e) noexcept { log_error(e); }));

// 4) Track with a scope and keep the result.
sender auto future = scope.spawn_future(my_task());
```

The wire dispatch generated in this project uses a fixed launcher: first
`starts_on(Runtime::io_scheduler(), task)` specifies the io scheduler as home, then appends
`noexcept` tails of `upon_error` / `upon_stopped`, and finally hands it to `start_detached`. The launcher validates against the actual io environment at compile time with
`sender_in<S, spawn_env_t>`, instead of only checking the bare `sender<S>`.

### 6.7 Lazy Coroutine Lambdas: Never Use Captures as Coroutine State

This is a high-risk trap that turns into dangling access in optimized builds:

```cpp
// Wrong: task is lazy. The lambda temporary is destroyed first, and captured members are already dangling at first resume.
auto bad = [session, request]() -> stdexec::task<void> {
  co_await dispatch(session, request);
}();

// Correct: zero-capture IIFE, putting all state into the coroutine frame as by-value parameters.
auto good = [](std::shared_ptr<Session> session, Request request)
              -> stdexec::task<void> {
  co_await dispatch(session, request);
}(std::move(session), std::move(request));
```

Captures of a coroutine lambda belong to the closure object and are not automatically copied into the coroutine frame; the closure may already be destroyed before the task really starts.
Coroutine **parameters**, in contrast, enter the coroutine frame at the call and live until the task completes. Therefore use named coroutine functions, or
"zero-capture IIFE + explicit by-value parameters". The IIFE must not secretly keep other captures either; any capture reintroduces the same risk.

---

## 7. Switching Executors

Migrating scheduling contexts is one of the most core capabilities of the senders model.

### 7.1 Migration Algorithms

| Algorithm                                    | Effect                                                                                            | Pipe syntax                          |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------- | ------------------------------------ |
| `stdexec::starts_on(sched, sndr)`            | **Start** sndr **on sched**; after starting, sndr schedules itself internally                     | **No pipe form**                     |
| `stdexec::continues_on(sndr, sched)`         | After sndr **completes**, migrate to sched and continue (run downstream)                          | `sndr \| continues_on(sched)`        |
| `stdexec::on(sched, sndr)` (form 1)          | Start sndr on sched, and after completion **migrate back to the "launch-site" scheduler**         | None (shadows form 2)                |
| `stdexec::on(sndr, sched, closure)` (form 2) | Run sndr in place -> switch to sched to apply closure -> switch back to the launch-site scheduler | `sndr \| on(sched, closure)`         |
| `exec::reschedule`                           | Migrate to the receiver environment's `get_start_scheduler`                                       | `sndr \| exec::reschedule()`         |
| `stdexec::schedule_from`                     | Internal building block of `continues_on` (single-argument marking use only in this version)      | Do not use directly in business code |

[!] `on()` is the most easily misunderstood algorithm: **after completion it does not stay on sched, but returns to the "launch-site" scheduler**.
Equivalence relations:

```text
on(sched, sndr)          = continues_on(starts_on(sched, sndr), old_sched)
on(sndr, sched, closure) = sndr completes in place -> continues_on(*, sched) -> apply closure
                           -> continues_on(*, old_sched)
```

`old_sched` is read from `get_start_scheduler` of the downstream receiver environment; the root env (bare connect)
falls back to `inline_scheduler`; a custom env that does not provide it -> compile error
`_CANNOT_RESTORE_EXECUTION_CONTEXT_AFTER_ON_` (see [Section 14](#14-common-compile-error-quick-reference)).

```cpp
using namespace stdexec;

exec::static_thread_pool    pool{4};
exec::single_thread_context ui;              // Single thread, simulating a UI thread

sender auto pipeline =
  just()                                     // Completes inline on the caller thread
  | on(pool.get_scheduler(),                 // Form 2: switch to the pool to apply the closure,
       then([] { return heavy_compute(); })) //   then return to the launch-site scheduler (here sync_wait's run_loop)
  | continues_on(ui.get_scheduler())         // Then migrate to the UI thread
  | then([](int r) { update_ui(r); });       // Run on the UI thread

sync_wait(std::move(pipeline));
```

`starts_on` has no pipe form; write it nested:

```cpp
sender auto s =
  starts_on(pool.get_scheduler(),             // Start as a whole on the pool and stay on the pool
            just(42) | then([](int x) { return x * 2; }));
```

Typical use of `exec::reschedule`: treat the scheduler in the current environment as the "return here" target,
often used to interface callback APIs with the sender world (after a C callback arrives, `| exec::reschedule()` returns to the thread pool/event loop).
Note that in a pipeline you must write `exec::reschedule()` (a zero-argument call returning a closure), not the bare `exec::reschedule`.

> Performance tip: every `on/continues_on` goes through one queue submission + wakeup; long chains add extra overhead;
> migrate as rarely as possible on hot paths.

### 7.2 get_start_scheduler: the "Going Home" Mechanism

`on()`, `exec::reschedule`, and `stdexec::task` all use `get_start_scheduler(env)` --
"on which scheduler was the current operation launched":

- `sync_wait`'s environment answers `get_scheduler` / `get_start_scheduler` /
  `get_delegation_scheduler` at the same time, all pointing to its internal run_loop -- so
  `sync_wait(on(pool, ...))` can return to the waiting thread.
- `stdexec::task` builds the home scheduler from the parent receiver environment at launch; the task's own promise
  environment then makes both `get_scheduler` / `get_start_scheduler` answer with this home (see 6.4).
- `exec::reschedule` = `continues_on(sndr, special scheduler)`, where this special scheduler at connect time
  reads `get_start_scheduler` from the receiver environment; a missing env entry is a compile error `_CANNOT_RESCHEDULE_`.
- stdexec extension (non-standard): when an env does not answer `get_scheduler` but answers `get_start_scheduler`,
  a `get_scheduler` query falls back to the latter.

---

## 8. Cancellation

### 8.1 Cancellation Infrastructure

```cpp
#include <stdexec/stop_token.hpp>

stdexec::inplace_stop_source  src;                      // Cancellation source (RAII)
stdexec::inplace_stop_token   tok = src.get_token();    // Read-only token
stdexec::inplace_stop_callback<F> cb{tok, f};           // Register a callback: call f when request_stop() happens
src.request_stop();                                     // Trigger cancellation: afterwards tok.stop_requested() == true
```

- After `request_stop()`, **each** registered callback is invoked **exactly once** (possibly synchronously on the
  calling thread of `request_stop()`).
- Destruction of a callback is synchronized thread-safely with the `request_stop()` thread: after callback destruction returns, the source side will no longer touch it.
- `inplace_stop_callback` must be destroyed **while the `inplace_stop_source` is still alive** (it holds the source's
  callback list); do not destroy the source inside a callback.

### 8.2 Feeding Cancellation into Senders: Environments

Cancellation is not passed via parameters, but via the **stop token in the receiver environment**:

```cpp
using namespace stdexec;

inplace_stop_source src;

sender auto work =
  schedule(pool.get_scheduler())
    | then([] { /* stoppable long-running work */ })
    | exec::unless_stop_requested()                       // If stop has been requested, short-circuit with set_stopped directly
    | write_env(prop{get_stop_token, src.get_token()});   // Inject a stop token into the upstream receiver environment
```

- `get_stop_token(env)`: query the current stop token from the environment; when missing it defaults to `never_stop_token` (not cancellable).
- `write_env(sndr, prop{...})` / `sndr | write_env(prop{...})`: inject the `prop` (key-value pair) into the environment visible to the
  left-hand sender. **Note the name is `write_env`** (`write` / `exec::write_env` are both
  deprecated old names), and when called directly the argument order is sender first.
- `exec::unless_stop_requested(sndr)`: check the stop flag before executing; if already stopped, short-circuit with `set_stopped`.
- Combinators (`when_all`, etc.) **automatically** propagate the outer stop token to child senders.

### 8.3 Responding to Cancellation in Business Code

If the work inside a sender is interruptible polling/waiting, read the token and check it yourself:

```cpp
sender auto cancellable_loop(inplace_stop_token tok)
{
  return schedule(pool.get_scheduler())
       | then([tok] {
            for (int i = 0; i < 1'000'000; ++i)
            {
              if (tok.stop_requested())
                return 0;                     // Exit early
              work_unit(i);
            }
            return 1;
          });
}
```

Or register an async callback with `inplace_stop_callback` (e.g. to interrupt a third-party call being waited on;
see [13.3](#133-making-the-wrapper-cancellable) for the complete recipe).

### 8.4 Turning Cancellation into Values/Errors: `stopped_as_*`

`set_stopped` carries no value, and callers often need to turn it into something handlable:

```cpp
// stopped -> optional (empty means cancelled)
sender auto opt = stopped_as_optional(work);      // set_value(std::optional<T>)

// stopped -> a specified error value
sender auto err = stopped_as_error(work, my_error{"cancelled"});  // set_error(my_error)

// stopped -> callback
sender auto cb  = upon_stopped(work, [] { std::cout << "cancelled\n"; });
```

`stopped_as_optional` only accepts senders with **exactly one successful completion signature, carrying exactly one value**;
`set_value()`, multiple values, or multiple value shapes do not satisfy the constraint. Unify multi-shape results with `into_variant` first.

### 8.5 Timeouts and Racing: Implement "Trigger Cancels" with when_any

> Note: `stop_when(sndr, trigger)` from early P2300 drafts was removed before standardization. In stdexec
> only the internal implementation `__stop_when` remains (`counting_scope::token::wrap` uses it), with **no public
> CPO** -- `stdexec::stop_when(...)` does not compile. To express "when trigger completes, cancel sndr", race with
> `exec::when_any`:

```cpp
exec::timed_thread_context timer;   // Long-lived object (member variable or static), see 12.1

sender auto fetch_with_timeout()
{
  auto timeout = exec::schedule_after(timer.get_scheduler(), 200ms)
               | then([]() -> int { throw timeout_error{}; }); // C++20; throwing -> set_error

  // Whoever finishes first wins; the losing branch receives request_stop (cooperative cancellation)
  return exec::when_any(fetch_from_network(), std::move(timeout));
}
```

- Network finishes first -> the timer branch is cancelled, and `when_any` completes with the network result;
- Timer fires first -> the `then` throws -> `when_any` completes with `set_error(timeout_error)`,
  and the network branch is cancelled.
- All branches inside `when_any` **share one** `inplace_stop_source`: after the first finisher wins, it calls
  `request_stop()` on it, and the losers receive the stop signal. Cancellation is **cooperative**.
- **This is not a hard timeout.** Although the current implementation picks the winner when the first result arrives, it waits until all branches have finished
  before sending that result downstream. If a loser ignores the stop token, gets stuck in non-cancellable I/O, or never calls back, the whole
  `when_any` keeps waiting; you cannot understand `200ms` as "the caller is guaranteed to return in 200ms".
- A real deadline requires the underlying operation to be cancellable and to guarantee post-cancel **quiescence/cleanup**: e.g. closing sockets,
  cancelling Asio operations, and waiting for their completion handlers to arrive. If you choose to detach the loser, you must use
  shared state to decouple its resource lifetime from the calling stack, and specify how late callbacks are discarded, instead of letting them keep referring to local variables.
- The completion signatures of `when_any` are the **union** of all branches (values keep their own shapes, not wrapped in a variant),
  and downstream `then` parameter types must be compatible with each branch's values.

### 8.6 Cancellation Inside Coroutines

`stdexec::task` natively links stop with the parent environment:

```cpp
auto guarded() -> stdexec::task<int>
{
  std::optional<int> r = co_await stopped_as_optional(expensive_work());
  co_return r.value_or(-1);
}
```

- A coroutine gets the parent-propagated token via `co_await get_stop_token()` and decides how to respond itself.
- When the parent coroutine or an outer `when_any` requests stop, the inner sender gets `set_stopped`, and the stop propagates upward along
  the promise chain (see 6.2 for the exact semantics).

### 8.7 Cooperative Cancellation for Channels (co::mpsc, Verified)

`co::mpsc`'s `send()` / `recv()` park paths natively support stop tokens (see `docs/channel_stop_token_design.md` for the full design and semantics). Three verified forms of injecting a token:

```cpp
auto [tx, rx] = co::mpsc::bounded<int>(1);
stdexec::inplace_stop_source src;

// Form 1: inject with write_env on the sender chain (note sender comes first)
auto result = stdexec::sync_wait(
  stdexec::write_env(tx.send(v),
                     stdexec::prop{stdexec::get_stop_token, src.get_token()}));
// After src.request_stop(): a parked send completes with set_stopped, sync_wait returns an empty optional,
// and the value is withdrawn, not dropped into the channel.

// Form 2: custom receiver -- get_env() returns
//   stdexec::env{stdexec::prop{stdexec::get_stop_token, tok}}

// Form 3: co_await inside a stdexec::task -- the token in the outer receiver env is forwarded by the task to
// the awaited channel operation (pass-through verified). Launch a cancellable task at the top level
// (starts_on specifies the task's home scheduler at the same time):
auto op = stdexec::connect(
  stdexec::starts_on(stdexec::inline_scheduler{},
    stdexec::write_env(task(), stdexec::prop{stdexec::get_stop_token, src.get_token()})),
  my_receiver{});
```

- **Withdrawal semantics (tokio cancel-safety)**: before delivery (claimed), the value always belongs to the sender-side opstate;
  cancellation (a stop request, or the fallback path of destroying the opstate) ==> the value does not land in the channel. When claiming races with stop, first arrival wins (arbitrated under the channel lock); after claiming, stop loses.
- **How `stdexec::task` behaves on `set_stopped` (verified)**: when the `co_await`-ed sender completes as stopped,
  the coroutine **no longer resumes** (symmetric transfer to the promise's `unhandled_stopped`), the task itself completes with
  `set_stopped`, and statements after the `co_await` do not run. Callers that need to distinguish "closed" from "cancelled"
  handle it with `stopped_as_optional` or the receiver's `set_stopped` branch.
- **Lifetime**: the `inplace_stop_source` must outlive opstates registered on it -- destroy the
  opstates first, then destroy the source.
- `co::oneshot` deliberately does not take stop tokens (scenarios like DartFn receipts use the destroy-means-cancel fallback path).

---

## 9. Composition (Combinators)

| Combinator                                     | Effect                                                                                                                                                                                                                           | Example                                                                   |
| ---------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `just(vs...)`                                  | Complete (synchronously) immediately with values                                                                                                                                                                                 | `just(42)`                                                                |
| `exec::just_from(f)`                           | Lazy `just`: call f only at **start**; f receives a sink, and calling `sink(vs...)` sends values (when f can throw, `set_error_t(std::exception_ptr)` is automatically attached)                                                 | Construct expensive objects                                               |
| `then(sndr, f)`                                | Map after success (when f can throw, a `set_error_t(std::exception_ptr)` signature is automatically attached)                                                                                                                    | `sndr \| then(f)`                                                         |
| `let_value(sndr, f)`                           | **Dynamically chain** a new sender after success (f returns a sender)                                                                                                                                                            | Launch a new request depending on the previous result                     |
| `upon_error(sndr, f)`                          | Error recovery                                                                                                                                                                                                                   | `sndr \| upon_error([](std::exception_ptr e){ ...; return fallback; })`   |
| `upon_stopped(sndr, f)`                        | Fallback on stop                                                                                                                                                                                                                 | `sndr \| upon_stopped(f)`                                                 |
| `when_all(sndrs...)`                           | Start all branches at the same time; complete only when all succeed; any failure/stop -> `request_stop` the remaining branches and fail/stop as a whole                                                                          | Concurrent requests (whether parallel depends on each branch's scheduler) |
| `exec::when_any(sndrs...)`                     | The first finisher wins and requests stop of the remaining branches, but completes only after all branches clean up                                                                                                              | Cooperative racing (not a hard timeout, see 8.5)                          |
| `bulk(sndr, pol, shape, f)`                    | Execute f in parallel over shape indices (auto-chunked on thread pools)                                                                                                                                                          | Parallel loops                                                            |
| `starts_on(sched, sndr)`                       | Specify the starting executor                                                                                                                                                                                                    | See [Section 7](#7-switching-executors)                                   |
| `continues_on(sndr, sched)`                    | Specify the continuation executor                                                                                                                                                                                                | See [Section 7](#7-switching-executors)                                   |
| `on(sched, sndr)` / `on(sndr, sched, closure)` | Start / run a section and then return to the launch-site scheduler                                                                                                                                                               | See [Section 7](#7-switching-executors)                                   |
| `exec::split(sndr)`                            | Turn a "single-consumption" sender into a multi-subscribable one; start only on first connect, cache the value and broadcast it as `const T&` to all subscribers                                                                 | Multiple consumers                                                        |
| `exec::ensure_started(sndr)`                   | Start immediately and cache the result; the returned sender can only be connected once, with the success value handed to that consumer as `T&&`                                                                                  | Warm up early; for multiple subscriptions use `split`                     |
| `exec::finally(sndr, cleanup)`                 | No matter which channel initial completes on, run cleanup next; cleanup must be a "sender of void" (only sends `set_value_t()`); a failing cleanup replaces initial's result downstream                                          | Release resources, tracing                                                |
| `exec::repeat_until(sndr, pred)`               | Execute in a loop until pred holds (`repeat_effect_until` is its alias; the old header `exec/repeat_effect_until.hpp` is deprecated)                                                                                             | Polling                                                                   |
| `exec::materialize(sndr)`                      | Turn completion signals into values: `set_value(vs...)` -> `set_value(set_value_t{}, vs...)`, `set_error(e)` -> `set_value(set_error_t{}, e)`, `set_stopped()` -> `set_value(set_stopped_t{})`; inverse is `exec::dematerialize` | Handle errors as values                                                   |
| `into_variant(sndr)`                           | Merge multiple value completion signatures into a variant                                                                                                                                                                        | Eliminate type branches                                                   |
| `stopped_as_optional(sndr)`                    | stopped -> empty optional                                                                                                                                                                                                        | See [Section 8](#8-cancellation)                                          |
| `stopped_as_error(sndr, e)`                    | stopped -> error                                                                                                                                                                                                                 | See [Section 8](#8-cancellation)                                          |
| `write_env(sndr, prop{...})` / `read_env(q)`   | Inject / read the environment                                                                                                                                                                                                    | Pass stop tokens, allocators                                              |
| `get_scheduler()` / `get_stop_token()`         | Query the environment in sender form (zero arguments = `read_env(query)`)                                                                                                                                                        | `co_await` inside coroutines                                              |

`let_value` example (dynamic composition depending on the previous result):

```cpp
sender auto download_and_parse(std::string url)
{
  return just(std::move(url))
       | let_value([](std::string u) {            // Return a new sender
           return download(u)                     // async sender
                | then([](std::vector<std::byte> raw) {
                    return parse(raw);
                  });
         });
}
```

`when_all` in parallel:

> **`when_all` value shape**: on full success it flat-concatenates each branch's values into one
> `set_value(vs1..., vs2..., ...)` (not tuple-of-tuples). Combined with the unpacking rules in 6.2,
> when each branch produces one value: `auto [a, b] = co_await when_all(x, y);` works directly.
> `when_all` starts all child senders, but "concurrent start" is not "multi-core parallelism": if all branches are on the same
> single-threaded event loop, they still advance serially; actual parallelism is determined by the scheduler each branch uses.

```cpp
using namespace stdexec;

// bulk needs an execution policy: seq / par / par_unseq (same semantics as <execution>)
// Parallelism really takes effect only when: the sender completes on a thread-pool scheduler (the pool's domain
// dispatches bulk_chunked as multi-threaded chunked execution).
sender auto parallel_double(exec::static_thread_pool& pool, span<int> data)
{
  return schedule(pool.get_scheduler())              // Start on the pool; set_value() with no value
       | bulk(stdexec::par, data.size(),             // Parallel loop (calls f(i, vs...) per index)
              [data](std::size_t i) { data[i] *= 2; })
       | then([data] { return sum(data); });         // Continue after all chunks finish
}
```

> Note: `bulk`'s function signature is per-index `f(i, vs...)` (`vs...` are upstream values shared by all iterations);
> the chunking strategy (chunked / unchunked) is decided internally by the thread pool's domain; business code just uses
> `stdexec::par`. The thread pool also supports `bulk_chunked` (explicit chunked function `f(begin, end, vs...)`).

---

## 10. Structured Concurrency

### 10.1 Why Structured Concurrency Is Needed

The problem with `start_detached` is: **the launcher cannot tell when background work finishes**, leaving dangling operations when the program exits;
the problem with manual `connect + start` is: **you must guarantee the opstate destruction order yourself**, which easily leads to lifetime bugs.
Structured concurrency binds "a group of concurrent child tasks" to a **scope object** and provides an explicit drain/join
protocol. This restores two valuable invariants:

1. **Child tasks do not outlive the parent scope** (parent scope alive => children alive; the scope does not become empty before children finish).
2. **Failure/cancellation can propagate as a whole**: scope.request_stop() notifies all child tasks.

> A scope's destructor **does not block and wait for you**. `exec::async_scope`'s destructor only asserts that it is already empty;
> `counting_scope` calls `std::terminate()` when destroyed in an illegal state. The so-called "no escape" is the guarantee the caller gets after correctly executing
> `on_empty()` or `close() + join()` before destruction, not work automatically done by the destructor.

### 10.2 exec::async_scope (Most Commonly Used)

```cpp
#include <exec/async_scope.hpp>

exec::static_thread_pool pool{4};

{
  exec::async_scope scope;                       // RAII: destructor asserts the scope is empty

  scope.spawn(schedule(pool.get_scheduler()) | then(task_a));
  scope.spawn(schedule(pool.get_scheduler()) | then(task_b));

  sender auto fut = scope.spawn_future(          // The one whose result you want
    schedule(pool.get_scheduler()) | then(task_c));

  sync_wait(when_all(scope.on_empty(),           // Wait until all child tasks finish
                     std::move(fut) | then([](int v) { use(v); })));
}  // The scope is guaranteed empty here (without waiting, debug assert fails / release UB -- see below)
```

Member quick reference:

| Member                                   | Effect                                                                                                                                                                                                                                                                                              |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `spawn(sndr, env = {})`                  | Fire-and-forget. **No compile-time interception** for senders that `set_error`: on error the built-in receiver directly calls `std::terminate()` (with a `BUGBUG NOT TO SPEC` comment in the source). Add `upon_error` first, or switch to the compile-time-constrained `stdexec::spawn` (see 10.3) |
| `spawn_future(sndr, env = {})`           | Launch and return an awaitable sender; the return value can only be connected once; when nobody connects it the result is discarded (no leak)                                                                                                                                                       |
| `nest(sndr)`                             | Get a "scope-adopted" sender (registered at connect, deregistered at completion) that can be manually connect/start-ed                                                                                                                                                                              |
| `on_empty()`                             | A sender: completes with `set_value()` when the scope becomes empty (= `when_empty(just())`)                                                                                                                                                                                                        |
| `when_empty(sndr)`                       | Start sndr only after the scope drains; completion channels are exactly the same as sndr's                                                                                                                                                                                                          |
| `request_stop()`                         | Request stop for all child tasks inside the scope (via the environment stop token)                                                                                                                                                                                                                  |
| `get_stop_source()` / `get_stop_token()` | Access the scope's own stop source                                                                                                                                                                                                                                                                  |

Typical pattern (service lifetime):

```cpp
struct server
{
  exec::async_scope scope;

  void start(exec::static_thread_pool& pool)
  {
    // accept_loop_sender must read the environment stop token and be able to cancel the underlying accept;
    // merely putting a blocking while-loop inside then() will not exit automatically on request_stop.
    scope.spawn(accept_loop_sender(pool)
              | upon_error([](std::exception_ptr e) noexcept { log_error(e); }));
  }

  void shutdown()
  {
    scope.request_stop();          // Notify accept_loop to stop
    sync_wait(scope.on_empty());   // Wait until it actually exits
  }
};
```

### 10.3 stdexec::counting_scope / simple_counting_scope (Standard)

Standard-version scopes (P3149, `stdexec::counting_scope` in `stdexec/execution.hpp`):

```cpp
using namespace stdexec;

counting_scope scope;

// Launch a child operation under the scope: wrap the sender with a token (wrap forwards stop requests to the child)
auto token = scope.get_token();
auto child = token.wrap(schedule(pool.get_scheduler()) | then(work));
exec::start_detached(std::move(child));    // Or sync_wait(child) / connect+start

scope.close();                             // No longer accept new associations
sync_wait(scope.join());                   // Wait until all associated operations finish

scope.request_stop();                      // (May be called before close) request cancellation of all
```

| Member                  | Effect                                                                                  |
| ----------------------- | --------------------------------------------------------------------------------------- |
| `get_token()`           | Get the association token; `token.wrap(sndr)` binds a sender to the scope's stop source |
| `token.try_associate()` | Manually associate (returns null assoc when the count is exhausted)                     |
| `max_associations()`    | Maximum allowed concurrent associations (defensive upper bound)                         |
| `close()`               | Close: afterwards `try_associate` fails                                                 |
| `join()`                | Return a sender: completes after all associated operations finish                       |
| `request_stop()`        | Cancel all associated operations (counting_scope only)                                  |

Difference between `simple_counting_scope` and `counting_scope`: the former has no stop source, and `wrap` does not forward cancellation (lighter weight).

> [!] **Destruction discipline**: an untouched `unused` state with no operations ever associated can be destroyed directly;
> `unused-and-closed` and `joined` are also legal end states. Once operations have actually been associated, you must `close()` before destruction and wait for
> `join()` to complete (`sync_wait` or `co_await`); destruction in any other state calls
> `std::terminate()`. Do not mistake "never used" as also requiring join.

### 10.4 Nested Scopes: Structured Concurrency Can Recurse

Scopes can nest -- the outer waits for the inner. The key point is that **the scope object's lifetime must be held by the structure
that waits for it to drain**. Holding it in a coroutine frame is most natural:

```cpp
// Correct pattern: inner lives in the coroutine frame; it is destroyed only after co_await-ing the drain
auto phase(exec::static_thread_pool& pool) -> stdexec::task<void>
{
  exec::async_scope inner;
  inner.spawn(schedule(pool.get_scheduler()) | then(sub_task1));
  inner.spawn(schedule(pool.get_scheduler()) | then(sub_task2));

  co_await inner.on_empty();      // Wait for inner to drain; the coroutine frame keeps inner alive
  finalize_inner();
}

// Launch (stdexec::task may set_error, and async_scope::spawn terminates on error, so handle it first):
outer.spawn(phase(pool) | upon_error([](std::exception_ptr e) noexcept { log_error(e); }));
```

> Counterexample: make `inner` a **local variable of a plain function**, then hang `inner.on_empty()` into the outer
> scope -- `inner` is destroyed as soon as the function returns, while its tasks and waiters may still be alive
> (debug assert `__active_ == 0` fails / release UB). `when_all(inner.on_empty())`
> only **references** it and does not extend its lifetime.

### 10.5 Relationship with connect/start

The essence of `async_scope::nest` is "connect with bookkeeping": `nest(sndr)` returns a sender
that increments the active count at connect and decrements it at completion (inside the completion callback, strictly obeying the "do not touch opstate after completion" rule).
`spawn` = `nest` + heap-allocated opstate + self-deletion; `spawn_future` = `nest` + shared state caching the result.

> Precisely because counts are maintained in completion callbacks, scope implementations have strict ordering requirements on completion callbacks:
> do not synchronously call potentially deadlocking things inside a completion callback (e.g. `sync_wait(scope.on_empty())`).

---

## 11. Lifetimes and RAII

1. **Senders are values**: they can be moved, captured by value into `then` lambdas; after connecting, the sender can be discarded.
2. **Opstates are immovable**: the result of `connect` must be placed in a stable storage that
   lives until after the operation completes (on the stack, in a member, or on the heap with the operation deleting itself).
3. **Lazy coroutine lambdas do not hold captures**: a lambda closure returning `stdexec::task` may be destroyed before the first
   resume; do not use `[x] { co_await ...; }()` to hold state. Use named functions, or zero-capture IIFEs
   with state passed by value into the coroutine frame (see 6.7).
4. **Do not touch after completion**: after a receiver's completion function is invoked, the opstate, the receiver, and
   everything captured into the operation state count as "dead" and must not be used anymore (this is the most common UB source).
5. **Destroying a scope before its child operations is an error**: if `async_scope` is destroyed with `__active_ != 0`,
   debug assert fails / release UB; the `counting_scope` family is even stricter -- destroying without finishing join directly calls
   `std::terminate()`. To "just quit without caring", first `request_stop()` + wait for drain/join,
   or let the scope live longer.
6. **Stop-callback lifetime**: `inplace_stop_callback` must be destroyed while the source is still alive;
   do not destroy the source inside a callback.
7. **Errors must be handled**: `stdexec::spawn` rejects senders that `set_error` at **compile time**;
   `exec::start_detached` / `async_scope::spawn` have **no** compile-time interception, and call
   `std::terminate()` on error; in `when_all`, failure of any branch cancels the remaining branches and fails as a whole.
8. **Cancellation is cooperative**: `request_stop()` only guarantees "the stop signal is received",
   not that the operation stops immediately; business code must check the stop token itself to exit early.

---

## 12. Advanced Facilities

### 12.1 Timed Scheduling: timed_thread_context + schedule_after

```cpp
#include <exec/timed_thread_scheduler.hpp>   // exec::timed_thread_context
#include <exec/timed_scheduler.hpp>          // exec::now / schedule_at / schedule_after (CPOs)

exec::timed_thread_context timer;             // Default construction starts one timer thread; destruction automatically does request_stop + join
auto tsch = timer.get_scheduler();

// Run after a 200ms delay:
sync_wait(exec::schedule_after(tsch, 200ms) | then([] { std::cout << "ding\n"; }));

// At a specified time point:
sync_wait(exec::schedule_at(tsch, exec::now(tsch) + 200ms) | then([] { /* ... */ }));
```

- `timed_thread_context` must outlive all operations hung on it (typically: member variable / static object).
- `timed_thread_scheduler` members are only `now()` / `schedule()` / `schedule_at()`;
  `schedule_after` is a CPO that automatically falls back to `schedule_at(now + d)` when the scheduler has no corresponding member.
- Timed senders complete with `set_value_t()` / `set_stopped_t()` -- they can be cancelled.
- See [8.5](#85-timeouts-and-racing-when-any-trigger-cancels) for the complete timeout-with-cancellation example.
- When you already maintain your own `asio::io_context`, timers can also directly use
  `steady_timer + async_wait(use_sender)` (see 12.6.3) without introducing a timer thread.

### 12.2 trampoline_scheduler: Protect Against Recursive-schedule Stack Overflow

Patterns like `repeat_until` / polling chains where "the completion callback schedules itself again"
recurse infinitely on single-threaded/inline schedulers. `trampoline_scheduler` puts recursive schedules beyond the depth/stack limits onto a
thread_local list, drained by the outermost frame in a loop:

```cpp
#include <exec/trampoline_scheduler.hpp>

exec::trampoline_scheduler tramp;             // Optional parameters: (max recursion depth, max recursion stack size)
sender auto s = schedule(tramp) | then([] { /* ... */ });
```

### 12.3 Coroutine Cleanup: at_coroutine_exit

This is an extension paired with `exec::task`: execute an **async** cleanup no matter how the coroutine exits (value/exception/stop):

```cpp
#include <exec/at_coroutine_exit.hpp>
#include <exec/on_coro_disposition.hpp>

auto use_connection() -> exec::task<void>
{
  auto conn = co_await open_connection();

  co_await exec::at_coroutine_exit(
    [&conn]() -> exec::task<void> { co_await conn.async_close(); });

  // Can also run only on a specific outcome (one of succeeded / failed / stopped):
  // co_await exec::on_coroutine_succeeded(
  //   [&conn]() -> exec::task<void> { co_await conn.commit(); });

  co_await conn.async_use();
}
```

- `at_coroutine_exit` takes a callable (with optional extra arguments) and `co_await`s its return value when the coroutine exits.
- Not supported on Apple Clang (the header directly `#error`s).
- It is not a general capability of the P3552 `stdexec::task`. This project uses `stdexec::task`; do not assume this
  `exec::task` example works by just changing the return type; prefer organizing async cleanup as an `exec::finally(initial, cleanup)`
  sender chain, or explicitly awaiting cleanup in the business protocol. Ordinary synchronous resources still use regular RAII.

### 12.4 System-wide Parallel Scheduler: get_parallel_scheduler

Corresponds to the "system context / parallel scheduler" in standard proposals: a process-shared parallel scheduler, so users of the library need not pass their own thread pool:

```cpp
auto psch = stdexec::get_parallel_scheduler();   // Throws std::runtime_error when no backend exists
sender auto work = schedule(psch) | bulk(stdexec::par, n, f);
```

- Off by default: turn on `STDEXEC_BUILD_PARALLEL_SCHEDULER=ON` in CMake and link
  `STDEXEC::parallel_scheduler`; or define `STDEXEC_PARALLEL_SCHEDULER_HEADER_ONLY`
  to use the header-inline default implementation.
- On Windows the default backend is `windows_thread_pool` (see 12.5); you can also use
  `parallel_scheduler_replacement::query_parallel_scheduler_backend()` (weak symbol,
  only effective on GCC/Clang) to replace it with your own backend at link time.
- Old names `exec/system_context.hpp`, `exec::get_parallel_scheduler`, `get_system_scheduler`
  are all deprecated; do not use them.

### 12.5 Windows Thread-pool Backend: windows_thread_pool

On Windows, `STDEXEC_ENABLE_WINDOWS_THREAD_POOL` is automatically enabled (enabled as soon as `windows.h` is detected):

```cpp
#include <exec/windows/windows_thread_pool.hpp>

exec::__win32::windows_thread_pool pool;            // Default: process-shared thread pool
// Or explicit range: exec::__win32::windows_thread_pool pool{minThreads, maxThreads};
auto sch = pool.get_scheduler();                    // Members include schedule() / now() / schedule_at() / schedule_after()
```

Note it lives in the `__win32` sub-namespace (an implementation-detail namespace), and the interface may change with versions;
for portable code still use `exec::static_thread_pool`.

### 12.6 Asio Adaptation: exec::asio

stdexec ships an Asio adaptation layer (the `exec::asio` namespace) with two pieces: the `use_sender` completion token
(Asio async operations -> senders) and `asio_thread_pool` (Asio-based thread-pool scheduler).
For code like this project that is already built around an `asio::io_context` event loop, the former is mainly used to wrap
io_context as a scheduler, without starting another thread pool.

#### 12.6.1 use_sender: Turn Asio Async Operations into Senders

```cpp
#include <exec/asio/use_sender.hpp>

asio::steady_timer timer{ioc, 200ms};
sender auto s = timer.async_wait(exec::asio::use_sender);
// socket.async_read_some(buf, exec::asio::use_sender) -> sender of (bytes_transferred)
```

Any Asio async operation taking a completion token can be wrapped. Completion mapping (the `error_code` parameter is stripped):

| Asio completion                            | Sender completion                                           |
| ------------------------------------------ | ----------------------------------------------------------- |
| `ec == 0`                                  | `set_value(args...)`                                        |
| `operation_aborted` / `operation_canceled` | `set_stopped()`                                             |
| Other non-zero `ec`                        | `set_error(std::exception_ptr)` (wrapped as `system_error`) |

Completion signatures = value shapes (with `error_code` stripped) + `set_error_t(std::exception_ptr)` +
`set_stopped_t()`. When the outer stop token requests stop, the adaptor issues
`emit(cancellation_type::all)` on the Asio operation (via Asio's `cancellation_slot` mechanism).

#### 12.6.2 Wrap an Existing io_context as a Scheduler

The underlying sender for "run once on the event loop" is `post(ioc, use_sender)`, but it cannot be used as-is as the
home scheduler of a `stdexec::task`: the Asio adaptor conservatively declares error/stopped channels, while the default
`task_scheduler` requires `schedule()` to be **infallible**. This project normalizes the two branches of `post` that never actually fail and are not cancellable
into `set_value()`:

```cpp
class io_context_scheduler
{
 public:
  using scheduler_concept = stdexec::scheduler_tag;

  explicit io_context_scheduler(asio::io_context& ioc) : ioc_(&ioc) {}

  stdexec::sender auto schedule() const noexcept
  {
    // post itself never fails and is not cancellable; use_sender still conservatively declares error/stopped,
    // so map both theoretically unreachable channels to success.
    return exec::asio::asio_impl::post(*ioc_, exec::asio::use_sender)
         | stdexec::upon_error([](std::exception_ptr) noexcept {})
         | stdexec::upon_stopped([]() noexcept {});
  }

  bool operator==(const io_context_scheduler&) const noexcept = default;

 private:
  asio::io_context* ioc_;
};
```

- `asio_impl` is a **generated** namespace alias: for standalone it is `::asio`, for boost it is
  `::boost::asio` (`asio_config.hpp`, see 12.6.6).
- Afterwards, `starts_on(sched, ...)` / `on(sched, ...)` / `continues_on(sched)` can all move
  chains onto the io thread; `starts_on(sched, stdexec_task())` sets it as the task's home, and the task
  automatically returns to the io thread after awaiting other senders internally.
- Passing only `stdexec::scheduler<io_context_scheduler>` does not verify the task constraints; you must actually instantiate
  `starts_on(sched, task())` or do a compile check with the corresponding `sender_in` environment.
- The schedule opstate after the above adaptation may exceed task_scheduler's default 72-byte inline buffer; this project
  uniformly defines `STDEXEC_TASK_SCHEDULE_OPSTATE_SIZE=256`. If your compiler/Asio combination still triggers the
  opstate-size `static_assert`, raise it according to the actual `sizeof` instead of changing to a dangling heap object.
- Lifetime: the sender from schedule() captures a reference to the io_context, so the **scheduler must not outlive the
  io_context** (guaranteed in this project by the process-wide `AsioRuntime`
  singleton and its controlled shutdown).
- Driver side: `io_context::run()` returns as soon as the queue becomes empty -- a resident event loop needs
  `asio::make_work_guard(ioc)` to keep it alive, and `guard.reset()` before exiting so `run()` can finish.

#### 12.6.3 Timers: steady_timer + use_sender (Cancellable Sleep)

```cpp
// timer must outlive the operation: keep it alive with a shared_ptr until completion
sender auto sleep_on(asio::io_context& ioc, std::chrono::milliseconds d)
{
  auto timer = std::make_shared<asio::steady_timer>(ioc, d);
  return timer->async_wait(exec::asio::use_sender)
       | then([timer] {});
}
```

- The effect is equivalent to `schedule_after` in 12.1, but runs on **your own event loop** without opening another
  timer thread. Requesting stop -> timer is cancelled -> `operation_aborted` -> `set_stopped`.
- Anti-pattern: a local-variable timer that does `async_wait` directly and the function returns -- timer destruction cancels the operation.

#### 12.6.4 asio_thread_pool: Asio-based Thread Pool

```cpp
#include <exec/asio/asio_thread_pool.hpp>

exec::asio::asio_thread_pool pool{4};        // Default construction = hardware_concurrency
auto sch = pool.get_scheduler();             // Inherits thread_pool_base: supports bulk
sync_wait(schedule(sch) | then([] { return 42; }));
```

- Same interface as `exec::static_thread_pool` (both inherit `thread_pool_base`), with `asio::thread_pool` underneath; `get_executor()` fetches the underlying Asio executor for interop with the Asio ecosystem.
- Destruction automatically does stop + join.

#### 12.6.5 executor_with_default / as_default_on: Default Completion Tokens

Bind a default completion token to io objects to avoid passing `use_sender` every time (`use_sender` is a token instance,
whose corresponding type is `use_sender_t`):

```cpp
auto timer2 = exec::asio::use_sender.as_default_on(asio::steady_timer{ioc, 100ms});
sender auto s = timer2.async_wait();        // No need to pass the token explicitly anymore
```

(Equivalent lower-level forms: `exec::asio::as_default_on<exec::asio::use_sender_t>(io_obj)`,
and hand-written `executor_with_default<Executor, Token>`.)

#### 12.6.6 CMake Integration (Important: Must Go Through CMake)

`exec::asio` headers depend on the **generated** `asio_config.hpp` (selecting the standalone/boost namespace),
and cannot be used with a bare `-I` like other headers:

```cmake
set(STDEXEC_ENABLE_ASIO ON CACHE BOOL "" FORCE)
set(STDEXEC_ASIO_IMPLEMENTATION "standalone" CACHE STRING "" FORCE)  # Or "boost" (default)
# In standalone mode stdexec automatically fetches asio-1.31.0
target_link_libraries(your_target PRIVATE STDEXEC::asioexec)  # Compatibility alias: STDEXEC::asio_pool

# Set only when a custom scheduler is used as home by stdexec::task and the default 72 bytes are really not enough.
# Must propagate to all downstream translation units that instantiate stdexec::task / schedulers.
target_compile_definitions(your_target PUBLIC STDEXEC_TASK_SCHEDULE_OPSTATE_SIZE=256)
```

`STDEXEC_TASK_SCHEDULE_OPSTATE_SIZE` changes the object layout of header templates; inconsistent values across translation units of the same program create ODR/ABI risk. Put it on the `PUBLIC` compile
definitions of a common CMake target; do not privately define it for a single `.cpp`. This project's `dcb_runtime` propagates it exactly this way.

---

## 13. Interoperating with Callback-style APIs

The most common need in bridging scenarios (FFI, C callbacks, platform APIs) is: wrap a "register a callback, it calls you back later" API
as a sender, plugging into the whole world of Sections 4-10. Two paths: `exec::create` (easy) and hand-written
senders (full control).

### 13.1 exec::create: The Easiest Wrapper

```cpp
// Hypothetical C API: register a callback, later called back with (user, result)
// void dcb_fetch(int id, void (*cb)(void* user, int result), void* user);

#include <exec/create.hpp>

sender auto fetch_async(int id)
{
  return exec::create<set_value_t(int)>(          // Completion signatures fixed at compile time
    [id]<class Ctx>(Ctx& ctx) noexcept {          // Called at start(); must be nothrow
      dcb_fetch(id, [](void* p, int result) noexcept {
        auto& c = *static_cast<Ctx*>(p);
        set_value(std::move(c.receiver), result); // Complete the receiver: exactly once
      }, &ctx);
    });
}
```

Key points:

- The template arguments are the completion-signature list; if the C API can fail, also list the error channel (e.g.
  `set_error_t(std::exception_ptr)`) and call `set_error` in the callback.
- The address of `ctx` can safely be handed to the C API as `void*`: the opstate is immovable, so the address is stable;
  but `ctx` becomes invalid immediately after the completion function is called (same rules as Section 11); do not touch it after completing in the callback.
- The receiver must be completed **exactly once** (one of value/error/stopped); completing more or fewer times violates the contract.
- `fn` executes **synchronously** at `start()` -- it should only do "register the callback", not run time-consuming logic
  (to migrate threads, wrap with `starts_on` / `continues_on`).
- When `fn` returns `void`, no extra state is saved; when it returns an object, `exec::create` stores that object in the
  opstate until completion. Use it to hold registration handles, cancellation callbacks, and other RAII state (see 13.3).

A wrapped sender is used exactly like an ordinary sender:
`sync_wait(fetch_async(1))`, `co_await fetch_async(1)`,
`scope.spawn(fetch_async(1) | upon_error(...))`.

### 13.2 Hand-written Minimal Sender (When Full Control Is Needed)

This version is the minimal boilerplate for a hand-written sender (compare `third_party/stdexec/test/test_common/schedulers.hpp`):

```cpp
struct tick_sender
{
  using sender_concept        = stdexec::sender_tag;
  using completion_signatures =
    stdexec::completion_signatures<stdexec::set_value_t(int)>;

  template <class Rcvr>
  struct opstate
  {
    using operation_state_concept = stdexec::operation_state_tag;
    Rcvr rcvr_;

    void start() & noexcept
    {
      // ...actually initiate the async operation; on completion:
      stdexec::set_value(std::move(rcvr_), 42);
    }
  };

  template <class Rcvr>
  auto connect(Rcvr rcvr) const -> opstate<Rcvr>
  {
    return {static_cast<Rcvr&&>(rcvr)};
  }
};
```

- `sender_concept` + `completion_signatures` (member alias; or
  `static consteval get_completion_signatures()`) + `connect` are enough to satisfy the
  `stdexec::sender` concept.
- An opstate needs `operation_state_concept` and `void start() & noexcept`;
  in real code it should be made immovable (`STDEXEC_IMMOVABLE` is used in the library).
- Optional: add `get_env()` to the sender answering `get_completion_scheduler<set_value_t>`,
  so `on()` / `continues_on` etc. know on which context it completes.
- When to hand-write instead of using `exec::create`: need to expose scheduler attributes, need complex
  completion-signature transforms, or need to do things at connect time (rather than start time).

### 13.3 Making the Wrapper Cancellable

Read the stop token from the receiver environment in the `exec::create` start function, and forward stop requests to the C API.
One key detail is: **the return value of the start function is stored by `exec::create` in the opstate until the operation ends**.
Therefore the cancellation handle and stop callback should be held by this returned state, not made locals of the start function:

```cpp
sender auto fetch_cancellable(int id)
{
  return exec::create<set_value_t(int), set_stopped_t()>(
    [id]<class Ctx>(Ctx& ctx) noexcept {
      auto tok = get_stop_token(get_env(ctx.receiver));

      // Here we assume the C API contract is:
      // 1) callback is never invoked inline before dcb_fetch returns;
      // 2) exactly one callback eventually, normal or cancelled;
      // 3) with cancelled=true the cancellation has quiesced and user is no longer accessed.
      auto handle = dcb_fetch(
        id,
        [](void* user, int value, bool cancelled) noexcept {
          auto& c = *static_cast<Ctx*>(user);
          if (cancelled)
            set_stopped(std::move(c.receiver));
          else
            set_value(std::move(c.receiver), value);
          // After completion c/opstate may already have been destroyed downstream; c must never be accessed again.
        },
        &ctx);

      struct cancel_fn
      {
        fetch_handle handle;
        void operator()() const noexcept { dcb_cancel(handle); }
      };
      using token_t = decltype(tok);
      using callback_t = stdexec::stop_callback_for_t<token_t, cancel_fn>;

      struct state
      {
        fetch_handle handle;
        callback_t callback;
      };

      // The return value is held by exec::create's opstate; when tok is already stopped,
      // callback construction may synchronously invoke cancel_fn immediately.
      return state{handle, callback_t{tok, cancel_fn{handle}}};
    });
}
```

The above example is a **contract sketch**, not a universal template valid for arbitrary C APIs. Confirm item by item before landing:

- When `stop_possible()` is false, registration can be skipped; but generic code usually uses
  `stop_callback_for_t<Token, F>` directly, letting the token type decide the concrete callback type. Before constructing the callback,
  still consider the case where `stop_requested()` is already true -- registration may synchronously execute the callback immediately.
- The safest model is: the stop callback **only requests the underlying cancellation**, and the single underlying completion callback sends
  `set_stopped` after it truly quiesces. Do not `set_stopped` immediately upon receiving stop while still allowing the C
  callback to arrive late referencing `ctx`; downstream may already have destroyed the opstate, and a late callback causes UAF.
- Only when the underlying cancel API explicitly guarantees "on return the callback is cancelled and no callback is executing",
  may the stop callback itself win the completion race. It still needs atomic-state arbitration between stop and normal completion to ensure the receiver
  is moved exactly once; no path may touch `ctx` after completion.
- If the registration function may **call back synchronously**, the `exec::create` shorthand above is unsafe: completion may trigger opstate destruction before the start function has returned and the returned
  state has been placed into the opstate. Hand-write a sender/shared state instead: fully build the state first, then call the registration function, with separate arbitration for synchronous completion.
- If the C API neither guarantees post-cancel callback quiescence nor a final callback, you cannot safely hand it the bare `ctx` pointer.
  Use an independent `shared_ptr` state plus generational/atomic completion flags, so late callbacks only touch shared state; also specify
  when the underlying handle is released. In that case a hand-written sender is usually clearer than stacking more `exec::create`.

---

## 14. Common Compile-Error Quick Reference

stdexec template diagnostics are organized as `_WHAT_(...) / _WHY_(...) / _WHERE_(_IN_ALGORITHM_, ...) /
_WITH_ENVIRONMENT_(...)`; once you understand the structure you can locate problems. Common entries:

| Error text (excerpt)                                                                                                                       | Source                 | Cause and fix                                                                                                                                                                                      |
| ------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `_CANNOT_RESTORE_EXECUTION_CONTEXT_AFTER_ON_` + `_THE_CURRENT_EXECUTION_ENVIRONMENT_DOESNT_HAVE_A_SCHEDULER_` (`on_t`)                     | `__on.hpp`             | `on()` cannot find the "going home" scheduler after completion. Connect to `sync_wait` (whose environment provides it) downstream, or provide `get_start_scheduler` in the receiver env            |
| `_CANNOT_RESCHEDULE_` (same WHY)                                                                                                           | `exec/reschedule.hpp`  | `exec::reschedule` needs the env's `get_start_scheduler`; same fix as above                                                                                                                        |
| `The argument to stdexec::sync_wait() is a sender that cannot complete successfully... exactly one signature of the form set_value_t(...)` | `__sync_wait.hpp`      | The awaited sender has no value channel (only stopped/error)                                                                                                                                       |
| `...can complete successfully in more than one way. Use stdexec::sync_wait_with_variant() instead.`                                        | `__sync_wait.hpp`      | Multiple value shapes; switch to `stdexec::sync_wait_with_variant()` (returns a variant)                                                                                                           |
| `spawn expects a sender that cannot fail`                                                                                                  | `__spawn.hpp`          | The `stdexec::spawn` sender carries a `set_error` signature; add `upon_error` handling first and mark the tail lambda `noexcept`                                                                   |
| `_INVALID_ARGUMENT_TO_THE_FINALLY_ALGORITHM_` / `_THE_FINAL_SENDER_MUST_BE_A_SENDER_OF_VOID_`                                              | `__finally.hpp`        | `finally`'s cleanup is not a void-sender; cleanup may only send `set_value_t()`                                                                                                                    |
| Cannot construct `task_scheduler` from a custom scheduler / constructor constraints not satisfied                                          | `__task_scheduler.hpp` | `schedule(sch)` still declares an error channel and does not satisfy the task home scheduler's infallible constraint; explicitly normalize impossible error/stopped channels, or change schedulers |
| `operation state ... too large to fit in the preallocated storage of task_scheduler`                                                       | `__task_scheduler.hpp` | The home scheduler's opstate exceeds the default 72 bytes; raise `STDEXEC_TASK_SCHEDULE_OPSTATE_SIZE` consistently in all relevant translation units (see 12.6.6)                                  |
| `sender_in<S, Env>` / completion-signatures query failure                                                                                  | sender constraints     | The sender's required scheduler, stop token, or allocator is not in the actual Env; check with the receiver's real env, not just `sender<S>`                                                       |

---

## 15. Appendix: Cheat Sheet

### Launching

```cpp
sync_wait(sndr);                              // Block and wait (plain functions); multi-shape uses sync_wait_with_variant
exec::start_detached(sndr);                   // Fire-and-forget (no scope; terminate on error)
stdexec::spawn(sndr, scope.get_token());      // Launch into a scope (compile-time rejection of failing senders)
scope.spawn(sndr);                            // Launch into async_scope (terminate on error, handle first)
scope.spawn_future(sndr);                     // Launch into a scope + return a result sender (connectable only once)
connect(sndr, rcvr) -> start(op);             // Manual (op must live until after the completion callback)
run_loop loop; loop.get_scheduler();          // Self-driven event loop: run() exits only after finish() is called in/out
co_await sndr;                                // Launch and wait inside a coroutine (single value gives bare value, multiple values give tuple)
stdexec::task<T> task();                      // The only task type in this project; the coroutine itself is a sender
starts_on(home, task());                      // Specify the task's home scheduler
```

### Executors

```cpp
exec::static_thread_pool pool{N};
auto sch = pool.get_scheduler();
auto sch0 = pool.get_scheduler_on_thread(0);   // Pin to thread 0
exec::single_thread_context single;            // Single-threaded context (internal run_loop + one thread)
stdexec::run_loop loop;                        // Manually driven
stdexec::inline_scheduler{};                   // Inline (immediate) execution
exec::timed_thread_context timer;              // Timer thread; auto tsch = timer.get_scheduler();
exec::trampoline_scheduler tramp;              // Protect against recursive-schedule stack growth
stdexec::get_parallel_scheduler();             // System-wide parallel scheduler (12.4, requires build option)
exec::asio::asio_thread_pool apool{N};         // Asio-based thread pool (requires STDEXEC_ENABLE_ASIO)
// Wrap an existing asio::io_context as a scheduler: schedule() returns
//   post(ioc, use_sender) | upon_error(noexcept) | upon_stopped(noexcept)
// When the task-home opstate is large, uniformly define STDEXEC_TASK_SCHEDULE_OPSTATE_SIZE (see 12.6.2/12.6.6)
// Asio timers: steady_timer + async_wait(exec::asio::use_sender) (see 12.6.3)
```

### Migration

```cpp
stdexec::on(sched, sndr);                    // Start on sched, return to the launch-site scheduler after completion
sndr | on(sched, closure);                   // Form 2: switch to sched to apply the closure, then switch back
stdexec::starts_on(sched, sndr);             // Start on sched (no pipe form)
sndr | continues_on(sched);                  // Migrate to sched after completion
sndr | exec::reschedule();                   // Return to the env's get_start_scheduler
co_await starts_on(worker, work);             // stdexec::task temporarily goes to worker, then automatically returns home
```

### Cancellation

```cpp
stdexec::inplace_stop_source src;  src.get_token();  src.request_stop();
sndr | write_env(prop{get_stop_token, tok});   // Inject a stop token (the name is write_env!)
get_stop_token(env);                           // Read the environment (in coroutines co_await get_stop_token())
read_env(get_stop_token);                      // Read the environment in sender form (read is the old name)
exec::unless_stop_requested(sndr);
stopped_as_optional(sndr);  stopped_as_error(sndr, err);  upon_stopped(sndr, f);
exec::when_any(a, b);                          // Cooperative racing; requests cancellation of losers and waits for their cleanup, not a hard timeout
scope.request_stop();        counting_scope::request_stop();
```

### Timers

```cpp
exec::timed_thread_context timer;  auto tsch = timer.get_scheduler();
exec::schedule_after(tsch, 200ms);             // Delayed execution (completion signatures set_value_t()/set_stopped_t())
exec::schedule_at(tsch, exec::now(tsch) + 200ms);
```

### Structured Concurrency

```cpp
exec::async_scope scope;
scope.spawn(s); scope.spawn_future(s); scope.nest(s);
sync_wait(scope.on_empty());  scope.when_empty(sndr);
scope.request_stop();
// Must drain before destruction (debug assert / release UB)

stdexec::counting_scope cs;
auto t = cs.get_token();  auto wrapped = t.wrap(s);  cs.close();  sync_wait(cs.join());
cs.request_stop();
// Once operations have been associated, close()+join() must complete before destruction, otherwise std::terminate()
```

---

## References

- This repository: `third_party/stdexec` @ `f0e8ae6f` (~= v0.11.0, nvhpc-26.05 baseline), see examples in
  `third_party/stdexec/examples/` (hello_world.cpp / hello_coro.cpp / scope.cpp, etc.).
- **P2300** `std::execution` (senders/receivers): merged into the C++26 working draft in 2024.
  Core facilities such as `schedule` / `then` / `when_all` / `on` / `starts_on` / `continues_on` / `sync_wait`
  all come from it.
- **P3149** `async_scope`: source of `spawn` / `spawn_future` / `counting_scope` /
  `simple_counting_scope` (advanced into C++26 in 2025).
- **P3325** A Utility for Creating Execution Environments: source of the `prop` / `env` /
  `write_env` environment utilities.
- **P3552R3** [Add a Coroutine Task Type](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2025/p3552r3.html):
  source of scheduler-affine `task` / `affine`; this clone's `stdexec::task` is implemented in that direction.
- [Current C++ working-draft execution/task chapters](https://eel.is/c++draft/exec.task): for checking standard
  namespaces and semantics; this clone's interfaces should still be judged by the vendored sources.
- `third_party/stdexec/README.md`: compiler support matrix and integration methods (CPM / add_subdirectory /
  Conan / manual `-I`).
