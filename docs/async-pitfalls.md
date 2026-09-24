# Sender Migration Pitfalls

This document records hard-won rules for the `core::`/`transport::`
callback-to-sender migration. Each rule below cost a real debugging
session; new sender-based code must follow them.

## Unspecified argument evaluation order plus move

C++ does not specify the order in which function-call arguments are
evaluated. This crashes:

```cpp
boost::asio::dispatch(self->executor_,
                      [self = std::move(self), ...] { ... });
```

clang evaluates the lambda first: the capture moves `self` out
(zeroing it) and the `self->executor_` read then observes the
moved-from state. It crashed deterministically in Release as a null
read inside the executor copy. Fix: hoist what the call needs into a
local before the move:

```cpp
auto executor = self->executor_;
boost::asio::dispatch(std::move(executor),
                      [self = std::move(self), ...] { ... });
```

Rule: never name an object in one call argument while moving from it
in a sibling argument. Moving a *member* while reading a *sibling*
member of the same object is safe; moving the object itself is not.
Member-init lists are fine (they follow declaration order, which is
specified). A whole-tree audit found only the QUIC pump in this shape;
re-audit when adding dispatch/post sites with move captures.

## Join the pump before reporting teardown

A session whose completions dispatch back to its strand must not
report failure (and let the caller stop the runtime) while pump
operations are still in flight. `QuicClientConnection::Impl::fail()`
cancels and closes the datagram but defers `events_.failed` through
`check_teardown()` until both the receive and send flags drain. Every
flag transition funnels through the check, and the check must run
*before* the retired early-returns in each continuation, otherwise the
join never fires in exactly the case it exists for. Same idea as the
`TcpRelay` atomic join.

## Close without releasing while ops are parked

`fail()`/`retire()` cancel and close handles but must not `reset()`
them while sender ops are still parked: the parked receivers keep the
owner alive and complete against the handle, which dies with the owner
once they drain. Releasing early is a use-after-free on the late
completion. (`CoreToIo`/`IoToCore` adapters follow the same rule.)

## stdexec shape notes

- `exec::task` has no `.connect()`; only `co_await` it.
- `exec::any_sender` receivers must declare
  `inplace_stop_token(get_stop_token_t)` handling.
- The erased sender invokes the wrapped receiver as an lvalue, so
  custom receivers need unqualified (non-ref-qualified) overloads, or
  explicit handling for lvalue invocation.
- `async_scope::spawn`ed senders must always terminate with value;
  an error-terminated child terminates the process. Long-running pump
  loops therefore never complete with error.
- Restoring from `let_error` must not throw; return an explicit
  `just_error` sender instead.
- `async_scope` is never `request_stop()`ed; teardown flows through
  guards, generations, and deadlines, with late completions dropped.
- Prefer re-armed receivers over tasks for single-outstanding-pull
  loops; never run two pulls on one consumer.

## What stays callback-shaped on purpose

Not every callback is debt. Linear connect/handshake chains become
tasks; the following keep their shape deliberately:

- Third-party engine drivers: Botan TLS opens (restls/jls/shadow-tls-v3),
  ngtcp2 (QUIC), nghttp2/3 (HTTP/2/3 sessions), Beast upgrade/forward
  orchestration with keep-alive session reuse. Task-ifying them means
  fighting the engine's own event model.
- Pump and timer loops: kcptun/smux/snappy sessions, KCP, UoT, cipher
  stream states, gRPC/WebSocket frame pumps, UDP single-pull loops.
  Re-armed receivers are the correct shape; see the teardown join rule
  above.
- Registry-pattern APIs: DNS resolvers, bootstrap, query service
  (cancel-by-ID). Converting them means redesigning the interface,
  not transliterating a chain.
- Single-call bridged leaves: obfs request/response helpers, TLS
  handshake narrow waist, pool queue/lifecycle managers.
- `exec::asio::use_sender` only supports value-carrying signatures
  (`(error, values...)`); void-signature initiations (Beast handshake,
  steady timers) and in-band-error contracts (http1 `HttpOpResult`)
  stay on `callback_sender`.
- Test-only APIs (e.g. the gRPC client): convert if and when a
  production caller appears.

## Never create exec::task from an immediately-invoked capturing lambda

A coroutine frame built from an immediately-invoked capturing lambda
(`[captures]() -> exec::task<T> { ... }()`) is corrupt on Windows
clang-cl with this stdexec version (proven by minimal repro: captures
read back null/garbage, bodies never run; AV/hang/stopped follow).
Named functions, capture-free lambdas, and stored (named) lambdas
invoked later are unaffected. Rules:

- Tasks come from named functions (static members, free functions)
  with explicit parameters, e.g. `scope.spawn(run(...))`, or from a
  stored lambda variable invoked later. Never an immediately-invoked
  `[captures]() -> exec::task` inline, however convenient.
  `tests/transport/task_coroutine_test.cpp` pins the allowed shapes.
- Drive a value-only chain to a callback with a plain shared state
  machine (`start_with_receiver` + small receivers) when no named
  function shape fits, not by adapting an inline task into a bridge.
- `exec::task` cannot be type-erased into `AnySender` either (sticky
  scheduler affinity fails `sender_to<any_receiver>`); expose chains as
  `bridge_sender` + `then`, like `async_tls_client_handshake`.
- A `Guard`-style RAII reservation must be filled in place
  (`make_shared<Guard>()` + assign); a `Guard{...}` temporary runs its
  armed destructor and releases early.
