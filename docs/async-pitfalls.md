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
