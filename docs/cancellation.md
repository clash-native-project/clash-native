# Precise Cancellation

Every connection-like unit must be abortable in isolation, without
disturbing its siblings: one TCP stream, one UDP association, one
streaming exchange, one multiplexed logical stream, one DNS query, one
proxy connection. Dropping the unit's sender (or firing its stop token)
cancels exactly that unit; siblings keep flowing.

## Status by plane

| Unit | Mechanism | Status |
| --- | --- | --- |
| TCP stream (`io::StreamHandle`) | `close()`; relay pumps join per direction | Isolated by construction; covered by relay tests |
| UDP association (`io::DatagramHandle`) | `close()` aborts parked send/receive | Isolated by construction; Trojan/UoT close paths tested |
| Streaming exchange (h2/h3) | abandon sender + body cancels | Verified: `http2_streaming_test` aborts one exchange (RST) while a sibling completes |
| Mux logical stream (ws-mux, smux, QUIC, h2 tunnel) | stream close / reset | Audited: per-stream close erases state + signals the peer (ws-mux close frame, smux FIN, ngtcp2 shutdown) without touching the session; no loopback peer exists for these client-only carriers, so coverage stays at review + interop |
| DNS query | `cancel(RequestId)` today | Redesign to sender-per-query (Phase 2) |
| Proxy connection | none | Needs `ProxyServer::close_connection(id)` (Phase 1) |
| Outbound open | bridge abort | Per-operation abort tested (Trojan config tests) |

## Phases

- Phase 0 (this document + baselines): pin the current behavior with
  isolation tests so the redesign cannot regress it.
- Phase 1: `ProxyServer::close_connection(id)` aborting exactly one
  session/route (relay close + handle close + registry removal),
  leaving siblings untouched.
- Phase 2: sender-per-query DNS. `DnsTransport::exchange` becomes an
  `AnySender<DnsPacket>`; the demux map moves inside the transports;
  `cancel(id)`/`stop()` shrink to session teardown. All seven
  transports, the resolver layers, and the DNS tests migrate together.
- Phase 3: close the gaps Phase 0 finds (streaming-exchange and mux
  carriers), with per-carrier isolation tests.

## Rules

- Cancellation is per-unit and RAII-driven: dropping the sender is the
  cancel. Explicit `cancel(id)` survives only where a multiplexing
  point genuinely needs it, and then it aborts exactly one unit.
- No scope is ever `request_stop()`ed for teardown (see
  `docs/async-pitfalls.md`); isolation flows through guards,
  generations, and per-unit close.
- Every new carrier ships a two-unit isolation test: open two, kill
  one, prove the other survives.
