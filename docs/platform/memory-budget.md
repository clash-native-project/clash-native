# Memory Budget Notes (Constrained Devices)

Cross-cutting note, not a platform target. There is no Apple backend in this
repository (`docs/architecture.md` §16 reserves an `apple/` slot; it is empty),
and the only validated profiles are Windows (primary) and Debian/WSL
(diagnosis only). Everything below is a conclusion plus an optimization plan,
not a claim of coverage. Read the matching platform document before doing
platform work.

## 1. Why this matters

Apple kills memory-hungry network extensions without warning (jetsam on iOS,
OOM killer on small routers — same shape, different killer). Known limits,
per XTLS/Xray-core #4422 (2025, confirmed by maintainers against current iOS):

| Provider       | Limit (MiB) |
|----------------|-------------|
| packet tunnel  | 50          |
| app proxy      | 15          |
| filter control | 50          |
| filter data    | 50          |
| DNS proxy      | 15          |
| app push       | 24          |

Correction to a common misquote: the 15 MB figure is the **app-proxy /
DNS-proxy** budget; a packet tunnel gets **50 MB**. That is still tight:
SagerNet/sing-box #3976 documents a 100 Mbps+ upload speedtest spiking past
the 50 MB cap and getting killed. Xray's own idle footprint sits around
15 MB, leaving ~35 MB for all live connections — at an estimated 200–400 KB
per TLS connection, that is on the order of a hundred concurrent connections
before the killer fires. Low-end routers (128–256 MB total) hit the same wall
via the OOM killer, faster with QUIC/KCP retransmit queues in play.

## 2. Where memory actually goes

Sender machinery is **not** the problem: `io::AnySender` keeps a 128-byte
sender buffer and a 256-byte op buffer inline (`io/any_sender.hpp`), so the
relay path allocates nothing on the heap and only holds transient stack/frame
memory (~hundreds of bytes per op, freed on completion). It affects CPU, not
RSS. Do not spend budget here.

The residents that matter, in order:

1. **Per-connection state** (dominant). Socket buffers (kernel-side, tunable
   where `set_buffer_size`-style options exist), TLS session objects, relay
   buffers (2 × 8 KB per `TcpRelay`, `src/proxy/tcp_relay.cpp`), Beast header
   buffers (64 KB cap, `src/proxy/proxy_session_http.cpp`), WebSocket message
   reassembly (up to `max_message_size`, default 16 MB), KCP/QUIC send queues
   and retransmit windows (`src/transport/kcp_client.cpp`,
   `src/transport/quic_client.cpp`). One 64 KB stack array already exists per
   legacy-datagram state (`kMaxUdpWireSize` in
   `src/outbound/shadowsocks_legacy_datagram.cpp`).
2. **Rule / config data** (startup killer). Xray's lesson from the same issue
   thread: `geosite:cn` (~100k rules, ~21 MB on disk) expands to 27–36 MB
   after unmarshal, and loading a category twice doubled it again (broken
   cache sharing). This repository has no geo data yet — keep it that way.
3. **Caches** (slow growth). The DNS cache is count-bounded (4096 entries,
   `include/clash_native/dns/dns_query_service.hpp`) but **not byte-bounded**;
   QUIC caps idle sessions (4) and exchanges per session (64), which is the
   right shape and should be copied elsewhere.

There is currently **no memory accounting anywhere**: no RSS gauge, no
`mallinfo`/`GetProcessMemorySize` hook, no per-connection attribution.

## 3. Current caps inventory (exact references)

| Resource              | Cap today                                              | File                                              |
|-----------------------|--------------------------------------------------------|---------------------------------------------------|
| Relay buffer          | 8 KB per direction                                     | `src/proxy/tcp_relay.cpp` (`kRelayBufferSize`)    |
| HTTP header parse     | 64 KB                                                  | `src/proxy/proxy_session_http.cpp`                |
| Exchange body         | 1 MB default (`response_body_limit`)                   | `include/clash_native/io/exchange_session.hpp`    |
| Rejection body        | 64 KB                                                  | same                                              |
| WebSocket message     | 16 MB default                                          | `include/clash_native/transport/websocket_client.hpp` |
| gRPC message          | 4 MB default                                           | `include/clash_native/transport/grpc_client.hpp`  |
| DNS cache             | 4096 entries (count only)                              | `include/clash_native/dns/dns_query_service.hpp`  |
| QUIC sessions         | 4 idle, 64 exchanges/session                          | `src/dns/quic_dns_transport.cpp`                  |
| Legacy datagram state | 64 KB fixed array                                      | `src/outbound/shadowsocks_legacy_datagram.cpp`    |

## 4. Optimization plan (in order)

1. **Measure first.** Add a resident-memory gauge to observability (RSS +
    per-connection attribution broken down by handle type). Add budget tests:
    N connections × traffic profile must stay under a configured cap. Without
    this, every later step is unverifiable.
2. **Make caps configurable and byte-budgeted.** Relay buffer size,
   header/body limits, WebSocket/gRPC max-message sizes, and DNS cache size
   (bytes, not just entry count) should come from one `MemoryBudget` config
   surfaced to integrators, with low-memory presets (e.g. capped for a 50 MB
   tunnel or a 128 MB router).
3. **Shrink connection state.** Cap KCP/QUIC windows and retransmit queues,
   reuse TLS sessions, reap idle connections (the relay idle watchdog is the
   pattern to extend), stop Beast `flat_buffer` growth from coasting at peak,
   and replace fixed 64 KB datagram arrays with sized buffers on constrained
   builds.
4. **Keep rule data lazy.** Never load a monolithic rule set fully into
   memory (the Xray failure mode). Index on disk, load only needed
   categories, compile to a compact trie, and share the compiled form across
   groups instead of per-group copies.
5. **Fail fast with explicit errors.** Budget exhaustion must surface as an
   explicit error (the existing `already_started` guard shape), never as
   silent growth into jetsam/OOM.

## 5. Explicit non-goals

- Further sender/SBO micro-optimization: CPU-only, RSS-neutral.
- The Apple port itself: TUN access, background execution, and jetsam
  behavior must be built and validated per `docs/architecture.md` §16 before
  any of the above is testable on iOS.
