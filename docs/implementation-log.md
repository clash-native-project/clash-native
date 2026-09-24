# Implementation Log

### 2026-09-22 — Add sender-based io handle abstractions (migration targets)

- Added `include/clash_native/io/` with sender-based counterparts of the four
  handle/session abstractions, using the same class names under the `io`
  namespace so old and new can coexist during migration: `sender.hpp`
  (`AnySender<T>` type-erased sender), `address.hpp` (`Destination`,
  `DatagramAddress`), `stream_handle.hpp`, `datagram_handle.hpp` (plus a
  `DatagramPacket` result), `multiplexed_session.hpp`, and
  `exchange_session.hpp` (request/response vocabulary plus body and tunnel
  streams/sessions).
- Conventions: async ops return senders completing exactly once;
  `set_value(optional<size_t>)` with disengaged meaning clean EOF on reads
  (maps to relay shutdown), `set_error` carrying `core::Error`,
  `set_stopped()` on cancellation (never `operation_aborted` as an error);
  handler-era `cancel(id)` is retained alongside stop-token cancellation;
  deadlines stay as parameters; at most one outstanding read/write per
  handle. Old `core::`/`transport::` abstractions are untouched.
- Added `tests/io/io_handles_test.cpp` (5 cases) with in-memory fakes
  proving the contracts: stream read/write/EOF, error surfacing, datagram
  echo, exchange round-trips (buffered/streaming/tunnel), and multiplexed
  open yielding a usable stream.
- Validated with the Windows x64 Release clang-cl/MSVC build: 77 async/io
  cases pass; `pixi run format-check` and `git diff --check` pass.

### 2026-09-22 — Add broadcast and watch channels (tokio parity: four kinds)

- Added `include/clash_native/async/broadcast.hpp`: MPMC broadcast with
  per-receiver sequence cursors, a bounded evicting buffer, and lag
  reporting. `send()` never blocks; slow receivers get `broadcast_lagged`
  (with the skipped count) as `set_error` while the stream stays alive, so a
  lag-tolerant loop can catch it around `co_await` and continue from the
  oldest buffered value. Includes `Sender::subscribe()` for late joiners
  (new subscribers observe only later values), receiver counting (send fails
  with no receivers), and the usual stop/destroy cancellation.
- Added `include/clash_native/async/watch.hpp`: single-slot latest-value
  channel with a version counter. `Receiver::next()` waits for a version
  newer than the seen one and yields a copy; `borrow()` snapshots
  synchronously, `mark_changed()` re-observes the current value, and close
  drains the last update before ending. Sender is move-only, receivers are
  copyable (tokio parity). Both new receivers natively satisfy
  `async_stream`, so all operators compose over them.
- Fixed a critical bug found by the watch tests: four waiter wake-up loops
  (new in broadcast/watch) missed the `node = next` list advance and spun
  forever growing the woken list (one test consumed ~20GB before bad_alloc).
  All list traversals across the async headers were re-audited; mpsc was
  already correct.
- Added `tests/core/broadcast_test.cpp` (11 cases) and
  `tests/core/watch_test.cpp` (10 cases) covering fan-out, late subscribe,
  lag counting and lag-tolerant loops, coalescing, independent receivers,
  close draining, cancellation, threaded producers, and operator composition.
- Validated with the Windows x64 Release clang-cl/MSVC build: 72 async cases
  pass in ~0.5s total; `pixi run format-check` and `git diff --check` pass.

### 2026-09-22 — Replace the blocking async channels with sender-native streams

- Rewrote `include/clash_native/async/oneshot.hpp` as a P2300 sender: the
  receiver connects directly to a caller receiver, completes with
  `set_value(optional<T>)` / `set_error` / `set_stopped`, and supports
  cancellation both by stop token and by destroying the parked operation.
  The state machine keeps the previous fine-grained locking (the mutex is
  never held across a completion) plus a detached flag so late sends fail.
- Rewrote `include/clash_native/async/mpsc_channel.hpp` on the same model:
  unbounded, bounded (backpressure), and rendezvous (`bounded(0)`) channels
  with synchronous `try_send` fast paths, direct hand-off to a parked
  receiver, intrusive parked-sender wait lists, stop-token cancellation that
  withdraws parked values, and single-consumer violation reporting. The
  previous `rigtorp/MPMCQueue` reference dependency was replaced with a
  mutex-guarded deque so no new third-party dependency was needed.
- Added `include/clash_native/async/async_stream.hpp`: an `async_stream`
  concept (`next()` returns a sender of `optional<T>`), factories
  (`empty`/`once`/`from_vector`/`interval_on`), statically composed pipeable
  operators (`async_map`, `async_filter`, `async_take`, `async_take_while`,
  `async_skip`, `async_skip_while`, `async_scan`, `async_flat_map`,
  `async_zip`, sequential `merge`, concurrent `async_merge`), sender
  consumers (`async_for_each`, `async_fold`, `collect`, `count`, `first`),
  and an `AnyAsyncStream` type-erased escape hatch. Repeat pulls use a
  trampoline so synchronous sources iterate instead of recursing; stop
  tokens propagate through every stage.
- Added `stdexec` (0.10.0) to `vcpkg.json` and linked `STDEXEC::stdexec` to
  `clash-native-core`.
- Rewrote `tests/core/channel_test.cpp` for the new API and added
  `tests/core/async_stream_test.cpp` plus `tests/core/async_test_helpers.hpp`
  (51 cases total, including cancellation, error propagation, move-only
  payloads, a 100k-item non-recursion case, early-drop driver cancellation,
  task-consumer composition with `when_all`/`then`/`starts_on`, a complex
  multi-stage pipeline, push-style `subscribe`, and a tokio-style
  `StreamMap`: readiness-based fan-in over named heterogeneous streams with
  first-wins pulls, per-source end accounting, and a heap
  self-deleting child protocol with a mutex abandon handshake so destroying a
  parked pull is safe. Supporting fixes: `AnyAsyncStream` pulls are erased to
  `exec::any_sender` (with the stop-token query declared so cancellation
  passes through the erasure instead of degrading to `never_stop_token`),
  and operator inner receivers use unqualified completions plus an eager
  stop-token snapshot env because erased machinery invokes receivers as
  lvalues and cannot copy immovable envs).
- Concurrent `async_merge` uses structured concurrency instead of threads:
  each source is pulled by an `exec::task` driver spawned into an
  `exec::async_scope` in the shared state, so parked drivers suspend without
  consuming any thread (verified: the merge tests create no library threads).
  Dropping the merged stream calls `scope.request_stop()`, which wakes parked
  drivers; each driver converts a stopped pull into end-of-stream via
  `let_stopped` and still delivers exactly one sentinel, so destruction
  completes synchronously. A source that ignores stop tokens and never ends
  still pins its driver until it does.
- Deleted the unreferenced reference copies at `include/channel.hpp`,
  `include/stream.hpp`, `include/stream_base.hpp`, and `include/runtime.hpp`
  (they pointed at a non-existent `dart_cpp_bridge` include prefix and were
  included by nothing).
- Validated with the Windows x64 Release clang-cl/MSVC build: the 38 new
  cases pass (threaded cases repeated 15 times), `pixi run format-check`
  and `git diff --check` pass. The full binary still reports 4 failing
  `ResolverService` UDP cases; they fail identically on the pristine tree
  (verified via `git stash` plus rebuild), so they are pre-existing
  environment failures unrelated to this change. Go interop was not rerun;
  no Go sources were modified.

### 2026-09-21 — Keep logging configuration at the process boundary

- Removed the project-specific logging configuration API and kept library code
  on direct `spdlog` calls.
- CLI and interoperability hosts configure their own default logger directly;
  embedded callers can install any spdlog sink, formatter, level, or async
  adapter before invoking the library.

### 2026-09-21 — Route command-line and test-host output through spdlog

- Replaced direct C++ standard-stream writes with direct `spdlog::info` and
  `spdlog::error` calls in the application and interoperability hosts.
- Kept the process-wide default logger configuration at the executable boundary
  so library embedding remains free to provide its own spdlog adapter.

### 2026-09-21 — Complete ResTLS TLS 1.3 outbound validation

- Added the native Botan TLS 1.3 ResTLS handshaker. Its ClientHello callback
  parses the emitted key-share and PSK identity extensions, derives the
  BLAKE3 authentication prefix, and preserves the required 32-byte
  compatibility Session ID.
- Added the TLS 1.3 Mihomo interoperability case using the fixed Go test
  executable workflow. The test covers the TLS handshake and the plain ResTLS
  application-record exchange through a TCP echo.
- Updated the Windows testing documentation to include both ResTLS TLS 1.2
  and TLS 1.3 validation.

### 2026-09-21 — Record Shadowsocks Windows and UDP known limitations

- Added the classic Shadowsocks TCP half-close/Windows relay EOF behavior to
  `docs/known-issues.md`, with the passing cipher-wire scope and current
  isolation boundary documented separately.
- Recorded the intentional `message_size` rejection for encrypted Shadowsocks
  UDP wire payloads above 1,500 bytes as an accepted transport guardrail.

### 2026-09-21 — Add the Shadowsocks JLS TLS 1.3 carrier

- Added the JLS username/password authentication primitives, ClientHello and
  ServerHello authentication-data handling, and the asynchronous Botan TLS 1.3
  stream adapter.
- Added a reproducible Botan vcpkg overlay patch for the ClientHello random
  callback and wired the JLS plugin into the Shadowsocks outbound.
- Added deterministic JLS vector/parser tests and a real Mihomo TLS 1.3
  interoperability case. The Mihomo JLS relay closes the complete tunnel when
  its generic TLS connection receives a peer FIN, so the interop case keeps
  the client write side open while validating the reverse echo. TLS 1.3
  ResTLS remains outside the validated scope.

### 2026-09-21 — Add the ResTLS framing and authentication primitives

- Added a native ResTLS transport module for the password-derived BLAKE3
  traffic key, TLS 1.2 and TLS 1.3 ClientHello authentication Session ID
  derivation, record-script parsing, and post-handshake application record
  encoding and decoding.
- Added deterministic CTest coverage for script validation, authenticated
  record round trips, tamper rejection, and both TLS version Session ID forms.
  The Shadowsocks `restls` plugin remains rejected at configuration time until
  the native TLS client can emit the matching custom ClientHello materials.

### 2026-09-20 — Record the kcptun half-close interoperability boundary

- Added a known-issues entry documenting that the tested Mihomo SMUX listener
  closes the complete stream after receiving an SMUX FIN. The record separates
  this peer behavior from the C++ FIN submission and from KCP packet, FEC,
  Snappy, and SMUX framing interoperability.

### 2026-09-20 — Complete kcptun session reuse and transport controls

- Added a bounded Shadowsocks kcptun session pool with configurable connection
  count, round-robin stream allocation, auto-expiry, scavenging, and SMUX
  stream multiplexing. Each opened stream remains exposed through the common
  `StreamHandle` interface.
- Applied Mihomo mode defaults, ACK-no-delay flushing, rate limiting, UDP
  socket buffer sizing, and DSCP configuration to the shared KCP carrier.
- Added a pooled-session interop case with four concurrent TCP streams and
  reran the independent Go packet pipeline plus Mihomo AES and AES-GCM
  profiles on Windows x64.

### 2026-09-20 — Match kcptun AES-GCM key width

- Corrected the `aes-128-gcm` kcptun packet codec to use the first 16 bytes of
  the PBKDF2-HMAC-SHA1 key, matching Mihomo's kcp-go profile. Updated the
  independent Go interoperability fixture to use the same AES-128 key width.
  The default AES profile and the AES-GCM profile now pass the real Mihomo
  listener check.

### 2026-09-20 — Complete the kcptun packet and compression pipeline

- Added kcp-go-compatible packet crypt methods, including AES CFB variants,
  legacy block methods, Salsa20, AES-GCM, the simple XOR construction, CRC32,
  and PBKDF2-HMAC-SHA1 key derivation.
- Added Botan ZFEC encoding and recovery with kcp-go's FEC headers and shard
  sequencing, plus a vcpkg Snappy dependency and the framed Snappy stream used
  below SMUX by Mihomo.
- Changed the kcptun default profile to Mihomo-compatible AES, 10/3 FEC, and
  compression-enabled settings. Added packet round-trip, FEC recovery, and
  Windows x64 Mihomo full-profile relay coverage. The external Mihomo listener
  still closes the complete stream after a peer FIN, so half-close behavior is
  recorded as an interop limitation rather than claimed as independently
  validated. FEC receive groups are now bounded like kcp-go, sequence numbers
  wrap at the protocol protection boundary, and encrypted data/parity loss is
  covered by a focused codec test. Added an independent Go kcp-go + SMUX +
  Shadowsocks relay fixture for AES-GCM/FEC packet-pipeline interoperability.

### 2026-09-20 — Complete SMUX v2 flow control for kcptun streams

- Added SMUX v2 peer-window accounting, update-frame handling, consumed-byte
  acknowledgements, and ordered FIN scheduling to the kcptun stream adapter.
- Added optional real-Mihomo coverage for SMUX version 2 and a payload larger
  than the initial peer window.

### 2026-09-20 — Add the initial Shadowsocks kcptun raw-KCP carrier

- Added a Shadowsocks `kcptun` client carrier that composes the shared KCP
  stream with a SMUX stream over UDP, then uses the existing Shadowsocks TCP
  framing and UDP-over-TCP adapters above it.
- Added Windows x64 Mihomo interoperability coverage for TCP relay and
  UDP-over-TCP relay, plus configuration validation for unsupported profiles.
- This initial subset was subsequently extended by the packet crypt, FEC, and
  Snappy implementation recorded below. The focused Mihomo relay case does not
  exercise TCP half-close because that listener closes the full kcptun stream
  when its peer sends FIN.

### 2026-09-20 — Add fixed-address bootstrap DNS fallback

- Added an asynchronous bootstrap resolver chain for hostname-based DNS
  upstreams. User-configured literal DNS servers are tried first, followed by
  `223.5.5.5`, `223.6.6.6`, `1.1.1.1`, `1.0.0.1`, `8.8.8.8`, and `8.8.4.4`.
- Bootstrap queries use Asio UDP with c-ares-backed DNS message parsing and
  fall back to the Windows system resolver only after the literal candidates
  are exhausted.
- Added configuration and tests for the ordered built-in list and the system
  resolver fallback.

### 2026-09-20 — Preserve domain addresses in datagram handles

- Replaced the endpoint-only `DatagramHandle` address contract with the
  variant-backed `core::DatagramAddress`, which preserves either an IP address
  or a domain name and its port.
- Migrated UDP stream, DNS, QUIC, KCP, proxy relay, Shadowsocks, and test
  call sites to the new address type. Native UDP sockets convert only IP
  addresses to OS endpoints, while protocol transports can return domain
  metadata without resolving it away.
- Added contract coverage for IP/domain datagram addresses and a UoT frame
  test that verifies a domain source address survives asynchronous parsing.

### 2026-09-20 — Add Shadowsocks WebSocket plugin carriers

- Added a reusable Shadowsocks byte carrier that can wrap a raw TCP socket or
  an existing `StreamHandle`.
- Added `v2ray-plugin` and `gost-plugin` WebSocket mode for classic AEAD,
  legacy stream ciphers, and Shadowsocks 2022 TCP. The carrier supports the
  optional TLS layer and deliberately leaves plugin mux disabled.
- Added independent Go/Gorilla WebSocket interoperability coverage for both
  plugin names and a TLS WebSocket case.
- Routed generic-carrier read completion and endpoint operations through the
  carrier executor so WebSocket-backed legacy and SS2022 streams do not depend
  on a raw TCP socket.

### 2026-09-19 — Complete QUIC handle completion paths

- Routed ngtcp2 stream-consumption notifications to both legacy QUIC events and
  `StreamHandle` observers, so asynchronous writes complete on the common
  handle interface.
- Completed pending stream and DATAGRAM operations when a QUIC connection is
  reset or retired, including receive cancellation and observer cleanup.

### 2026-09-19 — Connect QUIC carriers to the common capability interfaces

- Added the native QUIC `MultiplexedSession` implementation. Each opened
  bidirectional QUIC stream is returned as a `StreamHandle`, with shared
  connection capacity, cancellation, stream close/reset propagation, and
  asynchronous write completion.
- Added the QUIC DATAGRAM adapter as a `DatagramHandle`, including negotiated
  payload-size validation, asynchronous send/receive, peer association, and
  connection-retirement completion for pending operations.
- HTTP/2 and HTTP/3 exchange sessions now expose their multiplexed carrier
  capability and active-stream capacity; CONNECT and Extended CONNECT continue
  to produce `StreamHandle` values through `ExchangeSession`. HTTP/3 also
  exposes its QUIC DATAGRAM carrier handle.
- Added a Windows x64 clang-cl/MSVC interoperation test using a Go quic-go
  server. It opens four concurrent QUIC streams on one connection and echoes a
  QUIC DATAGRAM through the common handles.

### 2026-09-19 — Generalize HTTP exchange and carrier session interfaces

- Renamed the public HTTP-facing message and session vocabulary to
  `ExchangeField`, `ExchangeRequest`, `ExchangeResponse`, `ExchangeBodyStream`,
  `StreamUpgrade*`, and `ExchangeSession`. HTTP/1.1, HTTP/2, and HTTP/3
  implementations, DoH adapters, gRPC, the HTTP proxy outbound, and host tests
  now use the generic exchange interface.
- Added the public `MultiplexedSession` capability contract for logical stream
  allocation, cancellation, capacity, and retirement. HTTP exchange semantics
  remain separate from raw logical stream allocation. The old HTTP header and
  factory names remain as compatibility aliases only.

### 2026-09-19 — Add an HTTP/1.1 WebSocket client carrier

- Added an asynchronous WebSocket client over an injected `StreamHandle`. The
  carrier always uses HTTP/1.1 Upgrade, maps each write to one binary message,
  exposes incoming binary message payloads as a byte stream, and delegates
  masking, fragmentation, ping/pong, close handling, and handshake framing to
  Boost.Beast. A TLS-wrapped stream can be supplied for WSS composition;
  HTTP/2 and HTTP/3 Extended CONNECT are intentionally outside this API.
- Added a Beast-specific Asio stream adapter that keeps asynchronous buffer
  storage alive for framing operations. Added option/error coverage and a Go
  Gorilla interoperability test with an independent HTTP/1.1 server,
  ping control frame, custom handshake header, and a validated 256 KiB binary
  echo. Binary message validation and deferred Beast stream destruction cover
  the byte-stream adapter's protocol and cancellation boundaries. The Go
  fixture keeps the connection open until the client consumes the echo so the
  Windows TCP close path cannot race unread response data.
- Enforced the configured WebSocket message size limit for both incoming and
  outgoing binary messages.
- Validated the Windows x64 Release clang-cl/MSVC build, CTest 133/133, the
  full Go interoperability suite, `go vet ./...`, and repeated the WebSocket
  interoperability case ten times.

### 2026-09-19 — Add a reusable raw KCP stream carrier

- Added a client-side KCP carrier over an injected `DatagramHandle`, with
  Asio-driven update timers, ordered stream reads and writes, queued UDP packet
  output, option validation, and support for payloads larger than the KCP
  receive-window fragment limit.
- Added C++ setup coverage and a Go `kcp-go` interoperability test that starts
  an independent server and exchanges a validated 256 KiB payload in both
  directions. Raw KCP is covered; mKCP framing, KCP plugins, and proxy protocol
  composition remain separate work.

### 2026-09-19 — Centralize Base64 through BoringSSL

- Added a shared core Base64 wrapper backed by BoringSSL's standard padded
  encoder and strict decoder.
- Replaced the HTTP proxy Basic authentication and gRPC binary metadata
  implementations with the shared wrapper and added standard, binary, and
  malformed input coverage.

### 2026-09-19 — Replace the gRPC C++ runtime with a Protobuf/HTTP2 client

- Removed the upstream gRPC C++ runtime, its zlib-only direct dependency, and
  the local gRPC vcpkg overlay. Kept KCP as a separate vcpkg dependency.
- Added an asynchronous gRPC client wire layer over the existing HTTP/2
  session. It serializes `google::protobuf::MessageLite` values into the
  standard five-byte gRPC message envelope, supports metadata, deadlines,
  trailers, trailers-only status responses, incremental message reads,
  bidirectional half-close, cancellation, and identity message framing;
  compressed message encodings are rejected explicitly.
- Added a Protobuf/KCP smoke test and an independent grpc-go TLS interoperability
  fixture covering unary metadata and trailers, a trailers-only non-OK status,
  binary metadata, and bidirectional streaming. The client remains a wire
  implementation rather than a generated service API; message compression and
  service-specific generated bindings are not included.

### 2026-09-18 — Add gRPC and KCP dependencies

- Added the upstream gRPC C++ library and KCP C library through the pinned vcpkg manifest baseline (Apache-2.0 and MIT). The gRPC overlay reuses the existing BoringSSL package for its OpenSSL-compatible API and prefers config-package discovery for correct Debug and Release library selection, avoiding a conflicting second TLS provider. Added zlib as a direct static-link dependency for gRPC's compression objects.
- Linked both libraries to the core target and added API smoke tests for channel construction and KCP control-block lifecycle. This adds dependencies only; no gRPC or KCP proxy transport is implemented yet.

### 2026-09-18 — Record local proxy listener security scope

- Documented that local HTTP and SOCKS5 listeners currently use plaintext connections without inbound authentication, and distinguished destination TLS through HTTP `CONNECT` from TLS to the proxy itself.

### 2026-09-18 — Record HTTP/3 proxy integration limits

- Documented that the shared HTTP/3 client transport and DoH/3 support are not equivalent to HTTP/3 proxy ingress or an HTTP/3 upstream proxy outbound.

### 2026-09-18 — Scope the protocol reference

- Limited `protocol-reference.md` to proxy and tunnel protocols, carriers, security layers, protocol options, inbound listeners, and pinned Mihomo sources; removed routing-group, share-link, controller, and native-project status material.
- Corrected SSR wrapper order and clarified gRPC TLS options, WebSocket bootstrap, and SMUX stream semantics.

### 2026-09-18 — Add streaming HTTP tunnels

- Added a shared asynchronous full-duplex tunnel API while keeping buffered HTTP exchanges for DoH. HTTP/1.1 supports CONNECT and Upgrade; HTTP/2 and HTTP/3 support CONNECT and Extended CONNECT.
- Added bounded receive buffering, backpressure, half-close, cancellation, and error propagation across tunnel streams. Kept HTTP/2 provider data alive through socket write completion and deferred stream destruction until outstanding asynchronous I/O callbacks finish.
- Added independent Go interoperability coverage for HTTP/1.1 CONNECT and WebSocket Upgrade, HTTP/2 CONNECT and Extended CONNECT, and HTTP/3 CONNECT and Extended CONNECT.
- Validated Windows x64 Release with clang-cl/MSVC and vcpkg: CTest 123/123, the uncached full Go interoperability suite, `go vet ./...`, formatting checks, and the six-case tunnel matrix repeated five times.

### 2026-09-18 — Add streaming HTTP exchanges and forwarding

- Added asynchronous request and response body streams with trailers for HTTP/1.1, HTTP/2, and HTTP/3 sessions, including bounded response buffering, cancellation, and backpressure. Corrected HTTP/3 QUIC receive-credit accounting for DATA payloads in both streaming and buffered responses.
- Added an HTTP/1.1 forward-proxy path for absolute-form requests and an HTTP upstream proxy outbound with TLS CONNECT and Basic authentication. The forwarder strips hop-by-hop and proxy-authentication headers, handles `Expect: 100-continue`, and streams bodies and trailers.
- Added independent Go interoperability coverage for 2 MiB concurrent request/response streams and trailers across HTTP/1.1, HTTP/2, and HTTP/3, raw HTTP/3 request-trailer framing, normal HTTP forwarding, and plain/TLS HTTP proxy outbounds.
- Validated Windows x64 Release using clang-cl with the MSVC backend and vcpkg: CTest 123/123 and the full Go interoperability suite passed.

### 2026-09-18 — Extract shared HTTP/1.1 and HTTP/2 client sessions

- Added a common HTTP request/response exchange API over injected streams. HTTP/1.1 now owns Beast framing, body limits, cancellation, deadlines, and ordered keep-alive exchanges; HTTP/2 owns nghttp2 framing, concurrent streams, bounded response bodies, cancellation/reset, and GOAWAY retirement.
- Migrated DoH/1 and DoH/2 so DNS keeps `application/dns-message` construction and validation while transport owns HTTP serialization, parsing, and multiplexing. Added a loopback test proving queued HTTP/1.1 exchanges reuse one keep-alive connection.
- Fixed a DoH/3 setup race by creating nghttp3 state as soon as the QUIC handshake completes, before processing any HTTP/3 streams from the same datagram.
- Validated Windows x64 Release with standalone clang-cl/MSVC and vcpkg: CTest 119/119; full Go interop against independent DNSProxy and Mihomo processes; `go vet ./...`; DoH/3 DNSProxy interop repeated 10 times; and independent DoQ/DoH3 concurrent-stream tests.
- The HTTP API now supports full-duplex CONNECT/upgrade tunnels and streaming request/response bodies; a reusable cross-protocol session pool remains unimplemented extraction work.

### 2026-09-18 — Extract shared injected-stream TLS client

- Added an asynchronous TLS client connector over injected `StreamHandle` instances, centralizing trust roots, peer and server-name verification, ALPN, cancellation, handshake deadlines, and error classification.
- Moved the Asio stream adapter and embedded CA bundle ownership out of DNS, then migrated DoT, DoH/1.1, DoH/2, and Trojan to the shared TLS client. DoQ and DoH/3 retain their QUIC-specific TLS engine.
- Extended the independent Go DNSProxy interoperability test to cover DoT and DoH/2, including successful queries with verification disabled and rejection of the test server's untrusted certificate when enabled.
- Validated Windows x64 with clang-cl/MSVC and vcpkg: CTest 118/118, full Go interop, independent DNSProxy secure transports, public encrypted DNS upstreams, and real Mihomo server interoperability passed. Formatting checks passed.

### 2026-09-18 — Shared transport and carrier extraction plan

- Documented the staged extraction of TLS, HTTP/1.1, HTTP/2, QUIC, and HTTP/3 from DNS-specific implementations into reusable carrier capabilities.
- Defined separate extension boundaries for WebSocket/WSS and KCP/mKCP, including session ownership, pooling, consumer composition, and validation gates.
- Kept `DnsTransport` as a DNS application adapter and the existing `Outbound` stream/datagram contract as the engine-facing protocol boundary.
- Clarified that `EndpointDialer` executes an immutable, preselected endpoint egress plan and never performs traffic routing or outbound lookup.
- Marked WebSocket/WSS and KCP/mKCP as design constraints rather than current extraction deliverables, and separated DNS migration from the non-DNS proof required to close HTTP/QUIC generalization.
- Made shared TLS/HTTP/QUIC extraction and DNS migration a Stage 2 requirement, leaving Stage 4 to validate and extend the shared layer with non-DNS consumers.
- Added DoH/1 explicitly to the Stage 2 encrypted-DNS deliverables and functional gate.

### 2026-09-18 — Shadowsocks encrypted UDP size limit

- Reject Shadowsocks UDP datagrams whose encrypted wire payload exceeds 1500 bytes with `message_size`, and log size-limit errors from the SOCKS UDP relay.
- Added C++ boundary and rejection checks for all supported AEAD methods and a Go peer round trip at the exact 1500-byte encrypted datagram boundary.
- Reduced the real Mihomo UDP interoperability payload to 1200 bytes so Shadowsocks framing stays within the outbound limit.
- Validated Windows x64 with clang-cl/MSVC: 118/118 CTest cases, the full Go interoperability suite, and the real Mihomo server interoperability test passed.

### 2026-09-18 — Real Mihomo server interoperability

- Added an opt-in process integration test that starts Mihomo with temporary Shadowsocks and Trojan inbound listeners and verifies traffic through the C++ outbound.
- Covered all three supported Shadowsocks AEAD methods over TCP and UDP, plus Trojan TLS certificate acceptance and rejection.
- Kept the Mihomo UDP payload at 13 KiB to fit its current 16 KiB Windows packet read buffer; the independent Go peer continues to cover 60 KiB UDP payloads.

### 2026-09-17 — Encrypted outbound foundations

- Added asynchronous Shadowsocks AEAD TCP/UDP outbound foundations for AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305, plus a reusable TLS stream adapter and Trojan TCP/TLS outbound handshake.
- Added c-ares-backed hostname resolution for outbound server endpoints; Go interoperability peers and SOCKS5 UDP ASSOCIATE are recorded below.

### 2026-09-17 — SOCKS5 UDP association and independent Go peers

- Added SOCKS5 UDP ASSOCIATE handling with control-channel lifetime, client endpoint pinning, destination parsing, route selection, c-ares resolution, and UDP response framing through outbound datagram handles.
- Added test-host outbound injection and independent Go Shadowsocks AEAD TCP/UDP and Trojan TCP/TLS peers for end-to-end protocol tests.

### 2026-09-18 — Outbound interoperability diagnostics

- Log outbound stream-open failures with their classified cause and include test-host output when an independent Go interoperability test fails, so SOCKS5's generic failure reply does not hide protocol-stage errors.
- Preserve Boost.Asio's TLS handshake message in the Trojan error context instead of exposing only the lossy standard-library error code.
- Issue the Trojan Go fixture's localhost server certificate from a separate test CA, allowing trusted-chain and untrusted-chain behavior to be tested accurately.

### 2026-09-18 — SOCKS5 UDP buffer lifetime

- Fixed an argument-evaluation-order bug that could move the shared UDP payload before constructing its Asio buffer, causing an access violation before Shadowsocks datagrams were sent.
- Fixed the same call-argument ordering hazard for domain-form SOCKS5 UDP targets by copying the resolver before moving the runtime snapshot into its callback.
- Used Windows Debugging Tools stack traces to confirm both crash sites before fixing the lifetime hazards.
- Changed the independent Go Shadowsocks fixture to allocate UDP first and retry when Windows TCP/UDP excluded-port ranges prevent sharing its port.
- Corrected Shadowsocks' maximum datagram payload calculation for the longest domain-form target and enlarged the UDP interop payload to 60 KB.

### 2026-09-18 — c-ares hostname interoperability coverage

- Added a local independent Go DNS authority and used it to resolve test-only proxy and destination hostnames through the C++ c-ares-backed resolver in Shadowsocks and Trojan integration tests.
- Updated the independent Go protocol peers to map reserved `.test` target names to loopback so they can relay the domain-form address they receive without relying on the machine's DNS configuration.

### 2026-09-18 — TCP half-close interoperability

- Updated the independent Go relay fixtures to drain both stream directions before closing and added client half-close checks to Shadowsocks TCP and Trojan TCP/TLS tests.

### 2026-09-18 — Windows x64 encrypted outbound validation

- Built with standalone LLVM clang-cl using the MSVC toolchain and vcpkg `x64-windows-clang-cl`; all 117 CTest cases passed.
- The complete Go interoperability suite passed against the Release C++ test host. Focused outbound tests passed ten repeated runs, covering Shadowsocks TCP/UDP for all three supported AEAD methods, 60 KB UDP payloads, c-ares hostname resolution, TCP half-close, and Trojan TLS trusted/untrusted certificate behavior.
- `go vet ./...`, clang-format checks, and `git diff --check` passed.

### 2026-09-17 — Use the selected HTTP and QUIC libraries

- Use Boost.Beast for HTTP/1.1, nghttp2 for HTTP/2, and nghttp3 for HTTP/3
  over ngtcp2 QUIC connections.
- Removed obsolete generated build tooling together with its project scripts
  and dependency documentation.
- Resolve BoringSSL through vcpkg and fetch ngtcp2 through CMake FetchContent.
- Preserve DNS deadlines, cancellation, TLS certificate validation, response
  bounds, content-type checks, and DNS question validation at the transport
  boundary.
- Build and test on Windows x64 with standalone LLVM `clang-cl`, MSVC/UCRT,
  vcpkg, and CMake FetchContent. CTest passed 107/107. This does not establish
  successful DoQ or DoH/3 interoperability with an external server.
- Passed `pixi run format-check` and `git diff --check`.

### 2026-09-17 — Embed CA roots for encrypted DNS transports

- Added the curl CA bundle snapshot and documented its source, license,
  SHA-256, update procedure, and Mozilla-policy limitation.
- Added generated C++ source so CMake embeds the PEM data in
  `clash-native-core`; encrypted DNS transports load these roots rather than
  relying on platform certificate paths.
- Added certificate-verification regression tests for DoT and HTTPS DNS.

### 2026-09-17 — Statically link the Windows MSVC runtime

- Set CMake targets and the Windows vcpkg triplet to use the static MSVC CRT.
- Disabled MSVC STL iterator debugging consistently with
  `_HAS_ITERATOR_DEBUGGING=0` in CMake and vcpkg.
- Linked the Windows synchronization import library required by static Debug
  CRT atomic wait/notify support.
- Built Windows x64 Debug and Release configurations. Inspected compile
  parameters (`/MTd` for Debug and `/MT` for Release) and confirmed the
  Release executable does not import MSVC/UCRT runtime DLLs; Windows system
  DLLs remain.

This file records completed implementation changes. It is intentionally
separate from `docs/architecture.md`, which describes the project blueprint.

## 2026-09-16

- Fixed the local TCP DNS test upstream callback capture so persistent-connection coverage compiles with clang-cl.
- Propagated the TCP test fixture lifetime capture through each nested asynchronous read callback.
- Closed the persistent DNS test client before runtime shutdown so the fixture's next-read operation drains cleanly.
- Added temporary English checkpoint output to locate the persistent DNS test hang; this diagnostic will be removed after investigation.
- Removed the temporary DNS test checkpoint output after confirming the runtime shutdown fix.
- Applied clang-format after the persistent DNS test cleanup fix; third-party sources remained excluded.
- Updated the unsupported DNS dial-policy test with the required outbound ID so it continues to assert the missing-dialer validation path.
- Added an IP datagram handle to DirectOutbound so named-outbound DNS egress can use Plain UDP, with a loopback regression test.
- Cleaned the new DirectOutbound datagram regression test includes before formatting and compilation.
- Applied clang-format after adding DirectOutbound datagram support; third-party sources remained excluded.
- Added active TCP socket tracking to DnsServer so shutdown closes accepted connections and drains pending reads, with a shutdown regression test.
- Applied clang-format after the DnsServer active-socket shutdown change; third-party sources remained excluded.
- Added a local UDP DNS server forwarding regression test covering the complete request and response wire path.
- Corrected the UDP test receive call to use the required mutable sender endpoint.
- Applied clang-format after adding local UDP DNS forwarding coverage; third-party sources remained excluded.
- Made the persistent DNS test upstream stop its accepted socket on the runtime owner before shutdown, preventing an outstanding read from keeping the test process alive.

- Started the reusable Plain DNS TCP session boundary by adding transport-owned session and
  transaction-ID state to the Asio transport; the exchange implementation is still being
  completed in this change set.
- Completed the Plain DNS TCP session implementation with lazy connection establishment, queued
  writes, continuous length-framed reads, transaction-ID dispatch for concurrent exchanges,
  per-exchange deadline and cancellation handling, reconnect-on-I/O-failure behavior, and support
  for both direct sockets and injected stream dialers.
- Changed Plain DNS TCP exchanges to use the persistent session owned by `AsioDnsTransport`, while
  keeping UDP truncation fallback and response/question validation in the logical exchange.
- Added transaction-ID allocation that avoids IDs used by active exchanges and releases each ID
  exactly once when its exchange completes.
- Applied clang-format after the Plain DNS TCP session changes; third-party sources remained
  excluded.
- Corrected the transaction-ID exhaustion path to use the existing configuration error category
  exposed by the core error model.
- Added a persistent loopback DNS test server fixture that keeps one TCP connection alive, delays
  the first two responses, and writes them in reverse order to exercise session reuse and
  transaction-ID dispatch independently of production test helpers.
- Added a transport regression test that sends two Plain TCP exchanges through one session and
  verifies that reversed wire response order is delivered to the matching callers.
- Applied clang-format after the persistent-session test additions; third-party sources remained
  excluded.
- Added connection and query-count context to the persistent-session test's readiness assertions
  so intermittent session-dispatch failures identify whether the server received both frames.
- Extended the persistent-session test's result assertion with server connection and frame counts
  to distinguish response dispatch failures from fixture-side reception failures.
- Applied clang-format after adding the persistent-session failure diagnostics; third-party sources
  remained excluded.
- Added the persistent-session fixture's completed-response count to failure diagnostics to
  distinguish a missing server write from a client-side response-dispatch problem.
- Added the two wire response IDs to the persistent-session fixture diagnostics for tracing
  transaction-ID routing when both server writes complete.
- Included the recorded wire IDs in the test assertion output so a response-ID allocation or
  dispatch mismatch can be identified without changing the production transport behavior.
- Moved the persistent-session test's exchange submissions onto the transport owner runtime to
  honor the documented single-owner rule and remove a test-only cross-thread data race.
- Applied clang-format after moving the test submissions to the owner runtime; third-party sources
  remained excluded.
- Applied clang-format after adding wire response-ID diagnostics; third-party sources remained
  excluded.
- Expanded the core datagram contract with addressed asynchronous send/receive operations,
  executor and maximum-payload queries, and explicit cancellation/close ownership.
- Added an optional unsupported-by-default datagram operation to `DnsUpstreamDialer`, preserving
  existing custom stream dialers while allowing DNS transports to request an addressed carrier.
- Routed the Plain UDP transport through the new dialer-provided datagram carrier and added a
  Direct DNS dialer that supplies both direct TCP streams and bound UDP handles, removing the
  UDP socket from each DNS exchange operation.
- Relaxed DNS dialer validation so an injected dialer may provide either the stream or datagram
  carrier required by the configured Plain transport; unsupported operations still return a
  typed result from the dialer boundary.
- Added owner-runtime DNS upstream health tracking with capped exponential failure backoff. An
  upstream member is skipped while unhealthy, one member is probed when all members are backed
  off, successful exchanges reset the member state, and cancellation is excluded from failure
  accounting.
- Added a deterministic resolver test proving that a failed group member is skipped by the next
  request while the healthy member continues serving the group.
- Applied clang-format after the DNS upstream health and backoff changes; third-party sources
  remained excluded.
- Extended the proxy configuration boundary with an injectable connection registry so session
  ownership can be observed without coupling the core to a frontend.
- Registered accepted proxy sessions in the connection registry, retained their IDs through
  routing, and removed records when sessions close.
- Passed the optional connection-registry identity through proxy routing so outbound selection can
  update the record without changing the stream or inbound contracts.
- Made the proxy create a default connection registry while retaining an explicit setter for
  applications that provide their own observability sink.
- Carried connection identities through the proxy's metadata-enrichment recursion so a session
  remains associated with one registry record throughout routing.
- Updated connection records when Direct, Reject, or a named outbound is selected, including the
  concrete member selected from an outbound group.
- Captured the connection identity explicitly across the asynchronous IPv6 enrichment callback so
  the registry update remains tied to the original session.
- Propagated the connection identity into both address-family resolver callbacks so asynchronous
  routing remains compilable and preserves observability ownership.
- Added a proxy loopback test that inspects the live registry record after SOCKS5 routing and
  verifies the record is removed after the client connection closes.
- Made the proxy registry lifecycle test wait for the asynchronous EOF/relay close path before
  asserting that the session record has been removed.
- Applied clang-format after the proxy connection-registry integration and test; third-party
  sources remained excluded.
- Extended `FakeIpStore` with a configurable entry lifetime while preserving its existing
  constructor and configuration call shapes through defaults.
- Implemented FakeIP expiry cleanup for resolve, reverse, release, and size operations so expired
  mappings release their occupied addresses and can be reused.
- Kept FakeIP expiry cleanup `noexcept` so the existing release path retains its non-throwing
  contract.
- Declared the cleanup implementation `noexcept` to match the public ownership contract.
- Added a FakeIP regression test proving that an expired mapping disappears from reverse lookup
  and its address can be allocated to a replacement domain.
- Corrected the stable FakeIP lookup path to return the entry's address after adding expiry
  metadata.
- Strengthened the FakeIP expiry test to fill the pool before expiry, proving that the expired
  addresses are actually reusable rather than merely allowing a different free address.
- Extended DNS resource records with optional decoded target names for name-bearing records while
  keeping their original RDATA bytes intact.
- Made typed DNS address projection follow up to eight in-message CNAME hops, reject loops, ignore
  unrelated address records, and bound the resulting TTL by each CNAME and address record.
- Added packet tests for compressed CNAME target decoding and CNAME-aware A projection with the
  original question and bounded TTL preserved.
- Applied clang-format after the CNAME metadata and address-projection changes; third-party
  sources remained excluded.
- Added the explicit `DnsUpstreamDialer` boundary and tagged direct, named-outbound, and
  traffic-rule dial policies to DNS upstream configuration. The existing raw-socket transports
  remain direct-only until a stream/datagram carrier adapter is added.
- Preserved DoH and DNS dial-policy fields when legacy primary/fallback configuration is expanded
  into group members.
- Added an immutable `RuntimeSnapshot` and atomic `RuntimeSnapshotStore` that validate and publish
  router, outbound, resolver, and FakeIP state as one configuration unit.
- Added a proxy `reload` entry point and changed route operations to retain the immutable runtime
  snapshot selected when the connection starts.
- Added monotonically increasing runtime-snapshot generations to the proxy publication state.
- Published a validated initial runtime snapshot during proxy startup and added runtime snapshot
  replacement with generation assignment through `ProxyServer::reload`.
- Changed new proxy streams to load router, resolver, and FakeIP state from the published snapshot;
  an absent publication now produces an explicit configuration failure.
- Made named outbound selection use the same retained runtime snapshot as rule evaluation, so
  reload cannot mix a new registry with an old routing program.
- Added the codec error context to the CNAME regression assertion so malformed fixture framing is
  diagnosed directly when the packet cannot be decoded.
- Corrected the CNAME test RDATA length for the encoded `target.test` name so the multi-record
  fixture follows DNS wire framing exactly.

- Added nghttp2 1.70.0 to the vcpkg manifest and CMake core boundary for a real HTTP/2 DNS transport; extended upstream configuration with DoH2 mode, path, and authority fields.
- Added an asynchronous DoH2 transport using TLS ALPN `h2`, nghttp2 request/response framing, DNS media-type/status validation, raw DNS packet decoding, absolute deadlines, cancellation, and exactly-once completion.
- Enabled nghttp2's Windows-compatible signed-size API mode and used `nghttp2_session_mem_recv2` so the clang-cl build does not depend on POSIX `ssize_t`.
- Corrected DNS cache classification so only NXDOMAIN and NODATA are negatively cached; SERVFAIL is not cached, and negative TTLs are bounded by authoritative SOA TTL and MINIMUM values.
- Extended the deterministic DNS transport fixture so cache tests can return explicit DNS response codes without using real sockets.
- Added regression coverage proving NXDOMAIN is cached while SERVFAIL is queried again.
- Made the deterministic transport fixture reusable across sequential exchanges so the SERVFAIL cache regression exercises the same persistent upstream instance.
- Added a local self-signed TLS DNS fixture for deterministic DoT transport testing, including TLS framing, DNS packet response generation, and teardown gating.
- Added a deterministic DoT success test covering TLS handshake, DNS-over-TCP length framing, response decoding, and transaction/question validation.
- Adjusted the local DoT fixture to the Boost.Asio SSL context overload available in the pinned Boost release.
- Applied clang-format to the local DoT test fixture and test case; third-party sources remained excluded.
- Added a local TLS/HTTP2 DNS fixture and success test validating DoH2 ALPN negotiation, HTTP/2 request body handling, DNS media-type response validation, and packet decoding.
- Applied clang-format to the local DoH2 fixture and test case; third-party sources remained excluded.
- Applied clang-format after adding DNS negative-cache regression coverage; third-party code remained excluded.
- Applied clang-format to the DoH2 transport and its factory declaration; the formatter input remained limited to project files.

- Added a shared DNS query-service callback gate so queued asynchronous entry points can stop without dereferencing the service after shutdown.
- Guarded queued DNS query, cancel, and cache-clear operations with the gate and closed it before owner-runtime shutdown dispatch.
- Reapplied clang-format after the DNS query-service lifecycle changes; third-party sources remained excluded.

- Applied the project formatter after adding the DoT transport implementation; no third-party sources were formatted.

- Extended the DNS model with complete packet metadata, resource-record storage, and raw wire-message ownership while retaining the legacy address-answer types.
- Added codec API declarations for full packet decoding, query packet encoding, safe transaction-ID rewriting, and typed A/AAAA projection.
- Added the full-message `DnsQueryService` with policy selection, cache/coalescing, waiter cancellation, scheduler-aware completion, and injectable transport ownership.
- Corrected the initial full-message operation wiring so each waiter retains its caller-visible DNS transaction ID.
- Changed the transport exchange contract to carry complete DNS packets, preparing the Asio implementation to preserve all parsed sections and validate every query question.
- Added `AddressResolver` as the typed A/AAAA projection over `DnsQueryService`, leaving full-message forwarding to the query service.
- Converted the legacy `ResolverService` into a compatibility facade over `DnsQueryService` and `AddressResolver`, keeping existing callers source-compatible while moving address resolution out of the query engine.
- Removed the old ResolverService implementation so it can be replaced by a forwarding facade without retaining duplicate DNS query state.
- Added the forwarding ResolverService facade over the new query and address-resolution services.
- Registered the new full-message DNS query, address-resolution, and packet test sources in the core CMake targets.
- Adapted the deterministic DNS transport fixture to return validated full packets while keeping legacy ResolverService tests on the compatibility facade.
- Added packet codec tests for raw-wire preservation, authority/additional record storage, transaction-ID rewriting, and typed address projection.
- Applied the project formatter to the full-message DNS model, query service, transport, resolver facade, and packet tests.
- Fixed the full-message transport receive-buffer initialization for clang-cl so it allocates the intended 65535-byte UDP/TCP validation buffer.
- Added a persistent `DnsUpstream` owner that creates one transport instance per configured upstream and forwards exchange cancellation and shutdown to it.
- Moved the transport factory alias to the upstream boundary and gave DnsQueryService persistent default and named upstream objects.
- Routed each query through a long-lived `DnsUpstream`, so repeated requests reuse the configured transport owner and service shutdown can stop all upstream instances after cancelling in-flight exchanges.
- Added the persistent upstream implementation to the clash-native-core target.
- Corrected the fake transport shutdown fixture to distinguish an inactive upstream from an active exchange when counting cancellation callbacks.
- Applied the project formatter to the persistent DNS upstream and query-service changes.
- Added `DnsUpstreamGroup` with persistent members, sequential fallback, optional round-robin
  starting selection, one group deadline, and exactly-once cancellation/shutdown handling.
- Extended `DnsResolverConfig` with explicit group configurations while retaining the legacy
  one-member map and constructor compatibility. Policy default names now select a configured
  named group when present, otherwise they retain the legacy default-upstream behavior.
- Added a deterministic group-member fallback test and registered the group implementation in
  the core DNS boundary.
- Applied the project formatter after introducing the explicit upstream-group boundary and its
  deterministic fallback test.
- Moved legacy upstream fallback expansion into `DnsUpstreamGroup`, so each Asio transport now
  handles only one member exchange while the group owns member failover and divides one total
  deadline across remaining members.
- Retained the old fallback fields solely as compatibility input and added a comment documenting
  that they are consumed at the group boundary.
- Applied the project formatter after moving legacy fallback expansion into the upstream-group
  implementation.
- Removed the Direct outbound's system-resolver path for domain targets. Direct now requires an
  injected `ResolverService`, resolves through the core DNS facade, and reports a configuration
  error when no resolver is configured; literal IP targets remain unchanged.
- Propagated the proxy's resolver into its Direct outbound and added a regression test proving a
  domain connection cannot silently bypass the core DNS service.
- Corrected Direct resolver completion to use the resolver service's owner-runtime default
  scheduler, avoiding a dependency on a non-public runtime accessor.
- Applied the project formatter to the Direct outbound resolver integration and its regression
  test.
- Corrected direct connection candidate construction for Boost.Asio's endpoint-range overload
  after the first clang-cl build exposed the iterator overload mismatch.
- Added a full-message local DNS server path over `DnsQueryService`. UDP and TCP requests now
  preserve the upstream packet wire data and all record sections on success, while failures use a
  minimal DNS error response; the old `ResolverService` constructor remains a compatibility
  adapter.
- Added full-message error-response encoding and expanded the local UDP receive buffer to the DNS
  maximum message size.
- Applied the project formatter to the full-message local DNS server migration.
- Connected `DnsServer` to `FakeIpStore` through an explicit filter: matching A queries now receive
  synthesized stable FakeIP answers locally, while non-matching queries continue through
  `DnsQueryService`.
- Added proxy-entry reverse mapping for configured FakeIP IPv4 addresses so routing and Direct
  outbound resolution can recover the original domain name.
- Added a TCP local-DNS FakeIP integration test covering synthesized response IDs and address data.
- Applied the project formatter to the FakeIP local DNS and proxy integration changes.
- Strengthened the FakeIP DNS integration test to inspect the complete answer record before the
  typed A/AAAA projection, making packet-versus-projection failures diagnosable.
- Corrected the FakeIP integration fixture to use a `/24` pool for its requested capacity, avoiding
  an invalid `/30` pool configuration that intentionally produced an empty error response.
- Added configurable DNS cache capacity and TTL-aware caching: positive responses use the minimum
  answer TTL, NXDOMAIN/NODATA use the configured negative TTL, SERVFAIL is not cached, and the
  cache evicts an entry when its capacity is reached.
- Updated Direct domain resolution to collect both A and AAAA results before connecting, while
  retaining the first resolution error only when neither address family succeeds.
- Added packet-level query validation for the full-message service so callers cannot start an
  exchange without a decodable DNS wire header.
- Extended `ResolverDependencyGraph` with unified dependency-node kinds for DNS upstreams,
  outbounds, outbound groups, and proxy endpoints. Existing resolver-role APIs remain compatible,
  while validation now covers cycles across all registered node kinds.
- Added a cross-domain dependency-graph test covering resolver, DNS upstream, outbound, proxy
  endpoint, and group edges.
- Added an explicit plain/DoT transport mode to `DnsUpstreamConfig` and made fallback expansion
  preserve TLS mode, SNI, and peer-verification settings.
- Added OpenSSL as the vcpkg-owned TLS dependency and linked it through `clash-native-core` in
  preparation for the independent DoT transport implementation.
- Added an independent DoT DNS transport with TLS trust verification, SNI/hostname validation,
  two-byte TCP framing, full-packet response validation, deadline, cancellation, and shutdown
  ownership. DoT is exposed through the same `DnsTransport` factory and remains unvalidated at
  runtime until a local or controlled TLS integration fixture is added.
- Added direct `DnsQueryService` tests for injected full-packet completion and pre-transport wire
  validation, so the full-message API is verified independently of the compatibility facade.
- Applied the project formatter to the direct full-message DNS query-service tests.
- Added configurable DNS cache capacity and TTL-aware caching: positive responses use the minimum
  answer TTL, NXDOMAIN/NODATA use the configured negative TTL, SERVFAIL is not cached, and the
  cache evicts an entry when its capacity is reached.
- Updated Direct domain resolution to collect both A and AAAA results before connecting, while
  retaining the first resolution error only when neither address family succeeds.
- Added packet-level query validation for the full-message service so callers cannot start an
  exchange without a decodable DNS wire header.
- Applied the project formatter after the TTL-aware cache and dual-stack Direct resolution
  changes.
- Extended `ResolverDependencyGraph` with unified dependency-node kinds for DNS upstreams,
  outbounds, outbound groups, and proxy endpoints. Existing resolver-role APIs remain compatible,
  while validation now covers cycles across all registered node kinds.
- Added a cross-domain dependency-graph test covering resolver, DNS upstream, outbound, proxy
  endpoint, and group edges.

## 2026-09-15

- Established the Stage 0 CMake product boundary:
  - `clash-native-core` owns the runtime, platform adapter, and experimental
    SOCKS5 proxy sources.
  - `clash-native` owns the CLI, process entry point, and application lifecycle
    over the core library.
  - `clash-native-tests` links `clash-native-core` without recompiling core
    sources.
- Fixed the first-configuration CMake toolchain argument ordering in
  `scripts/build.py` so a clean MSYS2/vcpkg configure can run.
- Added the dated implementation-log rule to `AGENTS.md`.

### Stage 0 foundations

- Added the dependency-light core error taxonomy and stream/datagram outbound
  contracts with a shared unsupported-capability conformance harness.
- Added the Asio scheduler adapter and configurable `RuntimeSet`, including
  explicit single-use runtime lifecycle behavior.
- Added owned standard-library channel primitives for oneshot, bounded MPSC,
  unbounded MPSC, and zero-capacity rendezvous delivery with stop-token-aware
  waiting and close propagation.
- Added the core-only `clash-native-test-host`, deterministic Go process
  ownership helpers, and independent TCP/UDP endpoint scaffolding.
- Added x64 and x86 MSYS2 Clang profile configuration. The x64 UCRT64 profile
  passed; the x86 probe remains unvalidated because the local environment
  lacks 32-bit runtime and Windows import libraries.
- Added platform documentation routing and the Windows UCRT64 toolchain notes.
- Validation completed on Windows UCRT64: 18/18 CTest cases passed, the Go
  TCP process black-box case passed, `go vet ./...` passed, and the UDP
  endpoint case was explicitly skipped because UDP loopback is unavailable in
  the environment.
- Documented that current Windows testing is limited to x64 with MSYS2 UCRT64
  Clang; Win32/x86 remains unvalidated and outside the current test gate.
- Added the `tl::expected` dependency behind the project-owned `Result<T>` and
  `Status` aliases. Proxy listener startup now returns structured transport
  errors, while the application and test host translate them at their
  process-level boundaries.
- Added `fmt 12.2.0` as a vcpkg dependency and used `fmt::format` for proxy
  listener error-context construction.

### 2026-09-15 — Stage 1 ordinary proxy core

- Replaced the monolithic proxy session's direct-connect and relay ownership
  with core-owned `DirectOutbound`, `RejectOutbound`, `StreamHandle`, and
  `TcpRelay` boundaries.
- Added normalized connection metadata and first-match traffic routing for
  network, inbound, domain, port, and initial destination-IP rule decisions.
- Added HTTP `CONNECT` handling alongside the existing unauthenticated SOCKS5
  `CONNECT` flow, including buffered data handoff after the HTTP headers.
- Added C++ routing, HTTP relay, reject-outbound, and existing SOCKS5
  regression coverage, plus an independent Go HTTP process test.
- Added bounded connect, handshake, and relay-idle timeout handling with
  cancellation and half-close preservation.
- Validation: Windows x64 MSYS2 UCRT64 Clang build completed; 24/24 CTest
  cases, Go interop tests, and `go vet ./...` passed.

### 2026-09-15 — Stage 2 DNS and routing foundations

- Added normalized ordered routing snapshots with destination-IP CIDR matching,
  lazy destination enrichment, same-rule resumption, and `no-resolve`
  behavior.
- Added a dependency-free DNS message codec, a system resolver adapter, DNS
  policy routing, and a UDP resolver service with TCP length-framed fallback.
- Added positive and negative TTL caching, equivalent-query coalescing, and
  per-waiter cancellation without cancelling other live waiters.
- Added malformed-message, policy, routing, cache/coalescing, and truncation
  fallback tests. The truncation fallback integration test is skipped when
  Windows UDP loopback is unavailable; the TCP path remains covered directly.

### 2026-09-16 — Stage 2 integration boundaries

- Added resolver-role declarations and dependency-cycle validation, including
  the bootstrap resolver restriction.
- Added configurable primary/fallback DNS upstream attempts with stale callback
  suppression across retries.
- Added local UDP/TCP DNS forwarding, query/response codec support, initial
  bounded FakeIP allocation with reverse lookup, and connection registry state.
- Added outbound group selection, routing target validation, and tests for the
  new Stage 2 integration boundaries.

### 2026-09-16 — Stage 2 correctness fixes

- Fixed per-waiter cancellation completion and suppressed callbacks from a
  failed DNS attempt after fallback retry begins.
- Accepted DNS query additional records and corrected local response flag
  serialization while keeping malformed-message validation strict.

### 2026-09-16 — Runtime drain and concurrent outbound selection

- Changed runtime shutdown to release the work guard and join the worker so
  queued completion handlers can drain before the runtime exits.
- Made outbound group round-robin state atomic and added shared-snapshot
  concurrent selection coverage.

### 2026-09-16 — DNS ownership and response validation

- Serialized ResolverService state changes on its bound runtime, added
  caller-scheduler completion delivery, and made stop cancel operations before
  returning.
- Validated DNS UDP responses against the configured sender and original
  question, rejected multi-question responses, and preserved TCP fallback
  validation.
- Updated DNS test fixtures to cancel their listeners before runtime shutdown,
  matching the new drain contract.

### 2026-09-16 — Listener lifetime gates and dual-stack route metadata

- Added owner-runtime shutdown barriers and callback lifetime gates to the DNS
  and proxy listeners so cancellation callbacks cannot access destroyed
  listeners.
- Routed DNS completions back to the listener runtime and queried both A and
  AAAA records for domain IP rule evaluation while retaining the first address
  for outbound connection establishment.
- Extended destination-IP routing metadata to match any resolved address.
- Added regression coverage for unexpected DNS UDP senders, mismatched DNS
  questions, multi-question responses, and IPv6 CIDR matches among multiple
  resolved addresses.

### 2026-09-16 — Formatting cleanup

- Applied the repository's MSYS2 Clang format to the modified C++ sources,
  headers, and tests.
- Added a cross-runtime resolver test that verifies completion affinity stays
  on the caller's scheduler.
- Applied the repository's MSYS2 Clang format to the new test code.
- Kept concurrent test assertions in the joining thread so worker threads only
  report shared test state.
- Applied the repository's MSYS2 Clang format after the test cleanup.
- Added resolver request tracking so DNS and proxy listener shutdown actively
  cancels outstanding enrichment/forwarding requests before closing I/O.
- Applied the repository's MSYS2 Clang format after adding request tracking.

### 2026-09-16 — Core logging integration

- Linked `clash-native-core` with header-only spdlog and added basic runtime,
  DNS, resolver, and proxy lifecycle/error logging through spdlog's default
  logger.
- Restored the application caller's info-level logging without changing the
  existing CLI or interop readiness output; callers remain responsible for
  configuring logger sinks and destinations.
- Applied the repository's MSYS2 Clang format after the logging integration.

### 2026-09-16 — Logging include correction

- Added the direct spdlog include required by the proxy core translation unit.
- Applied the repository's MSYS2 Clang format after the include correction.

### 2026-09-16 — Pixi and clang-cl build alignment

- Moved the maintained CMake and Ninja dependencies to the Pixi workspace.
- Updated the Windows build entry point to use Pixi with standalone LLVM
  `clang-cl` and the installed x64 MSVC environment.
- Updated the Windows build documentation; full rebuild validation was pending.

### 2026-09-16 — MSVC environment loader fix

- Fixed Python's `cmd.exe /c` invocation so Visual Studio paths containing
  spaces are passed correctly while exporting the x64 MSVC environment.

### 2026-09-16 — Pixi clang-format tooling

- Added the Pixi-managed `clang-format` 22 dependency.
- Added Pixi `format` and `format-check` tasks that enumerate only project
  sources under `include`, `src`, and `tests`; vendored `third_party` sources
  are excluded by construction.

### 2026-09-16 — Project formatting validation

- Applied the Pixi-managed clang-format configuration to the project source
  roots and verified `format-check` successfully.
- Confirmed that vendored `third_party` sources are excluded from both tasks.

### 2026-09-16 — CMake Windows path handling

- Passed Windows paths to CMake cache variables with forward slashes so the
  Windows SDK resource compiler path is parsed correctly by CMake.

### 2026-09-16 — DNS server query ownership fix

- Copied the DNS question before moving the full query into asynchronous
  callbacks, avoiding unspecified argument evaluation order under clang-cl.
- This fixes the TCP DNS forwarding test receiving an empty query name.

### 2026-09-16 — Windows clang-cl build validation

- Configured and built the CMake project with Pixi-managed CMake and Ninja,
  standalone LLVM clang-cl 22.1.8, Visual Studio MSVC 14.51.36231, and the
  Windows 10 SDK resource compiler.
- Built `clash-native-core`, `clash-native`, `clash-native-tests`, and
  `clash-native-test-host` successfully with the `x64-windows-clang-cl`
  vcpkg triplet.
- CTest passed all 49 tests, and the Go interop suite passed on Windows x64.
- The validation covers only Windows x64; other architectures and operating
  systems remain untested.

### 2026-09-16 — Added proxy protocol reference

- Added a standalone English reference covering the current Mihomo outbound and
  inbound types, carriers, security layers, versions, aliases, proxy groups,
  and control-plane separation.
- Documented the difference between the Mihomo reference surface and the
  protocols currently implemented by <code>clash-native</code>.

### 2026-09-16 — DNS policy upstream selection

- Added a minimal `DnsResolverConfig` containing the existing default DNS
  upstream, optional named upstream groups, and an optional read-only
  `DnsPolicyRouter`.
- Updated `ResolverService` to select the upstream group on its owner runtime
  before cache lookup and operation creation.
- Made each DNS operation own its selected upstream configuration, preserving
  per-group TCP preference and fallback behavior.
- Included the selected upstream group in the cache key and rejected policy
  rules that reference an unknown group without sending a query.
- Added resolver integration tests for named-group routing and unknown-group
  configuration errors.

### 2026-09-16 — DNS transport boundary

- Added the `DnsTransport` exchange, cancellation, and stop contract together
  with an Asio implementation for the existing UDP/TCP DNS behavior.
- Moved DNS sockets, framing, response validation, transaction-ID allocation,
  and truncation fallback into the transport-owned exchange operation.
- Kept the transport deadline fixed across fallback attempts and preserved the
  existing plain DNS error taxonomy.

### 2026-09-16 — Resolver transport injection

- Moved `DnsUpstreamConfig` into the DNS transport boundary and added an
  injectable `DnsTransportFactory` to `DnsResolverConfig`.
- Preserved the legacy single-upstream constructor and existing named-upstream
  policy configuration while preparing ResolverService for transport-owned
  network operations.

### 2026-09-16 — ResolverService transport ownership

- Removed UDP/TCP sockets, DNS framing buffers, response validation, and query
  ID allocation from `ResolverService::Operation`.
- Made each resolver operation own a selected transport exchange and its
  cancellation handle while retaining cache, policy, coalescing, waiter, and
  completion-scheduler responsibilities in ResolverService.
- Preserved the legacy single-upstream constructor and existing resolver
  lifecycle behavior.

### 2026-09-16 — DNS transport CMake integration

- Added the transport implementation to `clash-native-core` so the resolver
  service and all test targets use the same transport boundary implementation.

### 2026-09-16 — DNS deterministic transport tests

- Added an injectable fake DNS transport test fixture that performs no socket
  I/O and records exchange and cancellation ownership.
- Added coverage for policy-selected transport creation, unknown-group
  rejection, per-request cancellation, and resolver shutdown completion.
- Registered the new test source with the existing `clash-native-tests` target.

### 2026-09-16 — DNS transport compile fixes

- Defined Asio transport methods after the exchange operation type so the
  transport owns complete operation objects before starting or cancelling them.
- Added transport stopped-state storage, adapted timer cancellation to the
  active Boost.Asio API, and corrected the fake transport test type reference.

### 2026-09-16 — DNS transport endpoint selection fix

- Kept the active transport endpoint when switching from UDP to TCP so
  truncation fallback honors an explicitly configured TCP endpoint and later
  fallback attempts use their selected endpoint.
### 2026-09-16

- Applied the project formatter to the added unknown-upstream transport test.

- Added a deterministic unknown-upstream policy test confirming that ResolverService rejects the configuration without invoking the injected transport factory.

- Reserved part of the fixed DNS exchange deadline for a configured fallback attempt, allowing fallback to run without extending the original absolute deadline.

- Restored timeout-triggered fallback in the extracted DNS transport while keeping the same absolute exchange deadline for the primary and fallback attempts.

- Stabilized the injected transport shutdown test by waiting for the fake exchange to start before invoking resolver shutdown, so the test verifies transport cancellation rather than queued-request rejection.

- Applied clang-format after the immutable runtime snapshot and proxy reload integration; third-party sources remained excluded.

- Replaced deprecated C++20 atomic free functions for runtime snapshots with the standard `std::atomic<shared_ptr>` specialization and allowed snapshot validation to report allocation failures normally.

### 2026-09-16 — Runtime snapshot publication tests

- Added deterministic coverage for publishing validated immutable runtime snapshots, replacing the current value atomically, retaining older snapshots, and rejecting incomplete replacements.
- Registered the snapshot tests with the existing core-linked test target.

- Applied clang-format after adding runtime snapshot publication tests and the atomic snapshot store implementation; third-party sources remained excluded.

### 2026-09-16 — DNS cache isolation and eviction

- Added a cache generation component to DNS cache keys so separately published resolver configurations cannot reuse answers from another generation.
- Replaced arbitrary cache-entry removal with bounded LRU eviction and updated cache hit, expiry, and clear paths to maintain the eviction index.

- Added a deterministic cache-capacity test proving that the least-recently-used DNS entry is evicted and a subsequent query starts a new exchange.

- Applied clang-format after the DNS cache generation, LRU eviction, and capacity test changes; third-party sources remained excluded.

### 2026-09-16 — DNS response flag validation

- Required UDP, plain TCP, and DoT transport response validation to include the DNS response flag in addition to transaction ID and question matching.
- Added a loopback regression test proving that an upstream query packet is ignored and the exchange expires at its original deadline.

- Applied clang-format after the DNS response-flag validation and regression test changes; third-party sources remained excluded.

### 2026-09-16 — DNS group deadline allocation fix

- Corrected per-member deadline allocation so the current attempt reserves time for all remaining upstream-group members, including the two-member fallback case.

### 2026-09-16 — Monotonic runtime snapshot publication

- Changed runtime snapshot publication to use an atomic compare-and-exchange loop and reject stale or duplicate generations, preventing an older reload from replacing a newer snapshot under concurrent publication.
- Added regression coverage for stale-generation rejection and preservation of the currently published snapshot.

- Applied clang-format after the monotonic runtime snapshot publication changes; third-party sources remained excluded.

### 2026-09-16 — Proxy snapshot reload coverage

- Added a proxy integration test that publishes a replacement runtime snapshot while the listener is running and verifies that a new SOCKS5 connection follows the reloaded reject action.

- Added the standard array include required by the new proxy reload test.

- Added the Asio read and write headers required by the proxy reload integration test under the LLVM clang-cl build.

- Applied clang-format after the proxy reload test include changes; third-party sources remained excluded.

### 2026-09-16 — Plain DNS upstream dialer integration

- Routed Plain TCP DNS exchanges through the configured `DnsUpstreamDialer` when present, including length-prefixed reads, writes, cancellation, and shutdown of the returned `StreamHandle`.
- Preserved the existing direct Asio socket path when no dialer is configured; DoT and DoH2 continue to require their current direct TLS carrier path.

- Applied clang-format after integrating the Plain TCP DNS dialer stream path; third-party sources remained excluded.

### 2026-09-16 — Plain DNS dialer regression coverage

- Added a deterministic `StreamHandle` probe and dialer test proving Plain TCP transport uses the configured egress adapter and closes the returned stream on read failure.

- Applied clang-format after adding the Plain TCP DNS dialer regression fixture; third-party sources remained excluded.

### 2026-09-16 — DNS policy publication validation

- Added read-only ResolverService and DnsQueryService validation for DNS policy rules and made RuntimeSnapshot validation reject empty or missing upstream-group references before publication.
- Added regression coverage proving an invalid DNS policy is rejected before any runtime exchange is attempted.

- Applied clang-format after adding DNS policy publication validation; third-party sources remained excluded.

### 2026-09-16 — Application DNS wiring

- Added optional Application DNS configuration for constructing a shared ResolverService and local UDP/TCP DnsServer alongside the existing proxy listener.
- Reused the configured ResolverService and FakeIpStore for proxy routing and local DNS responses, while leaving the existing CLI defaults unchanged when no DNS configuration is supplied.

- Applied clang-format after the Application DNS wiring changes; third-party sources remained excluded.

### 2026-09-16 — DNS default policy validation

- Distinguished built-in default DNS group aliases from named upstream groups during policy selection and validation.
- Added regression coverage proving an unknown policy default group is rejected before a DNS exchange starts.

- Applied clang-format after the DNS default policy validation changes; third-party sources remained excluded.

- Preserved the existing `system` policy name as a built-in default-group alias after tightening named-group validation.

### 2026-09-16 — DNS upstream configuration validation

- Extended ResolverService validation to reject invalid DNS endpoints, non-positive timeouts, malformed fallback endpoints, invalid DoH2 paths, empty upstream groups, unsupported group selection values, and empty policy rule values before exchange startup.
- Added regression coverage proving an invalid upstream timeout is reported without creating a network exchange.

- Corrected the invalid-upstream regression fixture to use a valid endpoint so it specifically exercises timeout validation.

- Applied clang-format after the DNS upstream configuration validation changes; third-party sources remained excluded.

### 2026-09-16 — DNS unsupported egress rejection

- Rejected non-direct DNS dial policies without a dialer, custom dialers on DoT/DoH2, and custom Plain dialers without TCP mode instead of silently falling back to direct raw sockets.
- Added regression coverage proving an unsupported DNS dial policy fails validation before querying.

- Applied clang-format after the DNS unsupported egress rejection changes; third-party sources remained excluded.

### 2026-09-16 — DNS enum configuration validation

- Added explicit validation for DNS transport modes, dial policies, and policy rule kinds before runtime exchange creation.
- Added regression coverage proving an invalid DNS transport enum is rejected before querying.

- Applied clang-format after the DNS enum configuration validation changes; third-party sources remained excluded.

### 2026-09-17 — Stage 2 DNS parser and transport validation

- Added c-ares through the vcpkg manifest and replaced handwritten DNS wire-message decoding with c-ares while preserving the original packet bytes, unknown record data, EDNS options, and SOA negative-cache TTL data.
- Fixed DoQ stream FIN submission and added FakeIP, domain routing, and runtime snapshot reload regression coverage. Improved Windows allocation of shared UDP/TCP ports in the independent Go interop tests.
- Validated the Windows x64 clang-cl/MSVC build with 109/109 CTest cases and the uncached Go interop suite against independent dnsproxy, including successful DoQ and DoH3 queries.

### 2026-09-17 — c-ares typed address results

- Kept A and AAAA values in the project DNS packet model as typed addresses obtained through c-ares RR getters, so address-answer projection no longer reparses the raw RDATA bytes.
- Mapped c-ares typed fields for SOA, MX, TXT, and SRV records into the project packet model, with regression coverage for those record types.
- Rebuilt with Windows x64 clang-cl/MSVC; all 110 CTest cases and the uncached Go interop suite passed.

### 2026-09-17 — Generic c-ares resource record fields

- Exposed every c-ares-supported RR field through a generic DNS packet model, including numeric, name, binary, repeated binary, and option values while retaining convenience fields for common records.
- Added explicit SVCB, HTTPS, TLSA, NAPTR, HINFO, URI, CAA, and arbitrary numeric query-type support, with regression coverage for HTTPS service parameters and unknown RR fields.
- Validated the Windows x64 clang-cl/MSVC build with 112/112 CTest cases and the uncached Go interop suite against independent dnsproxy, including DoQ and DoH3.

### 2026-09-17 — Public encrypted DNS interoperability test

- Extended the test host endpoint syntax to select DoT and DoH/2, and added an opt-in Go black-box test that sends independent DNS queries through Google and Cloudflare DoT/DoH plus Quad9 DoQ/DoH3 public resolvers.
- Validated Windows x64 with clang-cl/MSVC: Google DoT/DoH2, Cloudflare DoH1, and Quad9 DoQ/DoH3 all returned a successful `example.com` A answer through the independent Go client. The public test stays disabled in normal runs unless `CLASH_NATIVE_DNS_LIVE=1` is set.

### 2026-09-17 — DNS response correctness and QUIC session reuse

- Enforced DoQ's zero DNS Message ID on the wire and restored the caller's ID after validating the response; expanded independent Go DoQ/DoH3 integration coverage to sequential reuse and parallel queries.
- Changed DNS cache and in-flight keys to include the full query message except transaction ID, retaining upstream-group and generation isolation.
- Preserved 12-bit extended response codes and query EDNS data in local error and FakeIP responses. Added c-ares based UDP RRset truncation that sets TC and respects the client's EDNS payload size (512 bytes when EDNS is absent).
- Added a bounded idle QUIC session pool for sequential DoQ/DoH3 requests; connections retire after 30 seconds idle or on transport failure.
- Validated with the Windows x64 clang-cl/MSVC build, CTest, uncached Go interoperability tests against independent dnsproxy, and public encrypted DNS upstream tests.

### 2026-09-17 — Roadmap milestone sequencing

- Moved DoQ and DoH over HTTP/3 implementation and validation into the Stage 2 DNS milestone, including the minimum QUIC/HTTP/3 foundation required by those DNS transports.
- Kept Stage 4 focused on generalizing and validating QUIC for proxy protocols, and moved the user-facing CLI and configuration-file interface to Stage 7.

### 2026-09-17 — Concurrent QUIC DNS stream reuse

- Refactored DoQ and DoH/3 transports to multiplex up to 64 active DNS exchanges on one QUIC session, with per-stream deadlines, response state, cancellation, and stream-limit handling.
- Kept DoQ exchanges queued when a QUIC packet makes no stream progress or carries only control frames, so later transport progress can resume each request.
- Added test-only Go quic-go upstream fixtures that assert eight simultaneous unique queries complete over exactly one accepted QUIC connection for both DoQ and DoH/3, and verify zero DNS message IDs on DoQ wire queries. The DNS TCP listener feeds 18 KB padded requests to exercise QUIC packetization and flow control without relying on fragmented local UDP datagrams.
- Validated Windows x64 with clang-cl/MSVC, all 117 CTest cases, the full Go interoperability suite, `go vet`, formatting checks, and ten repeated runs of the new DoQ/DoH/3 connection-reuse interoperability test.

### 2026-09-17 — Deferred large UDP DNS burst issue

- Recorded the observed Windows loopback loss rates for concurrent oversized UDP datagrams, the successful sequential size checks, and the limits of the current evidence in `docs/known-issues.md`.
- Kept the cause unresolved and deferred implementation changes; the loopback measurements do not establish IP-fragmentation loss or a fixed 13 KB limit.

### 2026-09-18 — Shared TLS, HTTP, QUIC, and endpoint dialing

- Added reusable TLS, HTTP/1.1, HTTP/2, HTTP/3, and QUIC client boundaries, then reduced the encrypted DNS transports to DNS framing, request mapping, and response validation over those shared components.
- Added immutable endpoint dial plans with stream/datagram capability checks, traffic-rule egress planning, outbound-chain tracing, and runtime cycle/depth guards. Removed DNS TCP transport's raw-socket fallback so upstream connections use the planned dialer.
- Validated the Windows x64 clang-cl/MSVC build and all 122 CTest cases, the uncached Go interoperability suite, independent dnsproxy coverage for DoT/DoH1/DoH2/DoQ/DoH3, and single-connection concurrent DoQ/DoH3 multiplexing.

### 2026-09-18 — Composed DNS policy, FakeIP, proxy routing, and reload

- Made `ProxyServer` and `DnsServer` share the same atomic runtime snapshot. Each DNS request captures one resolver/FakeIP generation, so reload changes DNS synthesis and proxy routing together while in-flight requests and established proxy sessions retain their prior owners.
- Exposed route rules, default action, outbound registry, FakeIP filter, and snapshot reload through the application API without adding CLI configuration. Direct domain routes now resolve against the resolver held by the request's snapshot.
- Added an independent Go integration that starts two dnsproxy processes and verifies policy-group selection, FakeIP synthesis, SOCKS5 domain routing to a real echo endpoint, snapshot reload, new-generation DNS/routing behavior, and an established connection surviving reload. Documented the topology and command in `docs/dns-testing.md`.

### 2026-09-18 — c-ares OPT projection and reload policy coverage

- Removed the remaining handwritten DNS wire walker for OPT metadata. The c-ares packet RCODE and OPT version/flags getters now provide the extended response code and OPT TTL fields used by local responses.
- Extended the independent Go composition scenario to verify DNS policy-group selection changes on reload, alongside FakeIP pool and proxy route changes.
- Validated Windows x64 with standalone clang-cl/MSVC and vcpkg: 122/122 CTest cases, the uncached Go interoperability suite with independent dnsproxy enabled, ten repeated composed reload runs, `go vet ./...`, formatting, and `git diff --check` passed. Public DNS and Mihomo tests remained opt-in and were skipped.

### 2026-09-18 — Split DoQ and DoH/3 DNS transports

- Moved DoQ stream framing and QUIC event handling into `doq_dns_transport.cpp`, and DoH/3 HTTP request/response handling into `doh3_dns_transport.cpp`.
- Kept the QUIC session pool, exchange lifecycle, deadlines, cancellation, and shared connection management in `quic_dns_transport.cpp` through a private internal declaration header.
- Validated with the Windows x64 clang-cl/MSVC build and 122/122 CTest cases. The uncached Go interoperability suite passed with the independent dnsproxy fixture, including ten repeated DoQ/DoH3 single-connection multiplexing runs.

### 2026-09-18 — Extract UDP stream adapter

- Added `net::UdpStream` as the Asio UDP socket adapter for `core::DatagramHandle`, including socket setup, async send/receive, executor access, local endpoint lookup, cancellation, close, and RAII shutdown.
- Replaced the direct outbound's private datagram wrapper and migrated the DNS listener, SOCKS UDP relay, and Shadowsocks datagram socket to the shared adapter while keeping their protocol behavior in the owning layers.
- Added a loopback test for datagram send/receive and peer endpoint reporting. Validated the Windows x64 clang-cl/MSVC Release build, 123/123 CTest cases, and uncached Go interoperability tests against independent DNS and proxy peers.
### 2026-09-20 — Start Shadowsocks transport decomposition

- Added the first reusable Shadowsocks transport module under
  `transport/shadowsocks`, including cipher metadata, AEAD subkey derivation,
  legacy key derivation, and stateful legacy stream cipher primitives.
- Registered the classic AES-GCM, ChaCha20-Poly1305, AES-CTR/CFB, and RC4-MD5
  families in the new transport boundary; outbound wiring and interoperability
  coverage remain the next step.

### 2026-09-20 — Route Shadowsocks crypto through the transport module

- Switched the Shadowsocks outbound to the shared `transport/shadowsocks`
  crypto registry and removed the duplicate outbound-local crypto implementation.
- Kept the existing AEAD wire path compatible while the legacy stream and
  Shadowsocks 2022 session protocols are moved into their own transport files.

### 2026-09-20 — Keep legacy AES-CFB inside the BoringSSL boundary

- Added the AES-ECB based CFB state machine to the reusable Shadowsocks stream
  cipher module because the BoringSSL vcpkg target does not export its decrepit
  CFB symbols through `OpenSSL::Crypto`.

### 2026-09-20 — Add classic Shadowsocks legacy stream framing

- Added reusable legacy stream and packet framing modules for IV based
  Shadowsocks ciphers.
- Wired outbound TCP setup through the legacy stream handle for the currently
  registered AES-CTR, AES-CFB, and RC4-MD5 methods; UDP wiring and additional
  cipher families remain in progress.
2026-09-20 Added the legacy Shadowsocks UDP datagram handle and wired its transport module into the build; classic UDP integration remains pending.
2026-09-20 Wired classic Shadowsocks UDP methods through the reusable legacy datagram transport.
2026-09-20 Added the crypto registry dependency to the classic Shadowsocks UDP adapter so its cipher family is validated before construction.
2026-09-20 Made AEAD Shadowsocks stream and datagram nonce sizing follow the selected method, including XChaCha20-Poly1305.
2026-09-20 Added the classic chacha20-ietf stream cipher using BoringSSL's ChaCha20 primitive.
2026-09-20 Added transport unit coverage for classic Shadowsocks cipher registration, AEAD, stream, and datagram round trips.
2026-09-20 Kept the CFB block keystream assignment compatible with the shared ChaCha keystream storage.
2026-09-20 Preserved BoringSSL's default AEAD tag configuration while exposing method overhead metadata to framing code.
2026-09-20 Kept the existing TCP half-close behavior while validating Shadowsocks framing through direct carrier captures.
2026-09-20 Extended the official Mihomo interop matrix to every currently registered classic Shadowsocks and AEAD method.
2026-09-20 Preserved the legacy stream cipher state after the initial destination record so subsequent TCP payloads continue the same keystream.
2026-09-20 Corrected RC4-MD5 key handling so the per-IV MD5 step is applied exactly once by the stream cipher initializer.
2026-09-20 Removed temporary UDP relay diagnostics after isolating the remaining interoperability issue to the SOCKS UDP relay path.
2026-09-20 Added an outbound-level encrypted UDP send test that decrypts the emitted AEAD packet with the shared transport module.
2026-09-20 Made the outbound UDP integration test wait for asynchronous hostname resolution before using the handle.
2026-09-20 Removed the temporary outbound UDP socket test because the existing Windows UdpStream smoke test currently cannot observe loopback datagrams.
### 2026-09-20 — Add the Shadowsocks 2022 transport foundation

- Added the vcpkg BLAKE3 dependency and reusable Shadowsocks 2022 session-key
  derivation using the protocol's Base64 PSK and BLAKE3 derive-key context.
- Added a separate asynchronous Shadowsocks 2022 TCP transport with encrypted
  record framing, response-header validation, and stream-handle adaptation.
- Routed Shadowsocks outbound TCP setup through the new transport for the three
  standard 2022 methods and added crypto round-trip coverage.

### 2026-09-20 — Add Shadowsocks 2022 UDP packet transport

- Added the reusable Shadowsocks 2022 UDP packet codec for AES-GCM packet-header
  protection and XChaCha20-Poly1305 packets, including session and packet IDs,
  BLAKE3 session keys, timestamp/padding headers, and response decoding.
- Routed 2022 UDP outbound handles through the codec and kept the encrypted wire
  size guard at 1500 bytes.
- Added an opt-in official Mihomo raw UDP interop harness; it is disabled by
  default while the Windows Mihomo UDP listener path is independently verified.

### 2026-09-20 — Complete the legacy ChaCha Shadowsocks stream variants

- Added the original `CHACHA20` and `XCHACHA20` legacy stream ciphers to the
  reusable Shadowsocks transport registry, including their protocol-specific
  nonce layouts and continuous stream counters.
- Extended the transport round-trip tests to cover both variants for TCP stream
  framing and native UDP packet framing.
- Extended the opt-in Mihomo classic TCP matrix to include both variants.

### 2026-09-20 — Align Shadowsocks validation documentation with the live tests

- Documented the complete classic TCP cipher matrix, the three SS2022 TCP
  methods, the retained half-close limitation, and the opt-in SS2022 UDP
  harness boundary in `docs/testing.md`.

### 2026-09-20 — Bound SS2022 UDP outbound payloads by the proxy address

- Made the SS2022 datagram outbound reserve the maximum encoded destination
  address when reporting its payload capacity, so callers cannot fill the
  advertised limit and then exceed the 1500-byte encrypted wire guard.
- Added transport coverage for the conservative capacity calculation.

- Kept the send path destination-aware: `max_datagram_size()` is a conservative
  caller hint for the longest address form, while the encrypted wire-size check
  decides whether a shorter IPv4 destination can use the remaining 1500-byte
  budget.

### 2026-09-20 — Add the remaining standard Shadowsocks AEAD methods

- Added AES-CCM and ChaCha8/XChaCha8-Poly1305 to the shared Shadowsocks AEAD
  registry and framing path.
- Added local round-trip coverage and extended the Mihomo server matrix so the
  new methods are validated as outbound protocols rather than registry-only
  entries.
- Added an explicit interop-test switch for running the cipher matrix without
  the separately tracked Windows relay half-close check.

### 2026-09-20 — Verify the XChaCha8 Mihomo alias boundary

- Matched Mihomo's current `XCHACHA8-IETF-POLY1305` constructor alias to
  XChaCha20 wire construction and extended deterministic transport coverage
  across empty, short, record-sized, and multi-kilobyte payloads.
- Confirmed the C++ primitive against an independent Go XChaCha20 peer; the
  current Windows Mihomo listener still closes this method's stream, so that
  upstream behavior remains documented as an interoperability boundary and is
  explicitly skipped in the Mihomo matrix while deterministic coverage stays
  enabled.

### 2026-09-20 — Replace handwritten Shadowsocks ChaCha primitives

- Added Botan 3.12 through the vcpkg manifest and linked its static target to
  the core library.
- Replaced the local ChaCha, HChaCha, and Poly1305 implementation with Botan's
  configurable ChaCha stream cipher and Poly1305 APIs, preserving the existing
  Shadowsocks framing and Mihomo's XChaCha8-to-XChaCha20 alias behavior.
- Kept BoringSSL only as the independent XChaCha20 reference in the deterministic
  transport test and retained the existing C++ and Mihomo interoperability
  coverage.

### 2026-09-20 — Close the remaining Shadowsocks outbound interop gaps

- Corrected the Mihomo-compatible XChaCha8 construction and removed the former
  interop skip; the full classic Shadowsocks TCP/UDP matrix now passes with
  Mihomo, including XChaCha8 and the legacy stream methods.
- Made the process test host's proxy bind address configurable and selected a
  non-loopback IPv4 address for Windows UDP interop environments that do not
  route loopback datagrams between processes.
- Completed real Mihomo UDP coverage for the three Shadowsocks 2022 methods and
  kept the 1500-byte encrypted wire guard exercised by the outbound tests.

### 2026-09-20 — Keep the Go interoperability test binary stable

- Changed the Windows build test path to compile `tests/interop` once with
  `go test -c` and run the resulting executable, instead of launching a new
  temporary Go test image for every run.
- Documented the same build-then-run workflow for focused Mihomo tests so
  Windows firewall approval can remain associated with one executable path.

### 2026-09-20 — Add Shadowsocks HTTP simple-obfs transport

- Added the client side `simple-obfs` HTTP carrier for Shadowsocks TCP, with
  the first encrypted request carried as an HTTP Upgrade body.
- Made the 101 response lazy and preserve any coalesced encrypted bytes so the
  carrier does not deadlock before application data is written.
- Applied the carrier to classic and Shadowsocks 2022 streams, while keeping
  native Shadowsocks UDP unwrapped.
- Added real Mihomo interoperability coverage for classic AEAD and SS2022
  HTTP simple-obfs streams.

### 2026-09-20 — Add Shadowsocks TLS simple-obfs transport

- Added the Mihomo-compatible fake TLS ClientHello and application-record
  carrier for Shadowsocks TCP.
- Applied the carrier to classic AEAD, legacy stream ciphers, and Shadowsocks
  2022 streams, with lazy server-response parsing and record reassembly.
- Added real Mihomo interoperability coverage for classic AEAD and SS2022 TLS
  simple-obfs streams; native Shadowsocks UDP remains unwrapped.

### 2026-09-20 — Add Shadowsocks UDP-over-TCP outbound transport

- Added the standardized Shadowsocks UDP-over-TCP version 1 and version 2
  datagram adapters. Version 2 writes the request header with the standard
  SOCKS address encoding, while packet frames use the UoT address encoding.
- Routed the outbound's `udp-over-tcp` mode through a Shadowsocks TCP stream
  and preserved the multi-destination `DatagramHandle` contract.
- Added real Mihomo listener interoperability coverage for both UoT versions
  using the independently built Go test binary and a UDP echo service.

### 2026-09-20 — Finalize Shadowsocks UDP-over-TCP cancellation behavior

- Made closed UoT datagram handles reject new reads immediately and complete an
  in-flight read with `operation_aborted` when the underlying stream is closed.
### 2026-09-20 — Record the plain-UDP DNS timeout baseline

- Documented the four reproducible Windows x64 DNS tests that time out on the
  local plain-UDP loopback path.
- Recorded that the same failures occur in the pre-KCP test binary, so they are
  an existing baseline issue rather than a kcptun/KCP regression.

### 2026-09-21 — Add Shadowsocks Shadow-TLS v1 and v2 outbound carriers

- Added a dedicated Shadow-TLS transport module and connected it to the
  Shadowsocks TCP outbound path without changing the Shadowsocks cipher layer.
- Implemented Mihomo-compatible v1 TLS pass-through and v2 handshake hashing,
  TLS-shaped application records, and the v2 post-handshake data delay.
- Added real Mihomo interoperability coverage for v1 and v2. The tests skip
  the existing half-close case because Mihomo's Shadow-TLS listener closes the
  whole stream after receiving FIN.
- Shadow-TLS v3 remains explicitly unsupported: the current BoringSSL client
  wrapper has no safe client-hello SessionID generation hook for the v3 HMAC.

### 2026-09-21 — Add the Shadowsocks ResTLS TLS 1.2 outbound carrier

- Added a native Botan TLS 1.2 client and ResTLS application-record adapter,
  including the TLS 1.2 GCM explicit counters, authenticated length and command
  fields, script target ranges, and response-record flow control.
- Connected the carrier to the Shadowsocks TCP outbound path and kept the
  plugin configuration separate from the Shadowsocks cipher framing.
- Added codec coverage for plain and TLS 1.2 GCM ResTLS records and a real
  Windows x64 Mihomo interoperability test using a separately built Go test
  executable and a clean Mihomo server binary.
- The native client currently accepts only the `tls12` version hint; `tls13`
  remains an explicit unsupported result until Botan's TLS 1.3 session-ID
  derivation and ResTLS record hooks are wired.

### 2026-09-21 — Add WebSocket plugin multiplexing

- Added a common `MultiplexedSession` implementation for v2ray-plugin mux and
  gost-plugin smux v1, exposing each logical stream through `StreamHandle`.
- Added a per-outbound WebSocket carrier pool so concurrent Shadowsocks TCP
  streams reuse one upgraded WebSocket connection.
- Added independent Go interoperability coverage for two logical streams over
  one v2ray mux or smux v1 carrier. Native Shadowsocks UDP remains unwrapped.

### 2026-09-21 — Add WebSocket plugin smux v2 flow control

- Added smux v2 selection for the gost WebSocket plugin carrier, including
  `UPD` window frames, per-stream send windows, receive-consumption accounting,
  and backpressure while a peer window is exhausted.
- Preserved smux v1 as the default and rejected smux v2 selection for the
  v2ray-plugin mux format.
- Added a large-payload Go interoperability case that exercises smux v2
  window updates over one reused WebSocket carrier.

### 2026-09-21 — Implement Shadowsocks Shadow-TLS v3

- Added a Botan TLS 1.3 Shadow-TLS v3 client with the password-authenticated
  32-byte ClientHello session ID required by the v3 wire protocol.
- Implemented the v3 bridge-record HMAC/XOR transformation and post-handshake
  authenticated application records as a dedicated carrier stream.
- Extended Shadowsocks configuration validation and Mihomo interoperability
  coverage to Shadow-TLS v3 alongside v1 and v2.

### 2026-09-21 — Tighten Shadow-TLS v3 certificate handling

- Removed the obsolete disabled v3 path from the v1/v2 carrier module so v3
  has one active implementation.
- Shadow-TLS v3 now uses the embedded CA bundle for Botan certificate
  verification when `skip_cert_verify` is disabled; the explicit skip path
  remains available for camouflage endpoints.

### 2026-09-21 — Keep the Go interop test executable stable

- Documented the fixed `go test -c` output directory in the ignore rules so
  repeated Windows interop runs use one executable path instead of a temporary
  test binary.

### 2026-09-21 — Finalize Shadow-TLS v3 carrier cleanup

- Kept the v3 frame reader self-contained and removed an unused per-stream
  header buffer from the carrier implementation.

### 2026-09-21 — Add the Shadow-TLS v3 embedded trust store

- Loaded the existing embedded CA bundle into Botan's in-memory certificate
  store so v3 can perform normal certificate and hostname verification.
- Kept the skip-verification path free of an empty trust-store object.

### 2026-09-21 — Complete the HTTP inbound core path

- Added an explicit HTTP-only inbound mode while preserving the existing mixed
  HTTP/SOCKS5 listener.
- Added optional HTTP Basic proxy authentication through `ProxyServer`.
- Added HTTP/1.1 client connection reuse for ordinary proxy exchanges, including
  repeated requests, proxy keep-alive headers, and streamed response framing.
- Kept HTTP/1.1 Upgrade out of scope; Upgrade requests continue to return
  `501 Not Implemented`. Inbound TLS and CLI configuration remain deferred.
- Added Windows x64 CTest coverage for HTTP-only authentication and two requests
  over one HTTP/1.1 proxy connection.

### 2026-09-21 — Add local HTTPS proxy listener support

- Added PEM-configured TLS byte-vector credentials to `ProxyServer` and
  `ApplicationOptions`, with certificate and private-key validation during
  listener startup.
- Added a shared local stream adapter that performs an asynchronous TLS server
  handshake and then exposes the decrypted connection through the existing
  `StreamHandle`, HTTP parser, SOCKS5 parser, and TCP relay paths.
- Added a Windows x64 CTest case covering an HTTPS proxy CONNECT request and
  bidirectional relay through a configured self-signed certificate.
- Kept certificate file loading, client certificate authentication, and CLI
  configuration outside this change; the API must be configured before
  `ProxyServer::start()`.

### 2026-09-21 — Store local TLS credentials as byte vectors

- Changed local certificate and private-key configuration from `std::string` to
  `std::vector<std::uint8_t>` in both `ProxyServer` and `ApplicationOptions`.
- Kept the TLS context setup and validation on the same PEM byte buffers and
  updated the HTTPS proxy test call site.

### 2026-09-21 — Validate a custom local TLS certificate chain

- Added a Windows x64 HTTPS proxy test with a custom leaf certificate and
  custom trusted root certificate in one PEM chain buffer.
- Enabled client certificate verification against the custom root and verified
  the HTTP CONNECT relay after the chain handshake.

### 2026-09-21 — Add HTTP/1.1 Upgrade forwarding to the local proxy

- Added a dedicated HTTP/1.1 Upgrade path for the local HTTP proxy listener.
  The proxy now forwards the handshake through the existing upstream exchange
  session, returns the upstream `101 Switching Protocols` response, and then
  relays the upgraded byte stream in both directions.
- Preserved client bytes read together with the request headers and forwarded
  selected end-to-end handshake headers while keeping proxy hop-by-hop and
  authentication headers local.
- Added Windows x64 coverage for a custom Upgrade protocol, forwarded headers,
  early data, and subsequent bidirectional stream data.

### 2026-09-21 — Add process-level HTTP Upgrade interoperability coverage

- Added a Go black-box test that runs the built native test host as an HTTP
  proxy and an independent Go TCP service as the Upgrade origin.
- The test verifies the forwarded handshake headers, the `101` response, data
  already coalesced with the client request, and later bidirectional payloads.
### 2026-09-21 — Split local proxy implementation by responsibility

- Split the local proxy implementation into server lifecycle, shared session,
  HTTP, SOCKS5, stream adapter, and HTTP parsing utility modules. Existing HTTP,
  CONNECT, Upgrade, SOCKS5 TCP, and SOCKS5 UDP behavior remains on the same
  runtime path.

### 2026-09-21 — Align SOCKS listener authentication and UDP behavior

- Added RFC 1929 username/password authentication with multiple configured
  users, authenticated-user metadata, and a SOCKS-only inbound mode.
- Added an optional standalone SOCKS5 UDP listener matching the Mihomo listener
  split while retaining TCP `UDP ASSOCIATE` compatibility.
- Added focused Windows tests for authenticated TCP CONNECT and standalone UDP
  relay behavior.
- Added SOCKS4 and SOCKS4a CONNECT parsing, USERID handling, status replies, and
  focused relay/parser tests.

### 2026-09-21 — Record deferred SOCKS4a interoperability failure

- Recorded that SOCKS4 IPv4 interoperability passes for both the native
  listener and Mihomo, while the current Windows x64 SOCKS4a checks fail in
  both server paths.
- Documented the repeated request-header bytes observed during domain parsing,
  the remaining uncertainty about the shared framing or loopback test path,
  and the standalone wire verification required before resuming the work.
- Intentionally skipped implementation changes for SOCKS4a.

### 2026-09-21 — Add Trojan WebSocket and WSS carriers

- Extended the shared HTTP/1.1 WebSocket client carrier with an optional TLS
  handshake, certificate verification, custom trust roots, SNI, and ALPN.
- Reused that carrier for Trojan `ws` and `wss` outbound modes and moved the
  Shadowsocks WebSocket plugin TLS path onto the same implementation.
- Added Trojan carrier configuration for the WebSocket host, path, headers,
  and plain-versus-TLS WebSocket selection.
- Added Mihomo interoperability coverage for Trojan TCP/TLS, WSS, and plain
  WS with a 50 KiB bidirectional payload. The existing Windows/Mihomo
  half-close EOF condition is documented separately and can be skipped with
  `CLASH_NATIVE_SKIP_INTEROP_HALF_CLOSE=1`.

### 2026-09-21 — Document Go test reuse and transport directory boundaries

- Documented the Windows rule to build Go helpers and test binaries once and
  reuse stable executable paths instead of invoking `go run` for network tests.
- Added transport layout rules separating reusable base transports,
  cross-protocol proxy carriers, and protocol-specific implementations.
- Defined `src/transport/proxy` as the shared home for carriers such as
  ShadowTLS, ResTLS, and JLS, while keeping Shadowsocks-only framing under
  `src/transport/shadowsocks`.

### 2026-09-21 — Generalize the design guidelines document name

- Renamed the transport-specific design document to
  `docs/design-guidelines.md` so it can hold future project-wide design rules.

### 2026-09-21 — Move shared WebSocket multiplexing into the proxy transport layer

- Moved the reusable v2ray mux and SMUX framing/session implementation from
  `src/transport/shadowsocks` to `src/transport/proxy`.
- Kept Shadowsocks WebSocket plugin configuration and carrier pooling in the
  Shadowsocks module while consuming the shared proxy mux API.
- Updated CMake and outbound wiring so WS/WSS plugin multiplexing uses the
  shared transport boundary.

### 2026-09-21 — Keep WebSocket plugin muxing Shadowsocks-specific

- Restored the v2ray mux and gost SMUX implementation under
  `src/transport/shadowsocks` because no other proxy protocol currently uses
  the same wire framing.
- Kept the generic HTTP/1.1 WebSocket and optional TLS carrier in
  `src/transport`; the mux remains eligible for extraction after a second
  independent consumer appears.

### 2026-09-21 — Consolidate the Asio runtime into a shared worker pool

- Replaced the multiple independent `AsioRuntime` instances and `RuntimeSet`
  container with one process-wide runtime singleton.
- The singleton owns one shared `io_context`, work guard, and configurable
  runner-thread pool; callers must use session serialization when mutable state
  can be reached by different runner threads.
- Updated runtime tests and architecture/testing documentation for the shared
  multi-thread scheduler model.

### 2026-09-21 — Serialize shared-runtime service state

- Added a shared Asio strand to the singleton scheduler and associated the
  runtime-owned DNS, proxy, outbound, and bootstrap I/O objects with it.
- Marshalled DNS query, upstream, and completion state transitions through the
  serialized executor so multiple runner threads do not concurrently mutate a
  service's owner state.
- Updated the DNS completion test and runtime documentation for interchangeable
  worker threads and explicit scheduler affinity.

### 2026-09-22 — Finish singleton runtime migration on Windows

- Kept the DNS server's UDP and TCP listeners on the shared serialized executor
  so listener state and query bookkeeping remain single-owner with multiple
  runtime workers.
- Updated the architecture and stdexec usage notes to describe the process-wide
  runtime lifetime and runner-thread model accurately.
- Added bounded waits to the Windows DNS UDP listener tests so environments that
  do not deliver loopback UDP report a skip instead of hanging the CTest run.
- Kept the TCP test fixture's accepted socket alive until teardown so the
  multi-worker runtime test does not depend on a response timing race.
- Reused the Windows test address probe for direct UDP outbound coverage so
  the test does not require loopback UDP delivery.
- Moved the remaining Shadowsocks and KCP datagram sockets and pool timers to
  the shared serialized executor as well.

### 2026-09-22 — Match the Asio concurrency hint to the runner count

- Rebuilt the stopped singleton runtime's `io_context`, serialized executor,
  and work guard when the configured worker count changes.
- Constructed `io_context` with the runner count so single-worker mode can use
  Asio's lower-overhead single-thread scheduling path.
- Added a runtime test covering context replacement during worker-count
  reconfiguration and documented the executor lifetime requirement.

### 2026-09-22 — Finish proxy-plane sender migration and fix test-plane debt

- Migrated the remaining test doubles to the sender narrow waist: `EventReceiver` drops `&&` (erased `AnySender` invokes the receiver as an lvalue), `StreamOpenResult` is moved out of `sync_wait` tuples (it holds a `unique_ptr`), stub outbounds return `just(unsupported)`, DNS probe dialers adapt `core::` streams at the edge, and host probes take `io::` inputs (`websocket_client` adapts the handshake output back to `core::` for its callback-style echo checks).
- Fixed `Loopback` in `io_handles_test` with an `executor_work_guard` (the worker's `run()` previously returned with no work, hanging all `use_sender` pulls) and bound it to loopback instead of `0.0.0.0`.
- Fixed a use-after-move segfault in `http1_client`/`websocket_client` write adapters: `start_with_receiver(handle->async_write(buffer(*bytes)), Receiver{..., move(bytes)})` evaluates arguments in unspecified order, so the receiver move could null `bytes` before dereference. Sender creation is now split from the move with a comment.
- Validated with the Windows x64 Release clang-cl/MSVC build: zero build errors; `clash-native-tests` reports 224 passed, 3 skipped, 4 failed (the known DNS UDP environment baseline); `pixi run format`, `format-check`, and `git diff --check` pass.

### 2026-09-22 — Coroutine-ize TcpRelay on io:: senders

- Rewrote `proxy::TcpRelay` from callback chains into two `exec::task`
  pumps (initial payload plus read/write loop, EOF shuts the peer send
  side) spawned into an `exec::async_scope`; pumps always terminate with
  a value and joining is an atomic count, so no join state outlives the
  scope. Teardown stays close-driven like before (no stop source is
  used); the idle timer keeps its callback leaf shape with a mutex
  around re-arm/cancel. Rejected alternative, do not reintroduce:
  joining via `scope.on_empty()` driven with `start_with_receiver`
  plus `request_stop()` from pump catch/timer/`stop()` — ASan caught
  a heap-use-after-free where `request_stop()`'s synchronous callback
  iteration raced spawn opstate self-deletion (`inplace_stop_source`
  internals), and the join opstate could touch the scope member after
  its destruction. Closing handles to abort pulls is prompt enough
  and keeps all teardown on refcounted state.
- Moved `ProxySession::remote_` to `unique_ptr<io::StreamHandle>`: the
  open result passes through untouched (deletes the `adapt_io_to_core`
  debt there) and the HTTP factories take it directly (deletes two
  `adapt_core_to_io` debts); the relay's client side adapts
  `ProxyStream` at the edge and the accepted tunnel stream adapts at
  the sessions-plane edge.
- Fixed a latent use-after-free the new teardown exposed:
  `CoreToIoStream`/`IoToCoreStream::close()` released `inner_` while
  pulls were outstanding, destroying a TLS stream under a composed
  read. `close()` now only closes; destruction happens with the
  adapter after pulls drain. Diagnosed with an ASan-instrumented
  `clash-native-tests` build (heap-use-after-free in
  `ssl::detail::io_op` after `ProxyStream::~ProxyStream` from
  `TcpRelay::finish`).
- Validated with the Windows x64 Release clang-cl/MSVC build: the two
  HTTPS proxy tests pass 10/10 (previously segfaulted ~always),
  proxy/DNS/transport groups pass, and full runs report 224 passed
  with only the known DNS UDP environment failures; `pixi run
  format`, `format-check`, and `git diff --check` pass.

### 2026-09-22 — Add lldb to the pixi toolchain

- Added `lldb >=22.1.8,<23` to `pixi.toml` dependencies (matches the
  LLVM 22 toolchain) so crashes can be debugged with native backtraces
  instead of log bisection; verified with `pixi run lldb` driving a
  passing test to clean exit. Note: Release builds carry no PDBs, so
  rich symbolization still needs a debug-info build when the time comes.

### 2026-09-23 — Coroutine-ize the Http1 buffered exchange path

- Replaced `Http1ClientSession::read_response` plus its dispatch-side
  write chain with a straight-line `exec::task` (`run_buffered`):
  write request, read response, deliver or retire. Beast operations
  are awaited through `async::callback_sender` with results kept in
  band (Beast shape), so the spawned task always ends with a value;
  initiation throws collapse into `retire_all`. The tunnel branch
  keeps its existing chain untouched (it flips with the sessions
  plane) and still shares the queue/active discipline.
- Cancel/expire/stop semantics are unchanged: they retire the whole
  connection, so no per-exchange stop wiring is needed — the
  in-flight Beast op aborts on close and the task lands in the
  idempotent retire paths. An `exec::async_scope` member owns spawned
  tasks; like the relay, its token is never requested.
- Validated with the Windows x64 Release clang-cl/MSVC build:
  `ExchangeSessionTest` (queued reuse), all `HttpProxyTest`
  cases (upgrade/tunnel and keep-alive reuse), DoH transports, and a
  full run of 227 tests passed; `pixi run format`, `format-check`,
  and `git diff --check` pass.

### 2026-09-23 — Coroutine-ize the Http1 streaming and tunnel paths

- Replaced the remaining hand-written chains in `Http1ClientSession`
  with two straight-line tasks: `run_streaming` (header write, upload
  loop, response header, backpressured download loop) and `run_tunnel`
  (write, interim-response loop, handover or rejection body). Nine
  methods are gone (`read_streaming_request_body`,
  `probe_streaming_request_eof`, `handle_streaming_request_body`,
  `finish_streaming_request_body`, `fail_streaming_request`,
  `read_streaming_response_header`, `pump_streaming_response`,
  `read_tunnel_response_header`, `read_tunnel_rejection`); sync
  helpers (`finish_tunnel`, `fail_active`,
  `fail_streaming_response`, drained/cancel entries) stay.
- Beast operations are awaited through `async::callback_sender` with
  results in band, so spawned tasks always end with a value; the
  single-flight cancel/expire/stop semantics are unchanged (they
  retire the whole connection). Download backpressure parks on a new
  per-exchange `async::watch` space signal bumped by `consumed()` and
  every terminal path instead of direct repump calls.
- Added `tests/transport/http1_exchange_test.cpp` (registered in
  `CMakeLists.txt`): chunked upload with trailers plus a 1 MiB
  backpressured download with trailers, then connection reuse with a
  content-length upload (probe path), against an in-process Beast
  peer. Previously only the tunnel path had real coverage.
- Validated with the Windows x64 Release clang-cl/MSVC build: full
  run of 228 tests passed; `pixi run format`, `format-check`, and
  `git diff --check` pass.

## 2026-09-23

- Migrated the datagram narrow waist to sender-native `io::` handles
  (steps 1-7): `DatagramOpenResult::handle` is now
  `unique_ptr<io::DatagramHandle>` and `Outbound::open_datagram`,
  `EndpointDialer::open_datagram`, and
  `DnsUpstreamDialer::open_datagram` return
  `io::AnySender<DatagramOpenResult>`.
- `Reject`, `HttpProxy`, and `Trojan` outbounds answer opens with
  `stdexec::just`; `DirectOutbound` opens with `just` around a
  dual-inheritance `net::UdpStream` (now `io::DatagramHandle` plus
  `core::DatagramHandle`, with sender-based `async_send_to` /
  `async_receive_from` next to the legacy callback overloads kept for
  the unmigrated SOCKS5 UDP relay); `ShadowsocksOutbound` wraps its
  existing callback internals in `async::bridge_sender` and adapts the
  resulting core handles at the exit.
- Added `net/datagram_handle_adapter.hpp` with `IoToCoreDatagram`
  (io to core, for the DNS/QUIC edges) and `CoreToIoDatagram` (core
  to io, for the Shadowsocks exit); both `close()` implementations
  only close and never release the inner handle, following the
  stream-plane TLS lesson.
- DNS edges adapt at the boundary: query `Operation`s bridge the
  sender back with `start_with_receiver` plus a generation check and
  hand a core handle to the untouched sessions plane; the QUIC
  transport's strand hop ferries the payload through a shared state
  because dispatching a move-only lambda on the main-thread to strand
  path segfaulted in this environment (direct call passed 5/5 but
  would have broken strand safety).
- Migrated the test doubles and the Direct/Shadowsocks UDP tests to
  the sender shape (oversized-send assertion now unpacks the thrown
  `core::Error` via `net::unpack_error`).
- Validated with the Windows x64 Release clang-cl/MSVC build: full
  run of 232 tests passed; `pixi run format`, `format-check`, and
  `git diff --check` pass.

## 2026-09-23

- Started the ExchangeSession plane strangler (part 1): added
  `transport/exchange_session_adapter.hpp` (debt) with io/transport
  request/response/field converters, `TransportBodyStream` (callback
  body reads bridged per pull through `async::callback_sender`;
  EOF completes empty, abort maps to stopped), tunnel/body terminal
  mapping, and `TransportSession`, a generic io:: view over any
  callback transport:: session that captures terminals into an
  `async::oneshot`, rethrows failures as `core::Error`, and cancels
  the in-flight exchange when the downstream stops. A dual-inheritance
  session was rejected because `multiplexed_session()` collides by
  return type across the two bases; the multiplexed view stays null
  until the multiplexed plane migrates.
- Migrated DoH1/DoH2/DoH3, the HTTP proxy CONNECT tunnel, and the
  proxy HTTP upgrade tunnel onto io:: sessions through the adapter.
  DoH1's single-use session now stops instead of per-exchange cancel;
  DoH2's shared session drops per-exchange cancel (orphaned exchanges
  still terminate on their own deadline and late terminals find no
  pending); DoH3's exchange id degrades to a started flag (it was
  never cancelled, and complete_exchange's cancel of an already
  terminal exchange is removed as dead). The proxy upgrade tunnel
  stream now arrives as io:: with no edge adaptation; the HTTP proxy
  tunnel stream drives its io:: inner handle directly instead of
  bridging callbacks.
- Two traps hit during the work: base-class injected names shadow
  namespace vocabulary inside adapter classes (all inner types now
  explicitly `transport::`-qualified), and the transport `Handler`
  is a `std::function` so oneshot senders ride a shared_ptr into the
  terminal lambdas.
- Remaining for part 2: grpc and the proxy forward path (both need
  the streaming upload-body vocabulary), then native io:: session
  entries and deletion of transport::ExchangeSession.
- Validated with the Windows x64 Release clang-cl/MSVC build:
  targeted DNS/proxy/outbound runs green (30/30); `pixi run format`,
  `format-check`, and `git diff --check` pass.

## 2026-09-23

- Finished the ExchangeSession plane strangler (part 2): every
  remaining consumer now runs on io:: sessions through the adapter.
- Added `IoUploadBody` (io to transport upload bridge): each
  transport pull starts one io pull and forwards bytes, EOF (with
  trailer caching), unpacked `core::Error` causes, or abort on stop.
  `TransportSession::exchange_streaming` accepts io:: upload bodies
  through it instead of rejecting them.
- Migrated gRPC: the session, request (framed producer crosses via
  `adapt_transport_body`), response head, and body pulls are io::;
  the header helpers are templated over both field vocabularies.
  Per-exchange cancel in the destructor/close path is dropped in
  favor of body cancels plus late-terminal drops.
- Migrated the proxy forward path: request/response/session are io::,
  the client-body producer crosses via the adapter, the response body
  loop pulls through a terminal-mapping receiver into the existing
  chunk-framing body, and the single-use forward session stops
  instead of per-exchange cancel (`http_exchange_id_` is gone).
- Validated with the Windows x64 Release clang-cl/MSVC build: full
  run of 232 tests passed; `pixi run format`, `format-check`, and
  `git diff --check` pass.
- Remaining for part 3: native io:: session entries in
  http1/http2/http3, io:: upload producers, then deletion of
  transport::ExchangeSession, transport::ExchangeBodyStream, and the
  adapter header.

## 2026-09-23

- Moved the SOCKS5 UDP relay (standalone listener and per-session
  association paths) onto io:: datagram handles: path handles are the
  opened io:: handles with no adaptation, sends drive io:: senders
  with terminal-mapping receivers, and the response loops re-arm one
  io:: pull per completion. The proxy no longer uses
  `IoToCoreDatagram`. Added `net::to_core_destination` for the proxy
  address codec, which still speaks core:: destinations.
- Single-pull loops stay callback re-armed rather than tasks: a pump
  task version was tried first and crashed intermittently in
  teardown; tasks pay off for multi-step chains (relay pumps, HTTP/1
  tasks), not for one pull plus re-arm. Path maps are now mutex
  guarded because receiver terminals race stop()/close() from owner
  threads during teardown.
- Three latent issues fixed along the way, all with permanent tests:
  a use-after-move from unspecified argument evaluation order (the
  sender must be named before the receiver moves the payload; same
  class as the earlier http1/websocket fixes), throwing out of
  `let_error` recovery functions in the `UdpStream` io send/receive
  chains (recoveries now return explicit `just_error` senders), and
  the previously untested io receive path (new sync_wait, task-await,
  and abort-while-parked tests; aborts surface as stopped per the
  handle contract).
- Validated with the Windows x64 Release clang-cl/MSVC build: full
  run of 235 tests passed (including the SOCKS5/Stage1/proxy-server
  combination that caught the teardown race); `pixi run format`,
  `format-check`, and `git diff --check` pass.

## 2026-09-23

- Finished the ExchangeSession plane (part 3): the HTTP/1, HTTP/2,
  and HTTP/3 sessions natively implement io::ExchangeSession, and
  transport::ExchangeSession, transport::ExchangeBodyStream, the
  exchange adapter header, the old http_client.hpp alias header, and
  the shared transport body/tunnel stream headers are deleted.
- Sessions enqueue pendings with oneshot terminal fulfillers
  (success carries the io:: response, failure the core::Error in
  band); entries wrap the receiver with unwrap-and-rethrow plus
  stop-to-cancel, so per-exchange ids only survive inside the
  sessions. HTTP/1 upload pulls now co_await io:: body senders; the
  HTTP/2 and HTTP/3 nghttp callback chains drive io:: uploads through
  a small terminal-mapping receiver into the unchanged resume logic.
- Shared infrastructure moved to io/: QueuedExchangeBodyStream (io::
  pulls over the same dispatch-queue core) and the HTTP CONNECT/
  Upgrade tunnel state/stream pair (sender-native, replacing the
  callback bridges). The HTTP/1 tunnel state/stream pair went the
  same way. Factories now return io:: sessions from the new
  transport/http_sessions.hpp.
- Upload producers (gRPC RequestBody, proxy client-body Beast
  parser, test bodies) implement io::ExchangeBodyStream; DNS/proxy/
  gRPC/test validations run directly on io:: responses with no
  converters left. The HTTP/2 and HTTP/3 io:: multiplexed views stay
  null (raw logical streams migrate with the multiplexed plane), and
  the HTTP/3 datagram view adapts the QUIC core handle at the edge.
- WebSocket handshake header vocabulary (websocket_client options,
  trojan config) moved to io::ExchangeField with the plane.
- Traps (same classes as before): base-class injected names shadow
  namespace vocabulary (explicit transport:: qualification for the
  remaining mux bases), transport Handler is std::function so
  oneshot senders were already shared, and base header removal drops
  transitive core/result.hpp includes (now explicit).
- Validated with the Windows x64 Release clang-cl/MSVC build: full
  run of 235 tests passed; `pixi run format`, `format-check`, and
  `git diff --check` pass.

## 2026-09-23

- Moved the Shadowsocks chain onto io:: handles (part of the
  stream-plane strangler): StreamCarrier exposes sender-native
  read/write over all three backing legs (raw socket and legacy
  core:: legs bridged per operation); the legacy, ss2022, and AEAD
  cipher states drive carrier io:: pulls/pushes through small
  terminal-mapping receivers instead of callback legs; shadow-tls-v3
  takes and returns io:: handles with an io:: shell over its shared
  framing state; UDP-over-TCP takes an io:: stream and serves an
  io:: datagram handle; legacy and AEAD UDP framers serve io::
  datagram handles. Both Shadowsocks outbound exits now hand io::
  handles out with no adaptation.
- Remaining core:: legs are all mux-fed (kcptun SMUX, WebSocket mux
  pool, snappy over kcptun) and migrate with the multiplexed plane;
  the carrier keeps those backing legs plus their per-op bridges.
- Fixed a test hang along the way: the rewritten UDP-over-TCP test
  dropped the context pump its posted completions need, so a runner
  thread now pumps the context during the blocking wait.
- Validated with the Windows x64 Release clang-cl/MSVC build: full
  run of 235 tests passed; `pixi run format`, `format-check`, and
  `git diff --check` pass.

## 2026-09-23

- Made the TLS client handshake sender-native:
  `async_tls_client_handshake(stream, options)` now returns
  `io::AnySender<TlsClientConnection>` (value on success,
  `core::Error` on failure, stop aborts). The existing Asio
  operation is bridged with `async::bridge_sender` plus an
  unwrap-and-rethrow `then`; the starter state rides a shared_ptr
  because the bridge starter must be copyable, and a second start
  fails fast instead of hanging.
- Migrated all nine call sites (DoH1/DoH2/DoT, HTTP proxy, Trojan,
  shadow-TLS, WebSocket client, grpc/http-tunnel test hosts) to
  start the sender with small terminal-mapping receivers.
  `TlsClientHandshake` handles are gone: teardown relies on the
  existing completed_/generation guards (closing strays) with
  request deadlines bounding orphans, matching the exchange-plane
  late-drop doctrine.
- Validated with the Windows x64 Release clang-cl/MSVC build: full
  run of 235 tests passed; `pixi run format`, `format-check`, and
  `git diff --check` pass.

## 2026-09-23

- Coroutine-ized the DoH1 exchange chain into a single `exec::task`:
  dial, TLS handshake, HTTP/1.1 exchange, and response validation
  run straight-line with all terminals funneling through `finish()`,
  replacing the connect/TLS/exchange receivers and their methods.
  The operation owns the task in an `async_scope` that is never
  stop-requested (teardown stays guard-driven with the request
  deadline bounding orphans); `http_response` now takes the response
  value and the exchange-started flag is gone.
- Validated with the Windows x64 Release clang-cl/MSVC build: full
  run of 235 tests passed; `pixi run format`, `format-check`, and
  `git diff --check` pass.

## 2026-09-23

- Coroutine-ized the DoH2 session and DoT session connect chains
  into `exec::task`s: DoH2's dial/TLS/session task plus one task per
  multiplexed query exchange, and DoT's dial/TLS task feeding its
  frame pumps. Receivers and chain glue are deleted; generation
  guards and pending lookups arbitrate late terminals as before.
  Scopes are owned by the session objects and never stop-requested.
- Validated with the Windows x64 Release clang-cl/MSVC build: full
  run of 235 tests passed; `pixi run format`, `format-check`, and
  `git diff --check` pass.

## 2026-09-23

- Coroutine-ized the HTTP proxy and Trojan outbound connect chains
  into per-operation tasks: resolve stays callback (foreign resolver
  API), then TCP connect, TLS/websocket transport, and tunnel or
  request write run straight-line with all terminals funneling
  through finish(). Receivers and stage methods are deleted; abort()
  marks completion so tasks bail at their next guard (the bridge
  drops the late terminal as before). Note: neither connect path has
  unit coverage (only registry validation), so both task bodies were
  re-read against the old stage logic before submitting.
- Validated with the Windows x64 Release clang-cl/MSVC build: full
  run of 235 tests passed; `pixi run format`, `format-check`, and
  `git diff --check` pass.

## 2026-09-23

- Migrated the multiplexed plane to io:: and deleted
  transport::MultiplexedSession: WebSocket mux sessions serve io::
  streams from sender-native opens (oneshot terminals with
  stop-to-cancel); the mux pool and plugin handshake carry io::
  sessions and streams; QUIC connections open io:: streams and
  datagrams with io:: handles throughout; the HTTP/2 and HTTP/3
  stub opens and transport bases are removed (their io::
  multiplexed view stays null, and nobody consumed the old stubs).
- WebSocket/QUIC stream and datagram states keep their
  callback-parked machinery underneath sender shells, matching the
  cipher-state treatment; kcptun SMUX stays on core:: (mux-fed, like
  its pool) and migrates with any future kcptun work.
- One repair along the way: splitting a stream handle edit dropped
  the original read body, which was reconstructed verbatim and
  re-verified by review before building.
- Validated with the Windows x64 Release clang-cl/MSVC build: full
  run of 235 tests passed; `pixi run format`, `format-check`, and
  `git diff --check` pass.

## 2026-09-23

- Migrated the DNS query operation and the QUIC UDP undercarriage to
  io:: datagrams: `AsioDnsTransport::Operation` keeps a
  `unique_ptr<io::DatagramHandle>` and drives send/receive through
  `start_with_receiver` receivers (mismatch re-arms the receive, stop
  and generation guards preserved); `QuicClientConnection` now takes
  `unique_ptr<io::DatagramHandle>`, with `receive_next` and
  `send_next_packet` running through sender receivers that hop back to
  the connection strand; the QUIC DNS transport passes the opened
  handle straight through. Deleted `IoToCoreDatagram` and
  `adapt_io_to_core_datagram`.
- Two repairs found while validating the QUIC flip with
  `DnsTransportTest.FailsWhenQuicDnsUpstreamIsUnavailable` (fast
  ECONNREFUSED on loopback). First, `dispatch(self->executor_,
  [self = std::move(self), ...])` is an unspecified-evaluation-order
  use-after-move: clang evaluates the lambda first and the executor
  read observes the moved-from handle; the executor is now hoisted
  into a local before the move. Never name an object in one call
  argument while moving from it in a sibling argument. Second,
  `fail()`/`retire()` now cancel and close the datagram without
  releasing it (parked sender ops still complete against the handle,
  which dies with the Impl), and `fail()` defers `events_.failed`
  through `check_teardown()` until both pump flags drain, so the
  session can no longer report (and let the caller stop the runtime)
  while completions are still in flight; every flag transition
  funnels through the check. The check must run before the
  retired early-returns, which was caught during the same debugging.
- Validated with the Windows x64 Release clang-cl/MSVC build: full
  run of 235 tests passed (the QUIC unavailable-upstream test 10/10);
  `pixi run format`, `format-check`, and `git diff --check` pass.

## 2026-09-24

- Added `docs/async-pitfalls.md` collecting the sender-migration rules
  that cost real debugging sessions (evaluation-order moves, pump
  teardown joins, close-without-release, stdexec shape notes).

## 2026-09-24

- Migrated `ProxyStream` off `core::StreamHandle`: it now implements
  `io::StreamHandle` with sender shells over the raw/TLS socket
  variant, keeps its handler-style members structurally for the Asio
  composed operations and Beast parsers that drive the proxy
  handshakes, and `detach()` hands the relay a native io:: handle
  (the `adapt_core_to_io` edge is gone). The SOCKS4 user-id/domain
  reads and the UDP-associate control probe now run through
  `start_with_receiver` receivers with matching EOF/close semantics.
- Validated with the Windows x64 Release clang-cl/MSVC build: full
  run of 235 tests passed; `pixi run format`, `format-check`, and
  `git diff --check` pass.

## 2026-09-24

- Migrated the kcptun stack off `core::StreamHandle`: KCP states pump
  UDP through sender receivers and serve io:: streams; the Snappy and
  SMUX framers drive io:: carriers with receiver-based write pumps and
  exact-read loops; the pooled SMUX session opens streams through a
  sender (`just`/`just_error`, synchronous preconditions) and the pool
  exposes `open_stream(endpoint)` as a sender, bridged with
  `start_with_receiver` at the Shadowsocks outbound edge, which now
  feeds `StreamCarrier` io:: handles on both the direct and pooled
  paths. The host KCP probe runs on senders as well.
- Validated with the Windows x64 Release clang-cl/MSVC build: full
  run of 235 tests passed; `pixi run format`, `format-check`, and
  `git diff --check` pass.

## 2026-09-24

- Finished the old handle bases: deleted `core::StreamHandle` and
  `core::DatagramHandle` from `core/outbound.hpp`. Handler aliases
  across the transports and the Shadowsocks outbound became file-local
  `StreamReadHandler`/`StreamWriteHandler`; `StreamCarrier` lost its
  core:: leg; `TcpStream`/`UdpStream` dropped their core:: bases and
  callback legs; `StreamHandleAdapter` is now a concrete io::
  Asio-concept adapter; `CoreToIoStream`/`IoToCoreStream` and both
  adapt functions are gone, and `datagram_handle_adapter.hpp` is
  deleted with `to_core_destination` moved next to the proxy address
  codec that is its only remaining consumer.
- Collateral flips the deletion flushed out: the DNS server's UDP
  receive/respond path, the SOCKS5 listener and session UDP receive
  paths, the DNS probe stream fake, the host WebSocket echo probe,
  and the UDP stream test all run on io:: senders now.
- Validated with the Windows x64 Release clang-cl/MSVC build: full
  run of 235 tests passed; `pixi run format`, `format-check`, and
  `git diff --check` pass.

## 2026-09-24

- Taskified `ShadowsocksConnectOperation`: the resolve / kcptun /
  mux-pool / TCP-plus-plugin / cipher-handshake chain now runs as
  `run()`/`connect_tcp()` coroutines over senders, with the remaining
  callback steps (resolve, mux pool, shadow-tls/restls/jls, ss2022,
  obfs writes) bridged per step and the timer/abort/completed_
  machinery unchanged. Branch behavior and error contexts were
  transliterated; the old step methods are deleted.
- Validated with the Windows x64 Release clang-cl/MSVC build: full
  run of 235 tests passed; `pixi run format`, `format-check`, and
  `git diff --check` pass.

## 2026-09-24

- Taskified the SOCKS5 handshake: `run_socks5_handshake()` runs method
  negotiation, username/password authentication, and request parsing as
  one coroutine over exact-read/full-write helpers, spawned on a new
  session `async_scope`; reply-and-close and target-open terminals stay
  as methods. The ten replaced step methods are deleted.
- Validated with the Windows x64 Release clang-cl/MSVC build: full
  run of 235 tests passed; `pixi run format`, `format-check`, and
  `git diff --check` pass.

## 2026-09-24

- Comment hygiene: removed stale debt notes that referenced the
  deleted datagram adapter (QUIC DNS strand hop) and the already
  migrated forward upload body (proxy upgrade session).
- Validated with the Windows x64 Release clang-cl/MSVC build: full
  run of 235 tests passed; `pixi run format`, `format-check`, and
  `git diff --check` pass.

## 2026-09-24

- Taskified three more connect/handshake chains: the ss2022 open
  operation (`run_open`: request build, carrier/obfs/socket write
  branches), the Shadow-TLS v1/v2 open (`run_open`: validation, TLS
  handshake sender, v1 short-circuit, v2 hash plus delay timer), the
  WebSocket client handshake (`run_open`: validation, deadline timer,
  TLS sender, Beast upgrade), and the direct outbound connect
  (`run_connect`/`connect_addresses`: A/AAAA resolve bridges plus
  async_connect). Timer/abort/completed_ discipline unchanged; old
  step methods deleted.
- Validated with the Windows x64 Release clang-cl/MSVC build: full
  run of 235 tests passed; `pixi run format`, `format-check`, and
  `git diff --check` pass.

## 2026-09-24

- Taskified proxy routing: `route_stream`/`route_datagram` (plus the
  snapshot/fake-ip wrappers `open_stream`/`open_datagram`) are now
  sender-returning coroutines over resolve bridges and dial senders,
  with server-stop gates mapping to cancelled results; the session and
  UDP listener drive them through spawned open/route tasks. Deleted
  the `start_open_for_handler`/`RouteReceiver` bridges.
- Validated with the Windows x64 Release clang-cl/MSVC build: full
  run of 235 tests passed; `pixi run format`, `format-check`, and
  `git diff --check` pass.

## 2026-09-24

- Taskified the SOCKS4 edges: the request read runs as
  `run_socks4_request` and the reply write as `run_socks4_reply` on
  the session scope; the user-id/domain pulls were already
  sender-native.
- Validated with the Windows x64 Release clang-cl/MSVC build: full
  run of 235 tests passed; `pixi run format`, `format-check`, and
  `git diff --check` pass.

## 2026-09-24

- Taskified the WebSocket plugin opens: `WebSocketPluginOperation`
  and `WebSocketPluginMuxOperation` run as `run_open` coroutines over
  handshake/mux bridges with cancel-handle aborters; the pool
  queue/lifecycle stays callback-driven by design.
- Validated with the Windows x64 Release clang-cl/MSVC build: full
  run of 235 tests passed; `pixi run format`, `format-check`, and
  `git diff --check` pass.

## 2026-09-24

- Coroutine pass assessment: all linear connect/handshake chains are
  now tasks (SS/Direct/Trojan/HTTP-proxy connects, SOCKS4/5
  handshakes, proxy routing, ss2022/shadow-tls/WS-plugin/WS-client
  opens, DNS DoH1/2/DoT chains). Deliberately left callback-shaped:
  Botan-driven opens (restls/jls/shadow-tls-v3), ngtcp2/nghttp/beast
  event loops (QUIC, HTTP/2/3 sessions, HTTP forward orchestration),
  pump/timer loops (kcptun/smux/UoT/cipher states, gRPC/WS frames),
  registry-pattern APIs (DNS resolvers, bootstrap), single-call
  bridged leaves (obfs helpers), and the test-only gRPC client API.

## 2026-09-24

- Replaced task-local `callback_sender` wrappers over value-carrying
  Asio initiations with `exec::asio::use_sender` plus `then`/`let_error`
  error-context mapping (direct/Trojan/SS/HTTP-proxy connects, SS
  TCP request writes, SOCKS5/4 handshake reads/writes, ss2022 socket
  write). Deliberately kept: void-signature initiations (`use_sender`
  only supports value-carrying signatures — Beast handshake, steady
  timers), in-band `HttpOpResult` sites in http1_client, custom
  non-Asio initiations, and all state-machine shells/pumps.
- Validated with the Windows x64 Release clang-cl/MSVC build: full
  run of 235 tests passed; `pixi run format`, `format-check`, and
  `git diff --check` pass.

## 2026-09-24

- Synced `docs/architecture.md` with the migrated reality: `io::`
  capability interfaces as the only async I/O bases, `io::AnySender`
  outbound narrow waist, sender completion contract
  (value/`core::Error`/stopped), actual `ErrorCode` vocabulary and
  field order, exchange-ID DNS registry shape, owned (non-Dart)
  channel primitives, no `request_stop` teardown flow, completed
  Stage 2/3 and partial Stage 4 statuses.

## 2026-09-24

- Closed the known-issues entry on the four plain-UDP DNS timeout
  tests: root cause was local AdGuard filtering intercepting loopback
  UDP DNS traffic, not a project defect. Verified all four pass on
  the current Windows x64 Release build.

## 2026-09-24

- Documented the taskification boundary in `docs/async-pitfalls.md`:
  engine drivers, pump loops, registry APIs, bridged leaves,
  void-signature initiations, and test-only APIs stay callback-shaped
  on purpose.

## 2026-09-24

- Added Trojan UDP-over-TCP: new `src/transport/trojan/` protocol
  directory with `packet_conn` (`addr|u16len|CRLF|payload` framing,
  8192-byte send chunking, CRLF/ceiling validation) over
  `io::StreamHandle`, wired into `TrojanOutbound::open_datagram`
  (UDP command header, multi-destination semantics). New
  `trojan_transport_test` covers wire bytes, round-trip, chunking,
  and framing errors. Full suite: 240 passed.

## 2026-09-24

- Matched Mihomo Trojan ALPN defaults: empty `alpn_protocols` now
  offers `{"h2", "http/1.1"}` on TCP and `{"http/1.1"}` on
  WebSocket; explicit lists override. Full suite: 240 passed.

## 2026-09-24

- Added Trojan-SS (ss-opts): extracted the stateless AEAD crypto
  primitives from `transport/shadowsocks/crypto` to shared
  `transport/proxy/crypto` (namespace `transport::proxy`; SS callers
  re-pointed, behavior unchanged), and added a Trojan-side AEAD
  stream wrapper in `transport/trojan/ss_stream` (salt + sealed
  0x3FFF chunks, classic AEAD only). The SS outbound's stateful
  stream handle was deliberately not extracted. New SsStream tests
  verify sealing against the shared primitives and bidirectional
  framing. Full suite: 243 passed.
