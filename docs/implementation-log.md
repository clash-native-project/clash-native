# Implementation Log

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
