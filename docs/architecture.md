# Architecture Blueprint

## 1. Status and intent

clash-native is an experimental native C++ proxy core inspired by the design
of Clash and Mihomo. It is an independent implementation: Mihomo provides
architectural and behavioral reference points, but its source tree is not part
of this project.

This document defines the intended boundaries of the project before the
protocol surface becomes large. It is a blueprint, not a claim that the
described system is already implemented or production-ready. The current
implementation establishes only the initial CMake core/frontend boundary and
the experimental SOCKS5 bootstrap path; the remaining modules are planned.

The existing SOCKS5 listener is only a bootstrap test used to verify that the
toolchain, Asio event loop, TCP connection establishment, and bidirectional
relay work together. Its `ProxyServer::Session` structure is not a target
architecture and must not be used as the template for future protocol code.

## 2. Goals

- Build a reusable native C++ proxy engine named `clash-native-core`.
- Keep the core independent of any particular process, CLI, or foreign
  language ABI.
- Support a standalone `clash-native` process as one frontend over the core.
- Support a C API as another frontend over the same core.
- Keep protocol logic portable and isolate operating-system integration behind
  platform capability interfaces.
- Complete and functionally validate the portable proxy core on Windows before
  implementing native platform traffic-capture and route-management features.
- Use explicit ownership, cancellation, and shutdown rules for every
  asynchronous resource.
- Scale network work across multiple Asio runtimes without sharing mutable
  connection state between them.
- Prefer dependencies available through vcpkg when their ports, build options,
  licenses, and supported targets are suitable.
- Use Zig's C and C++ compiler drivers as the Linux release and
  cross-compilation toolchain.
- Keep Linux deployment possible on old router-oriented systems, with Linux
  3.10 and glibc 2.17 as the initial compatibility baseline.

## 3. Non-goals for the first stage

- Production readiness or security claims.
- Source compatibility with Mihomo internals.
- Complete Mihomo configuration or control API compatibility.
- Implementing every proxy protocol before the core lifecycle is validated.
- Implementing TUN, transparent proxying, route manipulation, or other native
  platform features before ordinary proxy flows work.
- Replacing QUICHE's visitor, delegate, alarm, or packet-writer model with
  senders.
- Passing every packet or stream chunk through a cross-runtime channel.

Mihomo-compatible configuration and control surfaces may be added later as
frontends or translation layers. They must not redefine the internal core
model.

## 4. Product boundaries

```text
                    +-----------------------+
                    | clash-native process  |
                    | CLI, signals, control |
                    +-----------+-----------+
                                |
                                v
+-------------------+   +-----------------------+
| C API facade      |-->| clash-native-core     |
| opaque ABI types  |   | engine and lifecycle  |
+-------------------+   +-----------+-----------+
                                |
                   +------------+------------+
                   | runtime and platform     |
                   | capability adapters      |
                   +-------------------------+
```

`clash-native-core` is the primary product and owns the actual proxy engine.
The process executable and C API are peers above it:

- The process frontend owns command-line parsing, signals, process-level
  configuration sources, and an optional control service.
- The C API facade translates stable C ABI calls, callbacks, and error values
  into core operations.
- Neither frontend contains routing, protocol, DNS, relay, or QUIC logic.
- The core never depends on CLI or C API headers.

## 5. Dependency direction

The intended dependency direction is top to bottom only:

```text
frontends: daemon / C API
              |
composition: engine / lifecycle / configuration application
              |
policy: metadata / router / rules / groups / runtime snapshot
              |
data plane: inbound / outbound / relay / DNS
              |
protocols: SOCKS / HTTP / Shadowsocks / Trojan / QUIC-based protocols
              |
I/O: TCP / UDP / resolver / timers / buffers
              |
runtime and platform capability interfaces
```

Cross-cutting facilities such as logging, metrics, errors, and cancellation
must expose dependency-light interfaces. They must not create upward
dependencies from the I/O or protocol layers into a frontend.

## 6. Proposed core modules

The exact directory names may evolve, but each responsibility needs an
independent boundary.

| Module | Responsibility |
| --- | --- |
| `base` | Dependency-light types, addresses, errors, IDs, and utilities |
| `async` | stdexec integration, scopes, channels, and scheduler adapters |
| `runtime` | Worker runtimes, blocking pool, lifecycle, and task ownership |
| `net` | Portable TCP/UDP operations, buffers, timers, and resolver facade |
| `config` | Raw input model, validation, and immutable runtime descriptions |
| `inbound` | Listener/session interfaces and inbound protocol implementations |
| `metadata` | Normalized source, destination, network, and inbound information |
| `router` | Rule evaluation and outbound selection |
| `outbound` | Direct, reject, proxy, and proxy-group abstractions |
| `relay` | TCP copying, half-close, backpressure, idle timeout, and accounting |
| `dns` | Resolver policy, cache, hosts, and later enhanced DNS behavior |
| `protocol` | Proxy handshakes and protocol-specific stream/packet transports |
| `quic` | QUICHE ownership, visitor, packet writer, alarm, and TLS adapters |
| `platform` | Capability interfaces plus isolated operating-system backends |
| `observability` | Logging facade, metrics, connection registry, and tracing hooks |

A protocol implementation may depend on portable network and cryptographic
interfaces. It must not call Linux, Windows, or mobile APIs directly.

## 7. Core data path

### 7.1 TCP

The first architectural proxy flow is:

```text
listener
  -> inbound protocol session
  -> normalized ConnectionMetadata
  -> router and rule engine
  -> selected outbound
  -> outbound protocol connection
  -> bidirectional relay
  -> accounting and deterministic close
```

`Direct` and `Reject` are normal outbound implementations, not special cases
inside the listener. SOCKS5 and HTTP parsing belong to inbound protocol
sessions and do not own routing or direct dialing.

The relay layer must eventually define and test:

- backpressure and bounded buffering;
- cancellation of both directions;
- TCP half-close behavior;
- idle, connect, and handshake timeouts;
- first-error and simultaneous-close behavior;
- connection accounting and final status.

### 7.2 UDP

UDP has a separate session model:

```text
UDP listener
  -> PacketMetadata
  -> session/NAT key
  -> DNS and routing policy
  -> OutboundPacketTransport
  -> response mapping and expiry
```

UDP must not be modeled as a TCP connection with different read calls. It
requires explicit definitions for session identity, multiple destinations,
expiry, MTU, packet ownership, and error handling.

### 7.3 Stable protocol-facing contracts

The reusable boundary is not a universal wire-protocol base class. It is the
small contract between the engine and an outbound implementation. The router,
DNS dial policy, relay, accounting, and frontends must not need a new code path
when a protocol is added.

At that boundary, every outbound presents the same two data-plane entry points
and may support either or both:

- establish a byte-stream connection for a normalized destination;
- establish a datagram association capable of sending and receiving addressed
  packets.

The following sketch expresses the intended shape. Names and concrete result
types may change before implementation and are not a frozen public ABI:

```cpp
struct OutboundCapabilities {
  bool stream;
  DatagramSemantics datagram;
  TargetRequirement stream_target;
  TargetRequirement datagram_target;
};

class Outbound {
 public:
  virtual const OutboundDescriptor& descriptor() const noexcept = 0;
  virtual OutboundCapabilities capabilities() const noexcept = 0;

  virtual stdexec::task<Result<StreamOpenResult>> connect_stream(
      StreamRequest request) = 0;

  virtual stdexec::task<Result<DatagramOpenResult>> open_datagram(
      DatagramRequest request) = 0;

  virtual ~Outbound() = default;
};
```

`DatagramSemantics` distinguishes unsupported, fixed-destination, and
multi-destination associations. Whether the association uses native UDP,
stream encapsulation, or a multiplexed session is an implementation detail,
not a new router-facing operation.

`Direct`, `Reject`, encrypted proxy protocols, and outbound groups implement
the same engine-facing contract. Unsupported operations return a typed
unsupported result and must agree with the advertised capabilities.

The minimum descriptor contains stable identity and protocol kind for routing,
diagnostics, and configuration references. JSON serialization, API response
formatting, delay history, health state, and dashboard fields do not belong to
this interface.

This follows the useful part of Mihomo's `ProxyAdapter` design: its tunnel
normally needs only a stream dial operation or a packet operation. It
deliberately does not copy the broader interface, which also contains
presentation, health, group-unwrapping, and protocol-specific flags.

### 7.4 Requests, destinations, and established handles

`ConnectionMetadata` describes the observed inbound flow and routing facts. A
protocol must not mutate shared metadata to perform DNS resolution, redirect
routing, or signal a special control action.

The engine derives immutable operation requests from metadata:

| Type | Required contents |
| --- | --- |
| `StreamRequest` | Destination, immutable flow context, optional replayable first payload, deadline, and trace context |
| `DatagramRequest` | Initial destination when applicable, association policy, deadline, and trace context |
| `Destination` | Either a domain plus port or an IP address plus port |

The request types do not expose raw configuration nodes. They refer only to
validated runtime objects owned by the active snapshot.

Successful operations return move-only established objects rather than raw
Asio sockets:

| Type | Responsibility |
| --- | --- |
| `StreamOpenResult` | Established stream, selected chain, and first-payload commit state |
| `DatagramOpenResult` | Established datagram handle, selected chain, and association semantics |
| `StreamHandle` | Asynchronous read, write, half-close, cancellation, endpoints, and transport ownership |
| `DatagramHandle` | Addressed send/receive, cancellation, association semantics, MTU information, and transport ownership |
| `ConnectionTrace` | Selected outbound/group chain and diagnostic annotations outside the I/O interface |

An asynchronous buffer view must remain valid until its operation completes.
The buffer API must therefore carry explicit ownership or a lease; protocol
implementations must not retain an unowned `span` across suspension.

`DatagramHandle` preserves packet boundaries and source addresses. Its send
operation takes a destination for every packet unless the handle explicitly
has fixed-destination semantics. Its receive result contains both the payload
and the peer address. Native UDP, UDP over a stream, and a multiplexed QUIC
session may implement the same handle, but their framing and session ownership
remain internal.

The addressed datagram API retains `Destination`; it must not reduce every
domain to an IP-only socket address at the engine boundary. A protocol that
supports remote DNS can encode the domain in each packet, while an
`ip_required` implementation receives a separately resolved target.

### 7.5 Address resolution contract

Destination resolution is an orchestration decision, not an incidental side
effect of a protocol method. Each outbound advertises the accepted target form
for stream and datagram operations:

- `domain_or_ip`: preserve a domain when the remote protocol can resolve it;
- `ip_required`: resolve through the selected resolver role before opening the
  protocol operation.

Proxy server endpoint resolution and proxied destination resolution are
different operations. The former uses `ProxyEndpointResolver`; a direct
destination uses `DirectResolver`; an outbound that supports remote resolution
may receive the original domain unchanged.

Resolution creates a separate operation input or resolved target. It must not
overwrite the flow's original destination because rules, logging, FakeIP
mapping, retries, and response translation may still need it. Resolution and
retry also must not introduce an outbound/resolver dependency cycle.

Configuration validation builds one dependency graph containing at least:

- outbound-group membership;
- an outbound used to reach another outbound's proxy server;
- DNS upstream egress through a named outbound or group;
- resolver roles required by those outbound endpoints.

The graph is validated for missing references, incompatible stream/datagram
capabilities, and cycles before publication. Runtime operations still carry a
visited-outbound guard and a bounded depth as defense against stale provider
state or implementation defects.

Layer-three protocols are not represented by an `is_layer_three` boolean on
the stream interface. When layer-three outbound support becomes necessary, it
will use a separate capability contract. This prevents DNS-loop avoidance and
IP-packet behavior from leaking into ordinary stream and datagram operations.

### 7.6 Composable outbound construction

A concrete outbound is assembled from explicit components:

```text
validated outbound description
  -> proxy endpoint connector and dial policy
  -> optional carrier transport
  -> protocol handshake/framing
  -> established stream or datagram handle
```

The responsibilities are:

| Component | Responsibility |
| --- | --- |
| `EndpointConnector` | Resolve and connect to the proxy server through the selected dial policy |
| `CarrierConnector` | Establish reusable carriers such as TLS, WebSocket, HTTP-based transport, or a multiplexed session |
| `ProtocolClient` | Authenticate, encode the requested destination, and install protocol framing |
| `OutboundOrchestrator` | Apply deadlines, cancellation, cleanup, tracing, and common result conversion |

Composition is an implementation-reuse mechanism, not a promise that every
carrier and protocol can be combined arbitrarily. Configuration validation and
the protocol factory expose only combinations with defined semantics and
tests.

A simple stream protocol normally performs:

1. connect to its configured server through `EndpointConnector`;
2. establish its configured carrier, such as TLS;
3. execute its destination handshake through `ProtocolClient`;
4. return the resulting `StreamHandle` to the common relay.

A datagram implementation may open a native UDP socket, create an association
over a control stream, or borrow a logical channel from a multiplexed session.
Those choices must not change the router or UDP relay interface.

QUIC-based protocols fit the same public outbound contract but do not have to
pretend that a QUIC connection is a decorated TCP stream. Their internal
carrier component may own a reusable QUIC session and open protocol streams or
datagram channels from it.

Common carrier components own carrier behavior only. They must not know about
traffic rules, inbound types, frontend configuration syntax, or a particular
proxy protocol's authentication fields.

An `EndpointConnector` may use a physical Direct dial or delegate to a named
outbound. This is how chained proxies are represented; it is not a separate
socket API. The delegated operation uses normalized internal-flow metadata,
retains every selected outbound for the operation lifetime, and appends each
hop to the trace. A QUIC carrier requires a datagram-capable endpoint path,
while an ordinary TLS carrier requires a stream-capable path.

Protocol construction uses an explicit registry assembled by core startup. A
factory receives a typed, validated protocol description plus a narrow service
bundle and returns an outbound. Compatibility frontends translate their raw
configuration into those descriptions. The registry must not depend on global
static initialization, and a protocol omitted at build time produces an
explicit unavailable-feature validation error.

### 7.7 Establishment, first payload, and retry

`connect_stream` success means that every locally observable step required by
the selected mode has completed. This includes endpoint connection, carrier
handshake, request transmission, and a positive peer response when the wire
protocol defines one. For protocols such as Shadowsocks or Trojan that do not
acknowledge the final target, success means only that their defined opening
steps have completed; it cannot promise that the destination application is
reachable.

The baseline implementation completes establishment before returning an
ordinary `StreamHandle`. A handle must not secretly open its carrier, perform
authentication, or wait for a protocol response on an unrelated first read or
write.

Early-data optimization requires an explicit first-flight contract:

```text
replayable initial payload owned by StreamRequest
  -> endpoint/carrier/protocol first flight
  -> StreamOpenResult reports payload uncommitted or committed
  -> common relay advances its input only after committed success
```

The initial payload is all-or-nothing at this boundary. On an uncommitted
failure, a group may try another eligible outbound with the same payload. Once
application bytes may have reached a peer, transparent fallback is forbidden
unless that protocol has a separately documented replay-safe operation.
Groups and health observers receive establishment-stage and commit information
directly; they must not discover handshake state by downcasting wrappers or
attaching an invisible callback to the first ordinary write.

QUIC 0-RTT and protocol early data follow the same rule. Arbitrary application
payload is not considered replay-safe merely because a transport library can
send it before handshake confirmation. Each protocol must define what can be
replayed and how rejection falls back to a confirmed session.

Connect, carrier-handshake, protocol-handshake, and idle deadlines are separate
policy values. A single expired deadline cancels the underlying I/O and drains
its completion before the operation reports timeout.

### 7.8 Inbound protocol boundary

Inbound and outbound implementations are intentionally asymmetric and must not
be forced into one protocol interface. They may share address codecs,
cryptographic primitives, and carrier implementations, but they have different
control flow.

An inbound protocol session performs the following work:

```text
accepted stream or received packet
  -> protocol parsing and authentication
  -> normalized metadata and destination
  -> engine dispatch
  -> protocol-specific success or failure response
  -> common relay or datagram session
```

The normalized inbound request carries an exactly-once reply controller when
the protocol requires a response after outbound establishment. For example,
SOCKS5 and HTTP CONNECT must not report success before the selected outbound
has actually opened. Protocols without such an acknowledgement use a no-op
reply policy.

Authentication negotiation and final connection acknowledgement are distinct
reply phases. A SOCKS5 inbound may acknowledge its selected authentication
method immediately, but the final CONNECT result is produced only from the
outbound open result. The reply controller maps typed engine failures to the
closest protocol-specific response and prevents duplicate success/failure
writes during cancellation races.

Inbound code may parse, authenticate, and encode its own replies. It must not
select an outbound, implement traffic rules, call Direct directly, or own the
common relay. Native TUN and transparent-proxy adapters eventually produce the
same normalized requests without adding a second routing path.

### 7.9 Groups and management concerns

An outbound group implements the same stream and datagram operations. It
selects a member from the current immutable group state, retains that member
for the complete asynchronous operation, delegates the request, and appends a
selection record to `ConnectionTrace`.

Selection is operation-aware. A group asked for datagrams filters or rejects
members that cannot satisfy the required datagram and target semantics. Its
advertised capabilities are a conservative summary for validation and user
interfaces, not permission to select an incompatible member at runtime.

Failure feedback records the stage at which an operation failed and whether
application data was committed. Connection refusal, carrier handshake failure,
authentication failure, protocol rejection, timeout, and active-stream I/O
failure are not interchangeable health signals. Fallback policy may retry only
at a replay-safe boundary.

Selection, fallback, and load-balancing policy are separate from wire
protocols. A group must not unwrap itself through protocol-specific casts, and
the relay must not know whether its handle came through a group.

The following facilities wrap or observe an outbound instead of expanding the
core interface:

- health checking and URL tests;
- latency history and availability state;
- connection accounting and metrics;
- control-service and C API serialization;
- retry, fallback, and circuit-breaking policy;
- configuration compatibility views.

Routing actions that rewrite metadata or request another rule pass are also
separate router operations. They must never call a connection method merely to
produce a routing side effect.

### 7.10 Async ownership, cancellation, and reload

`stdexec::task` is lazy. Returning a task from a member function does not by
itself keep the outbound object alive until that task starts and completes.
The dispatch layer must retain a strong reference to the selected outbound in
the operation state. An established handle must likewise retain every carrier,
session pool, and immutable configuration object required for its lifetime.

Reload publishes a new outbound registry but retires the old registry only
after its operations and handles drain. A connection opened from an old
snapshot continues using that snapshot; it must not start reading protocol
options from the new configuration midway through a session.

Stateful outbounds and carrier pools follow `active -> retiring -> drained`.
A retiring instance rejects new opens but continues serving existing streams
and datagram associations. Its pool, timers, and transport are destroyed only
after all child handles and operations have released their ownership. New
configuration never closes a shared QUIC or multiplexed session out from under
an established flow.

Every connect, handshake, datagram-open, read, and write operation receives the
parent stop token. Cancellation must reach the lowest cancellable Asio or
QUICHE operation, and completion must be observed before its state is
destroyed. Protocol implementations must not start detached cleanup or reader
loops that escape their session scope.

Expected network failures use the project's typed error model. Cooperative
cancellation remains `set_stopped`; it is not silently converted into a
generic socket error. The common error taxonomy must distinguish at least
resolution, endpoint connection, carrier handshake, authentication, protocol
framing, timeout, rejection, unsupported capability, and transport I/O.

### 7.11 Protocol extension contract

Adding a normal outbound protocol should require only:

1. a validated protocol description and explicit factory registration;
2. its authentication, handshake, and stream framing implementation;
3. its datagram framing and association implementation when supported;
4. composition with supported endpoint and carrier components;
5. an accurate capability declaration;
6. protocol-specific interoperability and malformed-input tests.

It must not require edits to the router, common TCP relay, common UDP relay,
DNS policy engine, connection registry, standalone frontend, or C API.

Every outbound implementation, including Direct, Reject, and groups, runs
through a shared conformance suite covering:

- capability declarations and unsupported-operation behavior;
- domain and IP destination handling;
- direct and chained proxy-server endpoint paths, including dependency-cycle
  rejection;
- cancellation before start, during connection, during handshake, and during
  active I/O;
- establishment readiness, first-payload commit, replay-safe fallback, and
  protocol early-data rejection;
- timeout and failure cleanup without leaked operations;
- scheduler affinity and absence of detached work;
- TCP relay, half-close, peer-close, and backpressure behavior when stream is
  supported;
- packet boundaries, source-address preservation, multiple destinations, and
  association expiry when datagrams are supported;
- pooled-session capacity, retirement, and child-handle lifetime when
  multiplexing is supported;
- operation and handle lifetime across configuration reload;
- independent implementation interoperability for each wire protocol.

The current experimental SOCKS5 server proves only the earliest loopback flow.
It is not the base class or control-flow template for this contract and should
be decomposed when the real inbound, outbound, and relay modules are
introduced.

## 8. Runtime model

### 8.1 Runtime set

The core uses multiple independent Asio runtimes. The worker count is
configurable and defaults to four.

Each worker owns:

- one `boost::asio::io_context`;
- one scheduler adapter for stdexec;
- one work guard;
- one worker thread;
- a structured-concurrency scope for its long-lived child operations;
- the sessions and protocol objects assigned to that worker.

The runtime count is a configured count, not automatically identical to the
number of logical CPUs. A later configuration layer may offer an `auto` mode.

### 8.2 Affinity

A connection is assigned to one worker and remains there for its lifetime.
Its sockets, timers, resolver operations, QUICHE connection objects, and
mutable protocol state must not migrate between workers.

Load balancing happens when a new session is accepted. Listener distribution
is a platform/runtime strategy: implementations may use a shared acceptor,
per-worker acceptors where supported, or another adapter. Protocol code must
not depend on the selected accept strategy.

Cross-worker communication carries commands, immutable snapshots, ownership
transfers made before a session starts, and aggregated events. The hot data
path should not bounce packet buffers between workers.

### 8.3 Blocking work

A separately configurable blocking pool is allowed for operations that cannot
be expressed as non-blocking I/O, such as selected filesystem, database, or
CPU-heavy jobs.

Blocking work must never execute on an I/O worker. Its result returns through
a sender or channel and must resume on the owning I/O scheduler before it
touches session state.

## 9. stdexec and channel usage

### 9.1 stdexec boundary

Asio remains the network and timer runtime. stdexec is used to compose
operations, express cancellation, maintain scheduler affinity, and own
concurrent child work.

- `starts_on` selects where an operation and a task's home scheduler begin.
- `continues_on` moves downstream work to an explicitly selected scheduler.
- `on` is reserved for temporarily executing a nested operation elsewhere and
  returning to the caller's scheduler.
- QUICHE callbacks remain callbacks inside the QUIC adapter.
- Callback-based external APIs should be wrapped as senders at their adapter
  boundary instead of exposing callback state to business layers.

### 9.2 Channel primitive

The Tokio-style channel implementation from `dart_cpp_bridge` is a candidate
for extraction into the core async module. It provides:

- move-only `oneshot` request/result delivery;
- cloneable-producer, single-consumer MPSC delivery;
- bounded MPSC with asynchronous backpressure;
- zero-capacity rendezvous channels;
- close propagation;
- stop-token-aware cancellation of parked sends and receives.

The implementation may be reused, but it must be imported as an owned core
component rather than retaining Dart-specific names or include paths. The
import must also:

- preserve the applicable MIT license notice and record its provenance;
- port the existing channel concurrency and cancellation tests;
- decide whether the generic stream-combinator dependency is needed by the
  proxy core;
- account for its stdexec and `rigtorp::MPMCQueue` dependencies;
- use the project namespace and formatting rules.

Recommended uses are:

| Need | Primitive |
| --- | --- |
| one operation result or request/reply | `oneshot` |
| bounded worker/control queue | bounded MPSC |
| synchronous handoff with no queue | zero-capacity MPSC |
| low-volume event stream with a proven bound elsewhere | unbounded MPSC |

Unbounded channels are not the default for traffic-bearing queues. Channels
must not become a packet relay bus between I/O workers.

Channel completion can run on the thread that sends, closes, or requests
cancellation. A continuation that touches worker-owned state must explicitly
return to the owning scheduler or run inside a task whose home-scheduler
behavior has been verified.

### 9.3 What channels do not solve

Channels simplify cross-runtime ownership and request/reply flows, but they do
not by themselves guarantee:

- that child tasks have completed before their owner is destroyed;
- that a socket, timer, or QUICHE object is accessed only on its owner thread;
- that callback contexts outlive late callbacks;
- that all parked sends and receives are completed during shutdown;
- that application objects are destroyed after their runtime dependencies.

Those guarantees belong to the runtime, scope, adapter, and shutdown design.

## 10. Ownership, cancellation, and shutdown

Every long-lived asynchronous operation must be owned by a service scope or a
session scope. Detached work without an owner is not part of the core model.

Cancellation is cooperative and must propagate from engine to service, from
service to session, and from session to its I/O operations. Destructors are a
last safety boundary, not the primary cancellation mechanism.

The intended engine shutdown sequence is:

1. Reject new public operations and configuration changes.
2. Stop accepting new sessions.
3. Request stop on service and session scopes.
4. Close control/work channels and cancel outstanding I/O.
5. Drain all scopes while their worker event loops are still running.
6. Release work guards after owned operations have completed.
7. Join worker and blocking-pool threads.
8. Destroy runtime-dependent services and platform adapters.

No frontend may destroy `clash-native-core` while a callback into that
frontend is still possible.

## 11. Configuration and reload

The initial configuration model reuses Mihomo's core concepts but does not
promise syntax compatibility.

```text
configuration source
  -> RawConfig
  -> validation and normalization
  -> immutable RuntimeSnapshot
  -> Engine::apply(snapshot)
```

Runtime code consumes validated objects and must not repeatedly interpret raw
YAML fields. A future Mihomo-compatible parser should translate into the same
validated model rather than creating an alternate engine path.

Reload must construct and validate the replacement state before publishing
it. Reusable state may be retained deliberately, but running components must
not observe a half-applied configuration.

## 12. DNS architecture

DNS is a core routing subsystem, not a utility hidden inside a socket dialer.
The core needs rich DNS behavior comparable in shape to mature proxy engines,
but its protocol, policy, and lifecycle responsibilities must remain separate.

### 12.1 Responsibility split

The DNS subsystem is divided into the following components:

| Component | Responsibility |
| --- | --- |
| `DnsMessageCodec` | DNS message parsing, serialization, names, and resource records |
| `DnsTransport` | UDP, TCP, DoT, DoH, and later DoQ exchanges |
| `DnsUpstream` | One configured server, transport, endpoint, and dial policy |
| `DnsUpstreamGroup` | Concurrent selection, fallback, health, and retry policy |
| `DnsCache` | Positive/negative entries, TTL expiry, stale policy, and limits |
| `DnsPolicyRouter` | Select an upstream group from the queried domain |
| `DnsUpstreamDialer` | Select how the connection to an upstream DNS server exits |
| `ResolverService` | Lookup API, query coalescing, cancellation, and result assembly |
| `DnsServer` | Optional local UDP/TCP service over `ResolverService` |
| `FakeIpStore` | Fake-IP allocation, reverse mapping, persistence, and expiry |

The wire codec may initially use a suitable maintained dependency. Upstream
selection, routing integration, caching policy, resolver roles, FakeIP, and
lifecycle belong to clash-native-core regardless of the codec choice.

### 12.2 Three independent routing decisions

DNS-related routing contains three independent decisions:

```text
application connection
  -> TrafficRouter
  -> selected outbound

DNS question name
  -> DnsPolicyRouter
  -> selected DNS upstream group

DNS upstream endpoint
  -> DnsUpstreamDialer
  -> direct, named outbound, or normal traffic rules
```

These decisions must not be collapsed into one flag. Selecting a DNS server
does not imply how that server is reached, and selecting an outbound for the
application connection does not automatically select its resolver.

`DnsPolicyRouter` should eventually support exact names, suffixes, domain
sets, rule sets, and ordered first-match behavior. A compatibility frontend
may later translate Mihomo-style `nameserver-policy` configuration into this
internal model.

`DnsUpstreamDialer` supports three explicit egress policies:

- direct connection, optionally bound by a platform network capability;
- a named outbound or outbound group;
- the ordinary traffic router.

The last option is equivalent in purpose to rule-aware DNS upstream dialing,
but the internal API should express it as a dial policy instead of scattering
special `respect-rules` checks through transports.

### 12.3 Resolver roles and dependency cycles

The engine uses distinct resolver roles:

| Role | Purpose |
| --- | --- |
| `BootstrapResolver` | Resolve DNS upstream endpoints without using the general proxy DNS path |
| `DefaultResolver` | Resolve ordinary application destinations |
| `ProxyEndpointResolver` | Resolve proxy server hostnames before an outbound can connect |
| `DirectResolver` | Resolve destinations selected for the Direct outbound |

The roles may share implementations and cache storage, but they have different
policies. They must remain visible in the dependency graph.

`BootstrapResolver` is the root of that graph. Its configured upstream
endpoints must be usable without recursively depending on
`DefaultResolver`, `ProxyEndpointResolver`, or an outbound whose own server
still needs resolution.

Configuration validation must reject resolver/outbound dependency cycles
before a runtime snapshot is applied. Runtime recursion guards are still
required as a defensive boundary, but they are not the primary design.

### 12.4 Query pipeline

The logical query path is:

```text
DnsQuestion
  -> hosts/static override
  -> cache lookup
  -> in-flight query coalescing
  -> DnsPolicyRouter
  -> primary DnsUpstreamGroup
  -> response validation
  -> optional fallback decision
  -> cache insertion
  -> DnsAnswer
```

The fallback decision can depend on the question name, response code, returned
IP addresses, GeoIP/IP-set matchers, or transport failure. Lazy and eager
fallback queries are policy choices and must share the same cancellation
owner.

Cache keys must include every input that can change the answer, including at
least normalized name, query type, class, and relevant policy options. Expired
entries, negative answers, stale serving, and configuration reload behavior
must be explicit rather than accidental consequences of a generic container.

Concurrent equivalent misses should share one upstream operation. Cancelling
one waiter must not cancel the shared operation while other live waiters still
need it.

### 12.5 FakeIP and mapping

FakeIP is an enhancer over resolver results, not an upstream transport.

```text
local DNS request
  -> FakeIP policy
  -> allocate or reuse synthetic address
  -> store host <-> synthetic-address mapping
  -> return synthetic answer

intercepted connection to synthetic address
  -> reverse lookup
  -> restore original host metadata
  -> normal traffic routing
```

The store needs bounded allocation, address reuse rules, reverse lookup,
optional persistence, reload transfer, and clear failure behavior when a
mapping is missing. FakeIP filters may reuse domain/rule matchers, but they are
not the same decision as DNS upstream selection.

### 12.6 Multi-runtime ownership

The initial implementation assigns one logical `ResolverService` owner to a
selected I/O runtime. It owns the cache, in-flight-query table, upstream
connection pools, and DNS configuration generation. This does not require an
additional thread.

```text
caller worker
  -> bounded MPSC query request
  -> ResolverService owner runtime
  -> upstream exchange
  -> oneshot result
  -> caller's owning scheduler
```

The caller must resume on its own scheduler before touching connection state.
Shutdown stops new requests, closes the request channel, cancels upstream
operations, completes or stops pending replies, and drains the DNS scope
before its runtime work guard is released.

If measurement later shows the single owner is a bottleneck, transports and
cache shards may be distributed per worker without changing the public
resolver or policy interfaces.

### 12.7 Implementation order

DNS implementation proceeds in independently testable slices:

1. resolver interfaces, role separation, and a system-resolver adapter;
2. DNS message codec plus UDP and TCP forwarding with truncation fallback;
3. bounded cache, TTL handling, cancellation, and in-flight coalescing;
4. upstream groups, domain policy, fallback, and upstream dial policies;
5. local UDP/TCP DNS service, hosts, mapping, and FakeIP;
6. DoT and DoH;
7. DoQ after the QUICHE adapter is validated.

Each slice must include malformed-response, timeout, cancellation, reload, and
shutdown tests appropriate to the behavior it introduces.

## 13. QUICHE boundary

QUICHE owns QUIC and HTTP/3 protocol behavior. clash-native owns the event
loop, UDP sockets, routing, proxy protocols, application lifecycle, and
platform integration.

```text
Asio UDP receive
  -> QUICHE packet input
  -> QUICHE connection/session callbacks
  -> core QUIC stream abstraction

QUICHE packet writer
  -> core UDP writer
  -> Asio UDP send

QUICHE alarm
  -> core alarm adapter
  -> Asio steady timer
```

QUICHE connections, visitors, writers, alarms, and their buffers stay on one
I/O worker. Sender wrappers may represent completion to higher layers, but
they must not change QUICHE object affinity.

QUICHE and BoringSSL integration is a separate build milestone. It must be
validated independently for every target architecture and linkage profile
before a QUIC-based proxy protocol is placed on the main roadmap.

## 14. Platform boundary

Portable code depends on capability interfaces. Backends may be organized as:

```text
platform/
  common/
  posix/
  linux/
  windows/
  android/
  apple/
```

The POSIX layer contains genuinely portable POSIX behavior. Linux-specific
TUN, Netlink, transparent sockets, process lookup, and routing must remain in
the Linux backend.

Platform capabilities include:

- socket options and listener distribution;
- TUN/VPN device access;
- transparent proxy and original-destination lookup;
- route and DNS configuration;
- process attribution;
- filesystem and certificate locations;
- signal and service integration;
- platform logging sinks.

Missing capabilities must be reported explicitly. Protocol modules must not
accumulate platform preprocessor branches as a substitute for adapters.

### 14.1 Windows-first core development

Windows is the primary development and functional-test platform for the
portable proxy core. Before native platform work begins, the Windows test
suite is expected to cover:

- runtime ownership, scheduler affinity, cancellation, and clean shutdown;
- configuration validation, snapshots, and reload;
- Direct and Reject outbounds;
- SOCKS5 and HTTP inbounds;
- TCP and UDP relay behavior;
- DNS forwarding, cache, policy routing, fallback, and FakeIP;
- rule matching and outbound selection;
- Shadowsocks and Trojan;
- QUICHE integration and selected QUIC-based protocols;
- connection accounting, logging interfaces, and resource limits;
- protocol interoperability and malformed-input handling.

These features must depend only on portable core, Asio, protocol, crypto, and
dependency interfaces. A protocol must not require a TUN device, transparent
socket option, route mutation, process lookup, or another operating-system
feature to be testable.

### 14.2 Platform work starts after the core gate

Native platform work begins only after the portable core exit criteria in the
delivery roadmap are met. It then connects operating-system traffic sources
and controls to the existing core:

```text
platform traffic capture
  -> normalized core inbound
  -> existing metadata/router/outbound/relay path
  -> platform response and route handling
```

The intended order is:

1. finish portable proxy behavior and its full Windows functional suite;
2. establish Linux release builds and rerun the portable suite on Linux;
3. add Linux TUN, transparent proxy, Netlink, route, and DNS integration;
4. add other operating-system adapters only when required.

Platform adapters must not introduce alternate DNS, routing, outbound, or
relay engines. They supply capabilities to clash-native-core and reuse the
same data path validated on Windows.

Windows validation proves portable protocol and core behavior. It does not
prove Linux ABI compatibility, Linux 3.10 compatibility, platform socket
semantics, TUN/TProxy behavior, route changes, daemon integration, or
performance on router hardware. Those claims require their own target tests.

## 15. Frontends

### 15.1 Standalone process

The standalone `clash-native` process is a composition root over
`clash-native-core`. It may provide:

- CLI and configuration-file loading;
- signal and service lifecycle;
- a local control API;
- logging sink selection;
- Linux router integration.

The process frontend is initially Linux-oriented, but the core remains
portable.

### 15.2 C API

The C API is a thin ABI facade over the same engine. It exposes opaque handles,
fixed-width values, explicit ownership functions, callbacks, and stable error
objects. It must not expose:

- C++ templates or standard-library containers;
- Asio or stdexec types;
- QUICHE classes;
- C++ exceptions across the ABI;
- frontend-specific global state.

The first consumer platforms and ABI stability policy remain later decisions.

## 16. Build and deployment profiles

All supported project builds use Clang-family compiler drivers, CMake, Ninja,
and Python orchestration. Windows development uses MSYS2 Clang. Linux release
and cross-compilation builds use `zig cc` and `zig c++`. The initial
architecture scope is 32-bit and 64-bit x86.

| Profile | Architecture | Compiler target | Runtime target | Linkage intent | Status |
| --- | --- | --- | --- | --- | --- |
| Windows development | x86-64 | MSYS2 Clang | MSYS2 environment | vcpkg libraries as selected | bootstrap exists |
| Windows development | x86 | MSYS2 Clang | MSYS2 environment | custom triplet required | planned |
| Linux glibc | x86-64 | `x86_64-linux-gnu.2.17` | Linux 3.10, glibc 2.17 | compatible dynamic runtime | planned |
| Linux glibc | x86 | `x86-linux-gnu.2.17` | Linux 3.10, glibc 2.17 | compatible dynamic runtime | planned |
| Linux musl | x86-64 | `x86_64-linux-musl` | Linux 3.10 | static where feasible | feasibility required |
| Linux musl | x86 | `x86-linux-musl` | Linux 3.10 | static where feasible | feasibility required |

The glibc and musl profiles solve different deployment problems:

- The glibc profile must not require symbols newer than glibc 2.17.
- A musl static executable avoids a target glibc dependency, but still has a
  kernel/system-call baseline and runtime data requirements.
- Both profiles use Zig compiler drivers. The target triple selects the libc
  and ABI; Zig is the toolchain rather than an additional target ABI.

Static linkage claims apply only after inspecting the final executable. DNS,
certificate roots, configuration, GeoData, and other runtime files must be
documented separately from ELF linkage.

### 16.1 Linux toolchain policy

The project must pin one exact Zig version for release and CI builds. The
Python build entry point selects a named Linux profile and supplies the
corresponding Zig target to a CMake toolchain file. CMake continues to own the
project build graph; adopting Zig compiler drivers does not require adopting
the Zig build system.

All C and C++ dependencies in a final artifact must be compiled for the same
Zig target. A Linux cross build must not accidentally consume host object
files, static libraries, shared libraries, CMake package targets, or
`pkg-config` results. A vcpkg Linux triplet must chain-load the same Zig
toolchain and preserve the target ABI for every port it builds.

The initial planned triplet/profile matrix is:

```text
x64-linux-zig-glibc217
x86-linux-zig-glibc217
x64-linux-zig-musl
x86-linux-zig-musl
```

These are project profile names; their concrete triplet files and compiler
flags are accepted only after a minimal C and C++ probe, vcpkg dependency
probe, and final executable have been validated.

### 16.2 Compatibility validation

The glibc suffix in a Zig target constrains the libc ABI selected by the
toolchain. It does not by itself prove compatibility with Linux 3.10.
Dependencies and project code must also avoid unguarded use of newer kernel
interfaces.

The glibc profile is accepted only when the final ELF artifact:

- has no required `GLIBC_*` symbol version newer than `GLIBC_2.17`;
- uses the expected 32-bit or 64-bit ELF interpreter and architecture;
- contains no dependency built for the host ABI;
- runs on a representative glibc 2.17 environment.

The musl profile is accepted only when final-artifact inspection confirms the
intended static linkage and architecture. Both profiles require runtime tests
on a real or virtual Linux 3.10 kernel before the kernel baseline is claimed.
A container running on a newer host kernel is not sufficient evidence for
that claim.

Each third-party dependency must record:

- pinned version and source;
- license and notice requirements;
- supported architectures and minimum platform assumptions;
- static/dynamic linkage behavior;
- exceptions, RTTI, and compiler flags where relevant;
- binary-size and maintenance impact;
- whether vcpkg can own it or a separate integration is required.

## 17. Delivery roadmap

The roadmap has a hard boundary between the portable proxy core and native
platform integration. Stages 0 through 4 are developed and functionally
validated on Windows. Stages 5 and 6 begin only after the portable core gate.

### Stage 0: Windows core and build foundations

- define core/frontend/platform target boundaries;
- define the protocol-facing stream/datagram contracts and shared outbound
  conformance harness;
- introduce runtime-set and scheduler abstractions;
- import and validate the required channel primitives;
- establish Windows x86-64 and x86 Clang build profiles;
- define lifecycle, error, cancellation, and testing conventions;
- establish the Go black-box harness, minimal core test host, independent TCP
  and UDP endpoints, and deterministic process-lifecycle utilities.

### Stage 1: ordinary proxy core

- `Direct` and `Reject` outbounds;
- SOCKS5 and HTTP inbounds;
- replace the experimental monolithic SOCKS5 flow with the normalized inbound,
  outbound, handle, and relay boundaries;
- normalized metadata and router boundary;
- TCP relay with timeouts, cancellation, half-close, and accounting;
- C++ loopback integration tests plus Go-driven black-box and independent
  interoperability tests.

### Stage 2: DNS and routing

- resolver roles and bootstrap dependency validation;
- unified outbound, group, chained-endpoint, and resolver dependency graph with
  cycle validation;
- DNS UDP/TCP forwarding, cache, and in-flight query coalescing;
- DNS upstream policy, fallback, and upstream egress routing;
- local DNS service and FakeIP;
- validated routing rules;
- immutable runtime snapshots and reload;
- initial proxy groups and connection registry.

### Stage 3: encrypted stream protocols

- Shadowsocks;
- Trojan;
- protocol interoperability and failure-path tests.

### Stage 4: QUIC-based protocols

- QUICHE and BoringSSL build integration;
- Asio UDP writer/alarm/visitor adapters;
- a real QUIC/HTTP3 validation flow;
- pooled-session capacity, retirement, and 0-RTT replay-safety validation;
- selected QUIC-based proxy protocols.

### Portable core exit gate

Before Linux or other native traffic-capture features are implemented:

- all Stage 0 through Stage 4 targets build with the supported Windows Clang
  toolchain;
- the complete portable unit and integration suite passes on Windows;
- TCP, UDP, DNS, encrypted-stream, and selected QUIC-based flows pass
  interoperability tests;
- cancellation, reload, connection churn, and runtime shutdown stress tests
  pass;
- protocol and routing code contains no dependency on native platform traffic
  capture or route-management APIs;
- known gaps are recorded as portable-core issues rather than deferred into a
  platform adapter.

Meeting this gate means the proxy engine is ready to be hosted by platform
integrations. It does not mean that Linux builds or router deployment have
already been validated.

### Stage 5: Linux portability and process delivery

- pin the Zig version used by release and CI builds;
- establish x86 and x86-64 glibc 2.17 and musl profiles;
- build all dependencies with the selected Zig target;
- rerun the complete portable core suite on Linux;
- validate the Linux 3.10 and final-artifact requirements;
- provide the initial standalone Linux process over clash-native-core.

### Stage 6: native platform features

- Linux TUN and transparent proxy support first;
- Linux Netlink, route, socket-option, and DNS platform adapters;
- end-to-end tests through each native traffic-capture path;
- additional operating-system integrations only after their capability and
  lifecycle boundaries are defined.

### Stage 7: frontend compatibility

- standalone control service;
- C API facade and language bindings;
- optional Mihomo-compatible configuration or control translation layers.

## 18. Validation principles

Every stage must validate the narrow behavior it introduces:

- formatting and warning-clean Clang builds;
- unit tests for parsers, rules, ownership, and cancellation;
- loopback integration tests for complete proxy flows;
- interoperability tests against independent protocol implementations;
- stress tests for channel cancellation, connection churn, reload, and
  shutdown;
- target-architecture builds for both x86 and x86-64;
- final-artifact inspection for glibc symbol versions, static linkage, and
  binary size;
- dependency probes that confirm vcpkg ports inherit the selected Zig target;
- runtime tests on representative old Linux environments before claiming the
  Linux 3.10/glibc 2.17 baseline.

### 18.1 Independent evidence

Network-visible correctness must not be established only by having one
clash-native component communicate with another clash-native component. A
client and server that share the same protocol interpretation can contain
matching defects and still pass their tests. The same limitation applies when
the test imports the production parser, encoder, framing code, or configuration
normalizer to construct its expected result.

The project therefore distinguishes these forms of evidence:

- clash-native client to clash-native server is a useful integration and
  regression test, but is not an interoperability test;
- a test written in another language reduces accidental code sharing, but is
  not automatically an independent protocol oracle;
- a maintained external client or server, fixed RFC examples, published test
  vectors, and captured known-good messages provide independent evidence;
- agreement with two independent implementations is preferred for ambiguous
  behavior or security-sensitive protocol features.

No single layer replaces the others. C++ tests are still required for internal
invariants and failure paths that cannot be observed reliably through a socket.
External black-box tests are required for the behavior that peers actually
observe on the network.

### 18.2 Test implementation responsibilities

The intended division of responsibility is:

| Layer | Primary technology | Responsibility |
| --- | --- | --- |
| Build and suite orchestration | Python | Configure and build targets, select suites, prepare cached reference artifacts, and invoke CTest and Go tests |
| Unit and component tests | C++ | Parsers, codecs, standard vectors, state machines, ownership, schedulers, cancellation, channels, and platform adapter contracts |
| Portable black-box and interoperability tests | Go | Process management, TCP and UDP endpoints, independent clients, traffic verification, fault injection, and reference implementation orchestration |
| Control-plane tests | Deno, optional | HTTP, WebSocket, JSON schema, configuration API, and dashboard-facing behavior |
| Target platform tests | Platform-specific harnesses | TUN, transparent proxy, route changes, DNS mutation, service integration, and kernel behavior |

Go is the primary network-test language. Its test harness is test-only code and
must not become a dependency of `clash-native-core` or any shipped artifact.
Deno can be added where its Web APIs make control-plane tests simpler, but it
is not the primary harness for low-level TCP, UDP, DNS, or binary proxy
protocol behavior. The project should not maintain equivalent Go and Deno
network suites.

### 18.3 System under test

Black-box tests must exercise the real core data path through one of these
process boundaries:

- the `clash-native` standalone process when that frontend is available; or
- a minimal `clash-native-test-host` linked to `clash-native-core` during early
  core development.

The test host may load configuration, start and stop the core, expose selected
listener addresses, and report readiness. It must not implement proxy
handshakes, routing, DNS policy, relay behavior, or protocol framing on behalf
of the core. This keeps the early core independently testable without making
the later standalone product a prerequisite.

The C API requires additional ABI tests using small external consumers, but
those tests complement rather than replace the core network suite.

### 18.4 Black-box topology

Portable tests construct complete paths with independently observable ends:

```text
independent client
  -> clash-native inbound
  -> router and selected outbound
  -> independent TCP, UDP, HTTP, or DNS endpoint
```

For outbound wire protocols, the topology becomes:

```text
plain test client
  -> portable clash-native inbound
  -> clash-native protocol outbound
  -> pinned reference protocol server
  -> independent destination endpoint
```

For server-side protocol support, the direction is reversed:

```text
pinned reference protocol client
  -> clash-native protocol inbound
  -> independent destination endpoint
```

The harness verifies destination selection, byte integrity, packet boundaries,
addresses, errors, timing constraints, and shutdown behavior at the independent
endpoints. It must not declare success only because a handshake completed.

Initial protocol evidence should use:

- independent TCP and UDP echo endpoints for Direct and Reject behavior;
- a Go SOCKS5 client and standard HTTP client behavior for SOCKS5 and HTTP
  inbounds, supplemented by RFC-derived malformed and boundary cases;
- a mature DNS message library or reference DNS programs for authoritative
  answers and query inspection, rather than a second project-owned DNS codec;
- pinned external clients or servers for Shadowsocks, Trojan, and later
  QUIC-based protocols;
- fixed protocol vectors and negative cases alongside live interoperability.

Hand-written protocol messages are appropriate for narrowly targeted malformed
input and boundary tests. They must not be the sole success-path oracle for a
complete protocol implementation.

### 18.5 Portable network behavior

The Windows portable suite must cover behavior that frequently escapes simple
loopback success tests:

- TCP fragmentation and coalescing across every handshake field;
- partial writes, slow readers, backpressure, large transfers, half-close,
  reset, peer disappearance, and connection reuse where supported;
- cancellation and timeout during resolution, connection, authentication,
  handshake, first-flight delivery, and active relay;
- UDP packet boundaries, multiple sources and destinations, concurrent
  associations, expiry, loss, duplication, reordering, truncation, and useful
  MTU boundaries;
- DNS identifiers and flags, UDP and TCP behavior, truncation fallback, cache
  expiry, negative answers, concurrent identical queries, policy selection,
  and FakeIP mapping lifetime;
- authentication rejection, unsupported commands, malformed lengths,
  premature EOF, excess data, and failure without premature success;
- reload, draining, resource limits, repeated startup and shutdown, and
  reference process failure.

A user-space TCP or UDP fault proxy written in Go should provide portable
fragmentation, delay, bandwidth limiting, drop, duplication, and reordering on
Windows. Linux network namespaces and traffic-control facilities may later add
platform-specific coverage, but are not substitutes for the portable suite.

### 18.6 Harness lifecycle and reproducibility

Every black-box case owns all processes, sockets, temporary configuration,
certificates, and logs that it creates. The harness must:

- allocate isolated loopback listeners and avoid fixed shared ports;
- use an explicit readiness signal or bounded connection probe instead of a
  fixed startup sleep;
- apply a deadline to every process and network operation;
- capture stdout and stderr and include them in failures;
- terminate owned process trees and wait for their exit on every path;
- clean temporary resources after success, failure, cancellation, or timeout;
- record random seeds and preserve minimized failing inputs as regression
  cases;
- generate test certificates from a deterministic test CA and never use
  production credentials;
- support parallel execution without shared mutable configuration or port
  assumptions.

Reference implementations are supply-chain inputs. Each reference manifest
must record its project, version or commit, source, checksum or container
digest, license, supported architectures, and the cases that use it. Normal
test runs should consume already prepared artifacts and should not silently
download `latest` binaries or images from the network. Refreshing a reference
is an explicit, reviewable maintenance operation.

The planned additive layout is:

```text
tests/
  core/                  # C++ unit tests
  platform/              # C++ platform contract tests
  proxy/                 # C++ component and loopback tests
  runtime/               # C++ runtime and lifecycle tests
  interop/
    go.mod
    harness/             # process, readiness, ports, logs, and cleanup
    endpoints/           # independent TCP, UDP, HTTP, and DNS endpoints
    cases/               # black-box protocol and routing cases
    references/          # pinned reference manifests and configuration
scripts/
  build.py
  test.py                # suite selection and orchestration
```

Existing test directories need not be reorganized merely to create this
layout. New interop infrastructure should be added incrementally as real core
boundaries replace the experimental SOCKS5 path.

### 18.7 Test suites and gates

Tests are grouped by cost and evidence rather than by one undifferentiated
command:

- `unit`: fast C++ unit and component tests on every supported build;
- `blackbox`: portable Go-driven TCP, UDP, DNS, routing, and lifecycle flows;
- `interop`: cases requiring pinned independent protocol implementations;
- `stress`: repeated connection, cancellation, reload, fault, and shutdown
  scenarios;
- `platform`: Linux kernel and native traffic-capture integration tests;
- `reference-refresh`: an explicit maintenance workflow, never a normal test
  prerequisite.

The Windows core gate requires `unit`, `blackbox`, and the applicable `interop`
suite. Short pull-request runs may use a documented subset of stress cases;
scheduled or release validation runs the extended suite. A failure must report
the selected suite, topology, reference version, random seed when present, and
all participating process logs.

Validation claims are separated by scope:

| Evidence | What it proves |
| --- | --- |
| Windows portable suite | Core lifecycle, proxy, DNS, routing, and protocol behavior exercised by that suite |
| Linux portable suite | The same core behavior under the selected Linux runtime and toolchain |
| ELF and dependency inspection | Architecture, linkage, and glibc symbol-version requirements |
| Linux 3.10 runtime test | Compatibility of exercised paths with the kernel baseline |
| Platform integration test | TUN, transparent proxy, routes, DNS mutation, or other named native behavior |
| Router hardware test | Resource use and behavior on that tested device class |

A successful Windows test suite is therefore the required functional gate for
portable core development, but it is not evidence that another architecture,
libc, kernel, router environment, or platform adapter works.

## 19. Deferred decisions

The architecture deliberately leaves these questions open until evidence is
available:

- exact Zig version to pin for Linux release and CI builds;
- exact memory, thread-count, and final binary-size budgets;
- first platforms and stability policy for the C API;
- concrete listener distribution strategy on each operating system;
- QUICHE/BoringSSL feasibility and size on 32-bit x86;
- maintained DNS message codec dependency versus an owned implementation;
- exact type-erasure and typed-result forms used by the protocol-facing async
  contracts;
- exact Mihomo configuration and control API compatibility level;
- the first QUIC-based proxy protocol after the QUIC adapter is validated.

Deferred decisions should be recorded as short architecture decision records
when implementation evidence is available. They must not be hidden as
accidental behavior in a build script or protocol implementation.
