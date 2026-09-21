# Design Guidelines

This document defines where transport and proxy protocol code belongs. It is
an implementation structure guide, not a protocol catalogue or a progress
report.

## Layer model

The code is organized as a composition of three layers:

1. **Base transports** carry bytes, datagrams, exchanges, or multiplexed
   streams. They are useful outside one proxy protocol and belong under
   `src/transport`.
2. **Shared proxy carriers** are protocol layers commonly reused by more than
   one proxy protocol. They belong under `src/transport/proxy`.
3. **Proxy protocol implementations** define authentication, framing,
   addressing, and protocol-specific behavior. They belong with the owning
   outbound or in a protocol-specific transport directory; they must not be
   placed in another protocol's directory just because that directory already
   exists.

The dependency direction is one way:

```text
proxy protocol
    -> shared proxy carrier (when needed)
    -> base transport
```

Base transports must not include proxy protocol code. A shared proxy carrier
must not depend on Shadowsocks, Trojan, or another individual protocol.
Trojan code must therefore never include a Shadowsocks transport merely to
obtain a reusable carrier.

## Directory responsibilities

### `src/transport`

Use this directory for connection and application transports that do not
belong to one proxy protocol. Examples include:

- TCP, UDP, and TLS stream adapters;
- HTTP/1.1 exchange and tunnel clients;
- HTTP/2 and HTTP/3 sessions;
- QUIC sessions and datagram support;
- the generic HTTP/1.1 WebSocket client carrier;
- `StreamHandle`, `DatagramHandle`, `MultiplexedSession`, and
  `ExchangeSession` adapters.

DNS transports may use these modules directly. A base transport can be used by
an outbound proxy as well, but it must remain independent of that outbound's
authentication and wire framing.

### `src/transport/proxy`

Use this directory for proxy-oriented carriers that are shared by multiple
proxy protocols. Typical examples are:

- ShadowTLS;
- ResTLS;
- JLS;
- a shared proxy camouflage layer;
- another carrier whose framing is independent of the payload protocol.

These modules may compose the base transport interfaces, but they must expose a
carrier API rather than an API named after one consumer. A Shadowsocks or
Trojan outbound can use the same carrier without importing the other outbound.

### `src/transport/shadowsocks`

Keep this directory for Shadowsocks-specific transport code, including classic
and Shadowsocks 2022 framing, cipher and key handling, Shadowsocks UDP
encoding, and Shadowsocks-specific plugin or mux framing. The generic
WebSocket carrier itself belongs in `src/transport`; only the Shadowsocks
payload or plugin framing belongs here.

Existing files under this directory are not a reason to put new shared code
there. When an existing implementation is shown to be reusable by another
proxy protocol, extract the reusable part into `src/transport/proxy` and keep
only a thin protocol-specific wrapper in this directory if compatibility
requires one. The WebSocket v2ray mux and gost SMUX implementations remain in
this directory while they are consumed only by Shadowsocks plugins; they can
move to `src/transport/proxy` when another proxy protocol uses the same wire
framing.

### Outbound and protocol-specific code

Outbound classes under `src/outbound` own configuration, endpoint selection,
and composition of transport layers. Protocol-specific framing that is only
used by one outbound may stay next to that outbound or in a dedicated
`src/transport/<protocol>` directory when it is large enough to deserve a
transport module. It must not be placed under an unrelated protocol's
directory.

For example, Trojan authentication and request framing are Trojan code. A
Trojan outbound may compose the generic WebSocket client and a shared
`src/transport/proxy` carrier, but it must not depend on
`src/transport/shadowsocks`.

## Reuse criteria

Extract a component into a shared directory when all of the following are
true:

- at least two independent consumers need the same wire behavior;
- the component's framing and lifecycle can be described without naming one
  consumer protocol;
- its API maps cleanly to `StreamHandle`, `DatagramHandle`,
  `MultiplexedSession`, or `ExchangeSession`;
- ownership, cancellation, deadlines, and error reporting are defined at the
  shared layer.

Do not create a generic wrapper only to make directory names look uniform. A
single-protocol implementation should remain specific until a second real
consumer exists. When the second consumer appears, extract the common carrier
and update both callers in the same change; do not copy the implementation.

## New implementation checklist

Before adding a transport module:

1. Identify whether it is a base transport, a shared proxy carrier, or a
   protocol-specific framing layer.
2. Place it in the corresponding directory and state its allowed dependency
   direction in the header comment or design notes when the boundary is not
   obvious.
3. Keep proxy authentication and payload framing out of base transport APIs.
4. Add focused wire tests and, when a real peer exists, an interoperability
   test for the composed stack.
5. Record the module boundary and the validation scope in
   `docs/implementation-log.md`.
