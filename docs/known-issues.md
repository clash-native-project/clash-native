# Known Issues

This document records observed issues that are deferred for later investigation. It distinguishes measured behavior from suspected causes.

## Mihomo SMUX peer closes the full stream after FIN

- **Status:** Deferred; interoperability limitation in the tested Mihomo
  server path.
- **Scope:** Shadowsocks `kcptun` over KCP/SMUX on Windows x64.

The C++ kcptun stream adapter sends an SMUX FIN when the local caller invokes
`shutdown_send`. In the tested Mihomo listener, receiving that FIN causes the
listener-side stream to be closed completely. The peer therefore does not keep
the reverse direction available for a true bidirectional half-close. This is
different from a KCP packet-crypt, FEC, Snappy, or SMUX framing failure: normal
bidirectional streams and concurrent pooled streams interoperate successfully.

The current evidence only establishes the behavior of the tested Mihomo
listener and handler. It does not prove that every SMUX implementation has the
same behavior, nor does it justify claiming full half-close interoperability.
Revisit this issue with a peer that preserves the opposite direction after FIN,
then add an end-to-end test before changing the transport contract.

## Large UDP DNS bursts can lose datagrams on Windows

- **Status:** Deferred; root cause is not isolated.
- **Scope tested:** Windows x64, IPv4 loopback, large UDP datagrams sent concurrently.

### Evidence

A standalone Go UDP echo probe used eight concurrent clients and one server goroutine that read each datagram with `ReadFromUDP` and echoed it with `WriteToUDP`. Each client waited up to 500 ms for its echo. Across five bursts (40 datagrams per size), the following echoes timed out:

| Datagram size | Missing echoes |
| ---: | ---: |
| 12,300 bytes | 2 / 40 |
| 13,370 bytes | 10 / 40 |
| 18,058 bytes | 15 / 40 |

Sequential single-datagram echo checks succeeded 3 / 3 times at each tested size: 12,300, 13,370, 18,058, 60,000, and 65,507 bytes. This does not establish a fixed 13 KB datagram limit.

The same-machine DNS-over-QUIC interoperability size sweep sent eight concurrent padded DNS queries through the C++ DNS UDP listener. At 8,192 and 12,288 bytes of EDNS padding, both DoQ and DoH/3 completed 8 / 8 queries. At 13,312 bytes, both completed 7 / 8; at 14,336 bytes, DoQ completed 7 / 8 and DoH/3 6 / 8; at 16,384 and 18,000 bytes, DoQ completed 6 / 8 and DoH/3 5 / 8. This earlier sweep ran once per size, so it is indicative rather than a stable threshold measurement.

The Go probe's destination used the Windows `Loopback Pseudo-Interface 1`, whose reported MTU was 4,294,967,295. The observed loopback losses therefore do not establish loss caused by IP fragmentation. The current QUIC multiplex interoperability test uses the DNS TCP listener as its local input to isolate QUIC stream behavior; it does not cover this UDP-ingress scenario.

### Current assessment

The evidence shows burst-dependent loss for unusually large UDP datagrams, including in a standalone Go probe without the C++ DNS server. It does not identify whether the loss occurs in the receiving socket queue, receiver scheduling, or another part of the local loopback path. The project's `DnsServer` provides a 65,535-byte application buffer for each UDP receive operation; this is not a configured kernel `SO_RCVBUF` value and does not prove that bursts will be drained without loss.

This is not evidence that ordinary-sized DNS queries fail, nor does it establish a universal 13 KB limit. Large UDP datagrams can also encounter IP-fragmentation loss on real network paths; UDP guidance recommends avoiding datagrams larger than the path MTU because losing one fragment loses the whole datagram ([RFC 8085, Section 3.2](https://www.rfc-editor.org/rfc/rfc8085#section-3.2)). The loopback probe did not validate that network-path condition.

### Deferred investigation

When this issue is resumed, preserve a repeatable Go burst probe, record send and receive counts separately, inspect the effective socket receive-buffer size, and exercise the C++ DNS UDP listener independently from QUIC. Test pacing and burst sizes separately, then validate large packets over a real network interface before attributing loss to IP fragmentation. No production behavior change is made as part of this issue record.

## Local HTTP and SOCKS5 proxy listeners are plaintext and unauthenticated

- **Status:** Accepted for the current local-proxy scope; inbound TLS and authentication are not implemented.
- **Scope:** The local HTTP listener accepts plaintext HTTP/1.1, and the SOCKS5 listener negotiates only the no-authentication method. Neither listener wraps the client-to-proxy connection in TLS.

For HTTPS destinations, the HTTP listener supports `CONNECT`; TLS then runs between the client and destination inside that tunnel. This does not encrypt the client-to-proxy hop. The TLS and Basic authentication options on an upstream HTTP proxy outbound are separate capabilities and do not add TLS or authentication to the local listeners.

This is recorded as a scope limitation, not a current blocker for local use. Revisit it if the listeners are intended to serve remote clients.

## HTTP/3 is not integrated as a proxy endpoint

- **Status:** Deferred; the HTTP/3 client transport is implemented, but proxy ingress and HTTP-proxy outbound integration are not.
- **Scope:** The local proxy listener and the HTTP proxy outbound node.

The shared HTTP/3 client session supports buffered and streaming HTTP exchanges, CONNECT, and Extended CONNECT over QUIC. It is used by DoH/3 and has independent Go QUIC interoperability coverage, including concurrent streamed request and response bodies with trailers. This transport support does not make the local proxy listener or the HTTP proxy outbound speak HTTP/3.

The local proxy listener currently accepts HTTP/1.1 over TCP. The HTTP proxy outbound uses HTTP/1.1 over TCP for plaintext endpoints, and negotiates HTTP/2 or HTTP/1.1 over TLS for TLS endpoints. It does not use QUIC or HTTP/3. Consequently, clients cannot connect to this project as an HTTP/3 proxy, and an HTTP/3 upstream proxy cannot currently be selected as an outbound. DoH/3 support is separate from both proxy paths.
