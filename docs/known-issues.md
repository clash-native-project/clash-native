# Known Issues

This document records observed issues that are deferred for later investigation. It distinguishes measured behavior from suspected causes.

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
