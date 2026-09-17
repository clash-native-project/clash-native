# HTTP and QUIC Libraries

This document records the current implementation boundary. DNS transports are
experimental, and their presence does not imply production readiness or
interoperability with every upstream.

| Library | Responsibility in clash-native | Source |
| --- | --- | --- |
| Boost.Beast | HTTP/1.1 message construction and parsing for DoH | vcpkg |
| nghttp2 | HTTP/2 framing and multiplexed DoH streams | vcpkg |
| nghttp3 | HTTP/3 framing and QPACK for DoH3 | vcpkg |
| ngtcp2 | QUIC packet, connection, stream, and timer state | CMake FetchContent, commit `843aa72100b508e192f119439a943028b0c6f030` |
| BoringSSL | TLS and QUIC cryptographic callbacks for ngtcp2 | vcpkg |
| quic-go | Independent DoQ and DoH/3 multiplexing test servers; test-only dependency | Go module v0.54.0, MIT |

Boost.Asio owns the UDP handle, asynchronous reads and writes, deadlines, and
the strand that serializes each QUIC session. ngtcp2 and nghttp3 are library
components called by that adapter; they do not start another event loop.

The DNS transport source currently contains DoH/1.1, DoH/2, DoQ, and DoH/3
adapters. The DoH/2 loopback fixture uses nghttp2. A fresh Windows x64 build
and test run is required to validate this replacement; API smoke tests alone
do not prove public-server interoperability. The Go quic-go fixtures verify
that concurrent DoQ and DoH/3 exchanges share one accepted QUIC connection;
they are test-only and do not add a runtime dependency to clash-native.
