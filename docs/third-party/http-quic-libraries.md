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

Boost.Asio owns the UDP handle, asynchronous reads and writes, deadlines, and
the strand used by each QUIC exchange. ngtcp2 and nghttp3 are library
components called by that adapter; they do not start another event loop.

The DNS transport source currently contains DoH/1.1, DoH/2, DoQ, and DoH/3
adapters. The DoH/2 loopback fixture uses nghttp2. A fresh Windows x64 build
and test run is required to validate this replacement; API smoke tests alone
do not prove public-server interoperability.
