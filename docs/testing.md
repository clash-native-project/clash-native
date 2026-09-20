# Stage 0 Development and Testing Conventions

Stage 0 establishes testable ownership and lifecycle primitives without
claiming that the complete proxy engine exists.

## Ownership and lifecycle

- `clash-native-core` owns portable runtime, platform-adapter, and proxy
  implementation code.
- `clash-native` is a process composition root and must not become a home for
  routing, protocol, DNS, or relay logic.
- `AsioRuntime` and `RuntimeSet` own their worker threads and work guards.
- A runtime is started at most once and stopped explicitly or by its owner.
  Stop is idempotent, and owned asynchronous work must be drained before the
  worker thread is joined.
- Test processes own every child process, socket, and temporary resource they
  create. Cleanup is required on success, failure, cancellation, and timeout.

## Errors and cancellation

The Stage 0 error taxonomy distinguishes cancellation, resolution, endpoint
connection, carrier handshake, authentication, protocol framing, timeout,
rejection, unsupported capability, and transport I/O. Later operations may
carry richer details without collapsing these categories.

Channel send and receive operations accept `std::stop_token`. Cancellation
returns without publishing or consuming a value. Closing a channel wakes
parked producers and consumers. The channel is an ownership and coordination
primitive; it is not a packet relay bus between I/O workers.

## Test responsibilities

- C++ tests cover contracts, channels, runtime ownership, platform adapters,
  and loopback component behavior.
- Go tests cover process management and independently implemented network
  observations. Go code under `tests/interop` is test-only and is not a core
  or shipped dependency.
- CTest runs the C++ suite and process smoke tests. `scripts/build.py` also
  runs `go test ./...` with the built test host when tests are enabled.
- A passing Windows test run proves only the exercised Windows paths. It does
  not prove deferred 32-bit x86, Linux, Zig, musl, TUN, routing, or router
  hardware behavior.

## Mihomo server interoperability

`TestMihomoActualServerInteroperability` starts a real Mihomo process using a
temporary configuration. TCP-only fixtures use loopback; Shadowsocks listeners
and UDP echo traffic use a locally selected non-loopback IPv4 address when the
Windows host does not deliver UDP loopback traffic between processes. Its
Shadowsocks TCP matrix
covers the classic AEAD methods (`AES-GCM`, `CHACHA20-IETF-POLY1305`,
`XCHACHA20-IETF-POLY1305`, `CHACHA8-IETF-POLY1305`,
`XCHACHA8-IETF-POLY1305`, and `AES-CCM`), plus AES/RC4 stream,
`CHACHA20-IETF`, `CHACHA20`, and `XCHACHA20` methods.
`TestMihomoActualServerShadowsocks2022TCP` covers the three standard
Shadowsocks 2022 methods. Both tests use Mihomo as the server.
The classic ChaCha and Poly1305 primitives are provided by the vcpkg Botan
library; deterministic transport tests compare the XChaCha8 construction with
an independent BoringSSL XChaCha20 reference and a fixed Mihomo-compatible
XChaCha8 wire vector.
The classic matrix also retains a TCP half-close check; that check currently
exposes the existing Windows relay EOF behavior and is reported separately
from cipher wire compatibility. The Trojan cases verify both a trusted
certificate and rejection of an untrusted one.

For a cipher-only Mihomo wire run, set
`CLASH_NATIVE_SKIP_INTEROP_HALF_CLOSE=1`; this leaves the relay EOF check out
of that run while still exercising the complete Shadowsocks request and
response framing.

The C++ implementation follows Mihomo's dedicated XChaCha8 constructor,
including its 20-round HChaCha key derivation and 8-round payload cipher. The
full classic matrix, including `xchacha8-ietf-poly1305`, all three Shadowsocks
2022 TCP methods, and all three Shadowsocks 2022 UDP methods pass against the
real Mihomo server.
The same Mihomo listener test also covers the Shadowsocks `obfs` plugin in
HTTP and TLS modes for a classic AEAD stream and a Shadowsocks 2022 stream.
The plugin is a TCP carrier; native Shadowsocks UDP remains unwrapped. HTTP
101 and the fake TLS server response are consumed lazily on the first
downstream read, matching Mihomo's simple-obfs server timing.

`TestShadowsocksWebSocketPlugins` uses an independent Go/Gorilla WebSocket
server backed by the test Shadowsocks peer. It covers both `v2ray-plugin` and
`gost-plugin` in WebSocket mode, including a TLS-wrapped WebSocket case. The
current implementation intentionally leaves plugin multiplexing disabled and
does not apply WebSocket plugins to native Shadowsocks UDP.

`TestMihomoActualServerShadowsocksUoT` validates Shadowsocks UDP-over-TCP
version 1 and version 2 against a real Mihomo Shadowsocks listener. The test
uses a separately built Go test executable, a UDP echo service, and a
non-loopback IPv4 bind when required by the Windows UDP environment. Version 2
uses the standard SOCKS address encoding for its request header and the UoT
address encoding for each packet frame. `DatagramHandle` preserves either an IP
address or a domain name returned by the protocol. Native UDP socket adapters
still require an IP address when sending to the operating system.

Build Mihomo from its source checkout, then run the opt-in integration test
from `tests/interop` with both executable paths set:

```powershell
# From D:\Project\golang\mihomo
go build -o D:\Project\cpp\clash-native\build\windows-clang-cl-x64\mihomo-interop.exe .

# From D:\Project\cpp\clash-native\tests\interop
$env:MIHOMO_EXECUTABLE = 'D:\Project\cpp\clash-native\build\windows-clang-cl-x64\mihomo-interop.exe'
$env:CLASH_NATIVE_TEST_HOST = 'D:\Project\cpp\clash-native\build\windows-clang-cl-x64\clash-native-test-host.exe'
$interop = 'D:\Project\cpp\clash-native\build\windows-clang-cl-x64\clash-native-interop-tests.exe'
go test -c -o $interop .
& $interop '-test.count=1' '-test.run=^TestMihomoActualServerInteroperability$/Shadowsocks/' '-test.v=true'

# Run only the Shadowsocks HTTP simple-obfs case.
& $interop '-test.count=1' '-test.run=^TestMihomoActualServerInteroperability$/Shadowsocks/simple-obfs-http$' '-test.v=true'

# Run only the Shadowsocks TLS simple-obfs case.
& $interop '-test.count=1' '-test.run=^TestMihomoActualServerInteroperability$/Shadowsocks/simple-obfs-tls$' '-test.v=true'

# Run the SS2022 TCP matrix, including its HTTP simple-obfs case.
& $interop '-test.count=1' '-test.run=^TestMihomoActualServerShadowsocks2022TCP$' '-test.v=true'

# Run the Shadowsocks 2022 UDP listener test separately.
& $interop '-test.count=1' '-test.run=^TestMihomoActualServerShadowsocks2022UDP$' '-test.v=true'

# Run the v2ray-plugin/gost-plugin WebSocket cases.
$env:CLASH_NATIVE_TEST_HOST = 'D:\Project\cpp\clash-native\build\windows-clang-cl-x64\clash-native-test-host.exe'
& $interop '-test.count=1' '-test.run=^TestShadowsocksWebSocketPlugins$' '-test.v=true'

# Run Shadowsocks UDP-over-TCP versions 1 and 2.
& $interop '-test.count=1' '-test.run=^TestMihomoActualServerShadowsocksUoT$' '-test.v=true'
```

The classic UDP matrix uses a 1000-byte application payload so every supported
cipher stays below the proxy's conservative receive capacity for a maximum
length destination address. The encrypted payload limit is enforced before the
UDP socket write: the 1500-byte limit counts the encrypted Shadowsocks wire
payload, excluding IP and UDP headers, and is not a complete path-MTU
guarantee.
