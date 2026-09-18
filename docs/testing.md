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
temporary configuration and loopback listeners. It tests the C++ outbound
against Mihomo's Shadowsocks TCP/UDP listeners for AES-128-GCM, AES-256-GCM,
and ChaCha20-Poly1305, and against its Trojan TCP/TLS listener. The Trojan
cases verify both a trusted certificate and rejection of an untrusted one.

Build Mihomo from its source checkout, then run the opt-in integration test
from `tests/interop` with both executable paths set:

```powershell
# From D:\Project\golang\mihomo
go build -o D:\Project\cpp\clash-native\build\windows-clang-cl-x64\mihomo-interop.exe .

# From D:\Project\cpp\clash-native\tests\interop
$env:MIHOMO_EXECUTABLE = 'D:\Project\cpp\clash-native\build\windows-clang-cl-x64\mihomo-interop.exe'
$env:CLASH_NATIVE_TEST_HOST = 'D:\Project\cpp\clash-native\build\windows-clang-cl-x64\clash-native-test-host.exe'
go test -count=1 -run '^TestMihomoActualServerInteroperability$' -v .
```

The Mihomo UDP case uses a 1200-byte payload so the encrypted Shadowsocks UDP
payload remains within the outbound's 1500-byte limit. This counts the salt
and ciphertext passed to the UDP socket, excluding IP and UDP headers; it is
not a guarantee that the complete IP packet fits a 1500-byte path MTU. The
independent Go peer test verifies exact-limit delivery and rejection above the
limit for all supported AEAD methods.
