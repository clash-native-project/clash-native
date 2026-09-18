# DNS Testing

This document records the current Windows x64 procedure for validating
clash-native DNS behavior with an independent `dnsproxy` process. The
independent process is deliberately separate from the project-owned DNS
fixtures, so a successful request crosses a real local UDP or TCP socket.

## Test layers

The DNS tests use three complementary layers:

1. Deterministic C++ transport tests validate cache, coalescing, policy,
   cancellation, shutdown, and error behavior without creating sockets.
2. C++ loopback tests use real Windows UDP/TCP sockets and project-controlled
   DNS fixtures. They are used for wire-level cases such as malformed
   responses, unexpected senders, mismatched questions, TCP framing, and UDP
   truncation fallback.
3. The independent-process test starts AdGuardTeam's `dnsproxy` and sends
   requests through `clash-native-test-host` from the independent
   `github.com/miekg/dns` client. This validates the process boundary and the
   real request/response path without depending on a public DNS service.

The third layer is an automated Go interop test when both
`CLASH_NATIVE_TEST_HOST` and `dnsproxy` are available. It remains skippable
when the external executable is not installed.

## Build dnsproxy

The current manual validation used Go 1.27 on Windows x64:

```powershell
go install github.com/AdguardTeam/dnsproxy@master
```

In the recorded run, `master` resolved to module version `v0.84.2`. Future
continuous integration should pin an exact dnsproxy release instead of using
`master`.

The expected executable is:

```text
C:\Users\<user>\go\bin\dnsproxy.exe
```

## Prepare deterministic records

Create a hosts file outside the source tree or under an ignored build
directory. The recorded test file was:

```text
192.0.2.53 clash-native-dnsproxy-a.test
198.51.100.53 clash-native-dnsproxy-b.test
```

These addresses are documentation ranges and are used only as deterministic
test values. They are not expected to be reachable.

## Start the independent process

The following command starts both UDP and TCP DNS listeners on the same
loopback port:

```powershell
$dnsproxy = Join-Path (go env GOPATH) 'bin\dnsproxy.exe'
& $dnsproxy `
  --listen=127.0.0.1 `
  --port=15353 `
  --upstream=127.0.0.1:9 `
  --hosts-file-enabled `
  --hosts-files='D:\Project\cpp\clash-native\build\dnsproxy-test\hosts.txt' `
  --output='D:\Project\cpp\clash-native\build\dnsproxy-test\dnsproxy.log' `
  --verbose
```

`127.0.0.1:9` is intentionally an unavailable fallback upstream. Known test
names are answered from the hosts file, so this configuration does not need
the public internet. Use a controlled reachable upstream only when testing
forwarding beyond the local hosts-file path.

The command runs in the foreground. Keep that terminal open while running
the client or clash-native test. For a background process, use
`Start-Process -WindowStyle Hidden -PassThru` and retain the returned process
ID for cleanup.

## Verify the listeners and logs

```powershell
Get-NetUDPEndpoint -LocalPort 15353
Get-NetTCPConnection -LocalPort 15353
Get-Content 'D:\Project\cpp\clash-native\build\dnsproxy-test\dnsproxy.log' -Tail 30
```

The log should contain both of these lines:

```text
listening to udp ... addr=127.0.0.1:15353
listening to tcp ... addr=127.0.0.1:15353
```

## Send independent DNS queries

Configure the system under test to use:

```text
127.0.0.1:15353
```

Send an A query for `clash-native-dnsproxy-a.test` and verify that the
response contains `192.0.2.53`. Repeat over TCP and verify the same result.
The client must be independent of the project's in-process DNS fixtures.

The automated interop test uses `github.com/miekg/dns` as the independent
client. It sends one UDP and one TCP query through the test host and verifies
the expected deterministic A records. The companion FakeIP test verifies a
synthetic `198.18.0.1` answer and accesses a real loopback TCP endpoint through
the SOCKS5 proxy using that synthetic address. The earlier manual run used
minimal PowerShell UDP and TCP clients; both received a 62-byte DNS response,
preserved the query transaction ID `0x1234`, and contained `192.0.2.53`.

## Composed Stage 2 policy, FakeIP, routing, and reload test

`TestStage2PolicyFakeIPRoutingAndReloadComposition` exercises the composed
runtime through real loopback sockets. It starts two independent `dnsproxy`
processes with different hosts-file answers, then starts the C++ test host
with a DNS policy rule, a FakeIP filter, a proxy domain rule, and a shared
runtime snapshot store.

The test verifies this sequence:

1. An A query for `policy-route.test` returns `198.51.100.22` from the policy
   upstream group rather than `192.0.2.11` from the default upstream.
2. An A query for the FakeIP domain returns `198.18.0.1`; a SOCKS5 connection
   using that address is reversed to the domain, matches the direct traffic
   rule, and reaches a real loopback TCP echo service.
3. The Go test sends `reload` to a loopback-only control endpoint exposed by
   `clash-native-test-host` only when
   `CLASH_NATIVE_TEST_STAGE2_COMPOSITION=1`. The host publishes generation 2
   with a new DNS policy, a new FakeIP pool, and a reject default route.
4. A query for `policy-route.test` now returns `192.0.2.11` from the default
   upstream. A TCP DNS query for the FakeIP domain returns `198.19.0.1`; a new
   SOCKS5 connection using that address receives the reject reply, while the
   connection opened before reload continues relaying data.

Run it from `tests/interop` after building the Windows test host:

```powershell
$env:CLASH_NATIVE_TEST_HOST = 'D:\Project\cpp\clash-native\build\windows-clang-cl-x64\clash-native-test-host.exe'
go test -count=1 -run '^TestStage2PolicyFakeIPRoutingAndReloadComposition$' -v .
```

The test needs the independent `dnsproxy` executable described above. Its
reload control listener is test-host-only and is bound to loopback on an
ephemeral port.

For clash-native integration, the automated topology is:

```text
independent client
    -> clash-native-test-host or clash-native
    -> clash-native DNS resolver
    -> real UDP/TCP socket
    -> dnsproxy at 127.0.0.1:15353
    -> deterministic hosts-file answer
```

Run the automated test from `tests/interop` with the built test host:

```powershell
$env:CLASH_NATIVE_TEST_HOST = 'D:\Project\cpp\clash-native\build\windows-clang-cl-x64\clash-native-test-host.exe'
go test -count=1 -run '^TestDNSProcessWithIndependentDnsproxy$' -v ./...
```

Run the FakeIP composition test with:

```powershell
go test -count=1 -run '^TestFakeIPProcessWithIndependentDnsproxy$' -v ./...
```

## Stop and clean up

Stop the process using its recorded process ID:

```powershell
Stop-Process -Id <dnsproxy-pid>
```

Confirm that both listeners are gone before reusing port `15353`:

```powershell
Get-NetUDPEndpoint -LocalPort 15353 -ErrorAction SilentlyContinue
Get-NetTCPConnection -LocalPort 15353 -ErrorAction SilentlyContinue
```

## Validation boundary

These tests prove independent local DNS process boundaries, real Windows
loopback UDP/TCP exchange, one DNS-policy/FakeIP/traffic-route composition,
and a snapshot reload that updates both DNS synthesis and new proxy
connections. They do not prove public-internet reachability or every possible
combination of DNS policies, routes, FakeIP filters, and reload generations.
