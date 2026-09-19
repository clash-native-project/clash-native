# Proxy Protocol Reference

## Scope

This document describes proxy and tunnel protocols exposed by Mihomo, their
carriers and framing, and protocol-specific security or wrapper layers. The
Mihomo configuration names and option lists refer to the source revision linked
below.

It distinguishes three different layers:

1. A Mihomo configuration type, such as <code>vmess</code> or
   <code>hysteria2</code>.
2. The carrier or framing used to move that protocol, such as TCP, WebSocket,
   HTTP/2, or QUIC.
3. An optional security, camouflage, or multiplexing layer, such as TLS,
   Reality, ShadowTLS, or SMUX.

The referenced Mihomo revision is
<code>ab405bad5beeeac8b003bb01f60f134f6df54471</code>.

## 1. Layer model

A useful way to read a proxy configuration is from the inside out:

~~~text
application payload
  -> proxy protocol or tunnel protocol
  -> optional framing, carrier, or multiplexing
  -> optional encryption, authentication, or camouflage
  -> TCP, UDP, or QUIC
  -> IP
~~~

Examples:

~~~text
HTTP proxy CONNECT over HTTP/1.1 over TCP
SOCKS5 over TCP
Shadowsocks AEAD stream over TCP
VMess over WebSocket over TLS over TCP
VLESS over gRPC over HTTP/2 over TLS over TCP
Hysteria2 over QUIC over UDP
MASQUE CONNECT-UDP over HTTP/3 over QUIC over UDP
OpenVPN data channel over UDP
~~~

The terms are not interchangeable:

- <code>HTTP</code> can mean an HTTP proxy protocol or HTTP carrier framing.
- <code>QUIC</code> is a transport, not itself a Mihomo
  <code>proxies[].type</code>.
- <code>HTTP/3</code> is HTTP semantics over QUIC and is not TCP-based.
- <code>TLS</code> protects a carrier; it is not normally the proxy protocol.
- WebSocket is a framed bidirectional protocol established through HTTP.
- gRPC is an RPC framing and mapping over HTTP/2; Mihomo exposes it as a
  selectable transport option.
- HTTP/2 and HTTP/3 are HTTP versions; HTTP/3 runs over QUIC.
- SMUX, UoT, XUDP, and packet-address modes alter multiplexing or delivery
  semantics. They are not standalone top-level proxy types.

## 2. Proxy and tunnel protocol types

The following protocol and tunnel values are accepted by Mihomo's outbound
parser as <code>proxies[].type</code> values in the referenced source snapshot.

| Config type | Alias or family | Role | Primary carrier | Version or important variants |
| --- | --- | --- | --- | --- |
| <code>ss</code> | Shadowsocks | Encrypted proxy | TCP stream and native UDP | AEAD and legacy stream ciphers; optional plugins |
| <code>ssr</code> | ShadowsocksR | Encrypted proxy | TCP stream and native UDP | SSR obfuscation and protocol-plugin variants |
| <code>socks5</code> | SOCKS5 outbound | Generic proxy client | TCP control; UDP ASSOCIATE for UDP | SOCKS5; optional TLS and UDP-over-stream |
| <code>http</code> | HTTP proxy outbound | Generic proxy client | HTTP/1.1 over TCP; CONNECT for streams | Optional TLS, producing an HTTPS proxy connection |
| <code>vmess</code> | VMess | Encrypted proxy | TCP by default | TCP, WebSocket, HTTP/1.1, HTTP/2, gRPC, Mekya, KCP/mKCP |
| <code>vless</code> | VLESS | Authenticated proxy | TCP by default | TCP, WebSocket, HTTP/1.1, HTTP/2, gRPC, XHTTP |
| <code>snell</code> | Snell | Encrypted proxy | TCP; optional UDP | TLS, HTTP camouflage, ShadowTLS, ResTLS, JLS |
| <code>trojan</code> | Trojan | TLS-authenticated proxy | TCP by default | TCP, WebSocket, gRPC |
| <code>hysteria</code> | Hysteria v1 | QUIC proxy | QUIC over UDP | <code>udp</code>, <code>wechat-video</code>, <code>faketcp</code> |
| <code>hysteria2</code> | Hysteria 2 / Hysteria2 | QUIC proxy | QUIC over UDP | Salamander or Gecko obfuscation; optional Realm mode |
| <code>wireguard</code> | WireGuard | Layer-3 tunnel | UDP | WireGuard and AmneziaWG-related options |
| <code>tuic</code> | TUIC | QUIC proxy | QUIC over UDP | TUIC v4 and v5; native or QUIC UDP relay |
| <code>shadowquic</code> | ShadowQUIC | QUIC proxy | QUIC over UDP | QUIC v1 or v2; optional UDP-over-stream |
| <code>gost-relay</code> | GOST Relay | Relay proxy | TCP and optional UDP | GOST relay features, TLS, and optional multiplexing |
| <code>ssh</code> | SSH | SSH-based proxy | TCP | Password or private-key authentication |
| <code>mieru</code> | Mieru | Encrypted proxy | TCP or UDP | Mieru transport selection; optional UDP-over-stream |
| <code>anytls</code> | AnyTLS | TLS-based proxy | TCP/TLS stream | AnyTLS framing and padding; optional wrappers |
| <code>sudoku</code> | Sudoku | Encrypted proxy | TCP by default | Direct TCP or HTTPMask; AEAD and multiplexing |
| <code>masque</code> | IETF MASQUE | HTTP tunnel proxy | HTTP/3 over QUIC by default | HTTP/2 over TLS/TCP or <code>h3-l4proxy</code> |
| <code>trusttunnel</code> | TrustTunnel | Encrypted tunnel | TLS over TCP by default | Optional QUIC transport |
| <code>openvpn</code> | OpenVPN | Layer-3 tunnel | UDP or TCP | OpenVPN cipher and authentication options |
| <code>tailscale</code> | Tailscale | Overlay network | Tailscale overlay | Not a generic HTTP or SOCKS wire protocol |
| <code>zerotier</code> | ZeroTier | Overlay network | ZeroTier overlay | Not a generic HTTP or SOCKS wire protocol |
| <code>easytier</code> | EasyTier | Overlay network | EasyTier overlay | Not a generic HTTP or SOCKS wire protocol |

## 3. Per-protocol stack reference

### 3.1 HTTP proxy

~~~text
HTTP CONNECT request -> HTTP/1.1 -> TCP
HTTP CONNECT request -> HTTP/1.1 -> TLS -> TCP
~~~

The <code>http</code> type is the HTTP proxy protocol. It must not be confused
with HTTP carriers used to carry VMess or VLESS. HTTP/1.0 and HTTP/1.1 are
request versions relevant to the current Mihomo HTTP listener.

### 3.2 SOCKS5

~~~text
SOCKS5 greeting/authentication -> CONNECT -> TCP
SOCKS5 TCP control + UDP ASSOCIATE -> native UDP relay
~~~

The outbound type is <code>socks5</code>. Mihomo's inbound
<code>socks</code> listener also accepts SOCKS4 and SOCKS5. SOCKS5 UDP can be
placed inside an additional UDP-over-stream mode where the selected adapter
supports it.

### 3.3 Shadowsocks

~~~text
Shadowsocks cipher/framing -> TCP
Shadowsocks cipher/framing -> native UDP
~~~

AEAD names in the referenced core are:

- <code>AEAD_AES_128_GCM</code>, <code>AEAD_AES_192_GCM</code>,
  <code>AEAD_AES_256_GCM</code>
- <code>AEAD_CHACHA20_POLY1305</code>,
  <code>AEAD_XCHACHA20_POLY1305</code>
- <code>AEAD_CHACHA8_POLY1305</code>,
  <code>AEAD_XCHACHA8_POLY1305</code>
- <code>AEAD_AES_128_CCM</code>, <code>AEAD_AES_192_CCM</code>,
  <code>AEAD_AES_256_CCM</code>

Common aliases include <code>aes-128-gcm</code>, <code>aes-192-gcm</code>,
<code>aes-256-gcm</code>, <code>chacha20-ietf-poly1305</code>,
<code>xchacha20-ietf-poly1305</code>, <code>chacha8-ietf-poly1305</code>,
<code>xchacha8-ietf-poly1305</code>, and the three AES-CCM names.

Legacy stream methods are <code>RC4-MD5</code>, AES-128/192/256-CTR,
AES-128/192/256-CFB, <code>CHACHA20</code>, <code>CHACHA20-IETF</code>, and
<code>XCHACHA20</code>. The configuration reference also exposes
<code>2022-blake3-aes-128-gcm</code>, <code>2022-blake3-aes-256-gcm</code>,
and <code>2022-blake3-chacha20-poly1305</code>.

### 3.4 ShadowsocksR

~~~text
SSR payload -> protocol plugin -> cipher -> obfuscation -> TCP
SSR UDP payload -> protocol plugin -> cipher -> UDP
~~~

Obfuscation values:

- <code>plain</code>
- <code>http_simple</code>
- <code>http_post</code>
- <code>random_head</code>
- <code>tls1.2_ticket_auth</code>
- <code>tls1.2_ticket_fastauth</code>

Protocol values:

- <code>origin</code>
- <code>auth_sha1_v4</code>
- <code>auth_aes128_md5</code>
- <code>auth_aes128_sha1</code>
- <code>auth_chain_a</code>
- <code>auth_chain_b</code>

These SSR names are not interchangeable with the ordinary Shadowsocks plugin
names.

### 3.5 VMess

Default:

~~~text
VMess -> TCP
~~~

Carrier choices:

| <code>network</code> | Stack |
| --- | --- |
| omitted or <code>tcp</code> | VMess -> TCP |
| <code>ws</code> | VMess -> WebSocket -> TCP; optionally TLS/WSS |
| <code>http</code> | VMess -> HTTP/1.1 -> TCP |
| <code>h2</code> | VMess -> HTTP/2 -> TLS/TCP |
| <code>grpc</code> | VMess -> gRPC -> HTTP/2 -> optional TLS -> TCP |
| <code>mekya</code> | VMess -> Mekya carrier |
| <code>mkcp</code> or <code>kcp</code> | VMess -> mKCP/KCP -> UDP |

The VMess cipher or <code>auto</code> selection is separate from the carrier.
Masquerade headers can be selected for KCP/mKCP, including
<code>none</code>, <code>srtp</code>, <code>utp</code>,
<code>wechat-video</code>, <code>dtls</code>, and <code>wireguard</code>.
For VMess gRPC, TLS is controlled separately and may be disabled.

### 3.6 VLESS

Default:

~~~text
VLESS -> TCP
~~~

Carrier choices:

| <code>network</code> | Stack |
| --- | --- |
| omitted or <code>tcp</code> | VLESS -> TCP |
| <code>ws</code> | VLESS -> WebSocket -> TCP; optionally TLS/WSS |
| <code>http</code> | VLESS -> HTTP/1.1 -> TCP |
| <code>h2</code> | VLESS -> HTTP/2 -> TLS/TCP |
| <code>grpc</code> | VLESS -> gRPC -> HTTP/2 -> optional TLS -> TCP |
| <code>xhttp</code> | VLESS -> XHTTP -> HTTP carrier |

TLS, ECH, Reality, ShadowTLS, ResTLS, JLS, and TLS fingerprint options are
separate layers, not VLESS versions.
For VLESS gRPC, TLS is controlled separately and may be disabled.

### 3.7 Snell and Trojan

Snell:

~~~text
Snell -> TCP
Snell -> TLS/HTTP/ShadowTLS/ResTLS/JLS -> TCP
Snell -> UDP
~~~

Current Snell mode names are <code>tls</code>, <code>http</code>,
<code>shadow-tls</code>, <code>restls</code>, and <code>jls</code>.

Trojan:

~~~text
Trojan authentication/stream -> TLS -> TCP
Trojan -> WebSocket -> TLS/TCP
Trojan -> gRPC -> HTTP/2 -> TLS/TCP
~~~

Trojan password authentication and optional Trojan-SS behavior are protocol
options, not separate carriers.

### 3.8 Hysteria v1 and Hysteria2

Hysteria v1:

~~~text
Hysteria v1 -> QUIC -> UDP
~~~

<code>protocol</code> values are <code>udp</code>,
<code>wechat-video</code>, and <code>faketcp</code>. XPlus obfuscation is
enabled through <code>obfs</code>. Hysteria v1 uses TLS 1.3 for its QUIC
handshake.

Hysteria2:

~~~text
Hysteria2 -> QUIC -> UDP
~~~

Optional obfuscation values are <code>salamander</code> and
<code>gecko</code>. Hop/port-range behavior and Realm-related endpoint
behavior are separate options.

### 3.9 TUIC and ShadowQUIC

TUIC:

~~~text
TUIC v4 or v5 -> QUIC -> UDP
~~~

UDP relay modes are <code>native</code> and <code>quic</code>. UDP-over-stream
can be enabled separately.

ShadowQUIC:

~~~text
ShadowQUIC -> QUIC v1 or v2 -> UDP
~~~

The ShadowQUIC adapter exposes QUIC versions <code>v1</code> and
<code>v2</code>, plus optional UDP-over-stream.

### 3.10 Other stream and tunnel types

| Type | Stack and details |
| --- | --- |
| <code>gost-relay</code> | GOST Relay -> TCP or UDP; TLS, authentication, and multiplexing are GOST options |
| <code>ssh</code> | SSH session -> TCP; password or private-key authentication |
| <code>mieru</code> | Mieru -> TCP or Mieru -> UDP; optional UDP-over-stream |
| <code>anytls</code> | AnyTLS framing -> TLS -> TCP; optional padding, ShadowTLS, ResTLS, or JLS |
| <code>sudoku</code> | Sudoku AEAD framing -> TCP; optional HTTPMask and multiplexing |
| <code>masque</code> | MASQUE CONNECT/CONNECT-UDP -> HTTP/3 -> QUIC -> UDP by default; H2 alternative |
| <code>trusttunnel</code> | TrustTunnel -> TLS -> TCP by default; optional QUIC -> UDP |
| <code>wireguard</code> | IP packets -> WireGuard -> UDP -> IP; optional AmneziaWG paths |
| <code>openvpn</code> | IP packets -> OpenVPN channels -> UDP or TCP |
| <code>tailscale</code> | Tailscale overlay -> selected underlay; not a generic proxy protocol |
| <code>zerotier</code> | ZeroTier overlay -> selected underlay; not a generic proxy protocol |
| <code>easytier</code> | EasyTier overlay -> selected underlay; not a generic proxy protocol |

For Sudoku, HTTPMask modes are <code>legacy</code>, <code>stream</code>,
<code>poll</code>, <code>auto</code>, and <code>ws</code>; AEAD methods are
<code>chacha20-poly1305</code>, <code>aes-128-gcm</code>, and
<code>none</code>. Multiplexing is <code>off</code>, <code>auto</code>, or
<code>on</code>. The <code>none</code> method provides no AEAD protection.

OpenVPN transport values are <code>udp</code> and <code>tcp</code>. The Mihomo
configuration reference lists AES-128/192/256-GCM, AES-128/192/256-CBC, and
<code>CHACHA20-POLY1305</code>, with MD5, SHA1, SHA256, SHA384, and SHA512
authentication digest choices.

## 4. Carrier, framing, and multiplexing reference

The following values are commonly nested under an outbound protocol.

| Layer | Exact value or spelling | Underlying transport | Meaning |
| --- | --- | --- | --- |
| Raw stream | <code>tcp</code> | TCP | Ordered reliable byte stream |
| Raw datagram | <code>udp</code> | UDP | Native datagrams with packet boundaries |
| QUIC | <code>quic</code> | UDP | Encrypted multiplexed transport; commonly QUIC v1 or v2 |
| HTTP proxy | <code>http</code> | TCP | HTTP/1.1 proxy semantics, usually CONNECT |
| HTTP/1.1 carrier | <code>http</code> | TCP or TLS/TCP | HTTP request/response framing for VMess/VLESS transports |
| HTTP/2 | <code>h2</code> | TLS/TCP | Multiplexed HTTP/2 streams |
| HTTP/3 | <code>h3</code> | QUIC/UDP | HTTP semantics over QUIC |
| WebSocket | <code>ws</code> | TCP or TLS/TCP | WebSocket stream; TLS gives WSS behavior |
| HTTP Upgrade | <code>httpupgrade</code> | HTTP/1.1 over TCP or TLS/TCP | Upgrades an HTTP/1.1 request into a long-lived stream |
| gRPC | <code>grpc</code> | HTTP/2 over TCP; TLS depends on the adapter | gRPC stream framing and service-name routing |
| XHTTP | <code>xhttp</code> | HTTP carrier | XHTTP request, padding, and method modes used by VLESS |
| KCP | <code>kcp</code> | UDP | Packet-oriented reliable transport family |
| mKCP | <code>mkcp</code> | UDP | V2Ray-compatible KCP framing and masquerade headers |
| Mekya | <code>mekya</code> | Adapter-specific | VMess carrier with URL and nested options |
| UoT | <code>udp-over-stream</code> | A stream such as TCP or QUIC | Carries UDP packets inside a reliable stream |
| XUDP | <code>xudp</code> | Protocol-dependent | Packet addressing or relay mode |
| Packet address | <code>packetaddr</code> | Protocol-dependent | Packet framing/address representation |
| SMUX | <code>smux</code>, <code>yamux</code>, <code>h2mux</code> | A stream transport | Multiplexes logical streams |

### 4.1 HTTP versions

The practical stacks are:

~~~text
HTTP/1.1 -> TCP
HTTP/1.1 -> TLS -> TCP
HTTP/2 -> TLS -> TCP
HTTP/3 -> QUIC -> UDP
~~~

HTTP/2 changes framing and multiplexing; it is not merely HTTP/1.1 with a
different version number. HTTP/3 is not a TCP protocol.

### 4.2 WebSocket and HTTP Upgrade

In the Mihomo <code>ws</code> transports described here, WebSocket starts with
an HTTP/1.1 Upgrade handshake and then carries WebSocket frames. WSS is the
same transport protected by TLS. HTTP/2 has a separate WebSocket bootstrap
mechanism, Extended CONNECT [RFC 8441](https://www.rfc-editor.org/rfc/rfc8441.html);
it is not the HTTP/1.1 <code>ws</code> path described above.

HTTP Upgrade also starts with HTTP/1.1 but changes the connection into another
stream after the upgrade. <code>httpupgrade</code> is normally a transport
option inside a V2Ray-style configuration, not a top-level proxy protocol.

### 4.3 gRPC

The protocol stack is:

~~~text
gRPC -> HTTP/2 -> (optional TLS) -> TCP
~~~

The <code>grpc-service-name</code> identifies the service path. gRPC is RPC
framing carried over HTTP/2, not an independent IP transport. In this Mihomo
revision, VMess and VLESS allow TLS to be disabled for gRPC; Trojan's gRPC
transport uses TLS.

### 4.4 KCP and mKCP

KCP and mKCP are UDP-based packet transports. The VMess mKCP configuration
supports these optional masquerade headers:

- <code>none</code>
- <code>srtp</code>
- <code>utp</code>
- <code>wechat-video</code>
- <code>dtls</code>
- <code>wireguard</code>

These are packet-header or traffic-shape choices. They do not turn KCP into
the named protocol.

### 4.5 Multiplexing

The configuration names in this Mihomo revision include <code>smux</code>,
<code>yamux</code>, and <code>h2mux</code>. A selected adapter can use SMUX to
multiplex logical byte streams over an ordered stream carrier. This does not
make SMUX a native UDP datagram protocol; QUIC streams and any additional SMUX
layer are adapter-specific choices.

## 5. Security, authentication, and camouflage layers

These layers are separate from the proxy type and carrier.

| Layer | Names or versions | What it does | Typical carrier |
| --- | --- | --- | --- |
| TLS | TLS 1.2, TLS 1.3 | Server authentication and encryption | TCP; also HTTP/2 and QUIC handshakes |
| QUIC TLS | TLS 1.3-based handshake | Authenticates and encrypts QUIC packets | UDP |
| ECH | Encrypted ClientHello | Encrypts selected ClientHello information | TLS/TCP or TLS-enabled QUIC |
| Reality | Reality TLS camouflage | TLS handshake camouflage and authentication variant | TCP/TLS or a TLS carrier |
| ShadowTLS | Versions 1, 2, 3 | TLS camouflage or outer handshake wrapper | TCP/TLS |
| ResTLS | TLS 1.2 or TLS 1.3 mode hints | TLS-in-TLS traffic-shape wrapper | TCP/TLS |
| JLS | JLS wrapper | TLS/application traffic-shape wrapper | TCP/TLS; commonly h2 or http/1.1 |
| TLSMirror | TLS mirror behavior | Changes TLS handshake and traffic shape | TLS/TCP |
| simple-obfs | <code>http</code>, <code>tls</code> | Legacy Shadowsocks obfuscation | TCP |
| v2ray-plugin | <code>websocket</code> | Shadowsocks WebSocket camouflage | TCP; optional TLS |
| gost-plugin | <code>websocket</code> | GOST WebSocket plugin path | TCP; optional TLS |
| kcptun | KCP plugin | Carries Shadowsocks through KCP | UDP |
| Shadow-TLS plugin | <code>shadow-tls</code> | Shadowsocks outer wrapper | TCP/TLS |
| ResTLS plugin | <code>restls</code> | Shadowsocks outer wrapper | TCP/TLS |
| JLS plugin | <code>jls</code> | Shadowsocks outer wrapper | TCP/TLS |
| XPlus | Hysteria v1 obfuscator | Obfuscates Hysteria v1 traffic shape | QUIC/UDP |
| Salamander | Hysteria2 obfuscator | Hysteria2 obfuscation | QUIC/UDP |
| Gecko | Hysteria2 obfuscator | Hysteria2 obfuscation | QUIC/UDP |

### 5.1 TLS version notes

- Hysteria v1, Hysteria2, and TUIC use TLS 1.3-based QUIC handshakes.
- A generic <code>tls: true</code> option on a stream adapter does not
  automatically mean that the adapter is TLS 1.3-only. The actual minimum and
  maximum versions depend on the adapter and TLS implementation.
- ALPN values such as <code>h2</code> and <code>http/1.1</code> negotiate the
  application protocol carried over TLS; ALPN is not an encryption algorithm.

### 5.2 TLS fingerprints and certificates

Client fingerprints such as <code>chrome</code>, <code>firefox</code>,
<code>safari</code>, <code>ios</code>, and <code>random</code> change the
observable TLS ClientHello shape. They do not change the protocol stack or
cryptographic security level.

Certificate verification, <code>skip-cert-verify</code>, SNI/server name,
ALPN, ECH, and Reality keys are separate TLS configuration dimensions. A
configuration may use them only where the selected adapter supports the
combination.

## 6. Protocol-specific option details

### 6.1 Shadowsocks plugin options

Mihomo's Shadowsocks outbound supports these plugin families or wrappers:

- <code>obfs</code>: mode <code>http</code> or <code>tls</code>
- <code>v2ray-plugin</code>: mode <code>websocket</code>, optionally TLS
- <code>gost-plugin</code>: mode <code>websocket</code>, optionally TLS
- <code>shadow-tls</code>
- <code>restls</code>
- <code>jls</code>
- <code>kcptun</code>
- UDP-over-TCP

Example stacks:

~~~text
Shadowsocks -> obfs(http) -> TCP
Shadowsocks -> WebSocket -> TLS -> TCP
Shadowsocks -> KCP -> UDP
Shadowsocks -> UDP-over-TCP -> TCP
~~~

The plugin changes the carrier or camouflage; the top-level protocol remains
Shadowsocks.

### 6.2 Snell and SSR

Snell mode names are <code>tls</code>, <code>http</code>,
<code>shadow-tls</code>, <code>restls</code>, and <code>jls</code>. These are
wrapper choices around Snell's normal TCP or optional UDP behavior.

SSR has two independent option families:

~~~text
SSR obfs value + SSR protocol value + cipher value
~~~

The exact SSR lists are in Section 3.4. Do not replace them with the ordinary
Shadowsocks plugin list; <code>http_simple</code> and
<code>tls1.2_ticket_auth</code> are SSR obfs names.

### 6.3 V2Ray-style carriers

VMess and VLESS can select <code>tcp</code>, <code>ws</code>,
<code>http</code>, <code>h2</code>, and <code>grpc</code>. VMess additionally
supports <code>mekya</code> and <code>mkcp</code>/<code>kcp</code>; VLESS
additionally supports <code>xhttp</code>.

<code>httpupgrade</code> is a nested HTTP transport option rather than another
top-level V2Ray proxy type. TLS, Reality, ECH, ShadowTLS, ResTLS, JLS, and
TLSMirror are nested options.

### 6.4 Hysteria, Hysteria2, TUIC, and ShadowQUIC

Hysteria v1 uses QUIC over UDP, with <code>protocol</code> values
<code>udp</code>, <code>wechat-video</code>, and <code>faketcp</code>, plus
optional XPlus obfuscation. Hysteria2 uses QUIC over UDP with optional
<code>salamander</code> or <code>gecko</code> obfuscation.

TUIC supports protocol generations v4 and v5, uses QUIC over UDP, and has
UDP relay modes <code>native</code> and <code>quic</code>. ShadowQUIC uses
QUIC over UDP and exposes QUIC versions <code>v1</code> and <code>v2</code>.
All four can expose protocol-specific UDP-over-stream modes.

### 6.5 Sudoku and OpenVPN

Sudoku HTTPMask modes are <code>legacy</code>, <code>stream</code>,
<code>poll</code>, <code>auto</code>, and <code>ws</code>. Sudoku AEAD
methods are <code>chacha20-poly1305</code>, <code>aes-128-gcm</code>, and
<code>none</code>; multiplexing is <code>off</code>, <code>auto</code>, or
<code>on</code>. The <code>none</code> method provides no AEAD protection.

OpenVPN transport selection is <code>proto: udp</code> or
<code>proto: tcp</code>. The Mihomo configuration reference lists
AES-128/192/256-GCM, AES-128/192/256-CBC, and
<code>CHACHA20-POLY1305</code>, with MD5, SHA1, SHA256, SHA384, and SHA512
authentication digest choices.

### 6.6 AnyTLS padding and wrappers

AnyTLS padding changes record or request lengths to reduce recognizable traffic
shapes. Optional ShadowTLS, ResTLS, and JLS settings add outer behavior. They
are not replacements for the TLS handshake or AnyTLS authentication.

## 7. Inbound listener protocols

Mihomo's listener parser accepts these <code>listeners[].type</code> values:

| Listener type | Role | Protocol or carrier |
| --- | --- | --- |
| <code>socks</code> | SOCKS listener | SOCKS4 and SOCKS5 on the same listener |
| <code>http</code> | HTTP proxy listener | HTTP/1.0 and HTTP/1.1 proxy requests |
| <code>mixed</code> | Combined listener | HTTP plus SOCKS4/SOCKS5 |
| <code>shadowsocks</code> | Shadowsocks inbound | Shadowsocks TCP/UDP; cipher-dependent |
| <code>snell</code> | Snell inbound | Snell transport |
| <code>vmess</code> | VMess inbound | VMess with TCP/WS/H2/gRPC/Mekya/mKCP options |
| <code>vless</code> | VLESS inbound | VLESS with TLS and carrier options |
| <code>trojan</code> | Trojan inbound | Trojan with TLS and carrier options |
| <code>hysteria2</code> | Hysteria2 inbound | QUIC over UDP |
| <code>hysteria2-realm</code> | Hysteria2 Realm inbound | Realm-specific Hysteria2 entry |
| <code>tuic</code> | TUIC inbound | TUIC over QUIC/UDP |
| <code>shadowquic</code> | ShadowQUIC inbound | QUIC/UDP with v1/v2 options |
| <code>anytls</code> | AnyTLS inbound | AnyTLS over TLS/TCP |
| <code>mieru</code> | Mieru inbound | Mieru TCP or UDP |
| <code>sudoku</code> | Sudoku inbound | Sudoku and optional HTTPMask |
| <code>trusttunnel</code> | TrustTunnel inbound | TrustTunnel TCP/TLS or optional QUIC |

Important listener distinctions:

- <code>socks</code> is not SOCKS5-only. The listener checks the version byte
  and can handle SOCKS4 or SOCKS5.
- <code>mixed</code> combines HTTP proxy handling with SOCKS4/SOCKS5 handling.

## 8. Mihomo source references

The links below are pinned to Mihomo revision
<code>ab405bad5beeeac8b003bb01f60f134f6df54471</code>.

### Parser and configuration

- [Outbound parser](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/parser.go)
- [Inbound listener parser](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/listener/parse.go)
- [Mihomo configuration reference](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/docs/config.yaml)

### Protocol adapters and transports

- [Shadowsocks outbound](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/shadowsocks.go)
- [Shadowsocks cipher registry](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/transport/shadowsocks/core/cipher.go)
- [ShadowsocksR outbound](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/shadowsocksr.go)
- [VMess outbound](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/vmess.go)
- [VLESS outbound](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/vless.go)
- [Trojan outbound](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/trojan.go)
- [Snell outbound](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/snell.go)
- [Hysteria v1 outbound](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/hysteria.go)
- [Hysteria2 outbound](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/hysteria2.go)
- [TUIC outbound](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/tuic.go)
- [ShadowQUIC outbound](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/shadowquic.go)
- [MASQUE outbound](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/masque.go)
- [TrustTunnel outbound](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/trusttunnel.go)
- [Mieru outbound](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/mieru.go)
- [Sudoku outbound](https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/sudoku.go)
