#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>
#include <clash_native/io/sender.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace clash_native::transport {

// REALITY handshake parameters (Mihomo reality-opts). When set, the TLS
// handshake carries a REALITY authentication ticket in the session ID and
// the peer is authenticated either by its REALITY identity or, as a
// camouflage fallback, by normal certificate verification.
struct TlsRealityOptions {
    // Base64url-encoded 32-byte X25519 server public key.
    std::string public_key_base64url;
    // Hex-encoded short ID, up to 8 bytes (zero-padded).
    std::string short_id_hex;
};

struct TlsClientOptions {
    std::string server_name;
    bool verify_peer = true;
    std::string trusted_ca_pem;
    // Overrides the hostname used for certificate verification (Mihomo
    // name-cert-verify). Empty means server_name.
    std::string verify_hostname;
    // Optional mutual-TLS client credentials (Mihomo certificate +
    // private-key). Both must be set together.
    std::string client_certificate_pem;
    std::string client_private_key_pem;
    std::vector<std::string> alpn_protocols;
    // ClientHello camouflage profile (Mihomo client-fingerprint). Empty means
    // the default BoringSSL emission. Supported: chrome, chrome120,
    // firefox, firefox120, safari, safari16, ios, android, edge, 360, qq,
    // random (one weighted pick per process), randomized (per-handshake
    // shuffle). Required when reality is set, matching Mihomo.
    std::string fingerprint;
    // ECH ECHConfigList wire bytes (Mihomo ech-opts config). When set, the
    // handshake offers ECH; the outer ClientHello carries the config's
    // public name. An ECH rejection fails the handshake (no automatic
    // retry with backup configs in this version).
    std::optional<std::vector<std::uint8_t>> ech_config_list;
    // Server certificate SHA-256 pin, hex with optional colons (Mihomo
    // fingerprint = SSL pinning). When set, a chain containing the pinned
    // certificate is accepted (leaf outright, non-leaf via re-rooted chain
    // verification); anything else is rejected. Takes precedence over
    // normal chain verification but not over REALITY.
    std::string certificate_pin;
    std::optional<TlsRealityOptions> reality;
    bool handoff_raw_transport = false;
    std::optional<int> maximum_tls_version;
    std::optional<std::chrono::steady_clock::time_point> deadline;
};

struct TlsClientConnection {
    std::unique_ptr<io::StreamHandle> stream;
    std::string negotiated_alpn;
};

// Completes a TLS client handshake over an already established stream.
// Completes set_value(TlsClientConnection) on success or
// set_error(exception_ptr) carrying a core::Error on failure; downstream
// stop aborts the handshake. The operation runs on the stream's executor.
io::AnySender<TlsClientConnection>
async_tls_client_handshake(std::unique_ptr<io::StreamHandle> stream, TlsClientOptions options);

} // namespace clash_native::transport
