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

struct TlsClientOptions {
    std::string server_name;
    bool verify_peer = true;
    std::string trusted_ca_pem;
    std::vector<std::string> alpn_protocols;
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
