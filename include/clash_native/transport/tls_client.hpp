#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>

#include <chrono>
#include <functional>
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
    std::unique_ptr<core::StreamHandle> stream;
    std::string negotiated_alpn;
};

class TlsClientHandshake {
  public:
    virtual void cancel() noexcept = 0;
    virtual ~TlsClientHandshake() = default;
};

using TlsClientHandler = std::function<void(core::Result<TlsClientConnection>)>;

// Completes a TLS client handshake over an already established project stream.
// The completion runs on that stream's executor and is invoked exactly once.
std::shared_ptr<TlsClientHandshake>
async_tls_client_handshake(std::unique_ptr<core::StreamHandle> stream, TlsClientOptions options,
                           TlsClientHandler handler);

} // namespace clash_native::transport
