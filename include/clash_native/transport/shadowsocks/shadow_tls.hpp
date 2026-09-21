#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace clash_native::transport::shadowsocks {

struct ShadowTlsClientOptions {
    int version = 2;
    std::string password;
    std::string host;
    bool skip_cert_verify = false;
    std::vector<std::string> alpn_protocols{"h2", "http/1.1"};
};

using ShadowTlsOpenHandler = std::function<void(core::Result<std::unique_ptr<core::StreamHandle>>)>;

// Establishes a Shadowsocks Shadow-TLS carrier over an already connected TCP
// stream. The returned handle exposes the carrier bytes; Shadowsocks framing
// remains a separate layer above it.
void async_open_shadow_tls(std::unique_ptr<core::StreamHandle> stream,
                           ShadowTlsClientOptions options, ShadowTlsOpenHandler handler);

} // namespace clash_native::transport::shadowsocks
