#pragma once

#include <clash_native/transport/shadowsocks/shadow_tls.hpp>

namespace clash_native::transport::shadowsocks {

// Opens a Shadow-TLS v3 carrier over an already connected stream. The v3
// handshake uses a password-authenticated TLS 1.3 ClientHello and preserves
// the carrier's record authentication after the TLS handshake completes.
void async_open_shadow_tls_v3(std::unique_ptr<core::StreamHandle> stream,
                              ShadowTlsClientOptions options,
                              ShadowTlsOpenHandler handler);

} // namespace clash_native::transport::shadowsocks
