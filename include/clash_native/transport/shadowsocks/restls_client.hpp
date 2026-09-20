#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace clash_native::transport::shadowsocks {

struct RestlsClientOptions {
    std::string server_name;
    std::string password;
    std::string restls_script;
    bool skip_cert_verify = false;
    // The native implementation currently uses Botan's TLS 1.2 handshaker.
    // TLS 1.3 remains rejected until its ClientHello Session ID hook is wired.
    std::string version_hint = "tls12";
};

using RestlsOpenHandler =
    std::function<void(core::Result<std::unique_ptr<core::StreamHandle>>) >;

void async_open_restls(std::unique_ptr<core::StreamHandle> stream,
                       RestlsClientOptions options, RestlsOpenHandler handler);

} // namespace clash_native::transport::shadowsocks
