#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace clash_native::transport::proxy {

struct RestlsClientOptions {
    std::string server_name;
    std::string password;
    std::string restls_script;
    bool skip_cert_verify = false;
    // The version hint selects a fixed Botan TLS handshaker and the matching
    // ResTLS ClientHello authentication layout.
    std::string version_hint = "tls12";
};

using RestlsOpenHandler = std::function<void(core::Result<std::unique_ptr<io::StreamHandle>>)>;

void async_open_restls(std::unique_ptr<io::StreamHandle> stream, RestlsClientOptions options,
                       RestlsOpenHandler handler);

} // namespace clash_native::transport::proxy
