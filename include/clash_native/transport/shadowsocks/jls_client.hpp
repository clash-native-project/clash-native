#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace clash_native::transport::shadowsocks {

struct JlsClientOptions {
    std::string server_name;
    std::string username;
    std::string password;
    std::vector<std::string> alpn;
    bool skip_cert_verify = false;
};

using JlsOpenHandler = std::function<void(core::Result<std::unique_ptr<core::StreamHandle>>)>;

void async_open_jls(std::unique_ptr<core::StreamHandle> stream, JlsClientOptions options,
                    JlsOpenHandler handler);

} // namespace clash_native::transport::shadowsocks
