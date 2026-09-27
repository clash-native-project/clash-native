#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace clash_native::transport::proxy {

struct JlsClientOptions {
    std::string server_name;
    std::string username;
    std::string password;
    std::vector<std::string> alpn;
    bool skip_cert_verify = false;
};

using JlsOpenHandler = std::function<void(core::Result<std::unique_ptr<io::StreamHandle>>)>;

// Abort handle for an in-flight JLS open: timer cancel plus lower-stream
// close; the late terminal drops at the operation's completed_ guard.
class JlsOpenAborter {
  public:
    virtual ~JlsOpenAborter() = default;
    virtual void abort() noexcept = 0;
};

void async_open_jls(std::unique_ptr<io::StreamHandle> stream, JlsClientOptions options,
                    JlsOpenHandler handler);

std::shared_ptr<JlsOpenAborter> async_open_jls_abortable(std::unique_ptr<io::StreamHandle> stream,
                                                         JlsClientOptions options,
                                                         JlsOpenHandler handler);

} // namespace clash_native::transport::proxy
