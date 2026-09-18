#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace clash_native::transport {

class QuicClientConnection;

struct HttpHeader {
    std::string name;
    std::string value;
};

struct HttpRequest {
    std::string method;
    std::string scheme;
    std::string authority;
    std::string target;
    std::vector<HttpHeader> headers;
    std::vector<std::uint8_t> body;
    std::size_t response_body_limit = 1024 * 1024;
    bool keep_alive = true;
};

struct HttpResponse {
    unsigned version = 0;
    unsigned status = 0;
    std::vector<HttpHeader> headers;
    std::vector<std::uint8_t> body;
    bool keep_alive = false;
};

class HttpClientSession {
  public:
    using ExchangeId = std::uint64_t;
    using Handler = std::function<void(core::Result<HttpResponse>)>;

    virtual ExchangeId exchange(HttpRequest request, std::chrono::steady_clock::time_point deadline,
                                Handler handler) = 0;
    virtual void cancel(ExchangeId exchange_id) noexcept = 0;
    virtual void stop() noexcept = 0;
    virtual bool retired() const noexcept = 0;
    virtual ~HttpClientSession() = default;
};

// The session takes ownership of an established stream. Calls and callbacks
// must use the stream's executor.
std::shared_ptr<HttpClientSession>
make_http1_client_session(std::unique_ptr<core::StreamHandle> stream);
std::shared_ptr<HttpClientSession>
make_http2_client_session(std::unique_ptr<core::StreamHandle> stream);
std::shared_ptr<HttpClientSession>
make_http3_client_session(std::shared_ptr<QuicClientConnection> connection,
                          std::function<void(core::Error)> failure_handler = {});

} // namespace clash_native::transport
