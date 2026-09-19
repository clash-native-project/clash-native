#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
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

// A cancellable, asynchronous HTTP message body. Read until the handler receives
// boost::asio::error::eof; trailers() is then the final trailer field block.
// Implementations must allow at most one outstanding read at a time.
class HttpBodyStream {
  public:
    using ReadHandler = core::StreamHandle::ReadHandler;

    virtual void async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) = 0;
    virtual std::vector<HttpHeader> trailers() const = 0;
    virtual void cancel() noexcept = 0;
    virtual ~HttpBodyStream() = default;
};

struct HttpStreamingRequest {
    HttpRequest request;
    // When non-null, request.body must be empty. The source is read as the peer
    // accepts data; EOF may carry HTTP trailer fields through trailers().
    std::shared_ptr<HttpBodyStream> body;
    std::optional<std::uint64_t> content_length;
};

struct HttpStreamingResponse {
    // Contains the status line and initial headers. The response body is read
    // separately and remains bounded by transport flow control and consumer
    // demand. trailers() becomes available on EOF.
    HttpResponse response;
    std::shared_ptr<HttpBodyStream> body;
};

enum class HttpTunnelMode {
    connect,
    // HTTP/1.1 Upgrade; HTTP/2 and HTTP/3 use Extended CONNECT.
    upgrade
};

struct HttpTunnelRequest {
    HttpTunnelMode mode = HttpTunnelMode::connect;
    std::string scheme;
    std::string authority;
    std::string target;
    std::string protocol;
    std::vector<HttpHeader> headers;
    std::size_t rejection_body_limit = 64 * 1024;
};

struct HttpTunnelResponse {
    HttpResponse response;
    // Non-null only when the peer accepted the CONNECT or Upgrade handshake.
    std::unique_ptr<core::StreamHandle> stream;
};

class HttpClientSession {
  public:
    using ExchangeId = std::uint64_t;
    using Handler = std::function<void(core::Result<HttpResponse>)>;
    using StreamingHandler = std::function<void(core::Result<HttpStreamingResponse>)>;
    using TunnelHandler = std::function<void(core::Result<HttpTunnelResponse>)>;

    virtual ExchangeId exchange(HttpRequest request, std::chrono::steady_clock::time_point deadline,
                                Handler handler) = 0;
    virtual ExchangeId exchange_streaming(HttpStreamingRequest request,
                                          std::chrono::steady_clock::time_point deadline,
                                          StreamingHandler handler) = 0;
    virtual ExchangeId open_tunnel(HttpTunnelRequest request,
                                   std::chrono::steady_clock::time_point deadline,
                                   TunnelHandler handler) = 0;
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
