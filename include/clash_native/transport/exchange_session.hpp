#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/core/result.hpp>
#include <clash_native/transport/multiplexed_session.hpp>

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

struct ExchangeField {
    std::string name;
    std::string value;
};

struct ExchangeRequest {
    std::string method;
    std::string scheme;
    std::string authority;
    std::string target;
    std::vector<ExchangeField> headers;
    std::vector<std::uint8_t> body;
    std::size_t response_body_limit = 1024 * 1024;
    bool keep_alive = true;
};

struct ExchangeResponse {
    unsigned version = 0;
    unsigned status = 0;
    std::vector<ExchangeField> headers;
    std::vector<std::uint8_t> body;
    bool keep_alive = false;
};

// A cancellable, asynchronous exchange message body. Read until the handler
// receives boost::asio::error::eof; trailers() is then the final trailer field
// block.
// Implementations must allow at most one outstanding read at a time.
class ExchangeBodyStream {
  public:
    using ReadHandler = core::StreamHandle::ReadHandler;

    virtual void async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) = 0;
    virtual std::vector<ExchangeField> trailers() const = 0;
    virtual void cancel() noexcept = 0;
    virtual ~ExchangeBodyStream() = default;
};

struct StreamingExchangeRequest {
    ExchangeRequest request;
    // When non-null, request.body must be empty. The source is read as the peer
    // accepts data; EOF may carry trailer fields through trailers().
    std::shared_ptr<ExchangeBodyStream> body;
    std::optional<std::uint64_t> content_length;
};

struct StreamingExchangeResponse {
    // Contains the response head. The response body is read separately and
    // remains bounded by transport flow control and consumer demand.
    // trailers() becomes available on EOF.
    ExchangeResponse response;
    std::shared_ptr<ExchangeBodyStream> body;
};

enum class StreamUpgradeMode {
    connect,
    // HTTP/1.1 Upgrade; HTTP/2 and HTTP/3 use Extended CONNECT.
    upgrade
};

struct StreamUpgradeRequest {
    StreamUpgradeMode mode = StreamUpgradeMode::connect;
    std::string scheme;
    std::string authority;
    std::string target;
    std::string protocol;
    std::vector<ExchangeField> headers;
    std::size_t rejection_body_limit = 64 * 1024;
};

struct StreamUpgradeResponse {
    ExchangeResponse response;
    // Non-null only when the peer accepted the CONNECT or Upgrade handshake.
    std::unique_ptr<core::StreamHandle> stream;
};

class ExchangeSession {
  public:
    using ExchangeId = std::uint64_t;
    using Handler = std::function<void(core::Result<ExchangeResponse>)>;
    using StreamingHandler = std::function<void(core::Result<StreamingExchangeResponse>)>;
    using TunnelHandler = std::function<void(core::Result<StreamUpgradeResponse>)>;

    virtual ExchangeId exchange(ExchangeRequest request,
                                std::chrono::steady_clock::time_point deadline,
                                Handler handler) = 0;
    virtual ExchangeId exchange_streaming(StreamingExchangeRequest request,
                                          std::chrono::steady_clock::time_point deadline,
                                          StreamingHandler handler) = 0;
    virtual ExchangeId open_tunnel(StreamUpgradeRequest request,
                                   std::chrono::steady_clock::time_point deadline,
                                   TunnelHandler handler) = 0;
    // Returns the raw logical-stream capability when the carrier exposes one.
    // HTTP/1.1 returns nullptr; HTTP/2 and HTTP/3 expose their session view.
    virtual MultiplexedSession *multiplexed_session() noexcept { return nullptr; }
    // Returns the carrier's datagram view when the underlying protocol supports
    // it. HTTP/3 uses this for QUIC DATAGRAM frames.
    virtual std::unique_ptr<core::DatagramHandle> open_datagram() { return {}; }
    virtual void cancel(ExchangeId exchange_id) noexcept = 0;
    virtual void stop() noexcept = 0;
    virtual bool retired() const noexcept = 0;
    virtual ~ExchangeSession() = default;
};

// The session takes ownership of an established stream. Calls and callbacks
// must use the stream's executor.
std::shared_ptr<ExchangeSession>
make_http1_exchange_session(std::unique_ptr<core::StreamHandle> stream);
std::shared_ptr<ExchangeSession>
make_http2_exchange_session(std::unique_ptr<core::StreamHandle> stream);
std::shared_ptr<ExchangeSession>
make_http3_exchange_session(std::shared_ptr<QuicClientConnection> connection,
                            std::function<void(core::Error)> failure_handler = {});

} // namespace clash_native::transport
