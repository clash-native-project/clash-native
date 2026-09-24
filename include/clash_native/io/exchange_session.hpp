#pragma once

#include <clash_native/io/datagram_handle.hpp>
#include <clash_native/io/multiplexed_session.hpp>
#include <clash_native/io/sender.hpp>
#include <clash_native/io/stream_handle.hpp>

#include <boost/asio/buffer.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace clash_native::io {

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

// A cancellable, asynchronous exchange message body. Read until the pull
// completes with disengaged (EOF); trailers() is then the final trailer field
// block. Implementations must allow at most one outstanding read at a time.
class ExchangeBodyStream {
  public:
    virtual AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) = 0;
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
    // When true, the operation deadline only bounds the response head:
    // the watchdog is disarmed once response headers arrive and the
    // bodies then flow without a session-imposed lifetime cap. Long-lived
    // bidirectional streams (gRPC Tun) opt in; the default keeps the
    // deadline over the whole exchange.
    bool head_deadline_only = false;
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
    std::unique_ptr<StreamHandle> stream;
};

// HTTP-style request/response exchanges over any carrier. Each operation completes
// set_value(Response) on success or set_error(exception_ptr) carrying a
// core::Error on failure; cancellation travels through the stop token, with
// cancel(id) retained for session-side aborts.
class ExchangeSession {
  public:
    using ExchangeId = std::uint64_t;

    virtual AnySender<ExchangeResponse>
    exchange(ExchangeRequest request, std::chrono::steady_clock::time_point deadline) = 0;
    virtual AnySender<StreamingExchangeResponse>
    exchange_streaming(StreamingExchangeRequest request,
                       std::chrono::steady_clock::time_point deadline) = 0;
    virtual AnySender<StreamUpgradeResponse>
    open_tunnel(StreamUpgradeRequest request, std::chrono::steady_clock::time_point deadline) = 0;
    // Returns the raw logical-stream capability when the carrier exposes one.
    // HTTP/1.1 returns nullptr; HTTP/2 and HTTP/3 expose their session view.
    virtual MultiplexedSession *multiplexed_session() noexcept { return nullptr; }
    // Returns the carrier's datagram view when the underlying protocol supports
    // it. HTTP/3 uses this for QUIC DATAGRAM frames.
    virtual std::unique_ptr<DatagramHandle> open_datagram() { return {}; }
    virtual void cancel(ExchangeId exchange_id) noexcept = 0;
    virtual void stop() noexcept = 0;
    virtual bool retired() const noexcept = 0;
    virtual ~ExchangeSession() = default;
};

} // namespace clash_native::io
