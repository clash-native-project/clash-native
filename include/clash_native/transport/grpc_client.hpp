#pragma once

#include <clash_native/core/result.hpp>
#include <clash_native/transport/http_client.hpp>

#include <google/protobuf/message_lite.h>

#include <boost/asio/any_io_executor.hpp>

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace clash_native::transport {

struct GrpcMetadata {
    std::string name;
    // Binary metadata values are raw bytes; names ending in "-bin" are
    // base64 encoded on the HTTP/2 wire.
    std::string value;
};

struct GrpcCallOptions {
    std::string scheme = "https";
    std::string authority;
    // Full gRPC method path, for example "/example.Echo/Unary".
    std::string method;
    std::vector<GrpcMetadata> metadata;
    std::optional<std::chrono::steady_clock::time_point> deadline;
    std::size_t max_message_size = 4 * 1024 * 1024;
};

struct GrpcStatus {
    unsigned int code = 0;
    std::string message;
    std::vector<GrpcMetadata> trailing_metadata;
};

// A gRPC-over-HTTP/2 call. Calls, callbacks, and protobuf objects must be used
// on the executor passed to GrpcClient. Compression is not implemented yet.
class GrpcClientCall final : public std::enable_shared_from_this<GrpcClientCall> {
  public:
    using OpenHandler = std::function<void(core::Status)>;
    using WriteHandler = std::function<void(core::Status)>;
    using ReadMessageHandler = std::function<void(core::Result<std::optional<std::string>>)>;
    using ReadProtobufHandler = std::function<void(core::Result<bool>)>;

    ~GrpcClientCall();

    void async_write(const google::protobuf::MessageLite &message, WriteHandler handler);
    void close_send();
    void async_read_message(ReadMessageHandler handler);
    void async_read_protobuf(google::protobuf::MessageLite &message, ReadProtobufHandler handler);
    void cancel() noexcept;

    const std::vector<GrpcMetadata> &initial_metadata() const noexcept;
    const std::optional<GrpcStatus> &status() const noexcept;

  private:
    friend class GrpcClient;
    class RequestBody;

    GrpcClientCall(boost::asio::any_io_executor executor,
                   std::shared_ptr<HttpClientSession> session, GrpcCallOptions options,
                   OpenHandler open_handler);
    void start();
    void on_response(core::Result<HttpStreamingResponse> result);
    void read_response();
    void on_response_read(const boost::system::error_code &error, std::size_t size);
    void deliver_or_read();
    core::Status finish_response();
    void fail_reads(core::Error error);
    void post_read(ReadMessageHandler handler, core::Result<std::optional<std::string>> result);

    boost::asio::any_io_executor executor_;
    std::shared_ptr<HttpClientSession> session_;
    GrpcCallOptions options_;
    OpenHandler open_handler_;
    std::shared_ptr<RequestBody> request_body_;
    std::shared_ptr<HttpBodyStream> response_body_;
    HttpClientSession::ExchangeId exchange_id_ = 0;
    std::vector<GrpcMetadata> initial_metadata_;
    std::optional<GrpcStatus> status_;
    std::vector<std::uint8_t> response_bytes_;
    std::size_t response_offset_ = 0;
    std::vector<std::uint8_t> read_buffer_;
    ReadMessageHandler pending_read_;
    std::optional<core::Error> read_error_;
    bool opened_ = false;
    bool reading_body_ = false;
    bool body_eof_ = false;
    bool response_finished_ = false;
    bool cancelled_ = false;
};

class GrpcClient final {
  public:
    GrpcClient(boost::asio::any_io_executor executor, std::shared_ptr<HttpClientSession> session);

    std::shared_ptr<GrpcClientCall> start_call(GrpcCallOptions options,
                                               GrpcClientCall::OpenHandler handler);

  private:
    boost::asio::any_io_executor executor_;
    std::shared_ptr<HttpClientSession> session_;
};

} // namespace clash_native::transport
