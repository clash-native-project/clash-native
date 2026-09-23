#include <clash_native/async/callback_sender.hpp>
#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/core/base64.hpp>
#include <clash_native/io/exchange_session.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>
#include <clash_native/transport/grpc_client.hpp>

#include <boost/asio/dispatch.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <limits>
#include <string_view>
#include <utility>

namespace clash_native::transport {
namespace {

constexpr std::size_t kReadBufferSize = 16 * 1024;
constexpr unsigned int kMaxGrpcStatus = 16;
core::Error make_error(core::ErrorCode code, std::string context) {
    return core::Error{code, std::move(context), {}};
}

std::string lower_copy(std::string_view value) {
    std::string result(value);
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}

bool is_metadata_name(std::string_view name) {
    if (name.empty() || name.front() == ':' ||
        std::any_of(name.begin(), name.end(),
                    [](unsigned char character) { return character >= 'A' && character <= 'Z'; })) {
        return false;
    }
    return std::all_of(name.begin(), name.end(), [](unsigned char character) {
        return (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
               character == '-' || character == '_' || character == '.';
    });
}

bool is_binary_metadata(std::string_view name) {
    return name.size() >= 4 && name.substr(name.size() - 4) == "-bin";
}

std::optional<std::string> percent_decode(std::string_view input) {
    const auto hex_value = [](char character) -> int {
        if (character >= '0' && character <= '9') {
            return character - '0';
        }
        if (character >= 'a' && character <= 'f') {
            return character - 'a' + 10;
        }
        if (character >= 'A' && character <= 'F') {
            return character - 'A' + 10;
        }
        return -1;
    };

    std::string result;
    result.reserve(input.size());
    for (std::size_t index = 0; index < input.size(); ++index) {
        if (input[index] != '%') {
            result.push_back(input[index]);
            continue;
        }
        if (index + 2 >= input.size()) {
            return std::nullopt;
        }
        const auto high = hex_value(input[index + 1]);
        const auto low = hex_value(input[index + 2]);
        if (high < 0 || low < 0) {
            return std::nullopt;
        }
        result.push_back(static_cast<char>((high << 4) | low));
        index += 2;
    }
    return result;
}

// Templated over the exchange vocabulary: transport:: and io:: fields share
// only name/value, and both flow through here during the migration.
template <typename Field>
std::optional<std::string_view> find_header(const std::vector<Field> &headers,
                                            std::string_view name) {
    for (const auto &header : headers) {
        if (lower_copy(header.name) == name) {
            return header.value;
        }
    }
    return std::nullopt;
}

template <typename Field>
std::vector<GrpcMetadata> application_metadata(const std::vector<Field> &headers) {
    std::vector<GrpcMetadata> result;
    for (const auto &header : headers) {
        const auto name = lower_copy(header.name);
        if (name.empty() || name.front() == ':' || name == "content-type" ||
            name == "content-length" || name == "date" || name == "server" ||
            name.starts_with("grpc-") || !is_metadata_name(name)) {
            continue;
        }
        auto value = header.value;
        if (is_binary_metadata(name)) {
            auto decoded = core::base64_decode(value);
            if (!decoded) {
                continue;
            }
            value = std::move(*decoded);
        }
        result.push_back({name, std::move(value)});
    }
    return result;
}

template <typename Field> core::Result<GrpcStatus> parse_status(const std::vector<Field> &headers) {
    const auto status_value = find_header(headers, "grpc-status");
    if (!status_value) {
        return core::fail(
            make_error(core::ErrorCode::protocol_framing, "gRPC response is missing grpc-status"));
    }
    unsigned int code = 0;
    const auto parsed =
        std::from_chars(status_value->data(), status_value->data() + status_value->size(), code);
    if (parsed.ec != std::errc{} || parsed.ptr != status_value->data() + status_value->size() ||
        code > kMaxGrpcStatus) {
        return core::fail(make_error(core::ErrorCode::protocol_framing,
                                     "gRPC response has an invalid grpc-status"));
    }
    GrpcStatus result;
    result.code = code;
    if (const auto message = find_header(headers, "grpc-message")) {
        auto decoded = percent_decode(*message);
        if (!decoded) {
            return core::fail(make_error(core::ErrorCode::protocol_framing,
                                         "gRPC response has an invalid grpc-message"));
        }
        result.message = std::move(*decoded);
    }
    result.trailing_metadata = application_metadata(headers);
    return result;
}

std::optional<std::string> grpc_timeout(std::chrono::steady_clock::time_point deadline) {
    const auto now = std::chrono::steady_clock::now();
    if (deadline <= now) {
        return "0n";
    }
    constexpr std::uint64_t kMaxValue = 99'999'999;
    const auto remaining = deadline - now;
    const auto format = [remaining](auto unit, char suffix) -> std::optional<std::string> {
        using Unit = decltype(unit);
        const auto exact = std::chrono::duration<long double, typename Unit::period>(remaining);
        const auto rounded = std::ceil(exact.count());
        if (rounded > static_cast<long double>(kMaxValue)) {
            return std::nullopt;
        }
        const auto count = static_cast<std::uint64_t>(std::max(1.0L, rounded));
        return std::to_string(count) + suffix;
    };
    if (auto value = format(std::chrono::nanoseconds{1}, 'n')) {
        return value;
    }
    if (auto value = format(std::chrono::microseconds{1}, 'u')) {
        return value;
    }
    if (auto value = format(std::chrono::milliseconds{1}, 'm')) {
        return value;
    }
    if (auto value = format(std::chrono::seconds{1}, 'S')) {
        return value;
    }
    if (auto value = format(std::chrono::minutes{1}, 'M')) {
        return value;
    }
    if (auto value = format(std::chrono::hours{1}, 'H')) {
        return value;
    }
    return std::nullopt;
}

core::Status validate_options(const GrpcCallOptions &options) {
    if (options.scheme != "http" && options.scheme != "https") {
        return core::fail(
            make_error(core::ErrorCode::configuration, "gRPC scheme must be http or https"));
    }
    if (options.authority.empty() || options.method.size() < 2 || options.method.front() != '/' ||
        options.method.find(' ', 1) != std::string::npos || options.max_message_size == 0 ||
        options.max_message_size > std::numeric_limits<std::uint32_t>::max()) {
        return core::fail(make_error(core::ErrorCode::configuration,
                                     "gRPC call authority, method, or message limit is invalid"));
    }
    for (const auto &metadata : options.metadata) {
        if (!is_metadata_name(metadata.name) || metadata.name.starts_with("grpc-") ||
            metadata.name == "content-type" || metadata.name == "te" ||
            metadata.value.find('\r') != std::string::npos ||
            metadata.value.find('\n') != std::string::npos) {
            return core::fail(make_error(core::ErrorCode::configuration,
                                         "gRPC metadata contains a reserved or invalid field"));
        }
    }
    return {};
}

} // namespace

class GrpcClientCall::RequestBody final : public io::ExchangeBodyStream,
                                          public std::enable_shared_from_this<RequestBody> {
  public:
    using ReadHandler = std::function<void(const boost::system::error_code &, std::size_t)>;
    using WriteHandler = std::function<void(core::Status)>;

    RequestBody(boost::asio::any_io_executor executor, std::size_t max_message_size)
        : executor_(std::move(executor)), max_message_size_(max_message_size) {}

    io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override {
        using Signatures =
            stdexec::completion_signatures<stdexec::set_value_t(std::optional<std::size_t>),
                                           stdexec::set_error_t(std::exception_ptr),
                                           stdexec::set_stopped_t()>;
        return io::AnySender<std::optional<std::size_t>>{async::callback_sender<Signatures>(
            [self = shared_from_this(), buffer](auto terminal) mutable {
                self->read_some(buffer, std::move(terminal));
            },
            [](auto receiver, const boost::system::error_code &error, std::size_t size) {
                if (!error) {
                    stdexec::set_value(std::move(receiver), std::optional<std::size_t>{size});
                    return;
                }
                if (error == boost::asio::error::eof) {
                    stdexec::set_value(std::move(receiver), std::optional<std::size_t>{});
                    return;
                }
                if (error == boost::asio::error::operation_aborted) {
                    stdexec::set_stopped(std::move(receiver));
                    return;
                }
                stdexec::set_error(
                    std::move(receiver),
                    std::make_exception_ptr(core::Error{core::ErrorCode::transport_io,
                                                        "gRPC request body read failed", error}));
            })};
    }

    void read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) {
        const auto self = shared_from_this();
        boost::asio::dispatch(executor_, [self, buffer, handler = std::move(handler)]() mutable {
            if (!handler) {
                return;
            }
            if (buffer.size() == 0) {
                boost::asio::post(self->executor_,
                                  [handler = std::move(handler)]() mutable { handler({}, 0); });
                return;
            }
            if (self->read_handler_) {
                boost::asio::post(self->executor_, [handler = std::move(handler)]() mutable {
                    handler(boost::asio::error::already_started, 0);
                });
                return;
            }
            if (self->cancelled_) {
                boost::asio::post(self->executor_, [handler = std::move(handler)]() mutable {
                    handler(boost::asio::error::operation_aborted, 0);
                });
                return;
            }
            if (!self->frame_.empty()) {
                self->deliver(buffer, std::move(handler));
                return;
            }
            if (self->closed_) {
                boost::asio::post(self->executor_, [handler = std::move(handler)]() mutable {
                    handler(boost::asio::error::eof, 0);
                });
                return;
            }
            self->read_buffer_ = buffer;
            self->read_handler_ = std::move(handler);
        });
    }

    std::vector<io::ExchangeField> trailers() const override { return {}; }

    void cancel() noexcept override {
        const auto self = shared_from_this();
        boost::asio::post(executor_, [self] {
            if (self->cancelled_) {
                return;
            }
            self->cancelled_ = true;
            self->frame_.clear();
            if (self->write_handler_) {
                auto handler = std::move(self->write_handler_);
                self->post_status(std::move(handler),
                                  core::fail(make_error(core::ErrorCode::cancelled,
                                                        "gRPC request write was cancelled")));
            }
            if (self->read_handler_) {
                auto handler = std::move(self->read_handler_);
                self->read_buffer_ = {};
                self->post_read(std::move(handler), boost::asio::error::operation_aborted, 0);
            }
        });
    }

    void async_write_message(std::string payload, WriteHandler handler) {
        const auto self = shared_from_this();
        boost::asio::dispatch(executor_, [self, payload = std::move(payload),
                                          handler = std::move(handler)]() mutable {
            if (self->cancelled_ || self->closed_) {
                self->post_status(
                    std::move(handler),
                    core::fail(make_error(self->cancelled_ ? core::ErrorCode::cancelled
                                                           : core::ErrorCode::protocol_framing,
                                          "gRPC request side is closed")));
                return;
            }
            if (!self->frame_.empty() || self->write_handler_) {
                self->post_status(
                    std::move(handler),
                    core::fail(make_error(core::ErrorCode::protocol_framing,
                                          "only one gRPC request write may be active")));
                return;
            }
            if (payload.size() > self->max_message_size_ ||
                payload.size() > std::numeric_limits<std::uint32_t>::max()) {
                self->post_status(
                    std::move(handler),
                    core::fail(make_error(core::ErrorCode::protocol_framing,
                                          "gRPC request message exceeds the configured limit")));
                return;
            }
            self->frame_.resize(payload.size() + 5);
            self->frame_[0] = 0;
            const auto size = static_cast<std::uint32_t>(payload.size());
            self->frame_[1] = static_cast<std::uint8_t>(size >> 24U);
            self->frame_[2] = static_cast<std::uint8_t>(size >> 16U);
            self->frame_[3] = static_cast<std::uint8_t>(size >> 8U);
            self->frame_[4] = static_cast<std::uint8_t>(size);
            std::copy(payload.begin(), payload.end(), self->frame_.begin() + 5);
            self->frame_offset_ = 0;
            self->write_handler_ = std::move(handler);
            if (self->read_handler_) {
                auto read_handler = std::move(self->read_handler_);
                const auto buffer = self->read_buffer_;
                self->read_buffer_ = {};
                self->deliver(buffer, std::move(read_handler));
            }
        });
    }

    void close_send() {
        const auto self = shared_from_this();
        boost::asio::dispatch(executor_, [self] {
            self->closed_ = true;
            if (self->frame_.empty() && self->read_handler_) {
                auto handler = std::move(self->read_handler_);
                self->read_buffer_ = {};
                self->post_read(std::move(handler), boost::asio::error::eof, 0);
            }
        });
    }

  private:
    void deliver(boost::asio::mutable_buffer buffer, ReadHandler handler) {
        const auto remaining = frame_.size() - frame_offset_;
        const auto amount = std::min(buffer.size(), remaining);
        const auto copied = boost::asio::buffer_copy(
            buffer, boost::asio::buffer(frame_.data() + frame_offset_, amount));
        frame_offset_ += copied;
        post_read(std::move(handler), {}, copied);
        if (frame_offset_ == frame_.size()) {
            frame_.clear();
            frame_offset_ = 0;
            if (write_handler_) {
                auto write_handler = std::move(write_handler_);
                post_status(std::move(write_handler), {});
            }
            if (closed_ && read_handler_) {
                auto read_handler = std::move(read_handler_);
                read_buffer_ = {};
                post_read(std::move(read_handler), boost::asio::error::eof, 0);
            }
        }
    }

    void post_read(ReadHandler handler, boost::system::error_code error, std::size_t size) {
        boost::asio::post(executor_, [handler = std::move(handler), error, size]() mutable {
            if (handler) {
                handler(error, size);
            }
        });
    }

    void post_status(WriteHandler handler, core::Status result) {
        boost::asio::post(executor_,
                          [handler = std::move(handler), result = std::move(result)]() mutable {
                              if (handler) {
                                  handler(std::move(result));
                              }
                          });
    }

    boost::asio::any_io_executor executor_;
    std::size_t max_message_size_;
    std::vector<std::uint8_t> frame_;
    std::size_t frame_offset_ = 0;
    boost::asio::mutable_buffer read_buffer_;
    ReadHandler read_handler_;
    WriteHandler write_handler_;
    bool closed_ = false;
    bool cancelled_ = false;
};

GrpcClientCall::GrpcClientCall(boost::asio::any_io_executor executor,
                               std::shared_ptr<io::ExchangeSession> session,
                               GrpcCallOptions options, OpenHandler open_handler)
    : executor_(std::move(executor)), session_(std::move(session)), options_(std::move(options)),
      open_handler_(std::move(open_handler)),
      request_body_(std::make_shared<RequestBody>(executor_, options_.max_message_size)),
      read_buffer_(kReadBufferSize) {}

GrpcClientCall::~GrpcClientCall() {
    if (request_body_) {
        request_body_->cancel();
    }
    if (response_body_) {
        response_body_->cancel();
    }
    // No per-exchange cancel: the io:: vocabulary cancels through the stop
    // token, and body cancels plus late-terminal drops wind the call down.
}

void GrpcClientCall::start() {
    if (cancelled_) {
        return;
    }
    if (!session_) {
        if (open_handler_) {
            auto handler = std::move(open_handler_);
            handler(core::fail(
                make_error(core::ErrorCode::configuration, "gRPC client has no HTTP/2 session")));
        }
        return;
    }
    if (auto validation = validate_options(options_); !validation) {
        if (open_handler_) {
            auto handler = std::move(open_handler_);
            handler(std::move(validation));
        }
        return;
    }

    io::StreamingExchangeRequest request;
    request.request.method = "POST";
    request.request.scheme = options_.scheme;
    request.request.authority = options_.authority;
    request.request.target = options_.method;
    request.request.headers.push_back({"content-type", "application/grpc+proto"});
    request.request.headers.push_back({"te", "trailers"});
    for (const auto &metadata : options_.metadata) {
        request.request.headers.push_back({metadata.name, is_binary_metadata(metadata.name)
                                                              ? core::base64_encode(metadata.value)
                                                              : metadata.value});
    }
    if (options_.deadline) {
        if (auto timeout = grpc_timeout(*options_.deadline)) {
            request.request.headers.push_back({"grpc-timeout", std::move(*timeout)});
        }
    }
    request.body = request_body_;
    const auto deadline = options_.deadline.value_or(std::chrono::steady_clock::time_point::max());
    struct ResponseReceiver {
        using receiver_concept = stdexec::receiver_tag;
        std::shared_ptr<GrpcClientCall> self;
        void set_value(io::StreamingExchangeResponse result) && noexcept {
            self->on_response(std::move(result));
        }
        void set_error(std::exception_ptr error) && noexcept {
            try {
                std::rethrow_exception(std::move(error));
            } catch (const core::Error &failure) {
                self->on_response(core::fail(failure));
            } catch (...) {
                self->on_response(core::fail(
                    make_error(core::ErrorCode::endpoint_connection, "gRPC exchange failed")));
            }
        }
        void set_stopped() && noexcept {
            self->on_response(
                core::fail(make_error(core::ErrorCode::cancelled, "gRPC exchange was stopped")));
        }
    };
    const auto self = shared_from_this();
    async::start_with_receiver(session_->exchange_streaming(std::move(request), deadline),
                               ResponseReceiver{self});
}

void GrpcClientCall::on_response(core::Result<io::StreamingExchangeResponse> result) {
    if (cancelled_) {
        return;
    }
    if (!result) {
        opened_ = true;
        auto error = std::move(result.error());
        fail_reads(error);
        if (open_handler_) {
            auto handler = std::move(open_handler_);
            handler(core::fail(error));
        }
        return;
    }
    if (result->response.status != 200) {
        auto error = make_error(core::ErrorCode::protocol_framing,
                                "gRPC endpoint returned HTTP status " +
                                    std::to_string(result->response.status));
        if (result->body) {
            result->body->cancel();
        }
        opened_ = true;
        fail_reads(error);
        if (open_handler_) {
            auto handler = std::move(open_handler_);
            handler(core::fail(error));
        }
        return;
    }
    const auto content_type = find_header(result->response.headers, "content-type");
    if (!content_type) {
        auto error =
            make_error(core::ErrorCode::protocol_framing, "gRPC response is missing content-type");
        if (result->body) {
            result->body->cancel();
        }
        opened_ = true;
        fail_reads(error);
        if (open_handler_) {
            auto handler = std::move(open_handler_);
            handler(core::fail(error));
        }
        return;
    }
    const auto media_type = lower_copy(content_type->substr(0, content_type->find(';')));
    if (media_type != "application/grpc" && media_type != "application/grpc+proto") {
        auto error = make_error(core::ErrorCode::protocol_framing,
                                "gRPC response has an unsupported content-type");
        if (result->body) {
            result->body->cancel();
        }
        opened_ = true;
        fail_reads(error);
        if (open_handler_) {
            auto handler = std::move(open_handler_);
            handler(core::fail(error));
        }
        return;
    }
    if (!result->body) {
        auto error =
            make_error(core::ErrorCode::protocol_framing, "gRPC response has no HTTP body stream");
        opened_ = true;
        fail_reads(error);
        if (open_handler_) {
            auto handler = std::move(open_handler_);
            handler(core::fail(error));
        }
        return;
    }

    response_body_ = std::move(result->body);
    initial_metadata_ = application_metadata(result->response.headers);
    if (find_header(result->response.headers, "grpc-status")) {
        auto status = parse_status(result->response.headers);
        if (!status) {
            auto error = std::move(status.error());
            fail_reads(error);
            if (open_handler_) {
                auto handler = std::move(open_handler_);
                handler(core::fail(error));
            }
            opened_ = true;
            return;
        }
        status_ = std::move(*status);
    }
    opened_ = true;
    if (open_handler_) {
        auto handler = std::move(open_handler_);
        handler({});
    }
    deliver_or_read();
}

void GrpcClientCall::async_write(const google::protobuf::MessageLite &message,
                                 WriteHandler handler) {
    std::string payload;
    if (!message.SerializeToString(&payload)) {
        boost::asio::post(executor_, [handler = std::move(handler)]() mutable {
            if (handler) {
                handler(core::fail(make_error(core::ErrorCode::protocol_framing,
                                              "failed to serialize the gRPC protobuf message")));
            }
        });
        return;
    }
    request_body_->async_write_message(std::move(payload), std::move(handler));
}

void GrpcClientCall::close_send() { request_body_->close_send(); }

void GrpcClientCall::async_read_message(ReadMessageHandler handler) {
    const auto self = shared_from_this();
    boost::asio::dispatch(executor_, [self, handler = std::move(handler)]() mutable {
        if (!handler) {
            return;
        }
        if (self->pending_read_) {
            self->post_read(std::move(handler),
                            core::fail(make_error(core::ErrorCode::protocol_framing,
                                                  "only one gRPC response read may be active")));
            return;
        }
        self->pending_read_ = std::move(handler);
        self->deliver_or_read();
    });
}

void GrpcClientCall::async_read_protobuf(google::protobuf::MessageLite &message,
                                         ReadProtobufHandler handler) {
    async_read_message([&message, handler = std::move(handler)](
                           core::Result<std::optional<std::string>> result) mutable {
        if (!result) {
            if (handler) {
                handler(core::fail(std::move(result.error())));
            }
            return;
        }
        if (!*result) {
            if (handler) {
                handler(false);
            }
            return;
        }
        if (!message.ParseFromString(**result)) {
            if (handler) {
                handler(core::fail(make_error(core::ErrorCode::protocol_framing,
                                              "failed to parse the gRPC protobuf response")));
            }
            return;
        }
        if (handler) {
            handler(true);
        }
    });
}

void GrpcClientCall::cancel() noexcept {
    if (cancelled_) {
        return;
    }
    cancelled_ = true;
    opened_ = true;
    if (open_handler_) {
        auto handler = std::move(open_handler_);
        boost::asio::post(executor_, [handler = std::move(handler)]() mutable {
            if (handler) {
                handler(core::fail(make_error(core::ErrorCode::cancelled,
                                              "gRPC call was cancelled before opening")));
            }
        });
    }
    if (request_body_) {
        request_body_->cancel();
    }
    if (response_body_) {
        response_body_->cancel();
    }
    if (pending_read_) {
        auto handler = std::move(pending_read_);
        post_read(std::move(handler),
                  core::fail(make_error(core::ErrorCode::cancelled, "gRPC call was cancelled")));
    }
}

const std::vector<GrpcMetadata> &GrpcClientCall::initial_metadata() const noexcept {
    return initial_metadata_;
}

const std::optional<GrpcStatus> &GrpcClientCall::status() const noexcept { return status_; }

void GrpcClientCall::read_response() {
    if (!response_body_ || reading_body_ || body_eof_ || read_error_) {
        return;
    }
    reading_body_ = true;
    struct BodyReceiver {
        using receiver_concept = stdexec::receiver_tag;
        std::shared_ptr<GrpcClientCall> self;
        void set_value(std::optional<std::size_t> size) && noexcept {
            if (size) {
                self->on_response_read({}, *size);
                return;
            }
            self->on_response_read(boost::asio::error::eof, 0);
        }
        void set_error(std::exception_ptr error) && noexcept {
            self->on_response_read(net::unpack_error(std::move(error)), 0);
        }
        void set_stopped() && noexcept {
            self->on_response_read(boost::asio::error::operation_aborted, 0);
        }
    };
    const auto self = shared_from_this();
    async::start_with_receiver(response_body_->async_read_some(boost::asio::buffer(read_buffer_)),
                               BodyReceiver{self});
}

void GrpcClientCall::on_response_read(const boost::system::error_code &error, std::size_t size) {
    reading_body_ = false;
    if (size != 0) {
        constexpr auto kMessageFramingAllowance = std::size_t{5} + kReadBufferSize;
        const auto buffered = response_bytes_.size() - response_offset_;
        if (size > options_.max_message_size + kMessageFramingAllowance -
                       std::min(buffered, options_.max_message_size + kMessageFramingAllowance)) {
            fail_reads(make_error(core::ErrorCode::protocol_framing,
                                  "gRPC response message exceeds the configured limit"));
            return;
        }
        response_bytes_.insert(response_bytes_.end(), read_buffer_.begin(),
                               read_buffer_.begin() + static_cast<std::ptrdiff_t>(size));
    }
    if (error == boost::asio::error::eof) {
        body_eof_ = true;
    } else if (error) {
        fail_reads(make_error(
            error == boost::asio::error::operation_aborted ? core::ErrorCode::cancelled
                                                           : core::ErrorCode::transport_io,
            "failed while reading the gRPC HTTP/2 response body: " + error.message()));
        return;
    } else if (size == 0) {
        fail_reads(make_error(core::ErrorCode::transport_io,
                              "gRPC HTTP/2 response read made no progress"));
        return;
    }
    deliver_or_read();
}

void GrpcClientCall::deliver_or_read() {
    if (!pending_read_ || !opened_) {
        return;
    }
    if (read_error_) {
        auto handler = std::move(pending_read_);
        post_read(std::move(handler), core::fail(*read_error_));
        return;
    }
    const auto available = response_bytes_.size() - response_offset_;
    if (available >= 5) {
        const auto *frame = response_bytes_.data() + response_offset_;
        const auto compressed = frame[0];
        const auto message_size = (static_cast<std::uint32_t>(frame[1]) << 24U) |
                                  (static_cast<std::uint32_t>(frame[2]) << 16U) |
                                  (static_cast<std::uint32_t>(frame[3]) << 8U) |
                                  static_cast<std::uint32_t>(frame[4]);
        if (compressed != 0) {
            fail_reads(make_error(core::ErrorCode::unsupported,
                                  "compressed gRPC messages are not supported"));
            deliver_or_read();
            return;
        }
        if (message_size > options_.max_message_size) {
            fail_reads(make_error(core::ErrorCode::protocol_framing,
                                  "gRPC response message exceeds the configured limit"));
            deliver_or_read();
            return;
        }
        if (available >= static_cast<std::size_t>(message_size) + 5) {
            std::string message(reinterpret_cast<const char *>(frame + 5), message_size);
            response_offset_ += static_cast<std::size_t>(message_size) + 5;
            if (response_offset_ == response_bytes_.size()) {
                response_bytes_.clear();
                response_offset_ = 0;
            } else if (response_offset_ >= kReadBufferSize) {
                response_bytes_.erase(response_bytes_.begin(),
                                      response_bytes_.begin() +
                                          static_cast<std::ptrdiff_t>(response_offset_));
                response_offset_ = 0;
            }
            auto handler = std::move(pending_read_);
            post_read(std::move(handler), std::optional<std::string>(std::move(message)));
            return;
        }
    }
    if (body_eof_) {
        auto status = finish_response();
        if (!status) {
            fail_reads(std::move(status.error()));
            deliver_or_read();
            return;
        }
        response_finished_ = true;
        auto handler = std::move(pending_read_);
        post_read(std::move(handler), std::optional<std::string>{});
        return;
    }
    read_response();
}

core::Status GrpcClientCall::finish_response() {
    if (response_finished_) {
        return {};
    }
    if (response_offset_ != response_bytes_.size()) {
        return core::fail(make_error(core::ErrorCode::protocol_framing,
                                     "gRPC response ended with a truncated message frame"));
    }
    const auto trailer_headers =
        response_body_ ? response_body_->trailers() : std::vector<io::ExchangeField>{};
    if (find_header(trailer_headers, "grpc-status")) {
        auto trailer_status = parse_status(trailer_headers);
        if (!trailer_status) {
            return core::fail(std::move(trailer_status.error()));
        }
        if (status_ && status_->code != trailer_status->code) {
            return core::fail(make_error(core::ErrorCode::protocol_framing,
                                         "gRPC initial and trailing status values disagree"));
        }
        status_ = std::move(*trailer_status);
    }
    if (!status_) {
        return core::fail(make_error(core::ErrorCode::protocol_framing,
                                     "gRPC response ended without grpc-status"));
    }
    response_finished_ = true;
    return {};
}

void GrpcClientCall::fail_reads(core::Error error) {
    if (read_error_) {
        return;
    }
    read_error_ = std::move(error);
    if (response_body_) {
        response_body_->cancel();
    }
    if (pending_read_) {
        auto handler = std::move(pending_read_);
        post_read(std::move(handler), core::fail(*read_error_));
    }
}

void GrpcClientCall::post_read(ReadMessageHandler handler,
                               core::Result<std::optional<std::string>> result) {
    boost::asio::post(executor_,
                      [handler = std::move(handler), result = std::move(result)]() mutable {
                          if (handler) {
                              handler(std::move(result));
                          }
                      });
}

GrpcClient::GrpcClient(boost::asio::any_io_executor executor,
                       std::shared_ptr<io::ExchangeSession> session)
    : executor_(std::move(executor)), session_(std::move(session)) {}

std::shared_ptr<GrpcClientCall> GrpcClient::start_call(GrpcCallOptions options,
                                                       GrpcClientCall::OpenHandler handler) {
    auto call = std::shared_ptr<GrpcClientCall>(
        new GrpcClientCall(executor_, session_, std::move(options), std::move(handler)));
    boost::asio::dispatch(executor_, [call] { call->start(); });
    return call;
}

} // namespace clash_native::transport
