#include "http_body_stream.hpp"
#include "http_tunnel_stream.hpp"
#include <clash_native/net/stream_handle_adapter.hpp>
#include <clash_native/transport/exchange_session.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

#include <nghttp2/nghttp2.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

namespace clash_native::transport {

namespace {

core::Error io_error(std::string context, const boost::system::error_code &error) {
    return {core::ErrorCode::transport_io, std::move(context),
            std::error_code(error.value(), std::system_category())};
}

core::Error protocol_error(std::string context) {
    return {core::ErrorCode::protocol_framing, std::move(context)};
}

core::Error timeout_error() { return {core::ErrorCode::timeout, "HTTP/2 exchange timed out"}; }

core::Error cancelled_error() {
    return {core::ErrorCode::cancelled, "HTTP/2 exchange was cancelled"};
}

boost::system::error_code body_stream_error(const core::Error &error) {
    if (error.code == core::ErrorCode::timeout) {
        return boost::asio::error::timed_out;
    }
    if (error.code == core::ErrorCode::transport_io) {
        return boost::asio::error::connection_reset;
    }
    return boost::asio::error::operation_aborted;
}

constexpr std::size_t kStreamingBodyReadSize = 16 * 1024;
constexpr std::size_t kStreamingResponseQueueCapacity = 256 * 1024;

bool contains_control(std::string_view value) {
    return std::any_of(value.begin(), value.end(), [](unsigned char character) {
        return character < 0x20 || character == 0x7f;
    });
}

bool contains_uri_whitespace(std::string_view value) {
    return std::any_of(value.begin(), value.end(), [](unsigned char character) {
        return character <= 0x20 || character == 0x7f;
    });
}

constexpr std::string_view kTokenPunctuation = "!#$%&'*+-.^_`|~";

bool is_token(std::string_view value) {
    if (value.empty()) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](unsigned char character) {
        return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
               (character >= '0' && character <= '9') ||
               kTokenPunctuation.find(character) != std::string_view::npos;
    });
}

bool forbidden_http2_header(std::string_view name, std::string_view value) {
    if (name == "connection" || name == "keep-alive" || name == "proxy-connection" ||
        name == "transfer-encoding" || name == "upgrade") {
        return true;
    }
    return name == "te" && value != "trailers";
}

std::string lower_copy(std::string_view value) {
    std::string result(value);
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}

class Http2ClientSession final : public ExchangeSession,
                                 public MultiplexedSession,
                                 public std::enable_shared_from_this<Http2ClientSession> {
  public:
    explicit Http2ClientSession(std::unique_ptr<io::StreamHandle> stream)
        : executor_(stream->executor()),
          stream_(std::make_unique<net::StreamHandleAdapter<io::StreamHandle>>(std::move(stream))) {
    }

    ~Http2ClientSession() { close_http2(); }

    bool initialize() {
        nghttp2_session_callbacks *callbacks = nullptr;
        if (nghttp2_session_callbacks_new(&callbacks) != 0) {
            initialization_error_ = protocol_error("failed to allocate nghttp2 callbacks");
            return false;
        }
        nghttp2_session_callbacks_set_on_header_callback(callbacks, &on_header);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, &on_data_chunk);
        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, &on_frame_received);
        nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, &on_stream_closed);
        nghttp2_option *options = nullptr;
        if (nghttp2_option_new(&options) != 0) {
            nghttp2_session_callbacks_del(callbacks);
            initialization_error_ = protocol_error("failed to allocate nghttp2 options");
            return false;
        }
        nghttp2_option_set_no_auto_window_update(options, 1);
        const auto created = nghttp2_session_client_new2(&http2_session_, callbacks, this, options);
        nghttp2_option_del(options);
        nghttp2_session_callbacks_del(callbacks);
        if (created != 0) {
            initialization_error_ = protocol_error("failed to create nghttp2 client session");
            return false;
        }
        const int settings_result =
            nghttp2_submit_settings(http2_session_, NGHTTP2_FLAG_NONE, nullptr, 0);
        if (settings_result != 0) {
            initialization_error_ = protocol_error("failed to submit HTTP/2 client settings");
            return false;
        }
        return true;
    }

    void start() {
        send_pending();
        read_response();
    }

    ExchangeId exchange(ExchangeRequest request, std::chrono::steady_clock::time_point deadline,
                        Handler handler) override {
        const auto exchange_id = next_exchange_id();
        if (stopped_ || retired_) {
            post_result(std::move(handler), core::fail(cancelled_error()));
            return exchange_id;
        }
        if (initialization_error_) {
            post_result(std::move(handler), core::fail(*initialization_error_));
            return exchange_id;
        }
        const auto validation_error = validate_request(request);
        if (validation_error) {
            post_result(std::move(handler), core::fail(*validation_error));
            return exchange_id;
        }
        if (deadline <= std::chrono::steady_clock::now()) {
            post_result(std::move(handler), core::fail(timeout_error()));
            return exchange_id;
        }

        auto pending = std::make_shared<Pending>(executor_);
        pending->request = std::move(request);
        pending->handler = std::move(handler);
        pending->timer.expires_at(deadline);
        const auto self = shared_from_this();
        pending->timer.async_wait([self, exchange_id](const boost::system::error_code &error) {
            if (!error) {
                self->fail_pending(exchange_id, timeout_error());
            }
        });
        pending_.emplace(exchange_id, pending);
        submit_request(exchange_id, pending);
        send_pending();
        return exchange_id;
    }

    ExchangeId exchange_streaming(StreamingExchangeRequest request,
                                  std::chrono::steady_clock::time_point deadline,
                                  StreamingHandler handler) override {
        const auto exchange_id = next_exchange_id();
        if (stopped_ || retired_) {
            post_streaming_result(std::move(handler), core::fail(cancelled_error()));
            return exchange_id;
        }
        if (initialization_error_) {
            post_streaming_result(std::move(handler), core::fail(*initialization_error_));
            return exchange_id;
        }
        if (const auto validation_error = validate_request(request.request)) {
            post_streaming_result(std::move(handler), core::fail(*validation_error));
            return exchange_id;
        }
        std::optional<core::Error> body_error;
        const auto content_length = resolve_content_length(request, body_error);
        if (body_error) {
            post_streaming_result(std::move(handler), core::fail(*body_error));
            return exchange_id;
        }
        if (deadline <= std::chrono::steady_clock::now()) {
            post_streaming_result(std::move(handler), core::fail(timeout_error()));
            return exchange_id;
        }

        auto pending = std::make_shared<Pending>(executor_);
        pending->request = std::move(request.request);
        pending->request_body = std::move(request.body);
        pending->request_content_length = content_length;
        pending->streaming_request = true;
        pending->streaming_handler = std::move(handler);
        pending->timer.expires_at(deadline);
        const auto self = shared_from_this();
        pending->timer.async_wait([self, exchange_id](const boost::system::error_code &error) {
            if (!error) {
                self->fail_pending(exchange_id, timeout_error());
            }
        });
        pending_.emplace(exchange_id, pending);
        submit_request(exchange_id, pending);
        send_pending();
        return exchange_id;
    }

    ExchangeId open_tunnel(StreamUpgradeRequest request,
                           std::chrono::steady_clock::time_point deadline,
                           TunnelHandler handler) override {
        const auto exchange_id = next_exchange_id();
        if (stopped_ || retired_) {
            post_tunnel_result(std::move(handler), core::fail(cancelled_error()));
            return exchange_id;
        }
        if (initialization_error_) {
            post_tunnel_result(std::move(handler), core::fail(*initialization_error_));
            return exchange_id;
        }
        if (request.authority.empty() || contains_uri_whitespace(request.authority) ||
            (request.mode == StreamUpgradeMode::upgrade &&
             (!is_token(request.protocol) || !is_token(request.scheme) ||
              (request.scheme != "http" && request.scheme != "https") || request.target.empty() ||
              contains_uri_whitespace(request.target) ||
              (request.target.front() != '/' && request.target != "*")))) {
            post_tunnel_result(std::move(handler),
                               core::fail(core::Error{core::ErrorCode::configuration,
                                                      "HTTP/2 tunnel request fields are invalid"}));
            return exchange_id;
        }
        for (const auto &header : request.headers) {
            if (!is_token(header.name) || contains_control(header.value)) {
                post_tunnel_result(
                    std::move(handler),
                    core::fail(core::Error{core::ErrorCode::configuration,
                                           "HTTP/2 tunnel header contains invalid characters"}));
                return exchange_id;
            }
            const auto name = lower_copy(header.name);
            if (name.front() == ':' || name == "content-length" ||
                forbidden_http2_header(name, header.value)) {
                post_tunnel_result(
                    std::move(handler),
                    core::fail(core::Error{core::ErrorCode::configuration,
                                           "HTTP/2 tunnel request contains a forbidden header"}));
                return exchange_id;
            }
        }
        if (deadline <= std::chrono::steady_clock::now()) {
            post_tunnel_result(std::move(handler), core::fail(timeout_error()));
            return exchange_id;
        }
        if (request.mode == StreamUpgradeMode::upgrade && peer_connect_protocol_received_ &&
            !peer_connect_protocol_enabled_) {
            post_tunnel_result(
                std::move(handler),
                core::fail(protocol_error("HTTP/2 peer did not enable extended CONNECT")));
            return exchange_id;
        }
        auto pending = std::make_shared<Pending>(executor_);
        pending->is_tunnel = true;
        pending->tunnel_request = std::move(request);
        pending->tunnel_handler = std::move(handler);
        pending->response.version = 20;
        pending->response.keep_alive = true;
        pending->timer.expires_at(deadline);
        const auto self = shared_from_this();
        pending->timer.async_wait([self, exchange_id](const boost::system::error_code &error) {
            if (!error) {
                self->fail_pending(exchange_id, timeout_error());
            }
        });
        pending_.emplace(exchange_id, pending);
        if (pending->tunnel_request.mode == StreamUpgradeMode::upgrade &&
            !peer_connect_protocol_enabled_) {
            waiting_for_connect_protocol_.push_back(exchange_id);
        } else {
            submit_tunnel(exchange_id, pending);
        }
        send_pending();
        return exchange_id;
    }

    MultiplexedSession *multiplexed_session() noexcept override { return this; }

    StreamId open_stream(MultiplexedStreamRequest, std::chrono::steady_clock::time_point,
                         StreamHandler handler) override {
        const auto stream_id = static_cast<StreamId>(next_exchange_id());
        boost::asio::post(executor_, [handler = std::move(handler)]() mutable {
            if (handler) {
                handler(core::fail(
                    core::Error{core::ErrorCode::unsupported,
                                "HTTP/2 exposes logical streams through ExchangeSession requests",
                                {}}));
            }
        });
        return stream_id;
    }

    std::size_t active_streams() const noexcept override { return stream_pending_.size(); }

    std::optional<std::size_t> max_concurrent_streams() const noexcept override {
        if (http2_session_ == nullptr) {
            return std::nullopt;
        }
        const auto maximum = nghttp2_session_get_remote_settings(
            http2_session_, NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS);
        if (maximum == NGHTTP2_INITIAL_MAX_CONCURRENT_STREAMS) {
            return std::nullopt;
        }
        return static_cast<std::size_t>(maximum);
    }

    void cancel(ExchangeId exchange_id) noexcept override {
        fail_pending(exchange_id, cancelled_error());
    }

    void stop() noexcept override {
        if (stopped_) {
            return;
        }
        stopped_ = true;
        retired_ = true;
        close_stream();
        close_http2();
        fail_all(cancelled_error());
    }

    bool retired() const noexcept override { return retired_; }

  private:
    struct Pending {
        explicit Pending(boost::asio::any_io_executor executor) : timer(std::move(executor)) {}

        ExchangeRequest request;
        StreamUpgradeRequest tunnel_request;
        ExchangeResponse response;
        Handler handler;
        StreamingHandler streaming_handler;
        TunnelHandler tunnel_handler;
        boost::asio::steady_timer timer;
        std::shared_ptr<ExchangeBodyStream> request_body;
        std::shared_ptr<detail::QueuedExchangeBodyStream> response_body;
        std::optional<std::uint64_t> request_content_length;
        std::vector<std::uint8_t> request_body_buffer;
        std::size_t request_body_buffer_offset = 0;
        std::size_t request_body_buffer_size = 0;
        std::uint64_t request_body_bytes_read = 0;
        std::vector<ExchangeField> request_trailers;
        std::vector<ExchangeField> response_trailers;
        std::size_t body_offset = 0;
        std::vector<std::uint8_t> tunnel_outgoing;
        std::size_t tunnel_outgoing_offset = 0;
        core::StreamHandle::WriteHandler tunnel_write_handler;
        std::size_t tunnel_write_size = 0;
        std::shared_ptr<detail::HttpTunnelStreamState> tunnel_state;
        std::int32_t stream_id = -1;
        bool completed = false;
        bool response_too_large = false;
        bool streaming_request = false;
        bool streaming_response_delivered = false;
        bool streaming_response_complete = false;
        bool streaming_body_overflow = false;
        bool request_body_read_in_progress = false;
        bool request_body_eof = false;
        bool request_body_complete = false;
        bool request_trailers_submitted = false;
        bool is_tunnel = false;
        bool tunnel_established = false;
        bool tunnel_write_closed = false;
        bool tunnel_write_ready = false;
        bool remote_end_stream = false;
    };

    using PendingPtr = std::shared_ptr<Pending>;

    static std::optional<core::Error> validate_request(const ExchangeRequest &request) {
        if (!is_token(request.method) || !is_token(request.scheme) || request.authority.empty() ||
            request.target.empty() || contains_uri_whitespace(request.authority) ||
            contains_uri_whitespace(request.target)) {
            return core::Error{core::ErrorCode::configuration,
                               "HTTP/2 method, scheme, authority, or target is invalid"};
        }
        if (request.scheme != "http" && request.scheme != "https") {
            return core::Error{core::ErrorCode::configuration,
                               "HTTP/2 scheme must be http or https"};
        }
        if (request.target.front() != '/' && request.target != "*") {
            return core::Error{core::ErrorCode::configuration,
                               "HTTP/2 target must use origin-form or asterisk-form"};
        }
        for (const auto &header : request.headers) {
            if (!is_token(header.name) || contains_control(header.value)) {
                return core::Error{core::ErrorCode::configuration,
                                   "HTTP/2 header contains invalid characters"};
            }
            const auto name = lower_copy(header.name);
            if (name.front() == ':' || forbidden_http2_header(name, header.value)) {
                return core::Error{core::ErrorCode::configuration,
                                   "HTTP/2 request contains a forbidden header"};
            }
        }
        return std::nullopt;
    }

    static std::optional<std::uint64_t>
    resolve_content_length(const StreamingExchangeRequest &request,
                           std::optional<core::Error> &error) {
        if (request.body && !request.request.body.empty()) {
            error = core::Error{core::ErrorCode::configuration,
                                "HTTP/2 streaming request cannot combine a body stream and a body "
                                "buffer"};
            return std::nullopt;
        }

        std::optional<std::uint64_t> header_length;
        for (const auto &header : request.request.headers) {
            if (lower_copy(header.name) != "content-length") {
                continue;
            }
            if (header_length) {
                error = core::Error{core::ErrorCode::configuration,
                                    "HTTP/2 request contains multiple Content-Length headers"};
                return std::nullopt;
            }
            auto value = std::string_view(header.value);
            const auto first = value.find_first_not_of(" \t");
            if (first == std::string_view::npos) {
                error =
                    core::Error{core::ErrorCode::configuration, "HTTP/2 Content-Length is empty"};
                return std::nullopt;
            }
            const auto last = value.find_last_not_of(" \t");
            value = value.substr(first, last - first + 1);
            std::uint64_t parsed_length = 0;
            const auto parsed =
                std::from_chars(value.data(), value.data() + value.size(), parsed_length);
            if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) {
                error =
                    core::Error{core::ErrorCode::configuration, "HTTP/2 Content-Length is invalid"};
                return std::nullopt;
            }
            header_length = parsed_length;
        }

        if (request.content_length && header_length && *request.content_length != *header_length) {
            error = core::Error{core::ErrorCode::configuration,
                                "HTTP/2 Content-Length does not match the streaming request"};
            return std::nullopt;
        }
        auto resolved = request.content_length ? request.content_length : header_length;
        const auto buffered_length = static_cast<std::uint64_t>(request.request.body.size());
        if (!request.body && resolved && *resolved != buffered_length) {
            error = core::Error{core::ErrorCode::configuration,
                                "HTTP/2 Content-Length does not match the buffered request body"};
            return std::nullopt;
        }
        if (!request.body && !request.request.body.empty() && !resolved) {
            resolved = buffered_length;
        }
        if (!request.body && request.request.body.empty() && resolved && *resolved != 0) {
            error = core::Error{core::ErrorCode::configuration,
                                "HTTP/2 Content-Length requires a request body"};
            return std::nullopt;
        }
        return resolved;
    }

    ExchangeId next_exchange_id() noexcept {
        auto result = next_exchange_id_++;
        if (result == 0) {
            result = next_exchange_id_++;
        }
        return result;
    }

    void post_result(Handler handler, core::Result<ExchangeResponse> result) {
        boost::asio::post(executor_,
                          [handler = std::move(handler), result = std::move(result)]() mutable {
                              if (handler) {
                                  handler(std::move(result));
                              }
                          });
    }

    void post_streaming_result(StreamingHandler handler,
                               core::Result<StreamingExchangeResponse> result) {
        boost::asio::post(executor_,
                          [handler = std::move(handler), result = std::move(result)]() mutable {
                              if (handler) {
                                  handler(std::move(result));
                              }
                          });
    }

    void post_tunnel_result(TunnelHandler handler, core::Result<StreamUpgradeResponse> result) {
        boost::asio::post(executor_,
                          [handler = std::move(handler), result = std::move(result)]() mutable {
                              if (handler) {
                                  handler(std::move(result));
                              }
                          });
    }

    static nghttp2_ssize read_request_body(nghttp2_session *session, std::int32_t stream_id,
                                           std::uint8_t *buffer, std::size_t length,
                                           std::uint32_t *flags, nghttp2_data_source *source,
                                           void *user_data) {
        auto *pending = static_cast<Pending *>(source->ptr);
        if (pending == nullptr) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        if (pending->completed && !pending->is_tunnel) {
            return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        }
        if (pending->is_tunnel) {
            if (pending->tunnel_outgoing_offset < pending->tunnel_outgoing.size()) {
                const auto remaining =
                    pending->tunnel_outgoing.size() - pending->tunnel_outgoing_offset;
                const auto amount = std::min(length, remaining);
                std::memcpy(buffer,
                            pending->tunnel_outgoing.data() + pending->tunnel_outgoing_offset,
                            amount);
                pending->tunnel_outgoing_offset += amount;
                *flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
                if (pending->tunnel_outgoing_offset == pending->tunnel_outgoing.size()) {
                    // nghttp2 is still serializing the DATA frame here. Keep the
                    // provider's backing storage alive until mem_send2 returns
                    // and the resulting frame has been written to the socket.
                    pending->tunnel_write_ready = true;
                }
                return static_cast<nghttp2_ssize>(amount);
            }
            if (pending->tunnel_write_closed) {
                *flags |= NGHTTP2_DATA_FLAG_EOF;
                return 0;
            }
            return NGHTTP2_ERR_DEFERRED;
        }
        if (pending->streaming_request && pending->request_body) {
            auto *self = static_cast<Http2ClientSession *>(user_data);
            if (self == nullptr || session != self->http2_session_ || pending->completed) {
                return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
            }
            if (pending->request_body_buffer_offset < pending->request_body_buffer_size) {
                const auto remaining =
                    pending->request_body_buffer_size - pending->request_body_buffer_offset;
                const auto amount = std::min(length, remaining);
                std::memcpy(buffer,
                            pending->request_body_buffer.data() +
                                pending->request_body_buffer_offset,
                            amount);
                pending->request_body_buffer_offset += amount;
                if (pending->request_body_eof &&
                    pending->request_body_buffer_offset == pending->request_body_buffer_size) {
                    if (!submit_request_trailers(session, stream_id, pending)) {
                        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
                    }
                    *flags |= NGHTTP2_DATA_FLAG_EOF;
                    if (pending->request_trailers_submitted) {
                        *flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
                    }
                    pending->request_body_complete = true;
                }
                return static_cast<nghttp2_ssize>(amount);
            }
            if (pending->request_body_eof) {
                if (!submit_request_trailers(session, stream_id, pending)) {
                    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
                }
                *flags |= NGHTTP2_DATA_FLAG_EOF;
                if (pending->request_trailers_submitted) {
                    *flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
                }
                pending->request_body_complete = true;
                return 0;
            }
            if (!pending->request_body_read_in_progress) {
                pending->request_body_read_in_progress = true;
                if (pending->request_body_buffer.empty()) {
                    pending->request_body_buffer.resize(kStreamingBodyReadSize);
                }
                auto pending_owner = self->stream_pending_.find(stream_id);
                if (pending_owner == self->stream_pending_.end() ||
                    pending_owner->second.get() != pending) {
                    pending->request_body_read_in_progress = false;
                    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
                }
                const auto weak = self->weak_from_this();
                pending->request_body->async_read_some(
                    boost::asio::buffer(pending->request_body_buffer),
                    [weak, pending_owner = pending_owner->second,
                     stream_id](const boost::system::error_code &error, std::size_t size) {
                        if (const auto locked = weak.lock()) {
                            boost::asio::post(locked->executor_, [locked, pending_owner, stream_id,
                                                                  error, size] {
                                locked->on_request_body_read(stream_id, pending_owner, error, size);
                            });
                        }
                    });
            }
            return NGHTTP2_ERR_DEFERRED;
        }
        if (pending->body_offset > pending->request.body.size()) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        const auto remaining = pending->request.body.size() - pending->body_offset;
        const auto amount = std::min(length, remaining);
        if (amount != 0) {
            std::memcpy(buffer, pending->request.body.data() + pending->body_offset, amount);
            pending->body_offset += amount;
        }
        if (pending->body_offset == pending->request.body.size()) {
            *flags |= NGHTTP2_DATA_FLAG_EOF;
            if (pending->streaming_request) {
                pending->request_body_complete = true;
            }
        }
        return static_cast<nghttp2_ssize>(amount);
    }

    static bool submit_request_trailers(nghttp2_session *session, std::int32_t stream_id,
                                        Pending *pending) {
        if (pending->request_trailers.empty() || pending->request_trailers_submitted) {
            return true;
        }
        std::vector<std::string> names;
        std::vector<std::string> values;
        names.reserve(pending->request_trailers.size());
        values.reserve(pending->request_trailers.size());
        for (const auto &trailer : pending->request_trailers) {
            names.push_back(lower_copy(trailer.name));
            values.push_back(trailer.value);
        }
        std::vector<nghttp2_nv> headers;
        headers.reserve(names.size());
        for (std::size_t index = 0; index < names.size(); ++index) {
            headers.push_back(make_header(names[index], values[index]));
        }
        if (nghttp2_submit_trailer(session, stream_id, headers.data(), headers.size()) != 0) {
            return false;
        }
        pending->request_trailers_submitted = true;
        return true;
    }

    static std::optional<core::Error>
    validate_request_trailers(const std::vector<ExchangeField> &trailers) {
        for (const auto &trailer : trailers) {
            if (!is_token(trailer.name) || contains_control(trailer.value)) {
                return core::Error{core::ErrorCode::configuration,
                                   "HTTP/2 request trailer contains invalid characters"};
            }
            const auto name = lower_copy(trailer.name);
            if (name.front() == ':' || name == "content-length" || name == "host" || name == "te" ||
                name == "trailer" || forbidden_http2_header(name, trailer.value)) {
                return core::Error{core::ErrorCode::configuration,
                                   "HTTP/2 request trailer contains a forbidden field"};
            }
        }
        return std::nullopt;
    }

    void on_request_body_read(std::int32_t stream_id, const PendingPtr &pending,
                              const boost::system::error_code &error, std::size_t size) {
        pending->request_body_read_in_progress = false;
        if (pending->completed || stopped_ || stream_closed_ || !http2_session_) {
            return;
        }
        const auto exchange = stream_ids_.find(stream_id);
        if (exchange == stream_ids_.end() || !stream_pending_.contains(stream_id) ||
            stream_pending_.at(stream_id) != pending) {
            return;
        }
        if (size > pending->request_body_buffer.size()) {
            fail_pending(exchange->second,
                         protocol_error("HTTP/2 request body source exceeded its read buffer"));
            return;
        }
        if (error && error != boost::asio::error::eof) {
            fail_pending(exchange->second, io_error("failed to read HTTP/2 request body", error));
            return;
        }
        if (size == 0 && !error) {
            fail_pending(exchange->second,
                         core::Error{core::ErrorCode::transport_io,
                                     "HTTP/2 request body source returned no data"});
            return;
        }
        if (size > std::numeric_limits<std::uint64_t>::max() - pending->request_body_bytes_read) {
            fail_pending(exchange->second, protocol_error("HTTP/2 request body length overflowed"));
            return;
        }
        if (pending->request_content_length &&
            (pending->request_body_bytes_read > *pending->request_content_length ||
             size > *pending->request_content_length - pending->request_body_bytes_read)) {
            fail_pending(exchange->second,
                         protocol_error("HTTP/2 request body exceeded Content-Length"));
            return;
        }
        pending->request_body_bytes_read += size;
        pending->request_body_buffer_size = size;
        pending->request_body_buffer_offset = 0;
        if (error == boost::asio::error::eof) {
            if (pending->request_content_length &&
                pending->request_body_bytes_read != *pending->request_content_length) {
                fail_pending(exchange->second,
                             protocol_error("HTTP/2 request body ended before Content-Length"));
                return;
            }
            auto trailers = pending->request_body->trailers();
            if (const auto trailer_error = validate_request_trailers(trailers)) {
                fail_pending(exchange->second, *trailer_error);
                return;
            }
            pending->request_trailers = std::move(trailers);
            pending->request_body_eof = true;
        }
        const auto resumed = nghttp2_session_resume_data(http2_session_, stream_id);
        if (resumed != 0) {
            fail_pending(exchange->second,
                         protocol_error("failed to resume HTTP/2 request body stream"));
            return;
        }
        send_pending();
    }

    static int on_header(nghttp2_session *, const nghttp2_frame *frame, const std::uint8_t *name,
                         std::size_t name_length, const std::uint8_t *value,
                         std::size_t value_length, std::uint8_t, void *user_data) {
        if (frame->hd.type != NGHTTP2_HEADERS) {
            return 0;
        }
        auto *self = static_cast<Http2ClientSession *>(user_data);
        const auto stream = self->stream_pending_.find(frame->hd.stream_id);
        if (stream == self->stream_pending_.end()) {
            return 0;
        }
        if (stream->second->tunnel_established) {
            return 0;
        }
        const std::string_view header_name(reinterpret_cast<const char *>(name), name_length);
        const std::string_view header_value(reinterpret_cast<const char *>(value), value_length);
        if (stream->second->streaming_response_delivered) {
            if (!header_name.empty() && header_name.front() != ':') {
                stream->second->response_trailers.push_back(
                    {std::string(header_name), std::string(header_value)});
            }
            return 0;
        }
        if (header_name == ":status") {
            unsigned status = 0;
            const auto parsed = std::from_chars(header_value.data(),
                                                header_value.data() + header_value.size(), status);
            if (parsed.ec == std::errc{} &&
                parsed.ptr == header_value.data() + header_value.size()) {
                stream->second->response.status = status;
            }
        } else if (!header_name.empty() && header_name.front() != ':') {
            stream->second->response.headers.push_back(
                {std::string(header_name), std::string(header_value)});
        }
        return 0;
    }

    static int on_data_chunk(nghttp2_session *, std::uint8_t, std::int32_t stream_id,
                             const std::uint8_t *data, std::size_t length, void *user_data) {
        auto *self = static_cast<Http2ClientSession *>(user_data);
        self->connection_bytes_pending_ += length;
        const auto stream = self->stream_pending_.find(stream_id);
        if (stream == self->stream_pending_.end()) {
            return 0;
        }
        auto &pending = stream->second;
        if (pending->is_tunnel && pending->tunnel_established) {
            if (pending->tunnel_state) {
                pending->tunnel_state->receive(data, length);
            }
            return 0;
        }
        if (pending->streaming_request) {
            if (!pending->streaming_response_delivered || !pending->response_body ||
                !pending->response_body->receive(data, length)) {
                pending->streaming_body_overflow = true;
            }
            return 0;
        }
        const auto body_limit = pending->is_tunnel ? pending->tunnel_request.rejection_body_limit
                                                   : pending->request.response_body_limit;
        if (length > body_limit - std::min(pending->response.body.size(), body_limit)) {
            pending->response_too_large = true;
            self->stream_bytes_pending_[stream_id] += length;
            return 0;
        }
        pending->response.body.insert(pending->response.body.end(), data, data + length);
        self->stream_bytes_pending_[stream_id] += length;
        return 0;
    }

    static int on_frame_received(nghttp2_session *, const nghttp2_frame *frame, void *user_data) {
        auto *self = static_cast<Http2ClientSession *>(user_data);
        if (frame->hd.type == NGHTTP2_GOAWAY) {
            self->handle_goaway(frame->goaway.last_stream_id);
            return 0;
        }
        if (frame->hd.type == NGHTTP2_SETTINGS && (frame->hd.flags & NGHTTP2_FLAG_ACK) == 0) {
            self->handle_peer_settings(frame->settings.iv, frame->settings.niv);
        }
        const auto stream = self->stream_ids_.find(frame->hd.stream_id);
        if (frame->hd.type == NGHTTP2_HEADERS &&
            (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS) != 0 &&
            stream != self->stream_ids_.end()) {
            self->handle_response_headers(stream->second);
        }
        if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) == 0) {
            return 0;
        }
        if (stream != self->stream_ids_.end()) {
            const auto pending = self->stream_pending_.find(frame->hd.stream_id);
            if (pending != self->stream_pending_.end() && pending->second->tunnel_established) {
                pending->second->remote_end_stream = true;
                if (pending->second->tunnel_state) {
                    pending->second->tunnel_state->remote_close();
                }
            } else if (pending != self->stream_pending_.end() &&
                       pending->second->streaming_request) {
                self->finish_streaming_response(stream->second, pending->second);
            } else {
                self->finish_pending(stream->second);
            }
        }
        return 0;
    }

    static int on_stream_closed(nghttp2_session *, std::int32_t stream_id, std::uint32_t error_code,
                                void *user_data) {
        auto *self = static_cast<Http2ClientSession *>(user_data);
        const auto stream = self->stream_ids_.find(stream_id);
        if (stream == self->stream_ids_.end()) {
            return 0;
        }
        const auto exchange_id = stream->second;
        const auto stream_pending = self->stream_pending_.find(stream_id);
        const auto pending = self->pending_.find(exchange_id);
        if (stream_pending != self->stream_pending_.end() &&
            stream_pending->second->tunnel_established && stream_pending->second->tunnel_state) {
            if (error_code == NGHTTP2_NO_ERROR) {
                stream_pending->second->tunnel_state->remote_close();
            } else {
                stream_pending->second->tunnel_state->fail(boost::asio::error::connection_reset);
            }
        }
        if (pending != self->pending_.end() && !pending->second->completed &&
            error_code != NGHTTP2_NO_ERROR) {
            self->fail_closed_pending(
                exchange_id, protocol_error("HTTP/2 response stream closed with an error"));
        } else if (pending != self->pending_.end() && !pending->second->completed) {
            self->fail_closed_pending(
                exchange_id, protocol_error("HTTP/2 response stream closed before END_STREAM"));
        }
        self->stream_ids_.erase(stream);
        self->stream_pending_.erase(stream_id);
        self->close_if_drained();
        return 0;
    }

    static nghttp2_nv make_header(const std::string &name, const std::string &value) {
        return {reinterpret_cast<std::uint8_t *>(const_cast<char *>(name.data())),
                reinterpret_cast<std::uint8_t *>(const_cast<char *>(value.data())), name.size(),
                value.size(), NGHTTP2_NV_FLAG_NONE};
    }

    void submit_request(ExchangeId exchange_id, const PendingPtr &pending) {
        std::vector<std::string> names;
        std::vector<std::string> values;
        names.reserve(4 + pending->request.headers.size());
        values.reserve(names.capacity());
        names.emplace_back(":method");
        values.push_back(pending->request.method);
        names.emplace_back(":scheme");
        values.push_back(pending->request.scheme);
        names.emplace_back(":authority");
        values.push_back(pending->request.authority);
        names.emplace_back(":path");
        values.push_back(pending->request.target);
        bool has_content_length = false;
        for (const auto &header : pending->request.headers) {
            auto name = lower_copy(header.name);
            has_content_length = has_content_length || name == "content-length";
            names.push_back(std::move(name));
            values.push_back(header.value);
        }
        if (pending->streaming_request && pending->request_content_length && !has_content_length) {
            names.emplace_back("content-length");
            values.push_back(std::to_string(*pending->request_content_length));
        } else if (!pending->streaming_request && !pending->request.body.empty() &&
                   !has_content_length) {
            names.emplace_back("content-length");
            values.push_back(std::to_string(pending->request.body.size()));
        }

        std::vector<nghttp2_nv> headers;
        headers.reserve(names.size());
        for (std::size_t index = 0; index < names.size(); ++index) {
            headers.push_back(make_header(names[index], values[index]));
        }
        nghttp2_data_provider2 provider{};
        nghttp2_data_provider2 *provider_ptr = nullptr;
        if ((pending->streaming_request && pending->request_body) ||
            !pending->request.body.empty()) {
            provider.source.ptr = pending.get();
            provider.read_callback = &read_request_body;
            provider_ptr = &provider;
        } else if (pending->streaming_request) {
            pending->request_body_complete = true;
        }
        const auto stream_id = nghttp2_submit_request2(http2_session_, nullptr, headers.data(),
                                                       headers.size(), provider_ptr, pending.get());
        if (stream_id < 0) {
            fail_pending(exchange_id, protocol_error("failed to submit HTTP/2 request"));
            return;
        }
        pending->stream_id = stream_id;
        pending->response.version = 20;
        pending->response.keep_alive = true;
        stream_ids_.emplace(stream_id, exchange_id);
        stream_pending_.emplace(stream_id, pending);
    }

    void send_pending() {
        if (stopped_ || stream_closed_ || !stream_ || write_in_progress_ ||
            http2_session_ == nullptr) {
            return;
        }
        const std::uint8_t *data = nullptr;
        const auto length = nghttp2_session_mem_send2(http2_session_, &data);
        if (length < 0) {
            connection_failed(protocol_error("nghttp2 failed to serialize HTTP/2 frames"));
            return;
        }
        if (length == 0) {
            return;
        }
        pending_write_.assign(data, data + length);
        std::vector<PendingPtr> completed_tunnel_writes;
        for (const auto &[stream_id, pending] : stream_pending_) {
            (void)stream_id;
            if (pending->tunnel_write_ready) {
                pending->tunnel_write_ready = false;
                completed_tunnel_writes.push_back(pending);
            }
        }
        write_in_progress_ = true;
        const auto self = shared_from_this();
        boost::asio::async_write(
            *stream_, boost::asio::buffer(pending_write_),
            [self, completed_tunnel_writes = std::move(completed_tunnel_writes)](
                const boost::system::error_code &error, std::size_t) mutable {
                self->write_in_progress_ = false;
                if (self->stopped_ || self->stream_closed_ || !self->stream_) {
                    self->release_closed_stream();
                    return;
                }
                if (error) {
                    self->connection_failed(io_error("failed to send HTTP/2 request", error));
                    return;
                }
                for (const auto &pending : completed_tunnel_writes) {
                    pending->tunnel_outgoing.clear();
                    pending->tunnel_outgoing_offset = 0;
                    const auto write_size = std::exchange(pending->tunnel_write_size, 0);
                    auto handler = std::move(pending->tunnel_write_handler);
                    if (handler) {
                        handler({}, write_size);
                    }
                }
                self->send_pending();
                self->close_if_drained();
            });
    }

    void read_response() {
        if (stopped_ || stream_closed_ || !stream_ || read_in_progress_) {
            return;
        }
        read_in_progress_ = true;
        const auto self = shared_from_this();
        stream_->async_read_some(
            boost::asio::buffer(read_buffer_),
            [self](const boost::system::error_code &error, std::size_t size) {
                self->read_in_progress_ = false;
                if (self->stopped_ || self->stream_closed_ || !self->stream_) {
                    self->release_closed_stream();
                    return;
                }
                if (error) {
                    self->connection_failed(io_error("failed to receive HTTP/2 response", error));
                    return;
                }
                const auto consumed = nghttp2_session_mem_recv2(self->http2_session_,
                                                                self->read_buffer_.data(), size);
                if (consumed < 0 || static_cast<std::size_t>(consumed) != size) {
                    self->connection_failed(protocol_error("invalid HTTP/2 response frames"));
                    return;
                }
                self->fail_streaming_body_overflows();
                if (self->stopped_ || self->stream_closed_ || !self->http2_session_) {
                    return;
                }
                self->update_receive_credit();
                self->send_pending();
                self->read_response();
            });
    }

    void handle_peer_settings(const nghttp2_settings_entry *settings, std::size_t count) {
        bool enabled = false;
        for (std::size_t index = 0; index < count; ++index) {
            if (settings[index].settings_id == NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL) {
                enabled = settings[index].value == 1;
                break;
            }
        }
        peer_connect_protocol_received_ = true;
        peer_connect_protocol_enabled_ = enabled;
        if (!enabled) {
            auto waiting = std::move(waiting_for_connect_protocol_);
            waiting_for_connect_protocol_.clear();
            for (const auto exchange_id : waiting) {
                fail_pending(exchange_id,
                             protocol_error("HTTP/2 peer did not enable extended CONNECT"));
            }
            return;
        }
        auto waiting = std::move(waiting_for_connect_protocol_);
        waiting_for_connect_protocol_.clear();
        for (const auto exchange_id : waiting) {
            const auto found = pending_.find(exchange_id);
            if (found != pending_.end()) {
                submit_tunnel(exchange_id, found->second);
            }
        }
        send_pending();
    }

    void submit_tunnel(ExchangeId exchange_id, const PendingPtr &pending) {
        if (pending->stream_id >= 0 || pending->completed || http2_session_ == nullptr) {
            return;
        }
        std::vector<std::string> names{":method"};
        std::vector<std::string> values{"CONNECT"};
        if (pending->tunnel_request.mode == StreamUpgradeMode::connect) {
            names.emplace_back(":authority");
            values.push_back(pending->tunnel_request.authority);
        } else {
            names.emplace_back(":protocol");
            values.push_back(pending->tunnel_request.protocol);
            names.emplace_back(":scheme");
            values.push_back(pending->tunnel_request.scheme);
            names.emplace_back(":authority");
            values.push_back(pending->tunnel_request.authority);
            names.emplace_back(":path");
            values.push_back(pending->tunnel_request.target);
        }
        for (const auto &header : pending->tunnel_request.headers) {
            names.push_back(lower_copy(header.name));
            values.push_back(header.value);
        }
        std::vector<nghttp2_nv> headers;
        headers.reserve(names.size());
        for (std::size_t index = 0; index < names.size(); ++index) {
            headers.push_back(make_header(names[index], values[index]));
        }
        nghttp2_data_provider2 provider{};
        provider.source.ptr = pending.get();
        provider.read_callback = &read_request_body;
        const auto stream_id = nghttp2_submit_request2(http2_session_, nullptr, headers.data(),
                                                       headers.size(), &provider, pending.get());
        if (stream_id < 0) {
            fail_pending(exchange_id, protocol_error("failed to submit HTTP/2 tunnel"));
            return;
        }
        pending->stream_id = stream_id;
        stream_ids_.emplace(stream_id, exchange_id);
        stream_pending_.emplace(stream_id, pending);
    }

    void handle_response_headers(ExchangeId exchange_id) {
        const auto found = pending_.find(exchange_id);
        if (found == pending_.end()) {
            return;
        }
        const auto &pending = found->second;
        if (pending->is_tunnel) {
            if (pending->tunnel_established || pending->response.status < 200) {
                return;
            }
            if (pending->response.status < 300) {
                accept_tunnel(exchange_id, pending);
            }
            return;
        }
        if (!pending->streaming_request || pending->streaming_response_delivered) {
            return;
        }
        if (pending->response.status < 200) {
            pending->response.status = 0;
            pending->response.headers.clear();
            return;
        }
        if (pending->response.status == 101) {
            fail_pending(exchange_id,
                         protocol_error("HTTP/2 does not permit status 101 Switching Protocols"));
            return;
        }
        pending->streaming_response_delivered = true;
        pending->response.keep_alive = true;
        const auto weak = weak_from_this();
        const auto stream_id = pending->stream_id;
        pending->response_body = std::make_shared<detail::QueuedExchangeBodyStream>(
            executor_, kStreamingResponseQueueCapacity,
            [weak, stream_id](std::size_t size) {
                if (const auto self = weak.lock()) {
                    self->consume_stream_data(stream_id, size);
                }
            },
            [weak, exchange_id] {
                if (const auto self = weak.lock()) {
                    self->fail_pending(exchange_id, cancelled_error());
                }
            },
            [] {});
        auto handler = std::move(pending->streaming_handler);
        auto response = std::move(pending->response);
        post_streaming_result(std::move(handler), StreamingExchangeResponse{
                                                      std::move(response), pending->response_body});
    }

    void consume_stream_data(std::int32_t stream_id, std::size_t size) {
        if (http2_session_ == nullptr || !stream_ids_.contains(stream_id) ||
            !stream_pending_.contains(stream_id)) {
            return;
        }
        if (nghttp2_session_consume_stream(http2_session_, stream_id, size) != 0) {
            connection_failed(protocol_error("failed to update HTTP/2 response flow control"));
            return;
        }
        send_pending();
    }

    void finish_streaming_response(ExchangeId exchange_id, const PendingPtr &pending) {
        if (pending->completed) {
            return;
        }
        if (!pending->streaming_response_delivered || !pending->response_body) {
            fail_pending(exchange_id,
                         protocol_error("HTTP/2 response ended before final response headers"));
            return;
        }
        pending->streaming_response_complete = true;
        pending->completed = true;
        (void)pending->timer.cancel();
        if (!pending->request_body_complete) {
            if (pending->request_body) {
                pending->request_body->cancel();
            }
            if (http2_session_ != nullptr && pending->stream_id >= 0) {
                (void)nghttp2_submit_rst_stream(http2_session_, NGHTTP2_FLAG_NONE,
                                                pending->stream_id, NGHTTP2_CANCEL);
            }
        }
        pending->request_body.reset();
        pending->response_body->finish(std::move(pending->response_trailers));
        pending_.erase(exchange_id);
        close_if_drained();
    }

    void accept_tunnel(ExchangeId exchange_id, const PendingPtr &pending) {
        pending->completed = true;
        pending->tunnel_established = true;
        (void)pending->timer.cancel();
        pending_.erase(exchange_id);
        const auto weak = weak_from_this();
        const auto stream_id = pending->stream_id;
        pending->tunnel_state = std::make_shared<detail::HttpTunnelStreamState>(
            executor_,
            [weak, pending, stream_id](std::vector<std::uint8_t> bytes,
                                       core::StreamHandle::WriteHandler handler) mutable {
                const auto self = weak.lock();
                if (!self || self->retired_ || pending->tunnel_write_closed ||
                    pending->tunnel_write_handler) {
                    const auto executor = self ? self->executor_ : pending->timer.get_executor();
                    boost::asio::post(executor, [handler = std::move(handler)]() mutable {
                        if (handler) {
                            handler(boost::asio::error::operation_aborted, 0);
                        }
                    });
                    return;
                }
                pending->tunnel_outgoing = std::move(bytes);
                pending->tunnel_outgoing_offset = 0;
                pending->tunnel_write_size = pending->tunnel_outgoing.size();
                pending->tunnel_write_handler = std::move(handler);
                if (nghttp2_session_resume_data(self->http2_session_, stream_id) != 0) {
                    auto failed = std::move(pending->tunnel_write_handler);
                    pending->tunnel_outgoing.clear();
                    pending->tunnel_write_size = 0;
                    if (failed) {
                        failed(boost::asio::error::operation_aborted, 0);
                    }
                    return;
                }
                self->send_pending();
            },
            [weak, pending, stream_id] {
                if (const auto self = weak.lock()) {
                    pending->tunnel_write_closed = true;
                    (void)nghttp2_session_resume_data(self->http2_session_, stream_id);
                    self->send_pending();
                }
            },
            [weak, stream_id] {
                if (const auto self = weak.lock()) {
                    boost::asio::post(self->executor_, [weak, stream_id] {
                        if (const auto locked = weak.lock();
                            locked && locked->http2_session_ != nullptr) {
                            (void)nghttp2_submit_rst_stream(locked->http2_session_,
                                                            NGHTTP2_FLAG_NONE, stream_id,
                                                            NGHTTP2_CANCEL);
                            locked->send_pending();
                        }
                    });
                }
            },
            [weak, stream_id](std::size_t size) {
                if (const auto self = weak.lock()) {
                    boost::asio::post(self->executor_, [weak, stream_id, size] {
                        if (const auto locked = weak.lock();
                            locked && locked->http2_session_ != nullptr &&
                            locked->stream_ids_.contains(stream_id)) {
                            if (nghttp2_session_consume_stream(locked->http2_session_, stream_id,
                                                               size) != 0) {
                                locked->connection_failed(
                                    protocol_error("failed to update HTTP/2 tunnel flow control"));
                                return;
                            }
                            locked->send_pending();
                        }
                    });
                }
            });
        auto handler = std::move(pending->tunnel_handler);
        auto response = std::move(pending->response);
        post_tunnel_result(
            std::move(handler),
            StreamUpgradeResponse{std::move(response),
                                  detail::make_http_tunnel_stream(pending->tunnel_state)});
    }

    void update_receive_credit() {
        if (http2_session_ == nullptr) {
            return;
        }
        if (connection_bytes_pending_ != 0) {
            if (nghttp2_session_consume_connection(http2_session_, connection_bytes_pending_) !=
                0) {
                connection_failed(
                    protocol_error("failed to update HTTP/2 connection flow control"));
                return;
            }
            connection_bytes_pending_ = 0;
        }
        auto consumed = std::move(stream_bytes_pending_);
        stream_bytes_pending_.clear();
        for (const auto &[stream_id, size] : consumed) {
            const auto pending = stream_pending_.find(stream_id);
            if (pending == stream_pending_.end() || pending->second->tunnel_established ||
                !stream_ids_.contains(stream_id)) {
                continue;
            }
            if (nghttp2_session_consume_stream(http2_session_, stream_id, size) != 0) {
                connection_failed(protocol_error("failed to update HTTP/2 stream flow control"));
                return;
            }
        }
    }

    void fail_streaming_body_overflows() {
        std::vector<ExchangeId> failed;
        for (const auto &[stream_id, pending] : stream_pending_) {
            (void)stream_id;
            if (pending->streaming_body_overflow && !pending->completed) {
                pending->streaming_body_overflow = false;
                const auto exchange = stream_ids_.find(pending->stream_id);
                if (exchange != stream_ids_.end()) {
                    failed.push_back(exchange->second);
                }
            }
        }
        for (const auto exchange_id : failed) {
            fail_pending(exchange_id,
                         protocol_error("HTTP/2 response body exceeded its bounded queue"));
        }
    }

    void finish_pending(ExchangeId exchange_id) {
        const auto found = pending_.find(exchange_id);
        if (found == pending_.end() || found->second->completed) {
            return;
        }
        const auto pending = found->second;
        pending->completed = true;
        (void)pending->timer.cancel();
        pending_.erase(found);
        if (pending->response_too_large) {
            if (pending->is_tunnel) {
                post_tunnel_result(
                    std::move(pending->tunnel_handler),
                    core::fail(protocol_error(
                        "HTTP/2 tunnel rejection exceeded the configured body limit")));
            } else {
                post_result(std::move(pending->handler),
                            core::fail(protocol_error(
                                "HTTP/2 response exceeded the configured body limit")));
            }
        } else if (pending->is_tunnel) {
            post_tunnel_result(std::move(pending->tunnel_handler),
                               StreamUpgradeResponse{std::move(pending->response), {}});
        } else {
            post_result(std::move(pending->handler), std::move(pending->response));
        }
        close_if_drained();
    }

    void fail_pending(ExchangeId exchange_id, core::Error error) {
        const auto found = pending_.find(exchange_id);
        if (found == pending_.end() || found->second->completed) {
            return;
        }
        const auto pending = found->second;
        pending->completed = true;
        (void)pending->timer.cancel();
        if (pending->request_body) {
            pending->request_body->cancel();
            pending->request_body.reset();
        }
        if (pending->response_body) {
            pending->response_body->fail(body_stream_error(error));
        }
        if (http2_session_ != nullptr && pending->stream_id >= 0) {
            (void)nghttp2_submit_rst_stream(http2_session_, NGHTTP2_FLAG_NONE, pending->stream_id,
                                            NGHTTP2_CANCEL);
        } else if (pending->stream_id >= 0) {
            stream_ids_.erase(pending->stream_id);
            stream_pending_.erase(pending->stream_id);
        }
        pending_.erase(found);
        if (pending->is_tunnel) {
            post_tunnel_result(std::move(pending->tunnel_handler), core::fail(std::move(error)));
        } else if (pending->streaming_request) {
            post_streaming_result(std::move(pending->streaming_handler),
                                  core::fail(std::move(error)));
        } else {
            post_result(std::move(pending->handler), core::fail(std::move(error)));
        }
        send_pending();
        close_if_drained();
    }

    void fail_closed_pending(ExchangeId exchange_id, core::Error error) {
        const auto found = pending_.find(exchange_id);
        if (found == pending_.end() || found->second->completed) {
            return;
        }
        const auto pending = found->second;
        pending->completed = true;
        (void)pending->timer.cancel();
        if (pending->request_body) {
            pending->request_body->cancel();
            pending->request_body.reset();
        }
        if (pending->response_body) {
            pending->response_body->fail(body_stream_error(error));
        }
        pending_.erase(found);
        if (pending->is_tunnel) {
            post_tunnel_result(std::move(pending->tunnel_handler), core::fail(std::move(error)));
        } else if (pending->streaming_request) {
            post_streaming_result(std::move(pending->streaming_handler),
                                  core::fail(std::move(error)));
        } else {
            post_result(std::move(pending->handler), core::fail(std::move(error)));
        }
    }

    void handle_goaway(std::int32_t last_stream_id) {
        if (retired_) {
            return;
        }
        retired_ = true;
        std::vector<ExchangeId> rejected;
        for (const auto &[stream_id, exchange_id] : stream_ids_) {
            if (stream_id > last_stream_id) {
                rejected.push_back(exchange_id);
            }
        }
        for (const auto exchange_id : rejected) {
            fail_pending(exchange_id,
                         protocol_error("HTTP/2 peer sent GOAWAY before processing the request"));
        }
        close_if_drained();
    }

    void close_if_drained() {
        const bool tunnel_active =
            std::any_of(stream_pending_.begin(), stream_pending_.end(),
                        [](const auto &entry) { return entry.second->tunnel_established; });
        if (retired_ && pending_.empty() && !tunnel_active && !write_in_progress_) {
            close_stream();
        }
    }

    void fail_all(const core::Error &error) {
        std::vector<Handler> handlers;
        std::vector<StreamingHandler> streaming_handlers;
        std::vector<TunnelHandler> tunnel_handlers;
        handlers.reserve(pending_.size());
        streaming_handlers.reserve(pending_.size());
        tunnel_handlers.reserve(pending_.size());
        for (const auto &[stream_id, pending] : stream_pending_) {
            (void)stream_id;
            if (pending->tunnel_established && pending->tunnel_state) {
                pending->tunnel_state->fail(boost::asio::error::connection_reset);
            } else if (pending->streaming_request && pending->response_body) {
                pending->response_body->fail(body_stream_error(error));
            }
        }
        for (auto &[exchange_id, pending] : pending_) {
            (void)exchange_id;
            const bool already_completed = pending->completed;
            pending->completed = true;
            (void)pending->timer.cancel();
            if (pending->request_body) {
                pending->request_body->cancel();
                pending->request_body.reset();
            }
            if (pending->response_body) {
                pending->response_body->fail(body_stream_error(error));
            }
            if (already_completed) {
                continue;
            }
            if (pending->is_tunnel && pending->tunnel_handler) {
                tunnel_handlers.push_back(std::move(pending->tunnel_handler));
            } else if (pending->streaming_request && pending->streaming_handler) {
                streaming_handlers.push_back(std::move(pending->streaming_handler));
            } else if (pending->handler) {
                handlers.push_back(std::move(pending->handler));
            }
        }
        pending_.clear();
        stream_ids_.clear();
        stream_pending_.clear();
        for (auto &handler : handlers) {
            post_result(std::move(handler), core::fail(error));
        }
        for (auto &handler : streaming_handlers) {
            post_streaming_result(std::move(handler), core::fail(error));
        }
        for (auto &handler : tunnel_handlers) {
            post_tunnel_result(std::move(handler), core::fail(error));
        }
    }

    void connection_failed(core::Error error) {
        if (stopped_ || stream_closed_) {
            return;
        }
        retired_ = true;
        close_stream();
        close_http2();
        fail_all(error);
    }

    void close_http2() noexcept {
        if (http2_session_) {
            nghttp2_session_del(http2_session_);
            http2_session_ = nullptr;
        }
    }

    void close_stream() noexcept {
        if (stream_ && !stream_closed_) {
            stream_closed_ = true;
            stream_->close();
        }
        release_closed_stream();
    }

    void release_closed_stream() noexcept {
        if (stream_closed_ && !read_in_progress_ && !write_in_progress_) {
            stream_.reset();
        }
    }

    boost::asio::any_io_executor executor_;
    std::unique_ptr<net::StreamHandleAdapter<io::StreamHandle>> stream_;
    nghttp2_session *http2_session_ = nullptr;
    std::optional<core::Error> initialization_error_;
    std::unordered_map<ExchangeId, PendingPtr> pending_;
    std::unordered_map<std::int32_t, ExchangeId> stream_ids_;
    std::unordered_map<std::int32_t, PendingPtr> stream_pending_;
    std::unordered_map<std::int32_t, std::size_t> stream_bytes_pending_;
    std::vector<ExchangeId> waiting_for_connect_protocol_;
    std::array<std::uint8_t, 16384> read_buffer_{};
    std::vector<std::uint8_t> pending_write_;
    std::size_t connection_bytes_pending_ = 0;
    ExchangeId next_exchange_id_ = 1;
    bool peer_connect_protocol_received_ = false;
    bool peer_connect_protocol_enabled_ = false;
    bool stream_closed_ = false;
    bool write_in_progress_ = false;
    bool read_in_progress_ = false;
    bool retired_ = false;
    bool stopped_ = false;
};

} // namespace

std::shared_ptr<ExchangeSession>
make_http2_exchange_session(std::unique_ptr<io::StreamHandle> stream) {
    if (!stream) {
        return {};
    }
    auto session = std::make_shared<Http2ClientSession>(std::move(stream));
    if (!session->initialize()) {
        session->stop();
        return {};
    }
    session->start();
    return session;
}

} // namespace clash_native::transport
