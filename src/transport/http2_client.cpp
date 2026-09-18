#include <clash_native/net/stream_handle_adapter.hpp>
#include <clash_native/transport/http_client.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

#include <nghttp2/nghttp2.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstring>
#include <memory>
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

class Http2ClientSession final : public HttpClientSession,
                                 public std::enable_shared_from_this<Http2ClientSession> {
  public:
    explicit Http2ClientSession(std::unique_ptr<core::StreamHandle> stream)
        : executor_(stream->executor()),
          stream_(std::make_unique<net::StreamHandleAdapter>(std::move(stream))) {}

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
        const auto created = nghttp2_session_client_new2(&http2_session_, callbacks, this, nullptr);
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

    ExchangeId exchange(HttpRequest request, std::chrono::steady_clock::time_point deadline,
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

        HttpRequest request;
        HttpResponse response;
        Handler handler;
        boost::asio::steady_timer timer;
        std::size_t body_offset = 0;
        std::int32_t stream_id = -1;
        bool completed = false;
        bool response_too_large = false;
    };

    using PendingPtr = std::shared_ptr<Pending>;

    static std::optional<core::Error> validate_request(const HttpRequest &request) {
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

    ExchangeId next_exchange_id() noexcept {
        auto result = next_exchange_id_++;
        if (result == 0) {
            result = next_exchange_id_++;
        }
        return result;
    }

    void post_result(Handler handler, core::Result<HttpResponse> result) {
        boost::asio::post(executor_,
                          [handler = std::move(handler), result = std::move(result)]() mutable {
                              if (handler) {
                                  handler(std::move(result));
                              }
                          });
    }

    static nghttp2_ssize read_request_body(nghttp2_session *, std::int32_t, std::uint8_t *buffer,
                                           std::size_t length, std::uint32_t *flags,
                                           nghttp2_data_source *source, void *) {
        auto *pending = static_cast<Pending *>(source->ptr);
        if (pending == nullptr || pending->completed ||
            pending->body_offset > pending->request.body.size()) {
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
        }
        return static_cast<nghttp2_ssize>(amount);
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
        const std::string_view header_name(reinterpret_cast<const char *>(name), name_length);
        const std::string_view header_value(reinterpret_cast<const char *>(value), value_length);
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
        const auto stream = self->stream_pending_.find(stream_id);
        if (stream == self->stream_pending_.end()) {
            return 0;
        }
        auto &pending = stream->second;
        if (length >
            pending->request.response_body_limit -
                std::min(pending->response.body.size(), pending->request.response_body_limit)) {
            pending->response_too_large = true;
            return 0;
        }
        pending->response.body.insert(pending->response.body.end(), data, data + length);
        return 0;
    }

    static int on_frame_received(nghttp2_session *, const nghttp2_frame *frame, void *user_data) {
        auto *self = static_cast<Http2ClientSession *>(user_data);
        if (frame->hd.type == NGHTTP2_GOAWAY) {
            self->handle_goaway(frame->goaway.last_stream_id);
            return 0;
        }
        if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) == 0) {
            return 0;
        }
        const auto stream = self->stream_ids_.find(frame->hd.stream_id);
        if (stream != self->stream_ids_.end()) {
            self->finish_pending(stream->second);
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
        self->stream_ids_.erase(stream);
        self->stream_pending_.erase(stream_id);
        const auto pending = self->pending_.find(exchange_id);
        if (pending != self->pending_.end() && !pending->second->completed &&
            error_code != NGHTTP2_NO_ERROR) {
            self->fail_pending(exchange_id,
                               protocol_error("HTTP/2 response stream closed with an error"));
        } else if (pending != self->pending_.end() && !pending->second->completed) {
            self->fail_pending(exchange_id,
                               protocol_error("HTTP/2 response stream closed before END_STREAM"));
        }
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
        if (!pending->request.body.empty() && !has_content_length) {
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
        if (!pending->request.body.empty()) {
            provider.source.ptr = pending.get();
            provider.read_callback = &read_request_body;
            provider_ptr = &provider;
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
        if (stopped_ || !stream_ || write_in_progress_ || http2_session_ == nullptr) {
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
        write_in_progress_ = true;
        const auto self = shared_from_this();
        boost::asio::async_write(*stream_, boost::asio::buffer(pending_write_),
                                 [self](const boost::system::error_code &error, std::size_t) {
                                     self->write_in_progress_ = false;
                                     if (self->stopped_ || !self->stream_) {
                                         return;
                                     }
                                     if (error) {
                                         self->connection_failed(
                                             io_error("failed to send HTTP/2 request", error));
                                         return;
                                     }
                                     self->send_pending();
                                     self->close_if_drained();
                                 });
    }

    void read_response() {
        if (stopped_ || !stream_ || read_in_progress_) {
            return;
        }
        read_in_progress_ = true;
        const auto self = shared_from_this();
        stream_->async_read_some(
            boost::asio::buffer(read_buffer_),
            [self](const boost::system::error_code &error, std::size_t size) {
                self->read_in_progress_ = false;
                if (self->stopped_ || !self->stream_) {
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
                self->send_pending();
                self->read_response();
            });
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
        auto response = std::move(pending->response);
        auto handler = std::move(pending->handler);
        if (pending->response_too_large) {
            post_result(
                std::move(handler),
                core::fail(protocol_error("HTTP/2 response exceeded the configured body limit")));
        } else {
            post_result(std::move(handler), std::move(response));
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
        if (http2_session_ != nullptr && pending->stream_id >= 0) {
            (void)nghttp2_submit_rst_stream(http2_session_, NGHTTP2_FLAG_NONE, pending->stream_id,
                                            NGHTTP2_CANCEL);
        } else if (pending->stream_id >= 0) {
            stream_ids_.erase(pending->stream_id);
            stream_pending_.erase(pending->stream_id);
        }
        pending_.erase(found);
        auto handler = std::move(pending->handler);
        post_result(std::move(handler), core::fail(std::move(error)));
        send_pending();
        close_if_drained();
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
        if (retired_ && pending_.empty() && !write_in_progress_) {
            close_stream();
        }
    }

    void fail_all(const core::Error &error) {
        std::vector<Handler> handlers;
        handlers.reserve(pending_.size());
        for (auto &[exchange_id, pending] : pending_) {
            (void)exchange_id;
            (void)pending->timer.cancel();
            if (!pending->completed && pending->handler) {
                pending->completed = true;
                handlers.push_back(std::move(pending->handler));
            }
        }
        pending_.clear();
        stream_ids_.clear();
        stream_pending_.clear();
        for (auto &handler : handlers) {
            post_result(std::move(handler), core::fail(error));
        }
    }

    void connection_failed(core::Error error) {
        if (stopped_ || (retired_ && !stream_)) {
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
        if (stream_) {
            stream_->close();
            stream_.reset();
        }
    }

    boost::asio::any_io_executor executor_;
    std::unique_ptr<net::StreamHandleAdapter> stream_;
    nghttp2_session *http2_session_ = nullptr;
    std::optional<core::Error> initialization_error_;
    std::unordered_map<ExchangeId, PendingPtr> pending_;
    std::unordered_map<std::int32_t, ExchangeId> stream_ids_;
    std::unordered_map<std::int32_t, PendingPtr> stream_pending_;
    std::array<std::uint8_t, 16384> read_buffer_{};
    std::vector<std::uint8_t> pending_write_;
    ExchangeId next_exchange_id_ = 1;
    bool write_in_progress_ = false;
    bool read_in_progress_ = false;
    bool retired_ = false;
    bool stopped_ = false;
};

} // namespace

std::shared_ptr<HttpClientSession>
make_http2_client_session(std::unique_ptr<core::StreamHandle> stream) {
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
