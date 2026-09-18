#include <clash_native/transport/http_client.hpp>
#include <clash_native/transport/quic_client.hpp>

#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

#include <nghttp3/nghttp3.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <memory>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

namespace clash_native::transport {

namespace {

std::uint64_t timestamp_now() noexcept {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                          std::chrono::steady_clock::now().time_since_epoch())
                                          .count());
}

core::Error protocol_error(std::string context) {
    return {core::ErrorCode::protocol_framing, std::move(context), {}};
}

core::Error timeout_error() { return {core::ErrorCode::timeout, "HTTP/3 exchange timed out", {}}; }

core::Error cancelled_error() {
    return {core::ErrorCode::cancelled, "HTTP/3 exchange was cancelled", {}};
}

core::Error io_error(std::string context) {
    return {core::ErrorCode::transport_io, std::move(context), {}};
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

bool forbidden_http3_header(std::string_view name, std::string_view value) {
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

class Http3ClientSession final : public HttpClientSession,
                                 public std::enable_shared_from_this<Http3ClientSession> {
  public:
    Http3ClientSession(std::shared_ptr<QuicClientConnection> connection,
                       std::function<void(core::Error)> failure_handler)
        : connection_(std::move(connection)), executor_(connection_->executor()),
          failure_handler_(std::move(failure_handler)) {}

    ~Http3ClientSession() { close_http3(); }

    void attach() {
        const auto weak = weak_from_this();
        QuicClientEvents events;
        events.ready = [weak](std::string alpn) {
            if (const auto self = weak.lock()) {
                self->on_quic_ready(std::move(alpn));
            }
        };
        events.stream_data = [weak](std::int64_t stream_id, const std::uint8_t *data,
                                    std::size_t length, bool fin) {
            if (const auto self = weak.lock()) {
                self->on_stream_data(stream_id, data, length, fin);
            }
        };
        events.stream_write_consumed = [weak](std::int64_t stream_id, std::size_t length,
                                              bool complete) {
            if (const auto self = weak.lock()) {
                self->on_stream_write_consumed(stream_id, length, complete);
            }
        };
        events.stream_data_acked = [weak](std::int64_t stream_id, std::uint64_t length) {
            if (const auto self = weak.lock()) {
                self->on_stream_data_acked(stream_id, length);
            }
        };
        events.stream_blocked = [weak](std::int64_t stream_id) {
            if (const auto self = weak.lock()) {
                self->on_stream_blocked(stream_id);
            }
        };
        events.stream_writable = [weak](std::int64_t stream_id) {
            if (const auto self = weak.lock()) {
                self->on_stream_writable(stream_id);
            }
        };
        events.stream_closed = [weak](std::int64_t stream_id, std::uint64_t application_error) {
            if (const auto self = weak.lock()) {
                self->on_stream_closed(stream_id, application_error);
            }
        };
        events.stream_reset = [weak](std::int64_t stream_id, std::uint64_t application_error) {
            if (const auto self = weak.lock()) {
                self->on_stream_reset(stream_id, application_error);
            }
        };
        events.stream_capacity = [weak] {
            if (const auto self = weak.lock()) {
                self->open_pending_requests();
            }
        };
        events.failed = [weak](core::Error error) {
            if (const auto self = weak.lock()) {
                self->connection_failed(std::move(error));
            }
        };
        connection_->set_events(std::move(events));
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
        if (const auto validation_error = validate_request(request)) {
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
        pending_order_.push_back(exchange_id);
        open_pending_requests();
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
        close_http3();
        connection_->close();
        fail_all(cancelled_error());
    }

    bool retired() const noexcept override { return retired_ || connection_->retired(); }

  private:
    struct Pending {
        explicit Pending(boost::asio::any_io_executor executor) : timer(std::move(executor)) {}

        HttpRequest request;
        HttpResponse response;
        Handler handler;
        boost::asio::steady_timer timer;
        std::size_t body_offset = 0;
        std::int64_t stream_id = -1;
        bool completed = false;
        bool response_too_large = false;
    };

    using PendingPtr = std::shared_ptr<Pending>;

    static std::optional<core::Error> validate_request(const HttpRequest &request) {
        if (!is_token(request.method) || !is_token(request.scheme) || request.authority.empty() ||
            request.target.empty() || contains_uri_whitespace(request.authority) ||
            contains_uri_whitespace(request.target)) {
            return core::Error{core::ErrorCode::configuration,
                               "HTTP/3 method, scheme, authority, or target is invalid",
                               {}};
        }
        if (request.scheme != "http" && request.scheme != "https") {
            return core::Error{
                core::ErrorCode::configuration, "HTTP/3 scheme must be http or https", {}};
        }
        if (request.target.front() != '/' && request.target != "*") {
            return core::Error{core::ErrorCode::configuration,
                               "HTTP/3 target must use origin-form or asterisk-form",
                               {}};
        }
        for (const auto &header : request.headers) {
            if (!is_token(header.name) || contains_control(header.value)) {
                return core::Error{core::ErrorCode::configuration,
                                   "HTTP/3 header contains invalid characters",
                                   {}};
            }
            const auto name = lower_copy(header.name);
            if (name.front() == ':' || forbidden_http3_header(name, header.value)) {
                return core::Error{core::ErrorCode::configuration,
                                   "HTTP/3 request contains a forbidden header",
                                   {}};
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

    static nghttp3_nv make_header(const std::string &name, const std::string &value) {
        return {reinterpret_cast<std::uint8_t *>(const_cast<char *>(name.data())),
                reinterpret_cast<std::uint8_t *>(const_cast<char *>(value.data())), name.size(),
                value.size(), NGHTTP3_NV_FLAG_NONE};
    }

    static nghttp3_ssize read_request_body(nghttp3_conn *, std::int64_t, nghttp3_vec *vectors,
                                           std::size_t vector_count, std::uint32_t *flags, void *,
                                           void *stream_user_data) {
        auto *pending = static_cast<Pending *>(stream_user_data);
        if (pending == nullptr || pending->completed || vector_count == 0 ||
            pending->body_offset > pending->request.body.size()) {
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        const auto remaining = pending->request.body.size() - pending->body_offset;
        if (remaining == 0) {
            *flags |= NGHTTP3_DATA_FLAG_EOF;
            vectors[0] = {nullptr, 0};
            return 1;
        }
        vectors[0] = {
            const_cast<std::uint8_t *>(pending->request.body.data() + pending->body_offset),
            remaining};
        pending->body_offset += remaining;
        *flags |= NGHTTP3_DATA_FLAG_EOF;
        return 1;
    }

    static int on_body(nghttp3_conn *, std::int64_t stream_id, const std::uint8_t *data,
                       std::size_t length, void *user_data, void *) {
        auto *self = static_cast<Http3ClientSession *>(user_data);
        const auto stream = self->stream_pending_.find(stream_id);
        if (stream == self->stream_pending_.end() || stream->second->completed) {
            return 0;
        }
        auto &pending = stream->second;
        const auto current = pending->response.body.size();
        const auto limit = pending->request.response_body_limit;
        if (current > limit || length > limit - current) {
            pending->response_too_large = true;
            return 0;
        }
        pending->response.body.insert(pending->response.body.end(), data, data + length);
        return 0;
    }

    static int on_header(nghttp3_conn *, std::int64_t stream_id, std::int32_t, nghttp3_rcbuf *name,
                         nghttp3_rcbuf *value, std::uint8_t, void *user_data, void *) {
        auto *self = static_cast<Http3ClientSession *>(user_data);
        const auto stream = self->stream_pending_.find(stream_id);
        if (stream == self->stream_pending_.end() || stream->second->completed) {
            return 0;
        }
        const auto header_name = nghttp3_rcbuf_get_buf(name);
        const auto header_value = nghttp3_rcbuf_get_buf(value);
        const std::string_view name_view(reinterpret_cast<const char *>(header_name.base),
                                         header_name.len);
        const std::string_view value_view(reinterpret_cast<const char *>(header_value.base),
                                          header_value.len);
        if (name_view == ":status") {
            unsigned status = 0;
            const auto parsed =
                std::from_chars(value_view.data(), value_view.data() + value_view.size(), status);
            if (parsed.ec == std::errc{} && parsed.ptr == value_view.data() + value_view.size()) {
                stream->second->response.status = status;
            }
        } else if (!name_view.empty() && name_view.front() != ':') {
            stream->second->response.headers.push_back(
                {std::string(name_view), std::string(value_view)});
        }
        return 0;
    }

    static int on_end_stream(nghttp3_conn *, std::int64_t stream_id, void *user_data, void *) {
        auto *self = static_cast<Http3ClientSession *>(user_data);
        const auto stream = self->stream_ids_.find(stream_id);
        if (stream != self->stream_ids_.end()) {
            self->finish_pending(stream->second);
        }
        return 0;
    }

    static int on_deferred_consume(nghttp3_conn *, std::int64_t stream_id, std::size_t consumed,
                                   void *user_data, void *) {
        auto *self = static_cast<Http3ClientSession *>(user_data);
        const auto extended = self->connection_->extend_receive_credit(stream_id, consumed);
        if (!extended) {
            self->connection_failed(extended.error());
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    void on_quic_ready(std::string alpn) {
        if (alpn != "h3") {
            connection_failed(
                {core::ErrorCode::authentication, "HTTP/3 requires the h3 QUIC ALPN", {}});
            return;
        }
        if (!initialize_http3()) {
            connection_failed(initialization_error_.value_or(
                protocol_error("failed to initialize HTTP/3 session")));
            return;
        }
        open_pending_requests();
    }

    bool initialize_http3() {
        if (http3_ != nullptr) {
            return true;
        }
        nghttp3_callbacks callbacks{};
        callbacks.recv_data = &on_body;
        callbacks.deferred_consume = &on_deferred_consume;
        callbacks.recv_header = &on_header;
        callbacks.end_stream = &on_end_stream;
        nghttp3_settings settings;
        nghttp3_settings_default(&settings);
        if (nghttp3_conn_client_new(&http3_, &callbacks, &settings, nghttp3_mem_default(), this) !=
            0) {
            initialization_error_ = protocol_error("failed to create nghttp3 client session");
            return false;
        }

        const auto control = connection_->open_unidirectional_stream();
        const auto encoder = connection_->open_unidirectional_stream();
        const auto decoder = connection_->open_unidirectional_stream();
        if (control.state != QuicOpenStreamResult::State::opened ||
            encoder.state != QuicOpenStreamResult::State::opened ||
            decoder.state != QuicOpenStreamResult::State::opened ||
            nghttp3_conn_bind_control_stream(http3_, control.stream_id) != 0 ||
            nghttp3_conn_bind_qpack_streams(http3_, encoder.stream_id, decoder.stream_id) != 0) {
            initialization_error_ =
                protocol_error("failed to bind HTTP/3 control and QPACK streams");
            return false;
        }
        pump_output();
        return true;
    }

    void open_pending_requests() {
        if (retired_ || !connection_->ready()) {
            return;
        }
        if (http3_ == nullptr && !initialize_http3()) {
            connection_failed(initialization_error_.value_or(
                protocol_error("failed to initialize HTTP/3 session")));
            return;
        }
        for (const auto exchange_id : pending_order_) {
            const auto found = pending_.find(exchange_id);
            if (found == pending_.end() || found->second->stream_id >= 0) {
                continue;
            }
            const auto opened = connection_->open_bidirectional_stream();
            if (opened.state == QuicOpenStreamResult::State::blocked) {
                return;
            }
            if (opened.state != QuicOpenStreamResult::State::opened) {
                connection_failed(opened.error.value_or(
                    protocol_error("QUIC connection failed to open an HTTP/3 request stream")));
                return;
            }
            submit_request(exchange_id, found->second, opened.stream_id);
            if (retired_) {
                return;
            }
        }
        std::erase_if(pending_order_, [this](ExchangeId exchange_id) {
            const auto found = pending_.find(exchange_id);
            return found == pending_.end() || found->second->stream_id >= 0;
        });
        pump_output();
    }

    void submit_request(ExchangeId exchange_id, const PendingPtr &pending, std::int64_t stream_id) {
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
        std::vector<nghttp3_nv> headers;
        headers.reserve(names.size());
        for (std::size_t index = 0; index < names.size(); ++index) {
            headers.push_back(make_header(names[index], values[index]));
        }
        nghttp3_data_reader reader{&read_request_body};
        const auto *reader_ptr = pending->request.body.empty() ? nullptr : &reader;
        if (nghttp3_conn_submit_request(http3_, stream_id, headers.data(), headers.size(),
                                        reader_ptr, pending.get()) != 0) {
            fail_pending(exchange_id, protocol_error("failed to submit HTTP/3 request"));
            return;
        }
        pending->stream_id = stream_id;
        pending->response.version = 30;
        pending->response.keep_alive = true;
        stream_ids_.emplace(stream_id, exchange_id);
        stream_pending_.emplace(stream_id, pending);
    }

    void pump_output() {
        if (retired_ || http3_ == nullptr || write_pending_) {
            return;
        }
        std::array<nghttp3_vec, 16> vectors{};
        std::int64_t stream_id = -1;
        int fin = 0;
        const auto count =
            nghttp3_conn_writev_stream(http3_, &stream_id, &fin, vectors.data(), vectors.size());
        if (count < 0) {
            connection_failed(protocol_error("nghttp3 failed to generate HTTP/3 frames"));
            return;
        }
        if (stream_id < 0) {
            return;
        }
        std::vector<std::uint8_t> data;
        for (nghttp3_ssize index = 0; index < count; ++index) {
            const auto &vector = vectors[static_cast<std::size_t>(index)];
            const auto *begin = static_cast<const std::uint8_t *>(vector.base);
            data.insert(data.end(), begin, begin + vector.len);
        }
        write_pending_ = true;
        connection_->write_stream_data(stream_id, std::move(data), fin != 0);
    }

    void on_stream_write_consumed(std::int64_t stream_id, std::size_t length, bool complete) {
        if (retired_ || http3_ == nullptr) {
            return;
        }
        if (length != 0 && nghttp3_conn_add_write_offset(http3_, stream_id, length) != 0) {
            connection_failed(protocol_error("nghttp3 failed to advance stream write offset"));
            return;
        }
        if (complete) {
            write_pending_ = false;
            pump_output();
        }
    }

    void on_stream_data_acked(std::int64_t stream_id, std::uint64_t length) {
        if (http3_ != nullptr && !retired_ &&
            nghttp3_conn_add_ack_offset(http3_, stream_id, length) != 0) {
            connection_failed(protocol_error("nghttp3 failed to acknowledge stream data"));
        }
    }

    void on_stream_blocked(std::int64_t stream_id) {
        if (http3_ != nullptr) {
            nghttp3_conn_block_stream(http3_, stream_id);
        }
    }

    void on_stream_writable(std::int64_t stream_id) {
        if (http3_ != nullptr && nghttp3_conn_unblock_stream(http3_, stream_id) != 0) {
            connection_failed(protocol_error("nghttp3 failed to unblock a QUIC stream"));
            return;
        }
        pump_output();
    }

    void on_stream_data(std::int64_t stream_id, const std::uint8_t *data, std::size_t length,
                        bool fin) {
        if (http3_ == nullptr) {
            connection_failed(protocol_error("received HTTP/3 data before session setup"));
            return;
        }
        const auto consumed =
            nghttp3_conn_read_stream2(http3_, stream_id, data, length, fin, timestamp_now());
        if (consumed < 0) {
            connection_failed(protocol_error("nghttp3 rejected HTTP/3 stream data"));
            return;
        }
        const auto extended =
            connection_->extend_receive_credit(stream_id, static_cast<std::size_t>(consumed));
        if (!extended) {
            connection_failed(extended.error());
            return;
        }
        pump_output();
    }

    void on_stream_closed(std::int64_t stream_id, std::uint64_t application_error) {
        if (http3_ != nullptr) {
            const auto result = nghttp3_conn_close_stream(http3_, stream_id, application_error);
            if (result != 0 && result != NGHTTP3_ERR_STREAM_NOT_FOUND) {
                connection_failed(protocol_error("nghttp3 failed to close a QUIC stream"));
                return;
            }
        }
        const auto stream = stream_ids_.find(stream_id);
        if (stream == stream_ids_.end()) {
            return;
        }
        const auto exchange_id = stream->second;
        stream_ids_.erase(stream);
        stream_pending_.erase(stream_id);
        if (const auto pending = pending_.find(exchange_id);
            pending != pending_.end() && !pending->second->completed) {
            fail_pending(exchange_id,
                         io_error("HTTP/3 response stream closed before the exchange completed"));
        }
    }

    void on_stream_reset(std::int64_t stream_id, std::uint64_t application_error) {
        if (http3_ != nullptr && nghttp3_conn_shutdown_stream_read(http3_, stream_id) != 0) {
            connection_failed(protocol_error("nghttp3 failed to handle a QUIC stream reset"));
            return;
        }
        const auto stream = stream_ids_.find(stream_id);
        if (stream != stream_ids_.end()) {
            fail_pending(stream->second, io_error("HTTP/3 peer reset request stream with code " +
                                                  std::to_string(application_error)));
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
        auto response = std::move(pending->response);
        auto handler = std::move(pending->handler);
        if (pending->response_too_large) {
            post_result(
                std::move(handler),
                core::fail(protocol_error("HTTP/3 response exceeded the configured body limit")));
        } else {
            post_result(std::move(handler), std::move(response));
        }
    }

    void fail_pending(ExchangeId exchange_id, core::Error error) {
        const auto found = pending_.find(exchange_id);
        if (found == pending_.end() || found->second->completed) {
            return;
        }
        const auto pending = found->second;
        pending->completed = true;
        (void)pending->timer.cancel();
        if (pending->stream_id >= 0 && connection_ && !connection_->retired()) {
            if (http3_ != nullptr) {
                (void)nghttp3_conn_shutdown_stream_read(http3_, pending->stream_id);
                (void)nghttp3_conn_shutdown_stream_write(http3_, pending->stream_id);
            }
            connection_->shutdown_stream(pending->stream_id, 0x10c);
        } else if (pending->stream_id >= 0) {
            stream_ids_.erase(pending->stream_id);
            stream_pending_.erase(pending->stream_id);
        }
        pending_.erase(found);
        auto handler = std::move(pending->handler);
        post_result(std::move(handler), core::fail(std::move(error)));
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
        pending_order_.clear();
        stream_ids_.clear();
        stream_pending_.clear();
        for (auto &handler : handlers) {
            post_result(std::move(handler), core::fail(error));
        }
    }

    void connection_failed(core::Error error) {
        if (retired_) {
            return;
        }
        retired_ = true;
        close_http3();
        fail_all(error);
        if (failure_handler_) {
            auto handler = std::move(failure_handler_);
            handler(std::move(error));
        }
    }

    void close_http3() noexcept {
        if (http3_ != nullptr) {
            nghttp3_conn_del(http3_);
            http3_ = nullptr;
        }
    }

    std::shared_ptr<QuicClientConnection> connection_;
    boost::asio::any_io_executor executor_;
    std::function<void(core::Error)> failure_handler_;
    nghttp3_conn *http3_ = nullptr;
    std::optional<core::Error> initialization_error_;
    std::unordered_map<ExchangeId, PendingPtr> pending_;
    std::unordered_map<std::int64_t, ExchangeId> stream_ids_;
    std::unordered_map<std::int64_t, PendingPtr> stream_pending_;
    std::vector<ExchangeId> pending_order_;
    ExchangeId next_exchange_id_ = 1;
    bool write_pending_ = false;
    bool retired_ = false;
    bool stopped_ = false;
};

} // namespace

std::shared_ptr<HttpClientSession>
make_http3_client_session(std::shared_ptr<QuicClientConnection> connection,
                          std::function<void(core::Error)> failure_handler) {
    if (!connection) {
        return {};
    }
    auto session =
        std::make_shared<Http3ClientSession>(std::move(connection), std::move(failure_handler));
    session->attach();
    return session;
}

} // namespace clash_native::transport
