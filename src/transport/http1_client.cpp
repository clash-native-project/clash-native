#include <clash_native/transport/http_client.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/async_result.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http.hpp>

#include <algorithm>
#include <cctype>
#include <deque>
#include <memory>
#include <optional>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>

namespace clash_native::transport {

namespace {

namespace http = boost::beast::http;
using HttpMessage = http::request<http::vector_body<std::uint8_t>>;
using HttpResponseParser = http::response_parser<http::vector_body<std::uint8_t>>;

// Beast's composed HTTP operations copy their stream and accept buffer
// sequences, while StreamHandle exposes a unique owner and single buffers.
class Http1StreamAdapter {
  public:
    using executor_type = boost::asio::any_io_executor;

    explicit Http1StreamAdapter(std::unique_ptr<core::StreamHandle> handle)
        : handle_(std::shared_ptr<core::StreamHandle>(std::move(handle))) {}

    executor_type get_executor() const noexcept { return handle_->executor(); }

    template <class MutableBufferSequence, class CompletionToken>
    auto async_read_some(const MutableBufferSequence &buffers, CompletionToken &&token) {
        auto first = boost::asio::buffer_sequence_begin(buffers);
        const auto last = boost::asio::buffer_sequence_end(buffers);
        boost::asio::mutable_buffer buffer;
        for (; first != last; ++first) {
            buffer = boost::asio::mutable_buffer(*first);
            if (buffer.size() != 0) {
                break;
            }
        }
        auto handle = handle_;
        return boost::asio::async_initiate<CompletionToken,
                                           void(boost::system::error_code, std::size_t)>(
            [handle = std::move(handle), buffer](auto completion_handler) mutable {
                using Handler = std::decay_t<decltype(completion_handler)>;
                auto shared_handler = std::make_shared<Handler>(std::move(completion_handler));
                handle->async_read_some(
                    buffer, [shared_handler = std::move(shared_handler)](
                                const boost::system::error_code &error, std::size_t size) mutable {
                        (*shared_handler)(error, size);
                    });
            },
            token);
    }

    template <class ConstBufferSequence, class CompletionToken>
    auto async_write_some(const ConstBufferSequence &buffers, CompletionToken &&token) {
        auto bytes = std::make_shared<std::vector<std::uint8_t>>(boost::asio::buffer_size(buffers));
        boost::asio::buffer_copy(boost::asio::buffer(*bytes), buffers);
        auto handle = handle_;
        return boost::asio::async_initiate<CompletionToken,
                                           void(boost::system::error_code, std::size_t)>(
            [handle = std::move(handle),
             bytes = std::move(bytes)](auto completion_handler) mutable {
                using Handler = std::decay_t<decltype(completion_handler)>;
                auto shared_handler = std::make_shared<Handler>(std::move(completion_handler));
                auto lifetime = bytes;
                handle->async_write(
                    boost::asio::buffer(*bytes),
                    [lifetime = std::move(lifetime), shared_handler = std::move(shared_handler)](
                        const boost::system::error_code &error, std::size_t size) mutable {
                        (void)lifetime;
                        (*shared_handler)(error, size);
                    });
            },
            token);
    }

    void close() noexcept {
        if (handle_) {
            handle_->close();
        }
    }

  private:
    std::shared_ptr<core::StreamHandle> handle_;
};

core::Error io_error(std::string context, const boost::system::error_code &error) {
    return {core::ErrorCode::transport_io, std::move(context),
            std::error_code(error.value(), std::system_category())};
}

core::Error protocol_error(std::string context) {
    return {core::ErrorCode::protocol_framing, std::move(context)};
}

core::Error timeout_error() { return {core::ErrorCode::timeout, "HTTP/1.1 exchange timed out"}; }

core::Error cancelled_error() {
    return {core::ErrorCode::cancelled, "HTTP/1.1 exchange was cancelled"};
}

bool has_http_control(std::string_view value) {
    return std::any_of(value.begin(), value.end(), [](unsigned char character) {
        return character < 0x20 || character == 0x7f;
    });
}

bool has_uri_whitespace(std::string_view value) {
    return std::any_of(value.begin(), value.end(), [](unsigned char character) {
        return character <= 0x20 || character == 0x7f;
    });
}

constexpr std::string_view kHttpTokenPunctuation = "!#$%&'*+-.^_`|~";

bool is_token(std::string_view value) {
    return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char character) {
        return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
               (character >= '0' && character <= '9') ||
               kHttpTokenPunctuation.find(character) != std::string_view::npos;
    });
}

bool is_host_header(std::string_view name) {
    if (name.size() != 4) {
        return false;
    }
    constexpr std::string_view expected = "host";
    return std::equal(name.begin(), name.end(), expected.begin(),
                      [](unsigned char actual, unsigned char wanted) {
                          return static_cast<unsigned char>(std::tolower(actual)) == wanted;
                      });
}

core::Result<HttpMessage> make_message(const HttpRequest &request) {
    if (!is_token(request.method) || request.target.empty() || has_uri_whitespace(request.target) ||
        has_uri_whitespace(request.authority)) {
        return core::fail(core::Error{core::ErrorCode::configuration,
                                      "HTTP/1.1 method, target, or authority is invalid"});
    }

    HttpMessage message;
    message.method_string(request.method);
    message.target(request.target);
    message.version(11);
    bool has_host = false;
    for (const auto &header : request.headers) {
        if (!is_token(header.name) || has_http_control(header.value)) {
            return core::fail(core::Error{core::ErrorCode::configuration,
                                          "HTTP/1.1 header contains invalid characters"});
        }
        has_host = has_host || is_host_header(header.name);
        message.insert(header.name, header.value);
    }
    if (!request.authority.empty() && !has_host) {
        message.set(http::field::host, request.authority);
    }
    message.keep_alive(request.keep_alive);
    message.body() = request.body;
    message.prepare_payload();
    return message;
}

HttpResponse make_response(http::response<http::vector_body<std::uint8_t>> message) {
    HttpResponse response;
    response.version = message.version();
    response.status = message.result_int();
    response.keep_alive = message.keep_alive();
    response.body = std::move(message.body());
    for (const auto &field : message.base()) {
        response.headers.push_back({std::string(field.name_string()), std::string(field.value())});
    }
    return response;
}

bool is_http_framing_error(const boost::system::error_code &error) {
    return error == http::error::body_limit || error == http::error::partial_message ||
           error == http::error::bad_chunk || error == http::error::bad_line_ending ||
           error == http::error::bad_version;
}

class Http1ClientSession final : public HttpClientSession,
                                 public std::enable_shared_from_this<Http1ClientSession> {
  public:
    explicit Http1ClientSession(std::unique_ptr<core::StreamHandle> stream)
        : executor_(stream->executor()),
          stream_(std::make_unique<Http1StreamAdapter>(std::move(stream))) {}

    ExchangeId exchange(HttpRequest request, std::chrono::steady_clock::time_point deadline,
                        Handler handler) override {
        const auto exchange_id = next_exchange_id();
        if (stopped_ || retired_) {
            post_result(std::move(handler),
                        core::fail(core::Error{core::ErrorCode::cancelled,
                                               "HTTP/1.1 session is not accepting requests"}));
            return exchange_id;
        }
        const auto message = make_message(request);
        if (!message) {
            post_result(std::move(handler), core::fail(message.error()));
            return exchange_id;
        }
        if (deadline <= std::chrono::steady_clock::now()) {
            post_result(std::move(handler), core::fail(timeout_error()));
            return exchange_id;
        }

        auto pending = std::make_shared<Pending>(executor_);
        pending->request = std::move(request);
        pending->message = std::move(message.value());
        pending->handler = std::move(handler);
        pending->timer.expires_at(deadline);
        const auto self = shared_from_this();
        pending->timer.async_wait([self, exchange_id](const boost::system::error_code &error) {
            if (!error) {
                self->expire(exchange_id);
            }
        });
        pending_.emplace(exchange_id, std::move(pending));
        queue_.push_back(exchange_id);
        start_next();
        return exchange_id;
    }

    void cancel(ExchangeId exchange_id) noexcept override {
        const auto found = pending_.find(exchange_id);
        if (found == pending_.end()) {
            return;
        }
        if (active_id_ == exchange_id) {
            retire_all(exchange_id, core::fail(cancelled_error()),
                       core::fail(core::Error{core::ErrorCode::cancelled,
                                              "HTTP/1.1 connection was retired"}));
            return;
        }
        complete(exchange_id, core::fail(cancelled_error()));
        start_next();
    }

    void stop() noexcept override {
        if (stopped_) {
            return;
        }
        stopped_ = true;
        retired_ = true;
        close_stream();
        complete_all(core::fail(cancelled_error()));
    }

    bool retired() const noexcept override { return retired_; }

  private:
    struct Pending {
        explicit Pending(boost::asio::any_io_executor executor) : timer(std::move(executor)) {}

        HttpRequest request;
        HttpMessage message;
        std::unique_ptr<HttpResponseParser> parser;
        Handler handler;
        boost::asio::steady_timer timer;
    };

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

    void start_next() {
        if (stopped_ || retired_ || active_id_ || !stream_) {
            return;
        }
        while (!queue_.empty()) {
            const auto exchange_id = queue_.front();
            queue_.pop_front();
            const auto found = pending_.find(exchange_id);
            if (found == pending_.end()) {
                continue;
            }
            active_id_ = exchange_id;
            auto pending = found->second;
            pending->parser = std::make_unique<HttpResponseParser>();
            pending->parser->body_limit(pending->request.response_body_limit);
            const auto self = shared_from_this();
            http::async_write(
                *stream_, pending->message,
                [self, exchange_id, pending](const boost::system::error_code &error, std::size_t) {
                    if (self->stopped_ || self->retired_ || self->active_id_ != exchange_id) {
                        return;
                    }
                    if (error) {
                        self->fail_active(exchange_id, error, "failed to write HTTP/1.1 request");
                        return;
                    }
                    self->read_response(exchange_id, pending);
                });
            return;
        }
    }

    void read_response(ExchangeId exchange_id, const std::shared_ptr<Pending> &pending) {
        const auto self = shared_from_this();
        http::async_read(
            *stream_, read_buffer_, *pending->parser,
            [self, exchange_id, pending](const boost::system::error_code &error, std::size_t) {
                if (self->stopped_ || self->retired_ || self->active_id_ != exchange_id) {
                    return;
                }
                if (error) {
                    self->fail_active(exchange_id, error, "failed to read HTTP/1.1 response");
                    return;
                }
                auto message = pending->parser->release();
                auto response = make_response(std::move(message));
                const bool reusable = pending->request.keep_alive && response.keep_alive;
                if (!reusable) {
                    self->retired_ = true;
                    self->close_stream();
                }
                self->active_id_.reset();
                self->complete(exchange_id, std::move(response));
                if (reusable) {
                    self->start_next();
                } else {
                    self->retire_queued();
                }
            });
    }

    void expire(ExchangeId exchange_id) {
        if (!pending_.contains(exchange_id)) {
            return;
        }
        if (active_id_ == exchange_id) {
            retire_all(exchange_id, core::fail(timeout_error()),
                       core::fail(core::Error{core::ErrorCode::transport_io,
                                              "HTTP/1.1 connection was retired after a timeout"}));
            return;
        }
        complete(exchange_id, core::fail(timeout_error()));
    }

    void fail_active(ExchangeId exchange_id, const boost::system::error_code &error,
                     std::string context) {
        auto failure = is_http_framing_error(error)
                           ? core::fail(protocol_error("HTTP/1.1 response framing failed"))
                           : core::fail(io_error(std::move(context), error));
        retire_all(exchange_id, std::move(failure),
                   core::fail(core::Error{core::ErrorCode::transport_io,
                                          "HTTP/1.1 connection was retired after an I/O error"}));
    }

    void retire_all(ExchangeId active_id, core::Result<HttpResponse> active_result,
                    const core::Result<HttpResponse> &queued_result) {
        retired_ = true;
        close_stream();
        active_id_.reset();
        complete(active_id, std::move(active_result));
        std::vector<ExchangeId> remaining;
        remaining.reserve(pending_.size());
        for (const auto &[exchange_id, pending] : pending_) {
            remaining.push_back(exchange_id);
        }
        for (const auto exchange_id : remaining) {
            complete(exchange_id, core::fail(queued_result.error()));
        }
        queue_.clear();
    }

    void retire_queued() {
        retired_ = true;
        close_stream();
        std::vector<ExchangeId> remaining;
        remaining.reserve(pending_.size());
        for (const auto &[exchange_id, pending] : pending_) {
            remaining.push_back(exchange_id);
        }
        for (const auto exchange_id : remaining) {
            complete(exchange_id,
                     core::fail(core::Error{core::ErrorCode::transport_io,
                                            "HTTP/1.1 connection closed before queued exchange"}));
        }
        queue_.clear();
    }

    void complete(ExchangeId exchange_id, core::Result<HttpResponse> result) {
        const auto found = pending_.find(exchange_id);
        if (found == pending_.end()) {
            return;
        }
        auto pending = std::move(found->second);
        pending_.erase(found);
        (void)pending->timer.cancel();
        auto handler = std::move(pending->handler);
        if (handler) {
            handler(std::move(result));
        }
    }

    void complete_all(const core::Result<HttpResponse> &result) {
        std::vector<ExchangeId> exchanges;
        exchanges.reserve(pending_.size());
        for (const auto &[exchange_id, pending] : pending_) {
            exchanges.push_back(exchange_id);
        }
        for (const auto exchange_id : exchanges) {
            complete(exchange_id, core::fail(result.error()));
        }
        queue_.clear();
    }

    void close_stream() noexcept {
        if (stream_) {
            stream_->close();
            stream_.reset();
        }
    }

    boost::asio::any_io_executor executor_;
    std::unique_ptr<Http1StreamAdapter> stream_;
    boost::beast::flat_buffer read_buffer_;
    std::unordered_map<ExchangeId, std::shared_ptr<Pending>> pending_;
    std::deque<ExchangeId> queue_;
    std::optional<ExchangeId> active_id_;
    ExchangeId next_exchange_id_ = 1;
    bool retired_ = false;
    bool stopped_ = false;
};

} // namespace

std::shared_ptr<HttpClientSession>
make_http1_client_session(std::unique_ptr<core::StreamHandle> stream) {
    if (!stream) {
        return {};
    }
    return std::make_shared<Http1ClientSession>(std::move(stream));
}

} // namespace clash_native::transport
