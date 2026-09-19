#include <clash_native/transport/websocket_client.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace clash_native::transport {

namespace {

class WebSocketStreamAdapter {
  public:
    using executor_type = boost::asio::any_io_executor;
    using lowest_layer_type = WebSocketStreamAdapter;

    explicit WebSocketStreamAdapter(std::unique_ptr<core::StreamHandle> handle)
        : handle_(std::shared_ptr<core::StreamHandle>(std::move(handle))) {}

    executor_type get_executor() const noexcept { return handle_->executor(); }

    lowest_layer_type &lowest_layer() noexcept { return *this; }
    const lowest_layer_type &lowest_layer() const noexcept { return *this; }

    template <typename MutableBufferSequence, typename CompletionToken>
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

    template <typename ConstBufferSequence, typename CompletionToken>
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

    boost::asio::ip::tcp::endpoint local_endpoint(boost::system::error_code &error) const noexcept {
        return handle_->local_endpoint(error);
    }

    void shutdown_send(boost::system::error_code &error) noexcept { handle_->shutdown_send(error); }

    void close() noexcept {
        if (handle_) {
            handle_->close();
        }
    }

  private:
    std::shared_ptr<core::StreamHandle> handle_;
};

inline void beast_close_socket(WebSocketStreamAdapter &stream) { stream.close(); }

inline void teardown(boost::beast::role_type, WebSocketStreamAdapter &stream,
                     boost::system::error_code &error) {
    stream.close();
    error.clear();
}

template <typename TeardownHandler>
void async_teardown(boost::beast::role_type, WebSocketStreamAdapter &stream,
                    TeardownHandler &&handler) {
    auto executor = stream.get_executor();
    stream.close();
    using Handler = std::decay_t<TeardownHandler>;
    boost::asio::post(
        executor,
        [handler = Handler(std::forward<TeardownHandler>(handler))]() mutable { handler({}); });
}

namespace websocket = boost::beast::websocket;
using BeastWebSocket = websocket::stream<WebSocketStreamAdapter>;

constexpr std::size_t kMaximumMessageSize = 64 * 1024 * 1024;

core::Error configuration_error(std::string context) {
    return {core::ErrorCode::configuration, std::move(context), {}};
}

core::Error handshake_error(const boost::system::error_code &error) {
    return {core::ErrorCode::carrier_handshake,
            "WebSocket HTTP/1.1 Upgrade handshake failed: " + error.message(),
            std::error_code(error.value(), std::system_category())};
}

core::Error timeout_error() {
    return {core::ErrorCode::timeout, "WebSocket HTTP/1.1 Upgrade handshake timed out", {}};
}

core::Error cancelled_error() {
    return {core::ErrorCode::cancelled, "WebSocket client handshake was cancelled", {}};
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
    return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char character) {
        return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
               (character >= '0' && character <= '9') ||
               kTokenPunctuation.find(character) != std::string_view::npos;
    });
}

std::string lower_copy(std::string_view value) {
    std::string result(value);
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}

bool is_managed_header(std::string_view name) {
    const auto lower = lower_copy(name);
    return lower == "host" || lower == "connection" || lower == "upgrade" ||
           lower == "content-length" || lower == "transfer-encoding" ||
           lower == "sec-websocket-key" || lower == "sec-websocket-version" ||
           lower == "sec-websocket-accept" || lower == "sec-websocket-extensions";
}

std::optional<core::Error> validate_options(const WebSocketClientOptions &options) {
    if (options.host.empty() || contains_uri_whitespace(options.host)) {
        return configuration_error("WebSocket HTTP/1.1 Host is invalid");
    }
    if (options.target.empty() || contains_uri_whitespace(options.target) ||
        (options.target.front() != '/' && options.target != "*")) {
        return configuration_error("WebSocket HTTP/1.1 target is invalid");
    }
    if (options.max_message_size == 0 || options.max_message_size > kMaximumMessageSize) {
        return configuration_error("WebSocket message size limit is invalid");
    }
    for (const auto &header : options.headers) {
        if (!is_token(header.name) || contains_control(header.value)) {
            return configuration_error("WebSocket handshake header is invalid");
        }
        if (is_managed_header(header.name)) {
            return configuration_error(
                "WebSocket handshake framing header is managed by the client");
        }
    }
    return std::nullopt;
}

class WebSocketStreamState final : public std::enable_shared_from_this<WebSocketStreamState> {
  public:
    WebSocketStreamState(std::shared_ptr<BeastWebSocket> stream, std::size_t max_message_size)
        : executor_(stream->get_executor()), stream_(std::move(stream)),
          max_message_size_(max_message_size) {}

    ~WebSocketStreamState() { close(); }

    void async_read_some(boost::asio::mutable_buffer buffer,
                         core::StreamHandle::ReadHandler handler) {
        const auto self = shared_from_this();
        boost::asio::dispatch(executor_, [self, buffer, handler = std::move(handler)]() mutable {
            self->read(buffer, std::move(handler));
        });
    }

    void async_write(boost::asio::const_buffer buffer, core::StreamHandle::WriteHandler handler) {
        auto bytes = std::make_shared<std::vector<std::uint8_t>>(buffer.size());
        boost::asio::buffer_copy(boost::asio::buffer(*bytes), buffer);
        const auto self = shared_from_this();
        boost::asio::dispatch(
            executor_, [self, bytes = std::move(bytes), handler = std::move(handler)]() mutable {
                self->write(std::move(bytes), std::move(handler));
            });
    }

    boost::asio::any_io_executor executor() noexcept { return executor_; }

    boost::asio::ip::tcp::endpoint local_endpoint(boost::system::error_code &error) const noexcept {
        if (stream_) {
            return stream_->next_layer().local_endpoint(error);
        }
        error = boost::asio::error::operation_aborted;
        return {};
    }

    void shutdown_send(boost::system::error_code &error) noexcept {
        error = boost::asio::error::operation_not_supported;
    }

    void close() noexcept {
        if (closed_) {
            return;
        }
        closed_ = true;
        read_closed_ = true;
        read_error_ = boost::asio::error::operation_aborted;
        if (stream_) {
            stream_->next_layer().close();
        }
        finish_read(read_error_, 0);
        finish_write(boost::asio::error::operation_aborted, 0);
        incoming_.clear();
        incoming_offset_ = 0;
        message_available_ = false;
    }

  private:
    void read(boost::asio::mutable_buffer buffer, core::StreamHandle::ReadHandler handler) {
        if (buffer.size() == 0) {
            post_read(std::move(handler), {}, 0);
            return;
        }
        if (closed_) {
            post_read(std::move(handler), boost::asio::error::operation_aborted, 0);
            return;
        }
        if (read_handler_) {
            post_read(std::move(handler), boost::asio::error::already_started, 0);
            return;
        }
        if (message_available_) {
            read_buffer_ = buffer;
            read_handler_ = std::move(handler);
            deliver_read();
            return;
        }
        if (read_closed_) {
            post_read(std::move(handler), read_error_, 0);
            return;
        }
        read_buffer_ = buffer;
        read_handler_ = std::move(handler);
        start_read_message();
    }

    void start_read_message() {
        if (closed_ || read_closed_ || read_in_progress_ || !read_handler_ || !stream_) {
            return;
        }
        read_in_progress_ = true;
        const auto self = shared_from_this();
        stream_->async_read(
            read_message_buffer_, [self](const boost::system::error_code &error, std::size_t size) {
                self->read_in_progress_ = false;
                if (self->closed_) {
                    return;
                }
                if (error) {
                    if (error == websocket::error::closed) {
                        self->remote_close(boost::asio::error::eof);
                    } else {
                        self->fail(error);
                    }
                    return;
                }
                if (!self->stream_->got_binary()) {
                    self->fail(
                        boost::system::errc::make_error_code(boost::system::errc::protocol_error));
                    return;
                }
                if (size > self->max_message_size_ ||
                    self->read_message_buffer_.size() > self->max_message_size_) {
                    self->fail(boost::asio::error::message_size);
                    return;
                }
                self->incoming_.resize(size);
                boost::asio::buffer_copy(boost::asio::buffer(self->incoming_),
                                         self->read_message_buffer_.data());
                self->read_message_buffer_.consume(size);
                self->incoming_offset_ = 0;
                self->message_available_ = true;
                self->deliver_read();
            });
    }

    void deliver_read() {
        if (closed_ || !read_handler_ || !message_available_) {
            return;
        }
        const auto available = incoming_.size() - incoming_offset_;
        const auto copied = boost::asio::buffer_copy(
            read_buffer_, boost::asio::buffer(incoming_.data() + incoming_offset_, available));
        incoming_offset_ += copied;
        if (incoming_offset_ == incoming_.size()) {
            incoming_.clear();
            incoming_offset_ = 0;
            message_available_ = false;
        }
        finish_read({}, copied);
    }

    void write(std::shared_ptr<std::vector<std::uint8_t>> bytes,
               core::StreamHandle::WriteHandler handler) {
        if (closed_ || !stream_) {
            post_write(std::move(handler), boost::asio::error::operation_aborted, 0);
            return;
        }
        if (write_handler_) {
            post_write(std::move(handler), boost::asio::error::already_started, 0);
            return;
        }
        if (bytes->size() > max_message_size_) {
            post_write(std::move(handler), boost::asio::error::message_size, 0);
            return;
        }
        if (bytes->empty()) {
            post_write(std::move(handler), {}, 0);
            return;
        }
        write_size_ = bytes->size();
        write_handler_ = std::move(handler);
        stream_->binary(true);
        auto payload = boost::asio::buffer(*bytes);
        const auto self = shared_from_this();
        stream_->async_write(
            payload, [self, bytes = std::move(bytes)](const boost::system::error_code &error,
                                                      std::size_t size) mutable {
                (void)bytes;
                if (self->closed_) {
                    return;
                }
                if (!error && size != self->write_size_) {
                    self->finish_write(boost::asio::error::message_size, size);
                    return;
                }
                self->finish_write(error, size);
            });
    }

    void remote_close(boost::system::error_code error) {
        if (closed_ || read_closed_) {
            return;
        }
        read_closed_ = true;
        read_error_ = error;
        finish_read(read_error_, 0);
    }

    void fail(const boost::system::error_code &error) {
        if (closed_) {
            return;
        }
        closed_ = true;
        read_closed_ = true;
        read_error_ = error ? error : boost::asio::error::connection_reset;
        if (stream_) {
            stream_->next_layer().close();
        }
        finish_read(read_error_, 0);
        finish_write(read_error_, 0);
        incoming_.clear();
        incoming_offset_ = 0;
        message_available_ = false;
    }

    void finish_read(const boost::system::error_code &error, std::size_t size) {
        if (!read_handler_) {
            return;
        }
        auto handler = std::move(read_handler_);
        read_buffer_ = {};
        post_read(std::move(handler), error, size);
    }

    void finish_write(const boost::system::error_code &error, std::size_t size) {
        if (!write_handler_) {
            return;
        }
        auto handler = std::move(write_handler_);
        write_size_ = 0;
        post_write(std::move(handler), error, size);
    }

    void post_read(core::StreamHandle::ReadHandler handler, const boost::system::error_code &error,
                   std::size_t size) {
        boost::asio::post(executor_, [handler = std::move(handler), error, size]() mutable {
            if (handler) {
                handler(error, size);
            }
        });
    }

    void post_write(core::StreamHandle::WriteHandler handler,
                    const boost::system::error_code &error, std::size_t size) {
        boost::asio::post(executor_, [handler = std::move(handler), error, size]() mutable {
            if (handler) {
                handler(error, size);
            }
        });
    }

    boost::asio::any_io_executor executor_;
    std::shared_ptr<BeastWebSocket> stream_;
    const std::size_t max_message_size_;
    boost::beast::flat_buffer read_message_buffer_;
    std::vector<std::uint8_t> incoming_;
    std::size_t incoming_offset_ = 0;
    boost::asio::mutable_buffer read_buffer_;
    core::StreamHandle::ReadHandler read_handler_;
    core::StreamHandle::WriteHandler write_handler_;
    std::size_t write_size_ = 0;
    boost::system::error_code read_error_;
    bool read_in_progress_ = false;
    bool message_available_ = false;
    bool read_closed_ = false;
    bool closed_ = false;
};

class WebSocketStream final : public core::StreamHandle {
  public:
    explicit WebSocketStream(std::shared_ptr<WebSocketStreamState> state)
        : state_(std::move(state)) {}

    void async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) override {
        state_->async_read_some(buffer, std::move(handler));
    }

    void async_write(boost::asio::const_buffer buffer, WriteHandler handler) override {
        state_->async_write(buffer, std::move(handler));
    }

    boost::asio::any_io_executor executor() noexcept override { return state_->executor(); }

    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept override {
        return state_->local_endpoint(error);
    }

    void shutdown_send(boost::system::error_code &error) noexcept override {
        state_->shutdown_send(error);
    }

    void close() noexcept override { state_->close(); }

  private:
    std::shared_ptr<WebSocketStreamState> state_;
};

class WebSocketClientHandshakeOperation final
    : public WebSocketClientHandshake,
      public std::enable_shared_from_this<WebSocketClientHandshakeOperation> {
  public:
    WebSocketClientHandshakeOperation(std::unique_ptr<core::StreamHandle> stream,
                                      WebSocketClientOptions options,
                                      WebSocketClientHandler handler)
        : executor_(stream->executor()), stream_(std::move(stream)), options_(std::move(options)),
          handler_(std::move(handler)), timer_(executor_) {}

    void start() {
        const auto self = shared_from_this();
        boost::asio::post(executor_, [self] { self->begin(); });
    }

    void cancel() noexcept override {
        try {
            const auto self = shared_from_this();
            boost::asio::dispatch(executor_,
                                  [self] { self->finish(core::fail(cancelled_error())); });
        } catch (...) {
            if (stream_) {
                stream_->close();
            }
        }
    }

  private:
    void begin() {
        if (completed_) {
            return;
        }
        if (const auto error = validate_options(options_)) {
            finish(core::fail(*error));
            return;
        }
        if (options_.deadline) {
            if (*options_.deadline <= std::chrono::steady_clock::now()) {
                finish(core::fail(timeout_error()));
                return;
            }
            timer_.expires_at(*options_.deadline);
            const auto self = shared_from_this();
            timer_.async_wait([self](const boost::system::error_code &error) {
                if (!error) {
                    self->finish(core::fail(timeout_error()));
                }
            });
        }

        websocket_ = std::make_shared<BeastWebSocket>(WebSocketStreamAdapter(std::move(stream_)));
        websocket_->set_option(
            websocket::stream_base::timeout::suggested(boost::beast::role_type::client));
        websocket_->read_message_max(options_.max_message_size);
        websocket_->auto_fragment(true);
        const auto headers = options_.headers;
        websocket_->set_option(
            websocket::stream_base::decorator([headers](websocket::request_type &request) {
                for (const auto &header : headers) {
                    request.set(header.name, header.value);
                }
            }));
        const auto self = shared_from_this();
        websocket_->async_handshake(
            options_.host, options_.target, [self](const boost::system::error_code &error) {
                if (self->completed_) {
                    self->websocket_.reset();
                    return;
                }
                if (error) {
                    self->finish(core::fail(handshake_error(error)));
                    return;
                }
                boost::asio::post(self->executor_, [self] { self->complete_success(); });
            });
    }

    void complete_success() {
        if (completed_) {
            if (websocket_) {
                websocket_->next_layer().close();
                websocket_.reset();
            }
            return;
        }
        auto state = std::make_shared<WebSocketStreamState>(websocket_, options_.max_message_size);
        websocket_.reset();
        auto stream = std::make_unique<WebSocketStream>(std::move(state));
        finish(std::unique_ptr<core::StreamHandle>(std::move(stream)));
    }

    void finish(core::Result<std::unique_ptr<core::StreamHandle>> result) {
        if (completed_) {
            return;
        }
        completed_ = true;
        (void)timer_.cancel();
        if (!result) {
            if (websocket_) {
                websocket_->next_layer().close();
            }
            if (stream_) {
                stream_->close();
                stream_.reset();
            }
        }
        auto handler = std::move(handler_);
        if (handler) {
            boost::asio::post(executor_,
                              [handler = std::move(handler), result = std::move(result)]() mutable {
                                  handler(std::move(result));
                              });
        }
    }

    boost::asio::any_io_executor executor_;
    std::unique_ptr<core::StreamHandle> stream_;
    WebSocketClientOptions options_;
    WebSocketClientHandler handler_;
    std::shared_ptr<BeastWebSocket> websocket_;
    boost::asio::steady_timer timer_;
    bool completed_ = false;
};

} // namespace

std::shared_ptr<WebSocketClientHandshake>
async_websocket_client_handshake(std::unique_ptr<core::StreamHandle> stream,
                                 WebSocketClientOptions options, WebSocketClientHandler handler) {
    if (!stream || !handler) {
        if (stream) {
            stream->close();
        }
        if (handler) {
            handler(core::fail(configuration_error(
                "WebSocket client handshake requires a stream and completion handler")));
        }
        return {};
    }
    auto operation = std::make_shared<WebSocketClientHandshakeOperation>(
        std::move(stream), std::move(options), std::move(handler));
    operation->start();
    return operation;
}

} // namespace clash_native::transport
