#include <clash_native/transport/websocket_client.hpp>

#include <clash_native/async/callback_sender.hpp>
#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/transport/tls_client.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/system/error_code.hpp>

#include <exec/async_scope.hpp>
#include <exec/task.hpp>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace clash_native::transport {

namespace {

using StreamReadHandler = std::function<void(const boost::system::error_code &, std::size_t)>;
using StreamWriteHandler = std::function<void(const boost::system::error_code &, std::size_t)>;

class WebSocketStreamAdapter {
  public:
    using executor_type = boost::asio::any_io_executor;
    using lowest_layer_type = WebSocketStreamAdapter;

    explicit WebSocketStreamAdapter(std::unique_ptr<io::StreamHandle> handle)
        : handle_(std::shared_ptr<io::StreamHandle>(std::move(handle))) {}

    executor_type get_executor() const noexcept { return handle_->executor(); }

    lowest_layer_type &lowest_layer() noexcept { return *this; }
    const lowest_layer_type &lowest_layer() const noexcept { return *this; }

    // Drives the sender-based handle to completion on the heap and translates
    // the terminal signal back into the Asio handler call. Unqualified
    // completions: the erased sender invokes the receiver as an lvalue.
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
                struct Receiver {
                    Handler handler;
                    void set_value(std::optional<std::size_t> count) noexcept {
                        if (count) {
                            std::move(handler)(boost::system::error_code{}, *count);
                        } else {
                            std::move(handler)(boost::asio::error::eof, std::size_t{0});
                        }
                    }
                    void set_error(std::exception_ptr error) noexcept {
                        std::move(handler)(unpack_error(std::move(error)), std::size_t{0});
                    }
                    void set_stopped() noexcept {
                        std::move(handler)(boost::asio::error::operation_aborted, std::size_t{0});
                    }
                };
                async::start_with_receiver(handle->async_read_some(buffer),
                                           Receiver{std::move(completion_handler)});
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
                struct Receiver {
                    Handler handler;
                    std::shared_ptr<std::vector<std::uint8_t>> lifetime;
                    void set_value(std::size_t count) noexcept {
                        std::move(handler)(boost::system::error_code{}, count);
                    }
                    void set_error(std::exception_ptr error) noexcept {
                        std::move(handler)(unpack_error(std::move(error)), std::size_t{0});
                    }
                    void set_stopped() noexcept {
                        std::move(handler)(boost::asio::error::operation_aborted, std::size_t{0});
                    }
                };
                // Split sender creation from the move below: function argument
                // evaluation order is unspecified, so dereferencing bytes for
                // the sender while moving it into the receiver in one call
                // risks use-after-move.
                auto sender = handle->async_write(boost::asio::buffer(*bytes));
                async::start_with_receiver(
                    std::move(sender), Receiver{std::move(completion_handler), std::move(bytes)});
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
    static boost::system::error_code unpack_error(std::exception_ptr error) noexcept {
        try {
            std::rethrow_exception(std::move(error));
        } catch (const core::Error &failure) {
            if (failure.cause) {
                return {failure.cause.value(), boost::system::system_category()};
            }
            return boost::asio::error::fault;
        } catch (...) {
            return boost::asio::error::fault;
        }
    }

    std::shared_ptr<io::StreamHandle> handle_;
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

// Base64URL without padding (Mihomo early-data encoding).
std::string base64url_encode(std::span<const std::uint8_t> input) {
    static constexpr char digits[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string output;
    output.reserve(((input.size() + 2) / 3) * 4);
    for (std::size_t index = 0; index < input.size(); index += 3) {
        const std::uint32_t chunk =
            static_cast<std::uint32_t>(input[index]) << 16 |
            (index + 1 < input.size() ? static_cast<std::uint32_t>(input[index + 1]) << 8 : 0) |
            (index + 2 < input.size() ? static_cast<std::uint32_t>(input[index + 2]) : 0);
        output.push_back(digits[(chunk >> 18) & 0x3f]);
        output.push_back(digits[(chunk >> 12) & 0x3f]);
        if (index + 1 < input.size()) {
            output.push_back(digits[(chunk >> 6) & 0x3f]);
        }
        if (index + 2 < input.size()) {
            output.push_back(digits[chunk & 0x3f]);
        }
    }
    return output;
}

struct EarlyDataSplit {
    std::string target;
    std::optional<io::ExchangeField> header;
    std::vector<std::uint8_t> remainder;
};

// Splits the initial payload into handshake-embedded early data and the
// post-handshake remainder, honouring `?ed=N` auto-configuration.
EarlyDataSplit split_early_data(const WebSocketClientOptions &options) {
    auto target = options.target;
    auto max_early_data = options.max_early_data;
    auto header_name = options.early_data_header_name;
    if (max_early_data == 0) {
        const auto query = target.find('?');
        if (query != std::string::npos) {
            auto query_string = target.substr(query + 1);
            std::size_t position = 0;
            while (position <= query_string.size()) {
                const auto next = query_string.find('&', position);
                const auto pair = query_string.substr(
                    position, next == std::string::npos ? next : next - position);
                const auto equals = pair.find('=');
                if (equals != std::string::npos && pair.substr(0, equals) == "ed") {
                    std::size_t parsed = 0;
                    const auto digits = std::from_chars(pair.data() + equals + 1,
                                                        pair.data() + pair.size(), parsed);
                    if (digits.ec == std::errc{} && digits.ptr == pair.data() + pair.size()) {
                        max_early_data = parsed;
                        header_name = "Sec-WebSocket-Protocol";
                    }
                    const auto stripped =
                        target.substr(0, query) +
                        (next == std::string::npos ? "" : "?" + query_string.substr(next + 1));
                    target = stripped.empty() ? "/" : stripped;
                    break;
                }
                if (next == std::string::npos) {
                    break;
                }
                position = next + 1;
            }
        }
    }
    EarlyDataSplit split{std::move(target), std::nullopt, {}};
    const auto early_size = std::min(options.initial_payload.size(), max_early_data);
    if (early_size > 0) {
        const auto encoded = base64url_encode(
            std::span<const std::uint8_t>(options.initial_payload.data(), early_size));
        if (!header_name.empty()) {
            split.header = io::ExchangeField{header_name, encoded};
        } else {
            split.target += encoded;
        }
    }
    split.remainder.assign(options.initial_payload.begin() + early_size,
                           options.initial_payload.end());
    return split;
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

    void async_read_some(boost::asio::mutable_buffer buffer, StreamReadHandler handler) {
        const auto self = shared_from_this();
        boost::asio::dispatch(executor_, [self, buffer, handler = std::move(handler)]() mutable {
            self->read(buffer, std::move(handler));
        });
    }

    void async_write(boost::asio::const_buffer buffer, StreamWriteHandler handler) {
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
    void read(boost::asio::mutable_buffer buffer, StreamReadHandler handler) {
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

    void write(std::shared_ptr<std::vector<std::uint8_t>> bytes, StreamWriteHandler handler) {
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

    void post_read(StreamReadHandler handler, const boost::system::error_code &error,
                   std::size_t size) {
        boost::asio::post(executor_, [handler = std::move(handler), error, size]() mutable {
            if (handler) {
                handler(error, size);
            }
        });
    }

    void post_write(StreamWriteHandler handler, const boost::system::error_code &error,
                    std::size_t size) {
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
    StreamReadHandler read_handler_;
    StreamWriteHandler write_handler_;
    std::size_t write_size_ = 0;
    boost::system::error_code read_error_;
    bool read_in_progress_ = false;
    bool message_available_ = false;
    bool read_closed_ = false;
    bool closed_ = false;
};

class WebSocketStream final : public io::StreamHandle {
  public:
    using ReadSignatures =
        stdexec::completion_signatures<stdexec::set_value_t(std::optional<std::size_t>),
                                       stdexec::set_error_t(std::exception_ptr),
                                       stdexec::set_stopped_t()>;
    using WriteSignatures = stdexec::completion_signatures<stdexec::set_value_t(std::size_t),
                                                           stdexec::set_error_t(std::exception_ptr),
                                                           stdexec::set_stopped_t()>;

    explicit WebSocketStream(std::shared_ptr<WebSocketStreamState> state)
        : state_(std::move(state)) {}

    io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override {
        auto state = state_;
        return io::AnySender<std::optional<std::size_t>>{async::callback_sender<ReadSignatures>(
            [state, buffer](auto terminal) mutable {
                state->async_read_some(
                    buffer, [terminal = std::move(terminal)](const boost::system::error_code &error,
                                                             std::size_t count) mutable {
                        terminal(error, count);
                    });
            },
            [](auto &&receiver, const boost::system::error_code &error, std::size_t count) {
                if (!error) {
                    stdexec::set_value(std::move(receiver), std::optional<std::size_t>(count));
                } else if (error == boost::asio::error::eof) {
                    stdexec::set_value(std::move(receiver), std::optional<std::size_t>());
                } else {
                    stdexec::set_error(
                        std::move(receiver),
                        std::make_exception_ptr(
                            core::Error{core::ErrorCode::transport_io, "websocket read",
                                        std::error_code(error.value(), std::system_category())}));
                }
            })};
    }

    io::AnySender<std::size_t> async_write(boost::asio::const_buffer buffer) override {
        auto state = state_;
        return io::AnySender<std::size_t>{async::callback_sender<WriteSignatures>(
            [state, buffer](auto terminal) mutable {
                state->async_write(
                    buffer, [terminal = std::move(terminal)](const boost::system::error_code &error,
                                                             std::size_t count) mutable {
                        terminal(error, count);
                    });
            },
            [](auto &&receiver, const boost::system::error_code &error, std::size_t count) {
                if (!error) {
                    stdexec::set_value(std::move(receiver), count);
                } else {
                    stdexec::set_error(
                        std::move(receiver),
                        std::make_exception_ptr(
                            core::Error{core::ErrorCode::transport_io, "websocket write",
                                        std::error_code(error.value(), std::system_category())}));
                }
            })};
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
    WebSocketClientHandshakeOperation(std::unique_ptr<io::StreamHandle> stream,
                                      WebSocketClientOptions options,
                                      WebSocketClientHandler handler)
        : executor_(stream->executor()), stream_(std::move(stream)), options_(std::move(options)),
          handler_(std::move(handler)), timer_(executor_) {}

    void start() {
        const auto self = shared_from_this();
        boost::asio::post(executor_, [self] { self->scope_.spawn(run_open(self)); });
    }

    // v2ray-http-upgrade: plain HTTP Upgrade tunnel without WebSocket
    // framing. Sends the GET (with early data), validates the 101 with
    // upgrade headers, writes the remainder raw, and delivers the inner
    // stream directly.
    static exec::task<void> run_raw_upgrade(std::shared_ptr<WebSocketClientHandshakeOperation> self,
                                            EarlyDataSplit early) {
        std::string request = "GET " + early.target + " HTTP/1.1\r\nHost: " + self->options_.host +
                              "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n";
        for (const auto &header : self->options_.headers) {
            request += header.name + ": " + header.value + "\r\n";
        }
        if (early.header) {
            request += early.header->name + ": " + early.header->value + "\r\n";
        }
        request += "\r\n";
        try {
            co_await self->stream_->async_write(boost::asio::buffer(request));
        } catch (const core::Error &failure) {
            self->finish(core::fail(failure));
            co_return;
        } catch (...) {
            self->finish(core::fail(handshake_error(boost::asio::error::fault)));
            co_return;
        }
        if (self->completed_) {
            co_return;
        }
        std::string head;
        head.reserve(1024);
        bool headed = false;
        for (int guard = 0; guard < 64 && !headed; ++guard) {
            std::array<std::uint8_t, 1024> chunk{};
            std::optional<std::size_t> got;
            try {
                got = co_await self->stream_->async_read_some(boost::asio::buffer(chunk));
            } catch (const core::Error &failure) {
                self->finish(core::fail(failure));
                co_return;
            } catch (...) {
                self->finish(core::fail(handshake_error(boost::asio::error::fault)));
                co_return;
            }
            if (self->completed_) {
                co_return;
            }
            if (!got) {
                self->finish(core::fail(handshake_error(boost::asio::error::eof)));
                co_return;
            }
            head.append(reinterpret_cast<const char *>(chunk.data()), *got);
            headed = head.find("\r\n\r\n") != std::string::npos;
        }
        if (!headed) {
            self->finish(core::fail(handshake_error(boost::asio::error::message_size)));
            co_return;
        }
        const auto status_line = head.substr(0, head.find("\r\n"));
        auto lower_head = lower_copy(head);
        const bool accepted = status_line.size() >= 12 && status_line.substr(9, 3) == "101" &&
                              lower_head.find("\nconnection:") != std::string::npos &&
                              lower_head.find("upgrade") != std::string::npos &&
                              lower_head.find("\nupgrade:") != std::string::npos &&
                              lower_head.find("websocket") != std::string::npos;
        if (!accepted) {
            self->finish(core::fail(handshake_error(boost::asio::error::fault)));
            co_return;
        }
        if (!early.remainder.empty()) {
            try {
                co_await self->stream_->async_write(boost::asio::buffer(early.remainder));
            } catch (const core::Error &failure) {
                self->finish(core::fail(failure));
                co_return;
            } catch (...) {
                self->finish(core::fail(handshake_error(boost::asio::error::fault)));
                co_return;
            }
            if (self->completed_) {
                co_return;
            }
        }
        self->finish(std::unique_ptr<io::StreamHandle>(std::move(self->stream_)));
    }

    static exec::task<void> run_open(std::shared_ptr<WebSocketClientHandshakeOperation> self) {
        if (const auto error = validate_options(self->options_)) {
            self->finish(core::fail(*error));
            co_return;
        }
        if (self->options_.deadline) {
            if (*self->options_.deadline <= std::chrono::steady_clock::now()) {
                self->finish(core::fail(timeout_error()));
                co_return;
            }
            self->timer_.expires_at(*self->options_.deadline);
            self->timer_.async_wait([self](const boost::system::error_code &error) {
                if (!error) {
                    self->finish(core::fail(timeout_error()));
                }
            });
        }
        if (self->options_.tls) {
            TlsClientOptions tls_options;
            tls_options.server_name = self->options_.tls_server_name.empty()
                                          ? self->options_.host
                                          : self->options_.tls_server_name;
            tls_options.verify_peer = self->options_.tls_verify_peer;
            tls_options.trusted_ca_pem = self->options_.tls_trusted_ca_pem;
            tls_options.verify_hostname = self->options_.tls_verify_hostname;
            tls_options.client_certificate_pem = self->options_.tls_client_certificate_pem;
            tls_options.client_private_key_pem = self->options_.tls_client_private_key_pem;
            tls_options.alpn_protocols = self->options_.tls_alpn_protocols;
            if (tls_options.alpn_protocols.empty()) {
                tls_options.alpn_protocols = {"http/1.1"};
            }
            tls_options.deadline = self->options_.deadline;
            try {
                // No explicit cancel: completed_ drops late terminals and
                // the operation deadline bounds orphans.
                auto connection = co_await async_tls_client_handshake(std::move(self->stream_),
                                                                      std::move(tls_options));
                if (self->completed_) {
                    if (connection.stream) {
                        connection.stream->close();
                    }
                    co_return;
                }
                self->stream_ = std::move(connection.stream);
            } catch (const core::Error &failure) {
                self->finish(core::fail(failure));
                co_return;
            } catch (...) {
                self->finish(core::fail(
                    core::Error{core::ErrorCode::endpoint_connection, "WebSocket TLS failed"}));
                co_return;
            }
        }
        if (self->completed_ || !self->stream_) {
            co_return;
        }
        const auto early = split_early_data(self->options_);
        if (self->options_.v2ray_http_upgrade) {
            co_await run_raw_upgrade(self, early);
            co_return;
        }
        self->websocket_ =
            std::make_shared<BeastWebSocket>(WebSocketStreamAdapter(std::move(self->stream_)));
        self->websocket_->set_option(
            websocket::stream_base::timeout::suggested(boost::beast::role_type::client));
        self->websocket_->read_message_max(self->options_.max_message_size);
        self->websocket_->auto_fragment(true);
        auto headers = self->options_.headers;
        if (early.header) {
            headers.push_back(*early.header);
        }
        const auto target = early.target;
        self->websocket_->set_option(
            websocket::stream_base::decorator([headers](websocket::request_type &request) {
                for (const auto &header : headers) {
                    request.set(header.name, header.value);
                }
            }));
        using HandshakeSigs =
            stdexec::completion_signatures<stdexec::set_value_t(bool),
                                           stdexec::set_error_t(std::exception_ptr),
                                           stdexec::set_stopped_t()>;
        try {
            co_await async::callback_sender<HandshakeSigs>(
                [self, target](auto terminal) mutable {
                    self->websocket_->async_handshake(self->options_.host, target,
                                                      std::move(terminal));
                },
                [](auto receiver, const boost::system::error_code &error) {
                    if (error) {
                        stdexec::set_error(std::move(receiver),
                                           std::make_exception_ptr(handshake_error(error)));
                        return;
                    }
                    stdexec::set_value(std::move(receiver), true);
                });
        } catch (const core::Error &failure) {
            self->finish(core::fail(failure));
            co_return;
        } catch (...) {
            self->finish(core::fail(handshake_error(boost::asio::error::fault)));
            co_return;
        }
        if (self->completed_) {
            co_return;
        }
        // Flush the post-handshake remainder as the first message(s)
        // before delivering the stream.
        if (!early.remainder.empty()) {
            auto state = std::make_shared<WebSocketStreamState>(self->websocket_,
                                                                self->options_.max_message_size);
            self->websocket_.reset();
            using WriteSigs =
                stdexec::completion_signatures<stdexec::set_value_t(),
                                               stdexec::set_error_t(std::exception_ptr),
                                               stdexec::set_stopped_t()>;
            try {
                co_await async::callback_sender<WriteSigs>(
                    [state, remainder = early.remainder](auto terminal) mutable {
                        state->async_write(boost::asio::buffer(remainder),
                                           [terminal = std::move(terminal)](
                                               const boost::system::error_code &error,
                                               std::size_t) mutable { terminal(error); });
                    },
                    [](auto receiver, const boost::system::error_code &error) {
                        if (error) {
                            stdexec::set_error(std::move(receiver),
                                               std::make_exception_ptr(handshake_error(error)));
                            return;
                        }
                        stdexec::set_value(std::move(receiver));
                    });
            } catch (const core::Error &failure) {
                self->finish(core::fail(failure));
                co_return;
            } catch (...) {
                self->finish(core::fail(handshake_error(boost::asio::error::fault)));
                co_return;
            }
            if (self->completed_) {
                co_return;
            }
            auto stream = std::make_unique<WebSocketStream>(std::move(state));
            self->finish(std::unique_ptr<io::StreamHandle>(std::move(stream)));
            co_return;
        }
        boost::asio::post(self->executor_, [self] { self->complete_success(); });
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
        finish(std::unique_ptr<io::StreamHandle>(std::move(stream)));
    }

    void finish(core::Result<std::unique_ptr<io::StreamHandle>> result) {
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
    std::unique_ptr<io::StreamHandle> stream_;
    WebSocketClientOptions options_;
    WebSocketClientHandler handler_;
    std::shared_ptr<BeastWebSocket> websocket_;
    boost::asio::steady_timer timer_;
    bool completed_ = false;
    exec::async_scope scope_;
};

} // namespace

std::shared_ptr<WebSocketClientHandshake>
async_websocket_client_handshake(std::unique_ptr<io::StreamHandle> stream,
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
