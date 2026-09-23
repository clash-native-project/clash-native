#include <clash_native/async/callback_sender.hpp>
#include <clash_native/async/oneshot.hpp>
#include <clash_native/async/watch.hpp>
#include <clash_native/core/result.hpp>
#include <clash_native/io/exchange_body_stream.hpp>
#include <clash_native/io/exchange_session.hpp>
#include <clash_native/io/sender.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/async_result.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http.hpp>
#include <boost/system/error_code.hpp>

#include <exec/async_scope.hpp>
#include <exec/task.hpp>
#include <stdexec/execution.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <deque>
#include <exception>
#include <limits>
#include <memory>
#include <optional>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <variant>

namespace clash_native::transport {

namespace {

namespace http = boost::beast::http;
using HttpMessage = http::request<http::vector_body<std::uint8_t>>;
using HttpTunnelMessage = http::request<http::empty_body>;
using HttpStreamingMessage = http::request<http::empty_body>;
using ExchangeResponseParser = http::response_parser<http::vector_body<std::uint8_t>>;
using StreamingExchangeResponseParser = http::response_parser<http::buffer_body>;

// Beast-shaped completions kept in band so a spawned task always ends
// with a value (a spawned sender completing with error would terminate).
struct HttpOpResult {
    boost::system::error_code error;
    std::size_t size = 0;
};
using HttpOpSigs = stdexec::completion_signatures<stdexec::set_value_t(HttpOpResult),
                                                  stdexec::set_error_t(std::exception_ptr),
                                                  stdexec::set_stopped_t()>;

// Beast's composed HTTP operations copy their stream and accept buffer
// sequences, while StreamHandle exposes a unique owner and single buffers.
class Http1StreamAdapter {
  public:
    using executor_type = boost::asio::any_io_executor;

    explicit Http1StreamAdapter(std::unique_ptr<io::StreamHandle> handle)
        : handle_(std::shared_ptr<io::StreamHandle>(std::move(handle))) {}

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
                        std::move(handler)(net::unpack_error(std::move(error)), std::size_t{0});
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
                struct Receiver {
                    Handler handler;
                    std::shared_ptr<std::vector<std::uint8_t>> lifetime;
                    void set_value(std::size_t count) noexcept {
                        std::move(handler)(boost::system::error_code{}, count);
                    }
                    void set_error(std::exception_ptr error) noexcept {
                        std::move(handler)(net::unpack_error(std::move(error)), std::size_t{0});
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

    void close() noexcept {
        if (handle_) {
            handle_->close();
        }
    }

    std::shared_ptr<io::StreamHandle> take_handle() noexcept { return std::exchange(handle_, {}); }

  private:
    std::shared_ptr<io::StreamHandle> handle_;
};

class Http1TunnelState final : public std::enable_shared_from_this<Http1TunnelState> {
  public:
    Http1TunnelState(std::shared_ptr<io::StreamHandle> stream, std::vector<std::uint8_t> buffered)
        : stream_(std::move(stream)), buffered_(std::move(buffered)) {}

    io::AnySender<std::optional<std::size_t>> async_read_some(boost::asio::mutable_buffer buffer) {
        if (buffer.size() == 0) {
            return io::AnySender<std::optional<std::size_t>>{
                stdexec::just(std::optional<std::size_t>{0})};
        }
        if (closed_) {
            return io::AnySender<std::optional<std::size_t>>{
                stdexec::just_error(std::make_exception_ptr(
                    core::Error{core::ErrorCode::cancelled, "HTTP/1.1 tunnel is closed"}))};
        }
        if (read_in_progress_) {
            return io::AnySender<std::optional<std::size_t>>{
                stdexec::just_error(std::make_exception_ptr(core::Error{
                    core::ErrorCode::transport_io, "HTTP/1.1 tunnel read already started"}))};
        }
        if (buffered_offset_ < buffered_.size()) {
            const auto size = boost::asio::buffer_copy(
                buffer, boost::asio::buffer(buffered_.data() + buffered_offset_,
                                            buffered_.size() - buffered_offset_));
            buffered_offset_ += size;
            return io::AnySender<std::optional<std::size_t>>{
                stdexec::just(std::optional<std::size_t>{size})};
        }
        read_in_progress_ = true;
        auto self = shared_from_this();
        auto reset = [self] { self->read_in_progress_ = false; };
        return io::AnySender<std::optional<std::size_t>>{
            stream_->async_read_some(buffer) |
            stdexec::then([reset](std::optional<std::size_t> size) {
                reset();
                return size;
            }) |
            stdexec::let_error([reset](std::exception_ptr error) {
                reset();
                return stdexec::just_error(std::move(error));
            })};
    }

    io::AnySender<std::size_t> async_write(boost::asio::const_buffer buffer) {
        if (closed_ || local_closed_) {
            return io::AnySender<std::size_t>{stdexec::just_error(std::make_exception_ptr(
                core::Error{core::ErrorCode::cancelled, "HTTP/1.1 tunnel is closed"}))};
        }
        if (write_in_progress_) {
            return io::AnySender<std::size_t>{
                stdexec::just_error(std::make_exception_ptr(core::Error{
                    core::ErrorCode::transport_io, "HTTP/1.1 tunnel write already started"}))};
        }
        if (buffer.size() == 0) {
            return io::AnySender<std::size_t>{stdexec::just(std::size_t{0})};
        }
        auto bytes = std::make_shared<std::vector<std::uint8_t>>(buffer.size());
        boost::asio::buffer_copy(boost::asio::buffer(*bytes), buffer);
        write_in_progress_ = true;
        auto self = shared_from_this();
        auto finish = [self, bytes](std::size_t size) {
            (void)bytes;
            self->write_in_progress_ = false;
            if (self->shutdown_requested_ && !self->closed_) {
                self->shutdown_requested_ = false;
                self->local_closed_ = true;
                boost::system::error_code ignored;
                self->stream_->shutdown_send(ignored);
            }
            return size;
        };
        return io::AnySender<std::size_t>{
            stream_->async_write(boost::asio::buffer(*bytes)) |
            stdexec::then([finish](std::size_t size) { return finish(size); }) |
            stdexec::let_error([self](std::exception_ptr error) {
                self->write_in_progress_ = false;
                return stdexec::just_error(std::move(error));
            })};
    }

    boost::asio::any_io_executor executor() noexcept { return stream_->executor(); }

    boost::asio::ip::tcp::endpoint local_endpoint(boost::system::error_code &error) const noexcept {
        return stream_->local_endpoint(error);
    }

    void shutdown_send(boost::system::error_code &error) noexcept {
        error.clear();
        if (closed_ || local_closed_) {
            return;
        }
        if (write_in_progress_) {
            shutdown_requested_ = true;
            return;
        }
        local_closed_ = true;
        stream_->shutdown_send(error);
    }

    void close() noexcept {
        if (closed_) {
            return;
        }
        closed_ = true;
        local_closed_ = true;
        buffered_.clear();
        buffered_offset_ = 0;
        stream_->close();
    }

  private:
    void post_read(core::StreamHandle::ReadHandler handler, boost::system::error_code error,
                   std::size_t size) {
        boost::asio::post(stream_->executor(),
                          [handler = std::move(handler), error, size]() mutable {
                              if (handler) {
                                  handler(error, size);
                              }
                          });
    }

    void post_write(core::StreamHandle::WriteHandler handler, boost::system::error_code error,
                    std::size_t size) {
        boost::asio::post(stream_->executor(),
                          [handler = std::move(handler), error, size]() mutable {
                              if (handler) {
                                  handler(error, size);
                              }
                          });
    }

    std::shared_ptr<io::StreamHandle> stream_;
    std::vector<std::uint8_t> buffered_;
    std::size_t buffered_offset_ = 0;
    bool read_in_progress_ = false;
    bool write_in_progress_ = false;
    bool shutdown_requested_ = false;
    bool local_closed_ = false;
    bool closed_ = false;
};

class Http1TunnelStream final : public io::StreamHandle {
  public:
    explicit Http1TunnelStream(std::shared_ptr<Http1TunnelState> state)
        : state_(std::move(state)) {}

    io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override {
        return state_->async_read_some(buffer);
    }

    io::AnySender<std::size_t> async_write(boost::asio::const_buffer buffer) override {
        return state_->async_write(buffer);
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
    std::shared_ptr<Http1TunnelState> state_;
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

bool is_header_name(std::string_view name, std::string_view expected) {
    return name.size() == expected.size() &&
           std::equal(name.begin(), name.end(), expected.begin(),
                      [](unsigned char actual, unsigned char wanted) {
                          return static_cast<unsigned char>(std::tolower(actual)) == wanted;
                      });
}

bool is_host_header(std::string_view name) { return is_header_name(name, "host"); }

bool is_forbidden_trailer_name(std::string_view name) {
    return is_header_name(name, "content-length") || is_header_name(name, "transfer-encoding") ||
           is_header_name(name, "host") || is_header_name(name, "trailer") ||
           is_header_name(name, "connection") || is_header_name(name, "proxy-authorization");
}

bool valid_trailer_declaration(std::string_view value) {
    while (true) {
        const auto separator = value.find(',');
        auto name = value.substr(0, separator);
        const auto first = name.find_first_not_of(" \t");
        const auto last = name.find_last_not_of(" \t");
        if (first == std::string_view::npos) {
            return false;
        }
        name = name.substr(first, last - first + 1);
        if (!is_token(name) || is_forbidden_trailer_name(name)) {
            return false;
        }
        if (separator == std::string_view::npos) {
            return true;
        }
        value.remove_prefix(separator + 1);
    }
}

core::Result<HttpMessage> make_message(const io::ExchangeRequest &request) {
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

core::Result<HttpStreamingMessage>
make_streaming_message(const io::StreamingExchangeRequest &request) {
    if (!is_token(request.request.method) || request.request.target.empty() ||
        has_uri_whitespace(request.request.target) ||
        has_uri_whitespace(request.request.authority)) {
        return core::fail(core::Error{core::ErrorCode::configuration,
                                      "HTTP/1.1 method, target, or authority is invalid"});
    }
    if (request.body && !request.request.body.empty()) {
        return core::fail(core::Error{core::ErrorCode::configuration,
                                      "HTTP/1.1 streaming request cannot have a buffered body"});
    }
    if (!request.body && request.content_length &&
        *request.content_length != request.request.body.size()) {
        return core::fail(core::Error{core::ErrorCode::configuration,
                                      "HTTP/1.1 buffered request body does not match its "
                                      "content length"});
    }

    HttpStreamingMessage message;
    message.method_string(request.request.method);
    message.target(request.request.target);
    message.version(11);
    bool has_host = false;
    bool has_trailer_declaration = false;
    for (const auto &header : request.request.headers) {
        if (!is_token(header.name) || has_http_control(header.value)) {
            return core::fail(core::Error{core::ErrorCode::configuration,
                                          "HTTP/1.1 header contains invalid characters"});
        }
        if (is_header_name(header.name, "content-length") ||
            is_header_name(header.name, "transfer-encoding")) {
            return core::fail(core::Error{core::ErrorCode::configuration,
                                          "HTTP/1.1 streaming framing headers are managed by the "
                                          "transport"});
        }
        if (is_header_name(header.name, "trailer")) {
            if (!valid_trailer_declaration(header.value)) {
                return core::fail(core::Error{core::ErrorCode::configuration,
                                              "HTTP/1.1 Trailer declaration is invalid"});
            }
            has_trailer_declaration = true;
        }
        has_host = has_host || is_host_header(header.name);
        message.insert(header.name, header.value);
    }
    if (has_trailer_declaration && (!request.body || request.content_length.has_value())) {
        return core::fail(core::Error{core::ErrorCode::configuration,
                                      "HTTP/1.1 trailers require an unknown-length body stream"});
    }
    if (!request.request.authority.empty() && !has_host) {
        message.set(http::field::host, request.request.authority);
    }
    message.keep_alive(request.request.keep_alive);
    if (request.body && request.content_length) {
        message.content_length(*request.content_length);
    } else if (request.body) {
        message.chunked(true);
    } else {
        message.content_length(request.request.body.size());
    }
    return message;
}

core::Result<HttpTunnelMessage> make_tunnel_message(const io::StreamUpgradeRequest &request) {
    if (request.authority.empty() || has_uri_whitespace(request.authority)) {
        return core::fail(
            core::Error{core::ErrorCode::configuration, "HTTP/1.1 tunnel authority is invalid"});
    }
    if (request.mode == io::StreamUpgradeMode::upgrade &&
        (request.target.empty() || has_uri_whitespace(request.target) ||
         !is_token(request.protocol))) {
        return core::fail(core::Error{core::ErrorCode::configuration,
                                      "HTTP/1.1 Upgrade target or protocol is invalid"});
    }

    HttpTunnelMessage message;
    message.method(request.mode == io::StreamUpgradeMode::connect ? http::verb::connect
                                                                  : http::verb::get);
    message.target(request.mode == io::StreamUpgradeMode::connect ? request.authority
                                                                  : request.target);
    message.version(11);

    bool has_host = false;
    for (const auto &header : request.headers) {
        if (!is_token(header.name) || has_http_control(header.value)) {
            return core::fail(core::Error{core::ErrorCode::configuration,
                                          "HTTP/1.1 tunnel header contains invalid characters"});
        }
        const auto name = std::string_view(header.name);
        const bool connection_header =
            name.size() == 10 &&
            std::equal(name.begin(), name.end(), "connection",
                       [](unsigned char actual, unsigned char wanted) {
                           return static_cast<unsigned char>(std::tolower(actual)) == wanted;
                       });
        const bool upgrade_header =
            name.size() == 7 &&
            std::equal(name.begin(), name.end(), "upgrade",
                       [](unsigned char actual, unsigned char wanted) {
                           return static_cast<unsigned char>(std::tolower(actual)) == wanted;
                       });
        if (connection_header || upgrade_header || is_header_name(name, "content-length") ||
            is_header_name(name, "transfer-encoding")) {
            return core::fail(core::Error{core::ErrorCode::configuration,
                                          "HTTP/1.1 tunnel framing, Connection, and Upgrade "
                                          "headers are managed by the transport"});
        }
        has_host = has_host || is_host_header(header.name);
        message.insert(header.name, header.value);
    }
    if (!has_host) {
        message.set(http::field::host, request.authority);
    }
    if (request.mode == io::StreamUpgradeMode::upgrade) {
        message.set(http::field::connection, "Upgrade");
        message.set(http::field::upgrade, request.protocol);
    }
    return message;
}

const std::string *find_header(const io::ExchangeResponse &response, std::string_view name) {
    for (const auto &header : response.headers) {
        if (header.name.size() == name.size() &&
            std::equal(header.name.begin(), header.name.end(), name.begin(),
                       [](unsigned char actual, unsigned char wanted) {
                           return static_cast<unsigned char>(std::tolower(actual)) == wanted;
                       })) {
            return &header.value;
        }
    }
    return nullptr;
}

bool contains_header_token(std::string_view value, std::string_view token) {
    while (!value.empty()) {
        const auto separator = value.find(',');
        auto item = value.substr(0, separator);
        const auto first = item.find_first_not_of(" \t");
        const auto last = item.find_last_not_of(" \t");
        if (first != std::string_view::npos) {
            item = item.substr(first, last - first + 1);
            if (item.size() == token.size() &&
                std::equal(item.begin(), item.end(), token.begin(),
                           [](unsigned char actual, unsigned char wanted) {
                               return static_cast<unsigned char>(std::tolower(actual)) == wanted;
                           })) {
                return true;
            }
        }
        if (separator == std::string_view::npos) {
            break;
        }
        value.remove_prefix(separator + 1);
    }
    return false;
}

bool tunnel_accepted(const io::StreamUpgradeRequest &request,
                     const io::ExchangeResponse &response) {
    if (request.mode == io::StreamUpgradeMode::connect) {
        return response.status >= 200 && response.status < 300;
    }
    const auto *upgrade = find_header(response, "upgrade");
    const auto *connection = find_header(response, "connection");
    return response.status == 101 && upgrade != nullptr && connection != nullptr &&
           contains_header_token(*upgrade, request.protocol) &&
           contains_header_token(*connection, "upgrade");
}

io::ExchangeResponse make_response(http::response<http::vector_body<std::uint8_t>> message) {
    io::ExchangeResponse response;
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

// Terminals captured into a oneshot per exchange: success carries the io::
// response, failure carries the core::Error in band. The entry wrapper
// rethrows failures so the session honors the io:: sender contract.
using BufferedTerminal = core::Result<io::ExchangeResponse>;
using StreamingTerminal = core::Result<io::StreamingExchangeResponse>;
using TunnelTerminal = core::Result<io::StreamUpgradeResponse>;

class Http1ClientSession final : public io::ExchangeSession,
                                 public std::enable_shared_from_this<Http1ClientSession> {
  public:
    explicit Http1ClientSession(std::unique_ptr<io::StreamHandle> stream)
        : executor_(stream->executor()),
          stream_(std::make_unique<Http1StreamAdapter>(std::move(stream))) {}

    io::AnySender<io::ExchangeResponse>
    exchange(io::ExchangeRequest request, std::chrono::steady_clock::time_point deadline) override {
        auto channel = async::oneshot::channel<BufferedTerminal>();
        const auto exchange_id = next_exchange_id();
        if (stopped_ || retired_) {
            channel.sender.send(core::fail(core::Error{
                core::ErrorCode::cancelled, "HTTP/1.1 session is not accepting requests"}));
            return wrap_result(exchange_id, std::move(channel.receiver));
        }
        const auto message = make_message(request);
        if (!message) {
            channel.sender.send(core::fail(message.error()));
            return wrap_result(exchange_id, std::move(channel.receiver));
        }
        if (deadline <= std::chrono::steady_clock::now()) {
            channel.sender.send(core::fail(timeout_error()));
            return wrap_result(exchange_id, std::move(channel.receiver));
        }

        auto pending = std::make_shared<Pending>(executor_);
        pending->request = std::move(request);
        pending->message = std::move(message.value());
        pending->handler = std::move(channel.sender);
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
        return wrap_result(exchange_id, std::move(channel.receiver));
    }

    io::AnySender<io::StreamingExchangeResponse>
    exchange_streaming(io::StreamingExchangeRequest request,
                       std::chrono::steady_clock::time_point deadline) override {
        auto channel = async::oneshot::channel<StreamingTerminal>();
        const auto exchange_id = next_exchange_id();
        if (stopped_ || retired_) {
            channel.sender.send(core::fail(core::Error{
                core::ErrorCode::cancelled, "HTTP/1.1 session is not accepting requests"}));
            return wrap_streaming(exchange_id, std::move(channel.receiver));
        }
        const auto message = make_streaming_message(request);
        if (!message) {
            channel.sender.send(core::fail(message.error()));
            return wrap_streaming(exchange_id, std::move(channel.receiver));
        }
        if (deadline <= std::chrono::steady_clock::now()) {
            channel.sender.send(core::fail(timeout_error()));
            return wrap_streaming(exchange_id, std::move(channel.receiver));
        }

        auto pending = std::make_shared<Pending>(executor_);
        pending->is_streaming = true;
        pending->streaming_request = std::move(request);
        pending->streaming_message = std::move(message.value());
        pending->streaming_handler = std::move(channel.sender);
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
        return wrap_streaming(exchange_id, std::move(channel.receiver));
    }

    io::AnySender<io::StreamUpgradeResponse>
    open_tunnel(io::StreamUpgradeRequest request,
                std::chrono::steady_clock::time_point deadline) override {
        auto channel = async::oneshot::channel<TunnelTerminal>();
        const auto exchange_id = next_exchange_id();
        if (stopped_ || retired_) {
            channel.sender.send(core::fail(core::Error{
                core::ErrorCode::cancelled, "HTTP/1.1 session is not accepting requests"}));
            return wrap_tunnel(exchange_id, std::move(channel.receiver));
        }
        const auto message = make_tunnel_message(request);
        if (!message) {
            channel.sender.send(core::fail(message.error()));
            return wrap_tunnel(exchange_id, std::move(channel.receiver));
        }
        if (deadline <= std::chrono::steady_clock::now()) {
            channel.sender.send(core::fail(timeout_error()));
            return wrap_tunnel(exchange_id, std::move(channel.receiver));
        }

        auto pending = std::make_shared<Pending>(executor_);
        pending->is_tunnel = true;
        pending->tunnel_request = std::move(request);
        pending->message = std::move(message.value());
        pending->tunnel_handler = std::move(channel.sender);
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
        return wrap_tunnel(exchange_id, std::move(channel.receiver));
    }

    void cancel(ExchangeId exchange_id) noexcept override {
        const auto found = pending_.find(exchange_id);
        if (found == pending_.end()) {
            return;
        }
        if (active_id_ == exchange_id) {
            retire_all(exchange_id, cancelled_error(),
                       core::Error{core::ErrorCode::cancelled, "HTTP/1.1 connection was retired"});
            return;
        }
        complete_error(exchange_id, cancelled_error());
        start_next();
    }

    void stop() noexcept override {
        if (stopped_) {
            return;
        }
        stopped_ = true;
        retired_ = true;
        // No stop token is distributed: closing aborts the in-flight Beast
        // op, and the parked task lands in the idempotent retire paths.
        close_stream();
        complete_all(core::fail(cancelled_error()));
    }

    bool retired() const noexcept override { return retired_; }

  private:
    struct Pending {
        explicit Pending(boost::asio::any_io_executor executor) : timer(std::move(executor)) {}

        bool is_tunnel = false;
        bool is_streaming = false;
        bool streaming_headers_delivered = false;
        bool streaming_response_done = false;
        bool streaming_request_chunked = false;
        // Level signal for download backpressure: the response task parks
        // on it when the receive queue is full; consumed() and every
        // terminal path bump it, so a parked task always wakes and
        // rechecks (capacity first, then session guards).
        std::uint64_t streaming_request_written = 0;
        std::size_t streaming_response_queued = 0;
        std::size_t streaming_header_field_count = 0;
        io::ExchangeRequest request;
        io::StreamingExchangeRequest streaming_request;
        io::StreamUpgradeRequest tunnel_request;
        std::variant<HttpMessage, HttpTunnelMessage> message;
        HttpStreamingMessage streaming_message;
        std::unique_ptr<http::request_serializer<http::empty_body>> streaming_serializer;
        std::unique_ptr<ExchangeResponseParser> parser;
        std::unique_ptr<StreamingExchangeResponseParser> streaming_parser;
        std::shared_ptr<io::detail::QueuedExchangeBodyStream> streaming_response_body;
        std::array<std::uint8_t, 16 * 1024> streaming_request_buffer{};
        std::array<std::uint8_t, 1> streaming_request_probe{};
        std::array<std::uint8_t, 16 * 1024> streaming_response_buffer{};
        async::watch::Channel<bool> space = async::watch::channel<bool>(false);
        // Terminal fulfillers: each pending completes exactly once, so the
        // move-only senders ride the shared pending and move out at
        // completion.
        async::oneshot::Sender<BufferedTerminal> handler;
        async::oneshot::Sender<StreamingTerminal> streaming_handler;
        async::oneshot::Sender<TunnelTerminal> tunnel_handler;
        boost::asio::steady_timer timer;
    };

    ExchangeId next_exchange_id() noexcept {
        auto result = next_exchange_id_++;
        if (result == 0) {
            result = next_exchange_id_++;
        }
        return result;
    }

    void post_result(async::oneshot::Sender<BufferedTerminal> sender, BufferedTerminal result) {
        boost::asio::post(executor_,
                          [sender = std::move(sender), result = std::move(result)]() mutable {
                              sender.send(std::move(result));
                          });
    }

    void post_tunnel_result(async::oneshot::Sender<TunnelTerminal> sender, TunnelTerminal result) {
        boost::asio::post(executor_,
                          [sender = std::move(sender), result = std::move(result)]() mutable {
                              sender.send(std::move(result));
                          });
    }

    void post_streaming_result(async::oneshot::Sender<StreamingTerminal> sender,
                               StreamingTerminal result) {
        boost::asio::post(executor_,
                          [sender = std::move(sender), result = std::move(result)]() mutable {
                              sender.send(std::move(result));
                          });
    }

    template <typename Terminal>
    io::AnySender<typename Terminal::value_type> wrap(io::ExchangeSession::ExchangeId exchange_id,
                                                      async::oneshot::Receiver<Terminal> receiver) {
        auto sender =
            std::move(receiver) |
            stdexec::then([](std::optional<Terminal> terminal) -> typename Terminal::value_type {
                if (!terminal) {
                    throw core::Error{core::ErrorCode::cancelled,
                                      "HTTP/1.1 exchange was abandoned"};
                }
                if (!*terminal) {
                    throw terminal->error();
                }
                return std::move(terminal->value());
            }) |
            stdexec::let_stopped([self = shared_from_this(), exchange_id] {
                self->cancel(exchange_id);
                return stdexec::just_stopped();
            });
        return io::AnySender<typename Terminal::value_type>{std::move(sender)};
    }

    io::AnySender<io::ExchangeResponse>
    wrap_result(io::ExchangeSession::ExchangeId exchange_id,
                async::oneshot::Receiver<BufferedTerminal> receiver) {
        return wrap<BufferedTerminal>(exchange_id, std::move(receiver));
    }

    io::AnySender<io::StreamingExchangeResponse>
    wrap_streaming(io::ExchangeSession::ExchangeId exchange_id,
                   async::oneshot::Receiver<StreamingTerminal> receiver) {
        return wrap<StreamingTerminal>(exchange_id, std::move(receiver));
    }

    io::AnySender<io::StreamUpgradeResponse>
    wrap_tunnel(io::ExchangeSession::ExchangeId exchange_id,
                async::oneshot::Receiver<TunnelTerminal> receiver) {
        return wrap<TunnelTerminal>(exchange_id, std::move(receiver));
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
            if (pending->is_streaming) {
                scope_.spawn(run_streaming(shared_from_this(), exchange_id, pending));
                return;
            }
            if (pending->is_tunnel) {
                scope_.spawn(run_tunnel(shared_from_this(), exchange_id, pending));
                return;
            }
            pending->parser = std::make_unique<ExchangeResponseParser>();
            pending->parser->body_limit(pending->request.response_body_limit);
            scope_.spawn(run_buffered(shared_from_this(), exchange_id, pending));
            return;
        }
    }

    // Streaming exchange as a straight-line coroutine: request header,
    // upload loop, response header, backpressured download loop. Upload
    // failures cancel the body source and retire; download failures reuse
    // fail_streaming_response; header failures reuse fail_active. The
    // download parks on the pending space signal when the receive queue
    // is full instead of direct repump calls.
    exec::task<void> run_streaming(std::shared_ptr<Http1ClientSession> self, ExchangeId exchange_id,
                                   std::shared_ptr<Pending> pending) {
        auto fail_upload = [&](core::Error error) {
            if (self->active_id_ != exchange_id) {
                return;
            }
            if (pending->streaming_request.body) {
                pending->streaming_request.body->cancel();
            }
            self->retire_all(exchange_id, std::move(error),
                             core::Error{core::ErrorCode::transport_io,
                                         "HTTP/1.1 connection was retired after a streaming "
                                         "request error"});
        };
        auto inactive = [&] {
            return self->stopped_ || self->retired_ || self->active_id_ != exchange_id;
        };
        try {
            pending->streaming_request_chunked =
                pending->streaming_request.body != nullptr &&
                !pending->streaming_request.content_length.has_value();
            pending->streaming_serializer =
                std::make_unique<http::request_serializer<http::empty_body>>(
                    pending->streaming_message);
            const auto header_written = co_await async::callback_sender<HttpOpSigs>(
                [&](auto terminal) {
                    http::async_write_header(*self->stream_, *pending->streaming_serializer,
                                             std::move(terminal));
                },
                [](auto &&receiver, const boost::system::error_code &error, std::size_t size) {
                    stdexec::set_value(std::move(receiver), HttpOpResult{error, size});
                });
            if (header_written.error) {
                fail_upload(io_error("failed to write HTTP/1.1 streaming request header",
                                     header_written.error));
                co_return;
            }
            if (inactive()) {
                co_return;
            }
            pending->streaming_serializer.reset();
            if (pending->streaming_request.body) {
                bool need_probe = false;
                while (true) {
                    if (inactive()) {
                        co_return;
                    }
                    if (pending->streaming_request.content_length &&
                        pending->streaming_request_written ==
                            *pending->streaming_request.content_length) {
                        need_probe = true;
                        break;
                    }
                    auto window = boost::asio::buffer(pending->streaming_request_buffer);
                    if (pending->streaming_request.content_length) {
                        const auto remaining = *pending->streaming_request.content_length -
                                               pending->streaming_request_written;
                        window = boost::asio::buffer(
                            pending->streaming_request_buffer.data(),
                            std::min<std::size_t>(pending->streaming_request_buffer.size(),
                                                  static_cast<std::size_t>(remaining)));
                    }
                    std::size_t size = 0;
                    bool saw_eof = false;
                    try {
                        const auto pulled =
                            co_await pending->streaming_request.body->async_read_some(window);
                        if (!pulled) {
                            saw_eof = true;
                        } else {
                            size = *pulled;
                        }
                    } catch (const core::Error &failure) {
                        fail_upload(failure);
                        co_return;
                    }
                    if (size == 0) {
                        if (saw_eof) {
                            if (pending->streaming_request.content_length &&
                                pending->streaming_request_written !=
                                    *pending->streaming_request.content_length) {
                                fail_upload(protocol_error("HTTP/1.1 request body ended before its "
                                                           "content length"));
                                co_return;
                            }
                            break;
                        }
                        fail_upload(
                            protocol_error("HTTP/1.1 request body source made no progress"));
                        co_return;
                    }
                    if (pending->streaming_request.content_length &&
                        size > *pending->streaming_request.content_length -
                                   pending->streaming_request_written) {
                        fail_upload(
                            protocol_error("HTTP/1.1 request body exceeded its content length"));
                        co_return;
                    }
                    pending->streaming_request_written += size;
                    auto wire = std::make_shared<std::vector<std::uint8_t>>();
                    const auto *data = pending->streaming_request_buffer.data();
                    if (pending->streaming_request_chunked) {
                        std::array<char, 2 * sizeof(std::size_t)> hex{};
                        const auto converted =
                            std::to_chars(hex.data(), hex.data() + hex.size(), size, 16);
                        if (converted.ec != std::errc{}) {
                            fail_upload(protocol_error("failed to encode HTTP chunk size"));
                            co_return;
                        }
                        wire->insert(wire->end(), hex.data(), converted.ptr);
                        wire->insert(wire->end(), {'\r', '\n'});
                    }
                    wire->insert(wire->end(), data, data + size);
                    if (pending->streaming_request_chunked) {
                        wire->insert(wire->end(), {'\r', '\n'});
                    }
                    const auto body_written = co_await async::callback_sender<HttpOpSigs>(
                        [self, wire](auto terminal) {
                            boost::asio::async_write(*self->stream_, boost::asio::buffer(*wire),
                                                     std::move(terminal));
                        },
                        [](auto &&receiver, const boost::system::error_code &write_error,
                           std::size_t written) {
                            stdexec::set_value(std::move(receiver),
                                               HttpOpResult{write_error, written});
                        });
                    if (body_written.error) {
                        fail_upload(
                            io_error("failed to write HTTP/1.1 request body", body_written.error));
                        co_return;
                    }
                    if (saw_eof) {
                        if (pending->streaming_request.content_length &&
                            pending->streaming_request_written !=
                                *pending->streaming_request.content_length) {
                            fail_upload(protocol_error("HTTP/1.1 request body ended before its "
                                                       "content length"));
                            co_return;
                        }
                        break;
                    }
                }
                if (need_probe) {
                    std::optional<std::size_t> probed;
                    try {
                        probed = co_await pending->streaming_request.body->async_read_some(
                            boost::asio::buffer(pending->streaming_request_probe));
                    } catch (const core::Error &failure) {
                        fail_upload(failure);
                        co_return;
                    }
                    if (probed.has_value()) {
                        fail_upload(
                            protocol_error("HTTP/1.1 request body exceeded its content length"));
                        co_return;
                    }
                    if (!pending->streaming_request.body->trailers().empty()) {
                        fail_upload(
                            protocol_error("HTTP/1.1 content-length request cannot have trailers"));
                        co_return;
                    }
                }
                if (pending->streaming_request_chunked) {
                    auto last_chunk = make_last_chunk(pending->streaming_request.body->trailers());
                    if (!last_chunk) {
                        fail_upload(last_chunk.error());
                        co_return;
                    }
                    auto terminator =
                        std::make_shared<std::vector<std::uint8_t>>(std::move(last_chunk.value()));
                    const auto terminator_written = co_await async::callback_sender<HttpOpSigs>(
                        [self, terminator](auto terminal) {
                            boost::asio::async_write(*self->stream_,
                                                     boost::asio::buffer(*terminator),
                                                     std::move(terminal));
                        },
                        [](auto &&receiver, const boost::system::error_code &error,
                           std::size_t size) {
                            stdexec::set_value(std::move(receiver), HttpOpResult{error, size});
                        });
                    if (terminator_written.error) {
                        fail_upload(io_error("failed to finish HTTP/1.1 chunked request body",
                                             terminator_written.error));
                        co_return;
                    }
                } else if (pending->streaming_request.content_length &&
                           pending->streaming_request_written !=
                               *pending->streaming_request.content_length) {
                    fail_upload(
                        protocol_error("HTTP/1.1 request body ended before its content length"));
                    co_return;
                }
            } else if (!pending->streaming_request.request.body.empty()) {
                const auto buffered = co_await async::callback_sender<HttpOpSigs>(
                    [&](auto terminal) {
                        boost::asio::async_write(
                            *self->stream_,
                            boost::asio::buffer(pending->streaming_request.request.body),
                            std::move(terminal));
                    },
                    [](auto &&receiver, const boost::system::error_code &error, std::size_t size) {
                        stdexec::set_value(std::move(receiver), HttpOpResult{error, size});
                    });
                if (buffered.error) {
                    fail_upload(io_error("failed to write HTTP/1.1 buffered streaming body",
                                         buffered.error));
                    co_return;
                }
            }
            pending->streaming_parser = std::make_unique<StreamingExchangeResponseParser>();
            pending->streaming_parser->body_limit(std::numeric_limits<std::uint64_t>::max());
            pending->streaming_parser->merge_all_trailers(true);
            if (pending->streaming_request.request.method == "HEAD") {
                pending->streaming_parser->skip(true);
            }
            while (true) {
                const auto header = co_await async::callback_sender<HttpOpSigs>(
                    [&](auto terminal) {
                        http::async_read_header(*self->stream_, self->read_buffer_,
                                                *pending->streaming_parser, std::move(terminal));
                    },
                    [](auto &&receiver, const boost::system::error_code &error, std::size_t size) {
                        stdexec::set_value(std::move(receiver), HttpOpResult{error, size});
                    });
                if (header.error) {
                    self->fail_active(exchange_id, header.error,
                                      "failed to read HTTP/1.1 streaming response headers");
                    co_return;
                }
                if (inactive()) {
                    co_return;
                }
                const auto status = pending->streaming_parser->get().result_int();
                if (status >= 100 && status < 200 && status != 101) {
                    continue;
                }
                break;
            }
            auto &message = pending->streaming_parser->get();
            io::StreamingExchangeResponse response;
            response.response.version = message.version();
            response.response.status = message.result_int();
            response.response.keep_alive = message.keep_alive();
            pending->streaming_header_field_count = static_cast<std::size_t>(
                std::distance(message.base().begin(), message.base().end()));
            for (const auto &field : message.base()) {
                response.response.headers.push_back(
                    {std::string(field.name_string()), std::string(field.value())});
            }
            const auto weak = self->weak_from_this();
            pending->streaming_response_body =
                std::make_shared<io::detail::QueuedExchangeBodyStream>(
                    self->executor_, 256 * 1024,
                    [weak, exchange_id](std::size_t size) {
                        if (const auto owner = weak.lock()) {
                            owner->streaming_response_consumed(exchange_id, size);
                        }
                    },
                    [weak, exchange_id] {
                        if (const auto owner = weak.lock()) {
                            owner->cancel(exchange_id);
                        }
                    },
                    [weak, exchange_id] {
                        if (const auto owner = weak.lock()) {
                            owner->streaming_response_drained(exchange_id);
                        }
                    });
            response.body = pending->streaming_response_body;
            pending->streaming_headers_delivered = true;
            pending->streaming_response_done = pending->streaming_parser->is_done();
            auto streaming_handler = std::move(pending->streaming_handler);
            if (streaming_handler) {
                streaming_handler.send(StreamingTerminal{std::move(response)});
            }
            if (pending->streaming_response_done) {
                pending->streaming_response_body->finish({});
                co_return;
            }
            constexpr std::size_t kReceiveCapacity = 256 * 1024;
            while (true) {
                if (inactive()) {
                    co_return;
                }
                if (pending->streaming_response_queued >= kReceiveCapacity) {
                    (void)co_await pending->space.receiver.next();
                    continue;
                }
                const auto capacity =
                    std::min(pending->streaming_response_buffer.size(),
                             kReceiveCapacity - pending->streaming_response_queued);
                auto &body = pending->streaming_parser->get().body();
                body.data = pending->streaming_response_buffer.data();
                body.size = capacity;
                const auto chunk = co_await async::callback_sender<HttpOpSigs>(
                    [&](auto terminal) {
                        http::async_read_some(*self->stream_, self->read_buffer_,
                                              *pending->streaming_parser, std::move(terminal));
                    },
                    [](auto &&receiver, const boost::system::error_code &error, std::size_t size) {
                        stdexec::set_value(std::move(receiver), HttpOpResult{error, size});
                    });
                if (inactive()) {
                    co_return;
                }
                auto &produced_body = pending->streaming_parser->get().body();
                const auto produced = capacity - produced_body.size;
                const bool need_buffer = chunk.error == http::error::need_buffer;
                if (chunk.error && !need_buffer) {
                    self->fail_streaming_response(exchange_id, pending, chunk.error);
                    co_return;
                }
                if (produced != 0) {
                    pending->streaming_response_queued += produced;
                    if (!pending->streaming_response_body->receive(
                            pending->streaming_response_buffer.data(), produced)) {
                        self->fail_streaming_response(exchange_id, pending,
                                                      boost::asio::error::no_buffer_space);
                        co_return;
                    }
                }
                if (pending->streaming_parser->is_done()) {
                    pending->streaming_response_done = true;
                    std::vector<io::ExchangeField> trailers;
                    std::size_t index = 0;
                    for (const auto &field : pending->streaming_parser->get().base()) {
                        if (index++ >= pending->streaming_header_field_count) {
                            trailers.push_back(
                                {std::string(field.name_string()), std::string(field.value())});
                        }
                    }
                    pending->streaming_response_body->finish(std::move(trailers));
                    co_return;
                }
            }
        } catch (...) {
            if (self->active_id_ == exchange_id) {
                if (pending->streaming_request.body) {
                    pending->streaming_request.body->cancel();
                }
                self->retire_all(
                    exchange_id,
                    io_error("HTTP/1.1 streaming exchange failed", boost::asio::error::fault),
                    core::Error{core::ErrorCode::transport_io, "HTTP/1.1 connection was retired"});
            }
        }
        co_return;
    }

    core::Result<std::vector<std::uint8_t>>
    make_last_chunk(const std::vector<io::ExchangeField> &trailers) const {
        auto wire = std::make_shared<std::vector<std::uint8_t>>();
        const std::string_view end = "0\r\n";
        wire->insert(wire->end(), end.begin(), end.end());
        for (const auto &header : trailers) {
            if (!is_token(header.name) || has_http_control(header.value) ||
                is_header_name(header.name, "content-length") ||
                is_forbidden_trailer_name(header.name)) {
                return core::fail(protocol_error("HTTP/1.1 request trailer is invalid"));
            }
            const std::string line = header.name + ": " + header.value + "\r\n";
            wire->insert(wire->end(), line.begin(), line.end());
        }
        wire->insert(wire->end(), {'\r', '\n'});
        return std::move(*wire);
    }

    void streaming_response_consumed(ExchangeId exchange_id, std::size_t size) {
        const auto found = pending_.find(exchange_id);
        if (found == pending_.end()) {
            return;
        }
        auto &pending = *found->second;
        pending.streaming_response_queued -= std::min(pending.streaming_response_queued, size);
        // Wake the response task parked on the space signal; it rechecks
        // capacity and session guards before reading. Harmless when the
        // task already returned (download done, awaiting drain).
        pending.space.sender.send(true);
    }

    void streaming_response_drained(ExchangeId exchange_id) {
        const auto found = pending_.find(exchange_id);
        if (found == pending_.end() || !found->second->streaming_response_done) {
            return;
        }
        const auto pending = found->second;
        const bool request_keep_alive = pending->streaming_request.request.keep_alive;
        const bool response_keep_alive = pending->streaming_parser->get().keep_alive();
        const bool reusable = request_keep_alive && response_keep_alive;
        pending_.erase(found);
        (void)pending->timer.cancel();
        active_id_.reset();
        if (!reusable) {
            retired_ = true;
            close_stream();
            retire_queued("HTTP/1.1 connection is not reusable: request keep-alive=" +
                          std::string(request_keep_alive ? "true" : "false") +
                          ", response keep-alive=" + (response_keep_alive ? "true" : "false"));
            return;
        }
        start_next();
    }

    void fail_streaming_response(ExchangeId exchange_id, const std::shared_ptr<Pending> &pending,
                                 const boost::system::error_code &error) {
        if (active_id_ != exchange_id) {
            return;
        }
        if (pending->streaming_response_body) {
            pending->streaming_response_body->fail(error);
        }
        retired_ = true;
        close_stream();
        active_id_.reset();
        pending_.erase(exchange_id);
        (void)pending->timer.cancel();
        retire_queued("HTTP/1.1 connection closed before queued exchange after streaming response "
                      "read failure (" +
                      std::to_string(error.value()) + ": " + error.message() + ")");
    }

    // Tunnel handshake as a straight-line coroutine: write the request,
    // skip interim responses, then hand the stream over or deliver the
    // rejection. Same in-band-error discipline as run_buffered.
    exec::task<void> run_tunnel(std::shared_ptr<Http1ClientSession> self, ExchangeId exchange_id,
                                std::shared_ptr<Pending> pending) {
        try {
            const auto *message = std::get_if<HttpTunnelMessage>(&pending->message);
            if (message == nullptr) {
                self->retire_all(
                    exchange_id, protocol_error("HTTP/1.1 request has no tunnel message"),
                    core::Error{core::ErrorCode::transport_io, "HTTP/1.1 connection was retired"});
                co_return;
            }
            pending->parser = std::make_unique<ExchangeResponseParser>();
            pending->parser->body_limit(pending->tunnel_request.rejection_body_limit);
            const auto written = co_await async::callback_sender<HttpOpSigs>(
                [&](auto terminal) {
                    http::async_write(*self->stream_, *message, std::move(terminal));
                },
                [](auto &&receiver, const boost::system::error_code &error, std::size_t size) {
                    stdexec::set_value(std::move(receiver), HttpOpResult{error, size});
                });
            if (written.error) {
                self->fail_active(exchange_id, written.error, "failed to write HTTP/1.1 request");
                co_return;
            }
            if (self->stopped_ || self->retired_ || self->active_id_ != exchange_id) {
                co_return;
            }
            while (true) {
                const auto header = co_await async::callback_sender<HttpOpSigs>(
                    [&](auto terminal) {
                        http::async_read_header(*self->stream_, self->read_buffer_,
                                                *pending->parser, std::move(terminal));
                    },
                    [](auto &&receiver, const boost::system::error_code &error, std::size_t size) {
                        stdexec::set_value(std::move(receiver), HttpOpResult{error, size});
                    });
                if (header.error) {
                    self->fail_active(exchange_id, header.error,
                                      "failed to read HTTP/1.1 tunnel response headers");
                    co_return;
                }
                if (self->stopped_ || self->retired_ || self->active_id_ != exchange_id) {
                    co_return;
                }
                const auto status = pending->parser->get().result_int();
                if (status >= 100 && status < 200 && status != 101) {
                    pending->parser = std::make_unique<ExchangeResponseParser>();
                    pending->parser->body_limit(pending->tunnel_request.rejection_body_limit);
                    continue;
                }
                break;
            }
            auto response = make_response(pending->parser->get());
            if (tunnel_accepted(pending->tunnel_request, response)) {
                self->finish_tunnel(exchange_id, pending, std::move(response));
                co_return;
            }
            const auto rejection = co_await async::callback_sender<HttpOpSigs>(
                [&](auto terminal) {
                    http::async_read(*self->stream_, self->read_buffer_, *pending->parser,
                                     std::move(terminal));
                },
                [](auto &&receiver, const boost::system::error_code &error, std::size_t size) {
                    stdexec::set_value(std::move(receiver), HttpOpResult{error, size});
                });
            if (rejection.error) {
                self->fail_active(exchange_id, rejection.error,
                                  "failed to read HTTP/1.1 tunnel rejection body");
                co_return;
            }
            if (self->stopped_ || self->retired_ || self->active_id_ != exchange_id) {
                co_return;
            }
            {
                auto rejection_response = make_response(pending->parser->release());
                const bool reusable = rejection_response.keep_alive;
                self->active_id_.reset();
                if (!reusable) {
                    self->retired_ = true;
                    self->close_stream();
                }
                self->complete_tunnel(exchange_id,
                                      io::StreamUpgradeResponse{std::move(rejection_response), {}});
                if (reusable) {
                    self->start_next();
                } else {
                    self->retire_queued();
                }
            }
        } catch (...) {
            self->retire_all(
                exchange_id, io_error("HTTP/1.1 tunnel failed", boost::asio::error::fault),
                core::Error{core::ErrorCode::transport_io, "HTTP/1.1 connection was retired"});
        }
        co_return;
    }

    void finish_tunnel(ExchangeId exchange_id, const std::shared_ptr<Pending> &pending,
                       io::ExchangeResponse response) {
        retired_ = true;
        active_id_.reset();
        std::vector<std::uint8_t> buffered(read_buffer_.size());
        if (!buffered.empty()) {
            const auto copied =
                boost::asio::buffer_copy(boost::asio::buffer(buffered), read_buffer_.data());
            buffered.resize(copied);
            read_buffer_.consume(copied);
        }
        std::shared_ptr<io::StreamHandle> raw_stream;
        if (stream_) {
            raw_stream = stream_->take_handle();
            stream_.reset();
        }
        if (!raw_stream) {
            complete_tunnel(exchange_id,
                            core::fail(core::Error{core::ErrorCode::transport_io,
                                                   "HTTP/1.1 tunnel lost its underlying stream"}));
            retire_queued();
            return;
        }
        auto state = std::make_shared<Http1TunnelState>(std::move(raw_stream), std::move(buffered));
        auto tunnel = std::make_unique<Http1TunnelStream>(std::move(state));
        complete_tunnel(exchange_id,
                        io::StreamUpgradeResponse{std::move(response), std::move(tunnel)});
        retire_queued();
        (void)pending;
    }

    // Buffered exchange as a straight-line coroutine: write the request,
    // read the response, deliver it. Transport failures stay in band (Beast
    // shape) so the spawned task always ends with a value; initiation
    // throws collapse into retire. Cancel/expire/stop retire the whole
    // connection, so no per-exchange stop wiring is needed: the in-flight
    // Beast op aborts on close and the task lands in retire_all, which is
    // idempotent against the maps.
    exec::task<void> run_buffered(std::shared_ptr<Http1ClientSession> self, ExchangeId exchange_id,
                                  std::shared_ptr<Pending> pending) {
        try {
            const auto *message = std::get_if<HttpMessage>(&pending->message);
            if (message == nullptr) {
                self->retire_all(
                    exchange_id, protocol_error("HTTP/1.1 request has no buffered message"),
                    core::Error{core::ErrorCode::transport_io, "HTTP/1.1 connection was retired"});
                co_return;
            }
            const auto written = co_await async::callback_sender<HttpOpSigs>(
                [&](auto terminal) {
                    http::async_write(*self->stream_, *message, std::move(terminal));
                },
                [](auto &&receiver, const boost::system::error_code &error, std::size_t size) {
                    stdexec::set_value(std::move(receiver), HttpOpResult{error, size});
                });
            if (written.error) {
                self->fail_active(exchange_id, written.error, "failed to write HTTP/1.1 request");
                co_return;
            }
            if (self->stopped_ || self->retired_ || self->active_id_ != exchange_id) {
                co_return;
            }
            const auto received = co_await async::callback_sender<HttpOpSigs>(
                [&](auto terminal) {
                    http::async_read(*self->stream_, self->read_buffer_, *pending->parser,
                                     std::move(terminal));
                },
                [](auto &&receiver, const boost::system::error_code &error, std::size_t size) {
                    stdexec::set_value(std::move(receiver), HttpOpResult{error, size});
                });
            if (received.error) {
                self->fail_active(exchange_id, received.error, "failed to read HTTP/1.1 response");
                co_return;
            }
            if (self->stopped_ || self->retired_ || self->active_id_ != exchange_id) {
                co_return;
            }
            auto response = make_response(pending->parser->release());
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
        } catch (...) {
            self->retire_all(
                exchange_id, io_error("HTTP/1.1 exchange failed", boost::asio::error::fault),
                core::Error{core::ErrorCode::transport_io, "HTTP/1.1 connection was retired"});
        }
        co_return;
    }

    void expire(ExchangeId exchange_id) {
        if (!pending_.contains(exchange_id)) {
            return;
        }
        if (active_id_ == exchange_id) {
            retire_all(exchange_id, timeout_error(),
                       core::Error{core::ErrorCode::transport_io,
                                   "HTTP/1.1 connection was retired after a timeout"});
            return;
        }
        complete_error(exchange_id, timeout_error());
    }

    void fail_active(ExchangeId exchange_id, const boost::system::error_code &error,
                     std::string context) {
        auto failure = is_http_framing_error(error)
                           ? protocol_error("HTTP/1.1 response framing failed")
                           : io_error(std::move(context), error);
        retire_all(exchange_id, std::move(failure),
                   core::Error{core::ErrorCode::transport_io,
                               "HTTP/1.1 connection was retired after an I/O error"});
    }

    void retire_all(ExchangeId active_id, core::Error active_error,
                    const core::Error &queued_error) {
        retired_ = true;
        close_stream();
        active_id_.reset();
        complete_error(active_id, std::move(active_error));
        std::vector<ExchangeId> remaining;
        remaining.reserve(pending_.size());
        for (const auto &[exchange_id, pending] : pending_) {
            remaining.push_back(exchange_id);
        }
        for (const auto exchange_id : remaining) {
            complete_error(exchange_id, queued_error);
        }
        queue_.clear();
    }

    void retire_queued(std::string reason = "HTTP/1.1 connection closed before queued exchange") {
        retired_ = true;
        close_stream();
        std::vector<ExchangeId> remaining;
        remaining.reserve(pending_.size());
        for (const auto &[exchange_id, pending] : pending_) {
            remaining.push_back(exchange_id);
        }
        for (const auto exchange_id : remaining) {
            complete_error(exchange_id, core::Error{core::ErrorCode::transport_io, reason});
        }
        queue_.clear();
    }

    void complete(ExchangeId exchange_id, BufferedTerminal result) {
        const auto found = pending_.find(exchange_id);
        if (found == pending_.end()) {
            return;
        }
        auto pending = std::move(found->second);
        pending_.erase(found);
        (void)pending->timer.cancel();
        auto handler = std::move(pending->handler);
        if (handler) {
            handler.send(std::move(result));
        }
    }

    void complete_tunnel(ExchangeId exchange_id, TunnelTerminal result) {
        const auto found = pending_.find(exchange_id);
        if (found == pending_.end()) {
            return;
        }
        auto pending = std::move(found->second);
        pending_.erase(found);
        (void)pending->timer.cancel();
        auto handler = std::move(pending->tunnel_handler);
        if (handler) {
            handler.send(std::move(result));
        }
    }

    void complete_error(ExchangeId exchange_id, core::Error error) {
        const auto found = pending_.find(exchange_id);
        if (found == pending_.end()) {
            return;
        }
        // Wake a response task parked on the space signal so it observes
        // the terminal state instead of stalling; a no-op for exchanges
        // that never park.
        found->second->space.sender.send(true);
        if (found->second->is_streaming) {
            auto pending = std::move(found->second);
            pending_.erase(found);
            (void)pending->timer.cancel();
            if (pending->streaming_headers_delivered && pending->streaming_response_body) {
                boost::system::error_code body_error = boost::asio::error::connection_reset;
                if (error.code == core::ErrorCode::timeout) {
                    body_error = boost::asio::error::timed_out;
                } else if (error.code == core::ErrorCode::cancelled) {
                    body_error = boost::asio::error::operation_aborted;
                }
                pending->streaming_response_body->fail(body_error);
            } else {
                post_streaming_result(std::move(pending->streaming_handler),
                                      core::fail(std::move(error)));
            }
            return;
        }
        if (found->second->is_tunnel) {
            complete_tunnel(exchange_id, core::fail(std::move(error)));
        } else {
            complete(exchange_id, core::fail(std::move(error)));
        }
    }

    void complete_all(const BufferedTerminal &result) {
        std::vector<ExchangeId> exchanges;
        exchanges.reserve(pending_.size());
        for (const auto &[exchange_id, pending] : pending_) {
            exchanges.push_back(exchange_id);
        }
        for (const auto exchange_id : exchanges) {
            complete_error(exchange_id, result.error());
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
    // Owns spawned exchange tasks; never requested, only joined by their
    // own completion (see run_buffered). The tasks keep the session alive,
    // so the scope always outlives its operations.
    exec::async_scope scope_;
    boost::beast::flat_buffer read_buffer_;
    std::unordered_map<ExchangeId, std::shared_ptr<Pending>> pending_;
    std::deque<ExchangeId> queue_;
    std::optional<ExchangeId> active_id_;
    ExchangeId next_exchange_id_ = 1;
    bool retired_ = false;
    bool stopped_ = false;
};

} // namespace

std::shared_ptr<io::ExchangeSession>
make_http1_exchange_session(std::unique_ptr<io::StreamHandle> stream) {
    if (!stream) {
        return {};
    }
    return std::make_shared<Http1ClientSession>(std::move(stream));
}

} // namespace clash_native::transport
