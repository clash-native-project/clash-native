#include "http_body_stream.hpp"
#include "http_tunnel_stream.hpp"
#include <clash_native/transport/exchange_session.hpp>
#include <clash_native/transport/quic_client.hpp>

#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

#include <nghttp3/nghttp3.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <deque>
#include <limits>
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

boost::system::error_code body_stream_error(core::ErrorCode code) {
    if (code == core::ErrorCode::timeout) {
        return boost::asio::error::timed_out;
    }
    if (code == core::ErrorCode::cancelled) {
        return boost::asio::error::operation_aborted;
    }
    return boost::asio::error::connection_reset;
}

constexpr std::size_t kHttp3ResponseBodyQueueLimit = 1024 * 1024;
constexpr std::size_t kHttp3RequestBodyReadSize = 64 * 1024;

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

class Http3ClientSession final : public ExchangeSession,
                                 public MultiplexedSession,
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
        std::optional<std::uint64_t> content_length;
        if (const auto validation_error = validate_streaming_request(request, content_length)) {
            post_streaming_result(std::move(handler), core::fail(*validation_error));
            return exchange_id;
        }
        if (deadline <= std::chrono::steady_clock::now()) {
            post_streaming_result(std::move(handler), core::fail(timeout_error()));
            return exchange_id;
        }

        auto pending = std::make_shared<Pending>(executor_);
        pending->request = std::move(request.request);
        pending->request_body_source = std::move(request.body);
        pending->request_content_length = content_length;
        pending->streaming_handler = std::move(handler);
        pending->is_streaming = true;
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
                                                      "HTTP/3 tunnel request fields are invalid",
                                                      {}}));
            return exchange_id;
        }
        for (const auto &header : request.headers) {
            if (!is_token(header.name) || contains_control(header.value)) {
                post_tunnel_result(
                    std::move(handler),
                    core::fail(core::Error{core::ErrorCode::configuration,
                                           "HTTP/3 tunnel header contains invalid characters",
                                           {}}));
                return exchange_id;
            }
            const auto name = lower_copy(header.name);
            if (name.front() == ':' || name == "content-length" ||
                forbidden_http3_header(name, header.value)) {
                post_tunnel_result(
                    std::move(handler),
                    core::fail(core::Error{core::ErrorCode::configuration,
                                           "HTTP/3 tunnel request contains a forbidden header",
                                           {}}));
                return exchange_id;
            }
        }
        if (deadline <= std::chrono::steady_clock::now()) {
            post_tunnel_result(std::move(handler), core::fail(timeout_error()));
            return exchange_id;
        }
        auto pending = std::make_shared<Pending>(executor_);
        pending->is_tunnel = true;
        pending->tunnel_request = std::move(request);
        pending->tunnel_handler = std::move(handler);
        pending->response.version = 30;
        pending->response.keep_alive = true;
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

    MultiplexedSession *multiplexed_session() noexcept override { return this; }

    StreamId open_stream(MultiplexedStreamRequest, std::chrono::steady_clock::time_point,
                         StreamHandler handler) override {
        const auto stream_id = static_cast<StreamId>(next_exchange_id());
        boost::asio::post(executor_, [handler = std::move(handler)]() mutable {
            if (handler) {
                handler(core::fail(
                    core::Error{core::ErrorCode::unsupported,
                                "HTTP/3 exposes logical streams through ExchangeSession requests",
                                {}}));
            }
        });
        return stream_id;
    }

    std::size_t active_streams() const noexcept override { return pending_.size(); }

    std::optional<std::size_t> max_concurrent_streams() const noexcept override {
        return connection_->max_concurrent_streams();
    }

    std::unique_ptr<core::DatagramHandle> open_datagram() override {
        return connection_->open_datagram();
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

        ExchangeRequest request;
        StreamUpgradeRequest tunnel_request;
        ExchangeResponse response;
        std::shared_ptr<ExchangeBodyStream> request_body_source;
        std::optional<std::uint64_t> request_content_length;
        std::vector<std::uint8_t> request_body_buffer;
        std::vector<ExchangeField> request_body_trailers;
        std::vector<ExchangeField> response_trailers;
        Handler handler;
        StreamingHandler streaming_handler;
        TunnelHandler tunnel_handler;
        boost::asio::steady_timer timer;
        std::size_t body_offset = 0;
        std::size_t request_body_offset = 0;
        std::size_t request_body_output_covered = 0;
        std::uint64_t request_body_bytes = 0;
        std::uint64_t stream_bytes_generated = 0;
        std::uint64_t stream_bytes_acked = 0;
        std::uint64_t request_body_ack_target = 0;
        std::uint64_t streaming_response_body_bytes_received = 0;
        std::uint64_t streaming_response_body_bytes_consumed = 0;
        std::size_t buffered_response_payload_credit = 0;
        std::vector<std::uint8_t> tunnel_outgoing;
        core::StreamHandle::WriteHandler tunnel_write_handler;
        std::size_t tunnel_write_size = 0;
        std::size_t pending_payload_credit = 0;
        std::size_t deferred_receive_credit = 0;
        std::shared_ptr<detail::HttpTunnelStreamState> tunnel_state;
        std::shared_ptr<detail::QueuedExchangeBodyStream> streaming_response_body;
        bool is_tunnel = false;
        bool is_streaming = false;
        bool streaming_response_delivered = false;
        bool streaming_response_finished = false;
        bool request_body_read_pending = false;
        bool request_body_source_eof = false;
        bool request_body_vector_in_flight = false;
        bool request_body_chunk_ack_waiting = false;
        bool request_body_ack_target_set = false;
        bool request_body_trailers_submitted = false;
        bool tunnel_established = false;
        bool tunnel_data_read = false;
        bool tunnel_write_closed = false;
        bool remote_end_stream = false;
        std::int64_t stream_id = -1;
        bool completed = false;
        bool response_too_large = false;
        bool response_body_overflow = false;
    };

    using PendingPtr = std::shared_ptr<Pending>;

    static std::optional<core::Error> validate_request(const ExchangeRequest &request) {
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

    static std::optional<core::Error>
    validate_streaming_request(const StreamingExchangeRequest &request,
                               std::optional<std::uint64_t> &content_length) {
        if (const auto error = validate_request(request.request)) {
            return error;
        }
        if (request.body && !request.request.body.empty()) {
            return core::Error{
                core::ErrorCode::configuration,
                "HTTP/3 streaming request cannot combine a body stream and buffered body",
                {}};
        }

        content_length = request.content_length;
        bool found_content_length = false;
        for (const auto &header : request.request.headers) {
            if (lower_copy(header.name) != "content-length") {
                continue;
            }
            auto value = std::string_view(header.value);
            const auto first = value.find_first_not_of(" \t");
            if (first == std::string_view::npos) {
                return core::Error{
                    core::ErrorCode::configuration, "HTTP/3 Content-Length is empty", {}};
            }
            const auto last = value.find_last_not_of(" \t");
            value = value.substr(first, last - first + 1);
            std::uint64_t parsed_length = 0;
            const auto parsed =
                std::from_chars(value.data(), value.data() + value.size(), parsed_length);
            if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) {
                return core::Error{
                    core::ErrorCode::configuration, "HTTP/3 Content-Length is invalid", {}};
            }
            if (found_content_length) {
                return core::Error{core::ErrorCode::configuration,
                                   "HTTP/3 request contains duplicate Content-Length fields",
                                   {}};
            }
            found_content_length = true;
            if (content_length && *content_length != parsed_length) {
                return core::Error{
                    core::ErrorCode::configuration,
                    "HTTP/3 Content-Length conflicts with the streaming request length",
                    {}};
            }
            content_length = parsed_length;
        }

        if (!request.body) {
            const auto buffered_length = static_cast<std::uint64_t>(request.request.body.size());
            if (content_length && *content_length != buffered_length) {
                return core::Error{core::ErrorCode::configuration,
                                   "HTTP/3 Content-Length does not match the buffered request body",
                                   {}};
            }
            if (!request.request.body.empty()) {
                content_length = buffered_length;
            }
        }
        return std::nullopt;
    }

    static std::optional<core::Error>
    validate_request_trailers(const std::vector<ExchangeField> &trailers) {
        for (const auto &header : trailers) {
            if (!is_token(header.name) || contains_control(header.value)) {
                return core::Error{core::ErrorCode::configuration,
                                   "HTTP/3 request trailer contains invalid characters",
                                   {}};
            }
            const auto name = lower_copy(header.name);
            if (name.front() == ':' || name == "content-length" || name == "host" || name == "te" ||
                name == "trailer" || forbidden_http3_header(name, header.value)) {
                return core::Error{core::ErrorCode::configuration,
                                   "HTTP/3 request trailer contains a forbidden field",
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

    PendingPtr find_pending_for_stream(std::int64_t stream_id) const {
        const auto found = stream_pending_.find(stream_id);
        return found == stream_pending_.end() ? PendingPtr{} : found->second;
    }

    void start_request_body_read(std::int64_t stream_id, const PendingPtr &pending) {
        if (!pending || !pending->is_streaming || !pending->request_body_source ||
            pending->request_body_read_pending || pending->request_body_source_eof ||
            pending->request_body_chunk_ack_waiting || pending->streaming_response_finished ||
            pending->completed || retired_) {
            return;
        }
        pending->request_body_buffer.assign(kHttp3RequestBodyReadSize, 0);
        pending->request_body_offset = 0;
        pending->request_body_read_pending = true;
        const auto weak_self = weak_from_this();
        const std::weak_ptr<Pending> weak_pending = pending;
        pending->request_body_source->async_read_some(
            boost::asio::buffer(pending->request_body_buffer),
            [weak_self, weak_pending, stream_id](const boost::system::error_code &error,
                                                 std::size_t size) {
                if (const auto self = weak_self.lock()) {
                    if (const auto pending = weak_pending.lock()) {
                        boost::asio::post(self->executor_, [self, pending, stream_id, error, size] {
                            self->on_request_body_read(stream_id, pending, error, size);
                        });
                    }
                }
            });
    }

    void on_request_body_read(std::int64_t stream_id, const PendingPtr &pending,
                              const boost::system::error_code &error, std::size_t size) {
        if (!pending->request_body_read_pending || pending->completed || retired_ ||
            pending->streaming_response_finished || pending->stream_id != stream_id) {
            return;
        }
        pending->request_body_read_pending = false;
        if (size > pending->request_body_buffer.size()) {
            if (const auto found = stream_ids_.find(stream_id); found != stream_ids_.end()) {
                fail_pending(
                    found->second,
                    protocol_error("HTTP/3 request body source exceeded the supplied buffer"));
            }
            return;
        }
        if (error && error != boost::asio::error::eof) {
            const auto found = stream_ids_.find(stream_id);
            if (found != stream_ids_.end()) {
                fail_pending(found->second,
                             io_error("failed to read HTTP/3 request body: " + error.message()));
            }
            return;
        }
        if (size > 0) {
            if (pending->request_body_bytes >
                std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(size)) {
                const auto found = stream_ids_.find(stream_id);
                if (found != stream_ids_.end()) {
                    fail_pending(found->second,
                                 protocol_error("HTTP/3 request body length overflowed"));
                }
                return;
            }
            pending->request_body_bytes += static_cast<std::uint64_t>(size);
            if (pending->request_content_length &&
                pending->request_body_bytes > *pending->request_content_length) {
                const auto found = stream_ids_.find(stream_id);
                if (found != stream_ids_.end()) {
                    fail_pending(found->second,
                                 protocol_error("HTTP/3 request body exceeded Content-Length"));
                }
                return;
            }
            pending->request_body_buffer.resize(size);
            pending->request_body_offset = 0;
        } else {
            pending->request_body_buffer.clear();
            pending->request_body_offset = 0;
        }

        if (error == boost::asio::error::eof) {
            pending->request_body_source_eof = true;
            if (pending->request_content_length &&
                pending->request_body_bytes != *pending->request_content_length) {
                const auto found = stream_ids_.find(stream_id);
                if (found != stream_ids_.end()) {
                    fail_pending(found->second,
                                 protocol_error("HTTP/3 request body ended before Content-Length"));
                }
                return;
            }
            pending->request_body_trailers = pending->request_body_source->trailers();
            if (const auto trailer_error =
                    validate_request_trailers(pending->request_body_trailers)) {
                const auto found = stream_ids_.find(stream_id);
                if (found != stream_ids_.end()) {
                    fail_pending(found->second, *trailer_error);
                }
                return;
            }
        } else if (size == 0) {
            const auto found = stream_ids_.find(stream_id);
            if (found != stream_ids_.end()) {
                fail_pending(found->second,
                             protocol_error("HTTP/3 request body source made no progress"));
            }
            return;
        }

        if (nghttp3_conn_resume_stream(http3_, stream_id) != 0) {
            const auto found = stream_ids_.find(stream_id);
            if (found != stream_ids_.end()) {
                fail_pending(found->second,
                             protocol_error("failed to resume HTTP/3 request body stream"));
            }
            return;
        }
        pump_output();
    }

    static nghttp3_nv make_header(const std::string &name, const std::string &value) {
        return {reinterpret_cast<std::uint8_t *>(const_cast<char *>(name.data())),
                reinterpret_cast<std::uint8_t *>(const_cast<char *>(value.data())), name.size(),
                value.size(), NGHTTP3_NV_FLAG_NONE};
    }

    static nghttp3_ssize read_request_body(nghttp3_conn *conn, std::int64_t stream_id,
                                           nghttp3_vec *vectors, std::size_t vector_count,
                                           std::uint32_t *flags, void *conn_user_data,
                                           void *stream_user_data) {
        auto *pending = static_cast<Pending *>(stream_user_data);
        if (pending == nullptr || (pending->completed && !pending->is_tunnel) ||
            vector_count == 0) {
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        if (pending->is_tunnel) {
            if (!pending->tunnel_outgoing.empty() && !pending->tunnel_data_read) {
                vectors[0] = {pending->tunnel_outgoing.data(), pending->tunnel_outgoing.size()};
                pending->tunnel_data_read = true;
                return 1;
            }
            if (pending->tunnel_write_closed) {
                *flags |= NGHTTP3_DATA_FLAG_EOF;
                vectors[0] = {nullptr, 0};
                return 1;
            }
            return NGHTTP3_ERR_WOULDBLOCK;
        }
        if (pending->is_streaming && pending->request_body_source) {
            if (pending->request_body_offset < pending->request_body_buffer.size() &&
                !pending->request_body_vector_in_flight) {
                const auto remaining =
                    pending->request_body_buffer.size() - pending->request_body_offset;
                vectors[0] = {pending->request_body_buffer.data() + pending->request_body_offset,
                              remaining};
                pending->request_body_offset += remaining;
                pending->request_body_vector_in_flight = true;
                pending->request_body_chunk_ack_waiting = true;
                pending->request_body_ack_target_set = false;
                pending->request_body_output_covered = 0;
                return 1;
            }
            if (pending->request_body_source_eof && !pending->request_body_vector_in_flight) {
                if (!pending->request_body_trailers.empty() &&
                    !pending->request_body_trailers_submitted) {
                    std::vector<std::string> names;
                    std::vector<std::string> values;
                    std::vector<nghttp3_nv> headers;
                    names.reserve(pending->request_body_trailers.size());
                    values.reserve(pending->request_body_trailers.size());
                    headers.reserve(pending->request_body_trailers.size());
                    for (const auto &trailer : pending->request_body_trailers) {
                        names.push_back(lower_copy(trailer.name));
                        values.push_back(trailer.value);
                    }
                    for (std::size_t index = 0; index < names.size(); ++index) {
                        headers.push_back(make_header(names[index], values[index]));
                    }
                    if (nghttp3_conn_submit_trailers(conn, stream_id, headers.data(),
                                                     headers.size()) != 0) {
                        return NGHTTP3_ERR_CALLBACK_FAILURE;
                    }
                    pending->request_body_trailers_submitted = true;
                }
                *flags |= NGHTTP3_DATA_FLAG_EOF;
                if (pending->request_body_trailers_submitted) {
                    *flags |= NGHTTP3_DATA_FLAG_NO_END_STREAM;
                }
                vectors[0] = {nullptr, 0};
                return 1;
            }
            if (!pending->request_body_read_pending && !pending->request_body_chunk_ack_waiting) {
                auto *self = static_cast<Http3ClientSession *>(conn_user_data);
                if (self == nullptr) {
                    return NGHTTP3_ERR_CALLBACK_FAILURE;
                }
                self->start_request_body_read(stream_id, self->find_pending_for_stream(stream_id));
            }
            return NGHTTP3_ERR_WOULDBLOCK;
        }
        if (pending->body_offset > pending->request.body.size()) {
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
        if (stream == self->stream_pending_.end()) {
            return 0;
        }
        auto &pending = stream->second;
        if (pending->tunnel_established) {
            pending->pending_payload_credit += length;
            if (pending->tunnel_state) {
                pending->tunnel_state->receive(data, length);
            }
            return 0;
        }
        if (pending->is_streaming) {
            if (!pending->streaming_response_body ||
                !pending->streaming_response_body->receive(data, length)) {
                pending->response_body_overflow = true;
                return 0;
            }
            pending->deferred_receive_credit += length;
            pending->streaming_response_body_bytes_received += length;
            return 0;
        }
        const auto current = pending->response.body.size();
        const auto limit = pending->is_tunnel ? pending->tunnel_request.rejection_body_limit
                                              : pending->request.response_body_limit;
        if (current > limit || length > limit - current) {
            pending->response_too_large = true;
            return 0;
        }
        pending->response.body.insert(pending->response.body.end(), data, data + length);
        pending->buffered_response_payload_credit += length;
        return 0;
    }

    static int on_header(nghttp3_conn *, std::int64_t stream_id, std::int32_t, nghttp3_rcbuf *name,
                         nghttp3_rcbuf *value, std::uint8_t, void *user_data, void *) {
        auto *self = static_cast<Http3ClientSession *>(user_data);
        const auto stream = self->stream_pending_.find(stream_id);
        if (stream == self->stream_pending_.end() ||
            (stream->second->completed && !stream->second->is_tunnel) ||
            stream->second->tunnel_established) {
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

    static int on_begin_trailers(nghttp3_conn *, std::int64_t stream_id, void *user_data, void *) {
        auto *self = static_cast<Http3ClientSession *>(user_data);
        const auto pending = self->find_pending_for_stream(stream_id);
        if (pending && pending->is_streaming) {
            pending->response_trailers.clear();
        }
        return 0;
    }

    static int on_trailer(nghttp3_conn *, std::int64_t stream_id, std::int32_t, nghttp3_rcbuf *name,
                          nghttp3_rcbuf *value, std::uint8_t, void *user_data, void *) {
        auto *self = static_cast<Http3ClientSession *>(user_data);
        const auto pending = self->find_pending_for_stream(stream_id);
        if (!pending || !pending->is_streaming) {
            return 0;
        }
        const auto header_name = nghttp3_rcbuf_get_buf(name);
        const auto header_value = nghttp3_rcbuf_get_buf(value);
        pending->response_trailers.push_back(
            {std::string(reinterpret_cast<const char *>(header_name.base), header_name.len),
             std::string(reinterpret_cast<const char *>(header_value.base), header_value.len)});
        return 0;
    }

    static int on_end_trailers(nghttp3_conn *, std::int64_t, int, void *, void *) { return 0; }

    static int on_end_stream(nghttp3_conn *, std::int64_t stream_id, void *user_data, void *) {
        auto *self = static_cast<Http3ClientSession *>(user_data);
        const auto stream = self->stream_ids_.find(stream_id);
        if (stream != self->stream_ids_.end()) {
            const auto pending = self->stream_pending_.find(stream_id);
            if (pending != self->stream_pending_.end() && pending->second->tunnel_established) {
                pending->second->remote_end_stream = true;
                if (pending->second->tunnel_state) {
                    pending->second->tunnel_state->remote_close();
                }
            } else if (pending != self->stream_pending_.end() && pending->second->is_streaming) {
                self->finish_streaming_response(stream->second, pending->second);
            } else {
                self->finish_pending(stream->second);
            }
        }
        return 0;
    }

    void deliver_streaming_response(ExchangeId exchange_id, const PendingPtr &pending) {
        if (pending->streaming_response_delivered || !pending->streaming_handler) {
            return;
        }
        pending->streaming_response_delivered = true;
        const auto weak = weak_from_this();
        pending->streaming_response_body = std::make_shared<detail::QueuedExchangeBodyStream>(
            executor_, kHttp3ResponseBodyQueueLimit,
            [weak, exchange_id](std::size_t size) {
                if (const auto self = weak.lock()) {
                    self->consume_streaming_response(exchange_id, size);
                }
            },
            [weak, exchange_id] {
                if (const auto self = weak.lock()) {
                    self->fail_pending(exchange_id, cancelled_error());
                }
            },
            [weak, exchange_id] {
                if (const auto self = weak.lock()) {
                    self->complete_streaming_response(exchange_id);
                }
            });
        auto handler = std::move(pending->streaming_handler);
        StreamingExchangeResponse response{std::move(pending->response),
                                           pending->streaming_response_body};
        post_streaming_result(std::move(handler), std::move(response));
    }

    void finish_streaming_response(ExchangeId exchange_id, const PendingPtr &pending) {
        if (!pending->is_streaming || pending->streaming_response_finished) {
            return;
        }
        pending->remote_end_stream = true;
        pending->streaming_response_finished = true;
        if (pending->request_body_source && !pending->request_body_source_eof) {
            pending->request_body_read_pending = false;
            pending->request_body_source->cancel();
            if (pending->stream_id >= 0) {
                const auto weak = weak_from_this();
                const auto stream_id = pending->stream_id;
                boost::asio::post(executor_, [weak, stream_id] {
                    if (const auto self = weak.lock(); self && self->http3_ != nullptr) {
                        (void)nghttp3_conn_shutdown_stream_write(self->http3_, stream_id);
                    }
                });
            }
        }
        if (pending->streaming_response_body) {
            pending->streaming_response_body->finish(std::move(pending->response_trailers));
        } else {
            fail_pending(exchange_id,
                         protocol_error("HTTP/3 response ended before its final headers"));
        }
    }

    void consume_streaming_response(ExchangeId exchange_id, std::size_t size) {
        const auto found = pending_.find(exchange_id);
        if (found == pending_.end()) {
            return;
        }
        const auto &pending = found->second;
        if (pending->stream_id < 0 || size == 0) {
            return;
        }
        pending->streaming_response_body_bytes_consumed += size;
        const auto consumed = std::min(size, pending->deferred_receive_credit);
        pending->deferred_receive_credit -= consumed;
        const auto extended = connection_->extend_receive_credit(pending->stream_id, consumed);
        if (!extended) {
            connection_failed(extended.error());
        }
    }

    void release_streaming_response_overhead(const PendingPtr &pending) {
        const auto unread_body_bytes = pending->streaming_response_body_bytes_received -
                                       std::min(pending->streaming_response_body_bytes_received,
                                                pending->streaming_response_body_bytes_consumed);
        if (pending->deferred_receive_credit <= unread_body_bytes) {
            return;
        }
        const auto overhead = pending->deferred_receive_credit - unread_body_bytes;
        pending->deferred_receive_credit -= overhead;
        const auto extended = connection_->extend_receive_credit(pending->stream_id, overhead);
        if (!extended) {
            connection_failed(extended.error());
        }
    }

    void complete_streaming_response(ExchangeId exchange_id) {
        const auto found = pending_.find(exchange_id);
        if (found == pending_.end()) {
            return;
        }
        const auto pending = found->second;
        if (!pending->streaming_response_finished) {
            return;
        }
        if (pending->deferred_receive_credit != 0 && connection_ && !connection_->retired()) {
            const auto extended = connection_->extend_receive_credit(
                pending->stream_id, pending->deferred_receive_credit);
            if (!extended) {
                connection_failed(extended.error());
                return;
            }
            pending->deferred_receive_credit = 0;
        }
        pending->completed = true;
        (void)pending->timer.cancel();
        pending_.erase(found);
    }

    static int on_deferred_consume(nghttp3_conn *, std::int64_t stream_id, std::size_t consumed,
                                   void *user_data, void *) {
        auto *self = static_cast<Http3ClientSession *>(user_data);
        const auto extended = self->release_receive_credit(stream_id, consumed);
        if (!extended) {
            self->connection_failed(extended.error());
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    static int on_end_headers(nghttp3_conn *, std::int64_t stream_id, int, void *user_data,
                              void *) {
        auto *self = static_cast<Http3ClientSession *>(user_data);
        const auto stream = self->stream_ids_.find(stream_id);
        if (stream != self->stream_ids_.end()) {
            const auto pending = self->find_pending_for_stream(stream_id);
            if (pending && pending->is_streaming && !pending->streaming_response_delivered) {
                if (pending->response.status >= 200) {
                    self->deliver_streaming_response(stream->second, pending);
                } else if (pending->response.status >= 100) {
                    pending->response.status = 0;
                    pending->response.headers.clear();
                }
            }
            self->accept_tunnel_if_ready(stream->second);
        }
        return 0;
    }

    static int on_remote_settings(nghttp3_conn *, const nghttp3_proto_settings *settings,
                                  void *user_data) {
        auto *self = static_cast<Http3ClientSession *>(user_data);
        self->remote_settings_received_ = true;
        self->remote_connect_protocol_enabled_ = settings->enable_connect_protocol != 0;
        return 0;
    }

    core::Status release_receive_credit(std::int64_t stream_id, std::size_t consumed) {
        auto withheld = std::size_t{0};
        const auto pending = stream_pending_.find(stream_id);
        if (pending != stream_pending_.end() && pending->second->tunnel_established) {
            withheld = std::min(consumed, pending->second->pending_payload_credit);
            pending->second->pending_payload_credit -= withheld;
        }
        if (consumed == withheld) {
            return {};
        }
        return connection_->extend_receive_credit(stream_id, consumed - withheld);
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
        callbacks.end_headers = &on_end_headers;
        callbacks.begin_trailers = &on_begin_trailers;
        callbacks.recv_trailer = &on_trailer;
        callbacks.end_trailers = &on_end_trailers;
        callbacks.end_stream = &on_end_stream;
        callbacks.recv_settings2 = &on_remote_settings;
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
            const auto &pending = found->second;
            if (pending->is_tunnel && pending->tunnel_request.mode == StreamUpgradeMode::upgrade) {
                if (!remote_settings_received_) {
                    continue;
                }
                if (!remote_connect_protocol_enabled_) {
                    fail_pending(exchange_id,
                                 protocol_error("HTTP/3 peer did not enable extended CONNECT"));
                    continue;
                }
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
            if (pending->is_tunnel) {
                submit_tunnel(exchange_id, pending, opened.stream_id);
            } else {
                submit_request(exchange_id, pending, opened.stream_id);
            }
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
        if (pending->is_streaming && pending->request_content_length && !has_content_length) {
            names.emplace_back("content-length");
            values.push_back(std::to_string(*pending->request_content_length));
        } else if (!pending->request.body.empty() && !has_content_length) {
            names.emplace_back("content-length");
            values.push_back(std::to_string(pending->request.body.size()));
        }
        std::vector<nghttp3_nv> headers;
        headers.reserve(names.size());
        for (std::size_t index = 0; index < names.size(); ++index) {
            headers.push_back(make_header(names[index], values[index]));
        }
        nghttp3_data_reader reader{&read_request_body};
        const auto *reader_ptr =
            pending->request_body_source || !pending->request.body.empty() ? &reader : nullptr;
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

    void submit_tunnel(ExchangeId exchange_id, const PendingPtr &pending, std::int64_t stream_id) {
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
        std::vector<nghttp3_nv> headers;
        headers.reserve(names.size());
        for (std::size_t index = 0; index < names.size(); ++index) {
            headers.push_back(make_header(names[index], values[index]));
        }
        nghttp3_data_reader reader{&read_request_body};
        if (nghttp3_conn_submit_request(http3_, stream_id, headers.data(), headers.size(), &reader,
                                        pending.get()) != 0) {
            fail_pending(exchange_id, protocol_error("failed to submit HTTP/3 tunnel"));
            return;
        }
        pending->stream_id = stream_id;
        pending->response.version = 30;
        pending->response.keep_alive = true;
        stream_ids_.emplace(stream_id, exchange_id);
        stream_pending_.emplace(stream_id, pending);
    }

    void accept_tunnel_if_ready(ExchangeId exchange_id) {
        const auto found = pending_.find(exchange_id);
        if (found == pending_.end()) {
            return;
        }
        const auto &pending = found->second;
        if (pending->is_tunnel && !pending->tunnel_established && pending->response.status >= 200 &&
            pending->response.status < 300) {
            accept_tunnel(exchange_id, pending);
        }
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
                pending->tunnel_write_size = pending->tunnel_outgoing.size();
                pending->tunnel_write_handler = std::move(handler);
                if (nghttp3_conn_resume_stream(self->http3_, stream_id) != 0) {
                    auto failed = std::move(pending->tunnel_write_handler);
                    pending->tunnel_outgoing.clear();
                    pending->tunnel_write_size = 0;
                    if (failed) {
                        failed(boost::asio::error::operation_aborted, 0);
                    }
                    return;
                }
                self->pump_output();
            },
            [weak, pending, stream_id] {
                if (const auto self = weak.lock()) {
                    pending->tunnel_write_closed = true;
                    if (nghttp3_conn_resume_stream(self->http3_, stream_id) == 0) {
                        self->pump_output();
                    }
                }
            },
            [weak, pending, stream_id] {
                if (const auto self = weak.lock()) {
                    if (self->http3_ != nullptr) {
                        (void)nghttp3_conn_shutdown_stream_read(self->http3_, stream_id);
                        (void)nghttp3_conn_shutdown_stream_write(self->http3_, stream_id);
                    }
                    self->connection_->shutdown_stream(stream_id, 0x10c);
                }
            },
            [weak, stream_id](std::size_t size) {
                if (const auto self = weak.lock()) {
                    const auto extended = self->connection_->extend_receive_credit(stream_id, size);
                    if (!extended) {
                        self->connection_failed(extended.error());
                    }
                }
            });
        auto handler = std::move(pending->tunnel_handler);
        auto response = std::move(pending->response);
        post_tunnel_result(
            std::move(handler),
            StreamUpgradeResponse{std::move(response),
                                  detail::make_http_tunnel_stream(pending->tunnel_state)});
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
        std::size_t request_body_output_covered = 0;
        const auto stream = stream_pending_.find(stream_id);
        const auto pending = stream == stream_pending_.end() ? PendingPtr{} : stream->second;
        if (pending && pending->is_streaming && pending->request_body_chunk_ack_waiting &&
            !pending->request_body_ack_target_set && !pending->request_body_buffer.empty()) {
            const auto body_begin =
                reinterpret_cast<std::uintptr_t>(pending->request_body_buffer.data());
            const auto body_end = body_begin + pending->request_body_buffer.size();
            for (nghttp3_ssize index = 0; index < count; ++index) {
                const auto &vector = vectors[static_cast<std::size_t>(index)];
                const auto vector_begin = reinterpret_cast<std::uintptr_t>(vector.base);
                const auto vector_end = vector_begin + vector.len;
                const auto overlap_begin = std::max(body_begin, vector_begin);
                const auto overlap_end = std::min(body_end, vector_end);
                if (overlap_end > overlap_begin) {
                    request_body_output_covered +=
                        static_cast<std::size_t>(overlap_end - overlap_begin);
                }
            }
        }
        for (nghttp3_ssize index = 0; index < count; ++index) {
            const auto &vector = vectors[static_cast<std::size_t>(index)];
            const auto *begin = static_cast<const std::uint8_t *>(vector.base);
            data.insert(data.end(), begin, begin + vector.len);
        }
        if (pending) {
            if (data.size() >
                std::numeric_limits<std::uint64_t>::max() - pending->stream_bytes_generated) {
                connection_failed(protocol_error("HTTP/3 stream write offset overflowed"));
                return;
            }
            pending->stream_bytes_generated += static_cast<std::uint64_t>(data.size());
            if (request_body_output_covered != 0) {
                pending->request_body_output_covered += request_body_output_covered;
                if (pending->request_body_output_covered >= pending->request_body_buffer.size()) {
                    pending->request_body_ack_target = pending->stream_bytes_generated;
                    pending->request_body_ack_target_set = true;
                }
            }
        }
        write_pending_ = true;
        if (pending && pending->tunnel_data_read) {
            tunnel_write_pending_stream_id_ = stream_id;
        }
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
            if (tunnel_write_pending_stream_id_ == stream_id) {
                const auto found = stream_pending_.find(stream_id);
                if (found != stream_pending_.end()) {
                    auto &pending = found->second;
                    pending->tunnel_data_read = false;
                    pending->tunnel_outgoing.clear();
                    auto handler = std::move(pending->tunnel_write_handler);
                    const auto size = std::exchange(pending->tunnel_write_size, 0);
                    if (handler) {
                        handler({}, size);
                    }
                }
                tunnel_write_pending_stream_id_.reset();
            }
            pump_output();
        }
    }

    void on_stream_data_acked(std::int64_t stream_id, std::uint64_t length) {
        if (http3_ != nullptr && !retired_ &&
            nghttp3_conn_add_ack_offset(http3_, stream_id, length) != 0) {
            connection_failed(protocol_error("nghttp3 failed to acknowledge stream data"));
            return;
        }
        const auto pending = find_pending_for_stream(stream_id);
        if (!pending || !pending->is_streaming) {
            return;
        }
        if (length > std::numeric_limits<std::uint64_t>::max() - pending->stream_bytes_acked) {
            connection_failed(protocol_error("HTTP/3 acknowledged stream offset overflowed"));
            return;
        }
        pending->stream_bytes_acked += length;
        if (!pending->request_body_chunk_ack_waiting || !pending->request_body_ack_target_set ||
            pending->stream_bytes_acked < pending->request_body_ack_target) {
            return;
        }

        pending->request_body_buffer.clear();
        pending->request_body_offset = 0;
        pending->request_body_output_covered = 0;
        pending->request_body_vector_in_flight = false;
        pending->request_body_chunk_ack_waiting = false;
        pending->request_body_ack_target_set = false;
        pending->request_body_ack_target = 0;
        if (pending->request_body_source_eof) {
            if (nghttp3_conn_resume_stream(http3_, stream_id) != 0) {
                const auto exchange = stream_ids_.find(stream_id);
                if (exchange != stream_ids_.end()) {
                    fail_pending(exchange->second,
                                 protocol_error("failed to resume HTTP/3 request body stream"));
                }
                return;
            }
            pump_output();
        } else {
            start_request_body_read(stream_id, pending);
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
        const auto pending = find_pending_for_stream(stream_id);
        if (pending && pending->is_streaming && pending->streaming_response_body) {
            pending->deferred_receive_credit += static_cast<std::size_t>(consumed);
            if (pending->response_body_overflow) {
                const auto exchange = stream_ids_.find(stream_id);
                if (exchange != stream_ids_.end()) {
                    fail_pending(exchange->second,
                                 protocol_error("HTTP/3 streaming response queue is full"));
                }
                return;
            }
            if (pending->streaming_response_finished) {
                release_streaming_response_overhead(pending);
            }
        } else {
            auto receive_credit = static_cast<std::size_t>(consumed);
            if (pending && pending->buffered_response_payload_credit != 0) {
                receive_credit += std::exchange(pending->buffered_response_payload_credit, 0);
            }
            if (pending && pending->response_too_large) {
                const auto message =
                    pending->is_tunnel
                        ? "HTTP/3 tunnel rejection exceeded the configured body limit"
                        : "HTTP/3 response exceeded the configured body limit";
                const auto exchange = stream_ids_.find(stream_id);
                if (exchange != stream_ids_.end()) {
                    fail_pending(exchange->second, protocol_error(message));
                }
                return;
            }
            const auto extended = release_receive_credit(stream_id, receive_credit);
            if (!extended) {
                connection_failed(extended.error());
                return;
            }
        }
        if (remote_settings_received_) {
            open_pending_requests();
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
        const auto pending = stream_pending_.find(stream_id);
        if (pending != stream_pending_.end() && pending->second->tunnel_established &&
            pending->second->tunnel_state) {
            if (application_error == 0) {
                pending->second->tunnel_state->remote_close();
            } else {
                pending->second->tunnel_state->fail(boost::asio::error::connection_reset);
            }
        }
        stream_ids_.erase(stream);
        stream_pending_.erase(stream_id);
        if (const auto exchange = pending_.find(exchange_id);
            exchange != pending_.end() && !exchange->second->completed) {
            if (exchange->second->is_streaming && exchange->second->streaming_response_finished) {
                return;
            }
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
            const auto pending = stream_pending_.find(stream_id);
            if (pending != stream_pending_.end() && pending->second->tunnel_established &&
                pending->second->tunnel_state) {
                pending->second->tunnel_state->fail(boost::asio::error::connection_reset);
            } else {
                fail_pending(stream->second,
                             io_error("HTTP/3 peer reset request stream with code " +
                                      std::to_string(application_error)));
            }
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
                        "HTTP/3 tunnel rejection exceeded the configured body limit")));
            } else {
                post_result(std::move(pending->handler),
                            core::fail(protocol_error(
                                "HTTP/3 response exceeded the configured body limit")));
            }
        } else if (pending->is_tunnel) {
            post_tunnel_result(std::move(pending->tunnel_handler),
                               StreamUpgradeResponse{std::move(pending->response), {}});
        } else {
            post_result(std::move(pending->handler), std::move(pending->response));
        }
    }

    void fail_pending(ExchangeId exchange_id, core::Error error) {
        const auto found = pending_.find(exchange_id);
        if (found == pending_.end() || found->second->completed) {
            return;
        }
        const auto pending = found->second;
        if (pending->is_streaming && pending->deferred_receive_credit != 0 && connection_ &&
            !connection_->retired()) {
            const auto extended = connection_->extend_receive_credit(
                pending->stream_id, pending->deferred_receive_credit);
            if (!extended) {
                connection_failed(extended.error());
                return;
            }
            pending->deferred_receive_credit = 0;
        }
        pending->completed = true;
        (void)pending->timer.cancel();
        pending->request_body_read_pending = false;
        if (pending->request_body_source && !pending->request_body_source_eof) {
            pending->request_body_source->cancel();
        }
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
        if (pending->streaming_response_body) {
            pending->streaming_response_body->fail(body_stream_error(error.code));
        }
        if (pending->is_tunnel) {
            post_tunnel_result(std::move(pending->tunnel_handler), core::fail(std::move(error)));
        } else if (pending->is_streaming && !pending->streaming_response_delivered) {
            post_streaming_result(std::move(pending->streaming_handler),
                                  core::fail(std::move(error)));
        } else if (!pending->is_streaming) {
            post_result(std::move(pending->handler), core::fail(std::move(error)));
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
            }
            if (pending->streaming_response_body) {
                pending->streaming_response_body->fail(boost::asio::error::connection_reset);
            }
        }
        for (auto &[exchange_id, pending] : pending_) {
            (void)exchange_id;
            (void)pending->timer.cancel();
            if (pending->completed) {
                continue;
            }
            pending->request_body_read_pending = false;
            if (pending->request_body_source && !pending->request_body_source_eof) {
                pending->request_body_source->cancel();
            }
            if (pending->is_tunnel && pending->tunnel_handler) {
                pending->completed = true;
                tunnel_handlers.push_back(std::move(pending->tunnel_handler));
            } else if (pending->is_streaming && !pending->streaming_response_delivered &&
                       pending->streaming_handler) {
                pending->completed = true;
                streaming_handlers.push_back(std::move(pending->streaming_handler));
            } else if (pending->handler) {
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
        for (auto &handler : streaming_handlers) {
            post_streaming_result(std::move(handler), core::fail(error));
        }
        for (auto &handler : tunnel_handlers) {
            post_tunnel_result(std::move(handler), core::fail(error));
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
    std::optional<std::int64_t> tunnel_write_pending_stream_id_;
    bool remote_settings_received_ = false;
    bool remote_connect_protocol_enabled_ = false;
    bool retired_ = false;
    bool stopped_ = false;
};

} // namespace

std::shared_ptr<ExchangeSession>
make_http3_exchange_session(std::shared_ptr<QuicClientConnection> connection,
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
