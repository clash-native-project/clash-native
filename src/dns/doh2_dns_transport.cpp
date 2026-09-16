#include <clash_native/dns/dns_codec.hpp>
#include <clash_native/dns/dns_transport.hpp>

#include "stream_handle_adapter.hpp"

#include <boost/asio/post.hpp>
#include <boost/asio/ssl.hpp>

#define NGHTTP2_NO_SSIZE_T
#include <nghttp2/nghttp2.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstring>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace clash_native::dns {

namespace {

core::Error io_error(std::string context, const boost::system::error_code &error) {
    return {core::ErrorCode::transport_io, std::move(context),
            std::error_code(error.value(), std::system_category())};
}

core::Error protocol_error(std::string context) {
    return {core::ErrorCode::protocol_framing, std::move(context)};
}

core::Error handshake_error(const boost::system::error_code &error) {
    return {core::ErrorCode::carrier_handshake, "DoH2 TLS handshake failed",
            std::error_code(error.value(), std::system_category())};
}

core::Error timeout_error() { return {core::ErrorCode::timeout, "DoH2 DNS query timed out"}; }

core::Error cancelled_error() {
    return {core::ErrorCode::cancelled, "DoH2 DNS query was cancelled"};
}

std::string lower_copy(std::string_view value) {
    std::string result(value);
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}

} // namespace

class Doh2DnsTransport final : public DnsTransport {
  private:
    class Operation;
    class Session;

  public:
    Doh2DnsTransport(runtime::AsioRuntime &runtime, DnsUpstreamConfig config)
        : runtime_(runtime), config_(std::move(config)) {
        if (!config_.dialer) {
            config_.dialer = make_direct_dns_upstream_dialer(runtime_);
        }
    }

    ExchangeId exchange(DnsExchangeRequest request, Handler handler) override;
    void cancel(ExchangeId exchange_id) noexcept override;
    void stop() noexcept override;

  private:
    void complete(ExchangeId exchange_id, core::Result<DnsPacket> result);
    std::shared_ptr<Session> session();
    std::optional<std::uint16_t> next_query_id() noexcept;

    runtime::AsioRuntime &runtime_;
    DnsUpstreamConfig config_;
    std::unordered_map<ExchangeId, std::shared_ptr<Operation>> operations_;
    std::shared_ptr<Session> session_;
    std::unordered_set<std::uint16_t> active_query_ids_;
    ExchangeId next_exchange_id_ = 1;
    std::uint16_t next_query_id_ = 1;
    bool stopped_ = false;

    friend class Operation;
};

class Doh2DnsTransport::Session final
    : public std::enable_shared_from_this<Doh2DnsTransport::Session> {
  public:
    using Handler = std::function<void(core::Result<std::vector<std::uint8_t>>)>;

    Session(runtime::AsioRuntime &runtime, boost::asio::ip::tcp::endpoint endpoint,
            std::string server_name, std::string authority, std::string path, bool verify_peer,
            std::shared_ptr<DnsUpstreamDialer> dialer)
        : runtime_(runtime), endpoint_(endpoint), server_name_(std::move(server_name)),
          authority_(std::move(authority)), path_(std::move(path)), verify_peer_(verify_peer),
          ssl_context_(boost::asio::ssl::context::tls_client), dialer_(std::move(dialer)) {}

    void exchange(std::uint16_t query_id, std::vector<std::uint8_t> query,
                  std::chrono::steady_clock::time_point deadline, Handler handler) {
        if (stopped_ || retired_) {
            complete_immediately(std::move(handler), cancelled_error());
            return;
        }
        if (query.empty() || query.size() > 0xffff) {
            complete_immediately(std::move(handler),
                                 protocol_error("DoH2 DNS query exceeds message capacity"));
            return;
        }

        auto pending = std::make_shared<Pending>(runtime_.context());
        pending->query_wire = std::move(query);
        pending->handler = std::move(handler);
        pending->authority = authority_;
        pending->path = path_;
        pending->content_length = std::to_string(pending->query_wire.size());
        pending->timer.expires_at(deadline);
        auto self = shared_from_this();
        pending->timer.async_wait([self, query_id](const boost::system::error_code &error) {
            if (!error) {
                self->fail_pending(query_id, timeout_error());
            }
        });
        pending_.emplace(query_id, pending);
        queued_queries_.push_back(query_id);
        connect_if_needed();
        submit_queued_requests();
        send_pending();
    }

    void cancel(std::uint16_t query_id) noexcept { fail_pending(query_id, cancelled_error()); }

    void stop() noexcept {
        if (stopped_) {
            return;
        }
        stopped_ = true;
        retired_ = true;
        close_connection();
        close_http2();
        fail_all(cancelled_error());
    }

    bool retired() const noexcept { return retired_; }

  private:
    struct Pending {
        explicit Pending(boost::asio::io_context &context) : timer(context) {}

        std::uint16_t query_id = 0;
        std::vector<std::uint8_t> query_wire;
        std::vector<std::uint8_t> response_body;
        std::string authority;
        std::string path;
        std::string content_length;
        std::string status;
        std::string content_type;
        std::string callback_error;
        std::vector<nghttp2_nv> headers;
        Handler handler;
        boost::asio::steady_timer timer;
        std::size_t body_offset = 0;
        std::int32_t stream_id = 0;
        bool response_complete = false;
        bool completed = false;
        bool stream_closed = false;
    };

    using PendingPtr = std::shared_ptr<Pending>;

    void complete_immediately(Handler handler, core::Error error) {
        boost::asio::post(runtime_.context(),
                          [handler = std::move(handler), error = std::move(error)]() mutable {
                              if (handler) {
                                  handler(core::fail(std::move(error)));
                              }
                          });
    }

    static nghttp2_ssize read_body(nghttp2_session *, int32_t, uint8_t *buffer, size_t length,
                                   uint32_t *data_flags, nghttp2_data_source *source, void *) {
        auto *pending = static_cast<Pending *>(source->ptr);
        if (pending->body_offset > pending->query_wire.size()) {
            return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        }
        const auto remaining = pending->query_wire.size() - pending->body_offset;
        const auto size = std::min(length, remaining);
        if (size > 0) {
            std::memcpy(buffer, pending->query_wire.data() + pending->body_offset, size);
            pending->body_offset += size;
        }
        if (pending->body_offset == pending->query_wire.size()) {
            *data_flags = NGHTTP2_DATA_FLAG_EOF;
        }
        return static_cast<nghttp2_ssize>(size);
    }

    static int on_header(nghttp2_session *, const nghttp2_frame *frame, const uint8_t *name,
                         size_t name_length, const uint8_t *value, size_t value_length, uint8_t,
                         void *user_data) {
        auto *self = static_cast<Session *>(user_data);
        const auto query = self->stream_queries_.find(frame->hd.stream_id);
        if (query == self->stream_queries_.end()) {
            return 0;
        }
        const auto found = self->pending_.find(query->second);
        if (found == self->pending_.end()) {
            return 0;
        }
        const std::string_view header_name(reinterpret_cast<const char *>(name), name_length);
        const std::string_view header_value(reinterpret_cast<const char *>(value), value_length);
        if (header_name == ":status") {
            found->second->status = std::string(header_value);
        } else if (lower_copy(header_name) == "content-type") {
            found->second->content_type = lower_copy(header_value);
        }
        return 0;
    }

    static int on_data(nghttp2_session *, uint8_t, int32_t stream_id, const uint8_t *data,
                       size_t length, void *user_data) {
        auto *self = static_cast<Session *>(user_data);
        const auto query = self->stream_queries_.find(stream_id);
        if (query == self->stream_queries_.end()) {
            return 0;
        }
        const auto found = self->pending_.find(query->second);
        if (found == self->pending_.end()) {
            return 0;
        }
        if (found->second->response_body.size() + length > 0xffff) {
            found->second->callback_error = "DoH2 DNS response exceeds message capacity";
            return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        }
        found->second->response_body.insert(found->second->response_body.end(), data,
                                            data + length);
        return 0;
    }

    static int on_frame(nghttp2_session *, const nghttp2_frame *frame, void *user_data) {
        auto *self = static_cast<Session *>(user_data);
        const auto query = self->stream_queries_.find(frame->hd.stream_id);
        if (query == self->stream_queries_.end()) {
            return 0;
        }
        const auto found = self->pending_.find(query->second);
        if (found == self->pending_.end()) {
            return 0;
        }
        if ((frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA) &&
            (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0) {
            found->second->response_complete = true;
        }
        return 0;
    }

    static int on_stream_close(nghttp2_session *, int32_t stream_id, uint32_t error_code,
                               void *user_data) {
        auto *self = static_cast<Session *>(user_data);
        const auto query = self->stream_queries_.find(stream_id);
        if (query == self->stream_queries_.end()) {
            return 0;
        }
        const auto query_id = query->second;
        const auto found = self->pending_.find(query_id);
        if (found == self->pending_.end()) {
            self->stream_queries_.erase(query);
            return 0;
        }
        if (error_code != NGHTTP2_NO_ERROR && !found->second->completed) {
            found->second->callback_error = "DoH2 response stream closed with an HTTP/2 error";
        }
        found->second->response_complete = true;
        found->second->stream_closed = true;
        self->stream_queries_.erase(query);
        if (found->second->completed) {
            self->pending_.erase(found);
        }
        return 0;
    }

    bool configure_tls() {
        boost::system::error_code error;
        if (verify_peer_) {
            ssl_context_.set_default_verify_paths(error);
            if (error) {
                connection_failed(io_error("failed to load DoH2 trust roots", error),
                                  connection_generation_);
                return false;
            }
        }
        ssl_stream_->set_verify_mode(verify_peer_ ? boost::asio::ssl::verify_peer
                                                  : boost::asio::ssl::verify_none);
        if (!server_name_.empty() &&
            SSL_set_tlsext_host_name(ssl_stream_->native_handle(), server_name_.c_str()) != 1) {
            connection_failed(
                {core::ErrorCode::configuration, "failed to configure DoH2 server name"},
                connection_generation_);
            return false;
        }
        if (verify_peer_) {
            ssl_stream_->set_verify_callback(
                boost::asio::ssl::host_name_verification(server_name_));
        }
        const unsigned char alpn[] = {2, 'h', '2'};
        if (SSL_set_alpn_protos(ssl_stream_->native_handle(), alpn, sizeof(alpn)) != 0) {
            connection_failed({core::ErrorCode::configuration, "failed to configure DoH2 ALPN"},
                              connection_generation_);
            return false;
        }
        return true;
    }

    void connect_if_needed() {
        if (stopped_ || retired_ || connected_ || connecting_ || pending_.empty()) {
            return;
        }
        connecting_ = true;
        const auto generation = connection_generation_;
        auto self = shared_from_this();
        dialer_->connect_stream(
            {core::Destination::address(endpoint_.address(), endpoint_.port()), std::nullopt},
            [self, generation](core::StreamOpenResult result) mutable {
                if (generation != self->connection_generation_ || self->stopped_) {
                    if (result.handle) {
                        result.handle->close();
                    }
                    return;
                }
                if (!result.succeeded()) {
                    self->connection_failed(
                        result.error.value_or(core::Error{core::ErrorCode::endpoint_connection,
                                                          "DoH2 dialer failed to open a stream"}),
                        generation);
                    return;
                }
                self->ssl_stream_ = std::make_unique<SslStream>(
                    StreamHandleAdapter(std::move(result.handle)), self->ssl_context_);
                if (self->configure_tls()) {
                    self->handshake(generation);
                }
            });
    }

    void handshake(std::uint64_t generation) {
        auto self = shared_from_this();
        ssl_stream_->async_handshake(
            boost::asio::ssl::stream_base::client,
            [self, generation](const boost::system::error_code &error) {
                if (generation != self->connection_generation_ || self->stopped_) {
                    return;
                }
                if (error) {
                    self->connection_failed(handshake_error(error), generation);
                    return;
                }
                const unsigned char *protocol = nullptr;
                unsigned int protocol_length = 0;
                SSL_get0_alpn_selected(self->ssl_stream_->native_handle(), &protocol,
                                       &protocol_length);
                if (protocol_length != 2 || protocol[0] != 'h' || protocol[1] != '2') {
                    self->connection_failed({core::ErrorCode::carrier_handshake,
                                             "DoH2 upstream did not negotiate the h2 protocol"},
                                            generation);
                    return;
                }
                self->start_http2(generation);
            });
    }

    void start_http2(std::uint64_t generation) {
        nghttp2_session_callbacks *callbacks = nullptr;
        if (nghttp2_session_callbacks_new(&callbacks) != 0) {
            connection_failed(protocol_error("failed to allocate DoH2 callbacks"), generation);
            return;
        }
        nghttp2_session_callbacks_set_on_header_callback(callbacks, &on_header);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, &on_data);
        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, &on_frame);
        nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, &on_stream_close);
        const auto result = nghttp2_session_client_new(&http2_session_, callbacks, this);
        nghttp2_session_callbacks_del(callbacks);
        if (result != 0) {
            connection_failed(protocol_error("failed to create DoH2 session"), generation);
            return;
        }
        if (nghttp2_submit_settings(http2_session_, NGHTTP2_FLAG_NONE, nullptr, 0) != 0) {
            connection_failed(protocol_error("failed to submit DoH2 settings"), generation);
            return;
        }
        connecting_ = false;
        connected_ = true;
        submit_queued_requests();
        send_pending();
    }

    static nghttp2_nv make_header(std::string_view name, std::string_view value) {
        return {const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(name.data())),
                const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(value.data())), name.size(),
                value.size(), NGHTTP2_NV_FLAG_NONE};
    }

    void submit_queued_requests() {
        if (!connected_ || http2_session_ == nullptr) {
            return;
        }
        while (!queued_queries_.empty()) {
            const auto query_id = queued_queries_.front();
            queued_queries_.pop_front();
            const auto found = pending_.find(query_id);
            if (found == pending_.end() || found->second->completed ||
                found->second->stream_id != 0) {
                continue;
            }
            const auto &pending = found->second;
            pending->query_id = query_id;
            pending->headers = {make_header(":method", "POST"),
                                make_header(":scheme", "https"),
                                make_header(":authority", pending->authority),
                                make_header(":path", pending->path),
                                make_header("accept", "application/dns-message"),
                                make_header("content-type", "application/dns-message"),
                                make_header("content-length", pending->content_length)};
            nghttp2_data_provider2 provider{};
            provider.source.ptr = pending.get();
            provider.read_callback = &read_body;
            pending->stream_id =
                nghttp2_submit_request2(http2_session_, nullptr, pending->headers.data(),
                                        pending->headers.size(), &provider, this);
            if (pending->stream_id < 0) {
                pending->callback_error = "failed to submit DoH2 DNS request";
                pending->response_complete = true;
            } else {
                stream_queries_.emplace(pending->stream_id, query_id);
            }
        }
    }

    void send_pending() {
        if (stopped_ || retired_ || http2_session_ == nullptr || write_in_progress_) {
            return;
        }
        const uint8_t *data = nullptr;
        const auto size = nghttp2_session_mem_send2(http2_session_, &data);
        if (size < 0) {
            connection_failed(protocol_error("failed to serialize DoH2 frames"),
                              connection_generation_);
            return;
        }
        if (size == 0) {
            read_response();
            return;
        }
        pending_write_.assign(data, data + size);
        write_in_progress_ = true;
        auto self = shared_from_this();
        boost::asio::async_write(*ssl_stream_, boost::asio::buffer(pending_write_),
                                 [self](const boost::system::error_code &error, std::size_t) {
                                     self->write_in_progress_ = false;
                                     if (self->stopped_ || self->retired_) {
                                         return;
                                     }
                                     if (error) {
                                         self->connection_failed(
                                             io_error("failed to send DoH2 DNS request", error),
                                             self->connection_generation_);
                                         return;
                                     }
                                     self->send_pending();
                                 });
    }

    void read_response() {
        if (stopped_ || retired_ || !connected_ || read_in_progress_) {
            return;
        }
        read_in_progress_ = true;
        auto self = shared_from_this();
        ssl_stream_->async_read_some(
            boost::asio::buffer(read_buffer_),
            [self](const boost::system::error_code &error, std::size_t size) {
                self->read_in_progress_ = false;
                if (self->stopped_ || self->retired_) {
                    return;
                }
                if (error) {
                    self->connection_failed(io_error("failed to receive DoH2 DNS response", error),
                                            self->connection_generation_);
                    return;
                }
                const auto consumed = nghttp2_session_mem_recv2(self->http2_session_,
                                                                self->read_buffer_.data(), size);
                if (consumed < 0) {
                    self->connection_failed(protocol_error("invalid DoH2 response frames"),
                                            self->connection_generation_);
                    return;
                }
                self->finish_ready();
                self->send_pending();
                if (!self->write_in_progress_) {
                    self->read_response();
                }
            });
    }

    void finish_ready() {
        std::vector<std::int32_t> ready;
        for (const auto &[query_id, pending] : pending_) {
            if (pending->response_complete && !pending->completed) {
                ready.push_back(query_id);
            }
        }
        for (const auto query_id : ready) {
            finish_pending(query_id);
        }
    }

    void finish_pending(std::uint16_t query_id) {
        const auto found = pending_.find(query_id);
        if (found == pending_.end() || found->second->completed) {
            return;
        }
        const auto pending = found->second;
        core::Result<std::vector<std::uint8_t>> result =
            core::fail(protocol_error("DoH2 DNS exchange did not produce a valid response"));
        if (pending->callback_error.empty() && pending->status == "200") {
            const auto content_type =
                pending->content_type.substr(0, pending->content_type.find(';'));
            if (content_type == "application/dns-message") {
                result = pending->response_body;
            } else {
                result =
                    core::fail(protocol_error("DoH2 upstream returned an invalid content type"));
            }
        } else if (!pending->callback_error.empty()) {
            result = core::fail(protocol_error(pending->callback_error));
        } else if (pending->status != "200") {
            result = core::fail(protocol_error("DoH2 upstream returned a non-success status"));
        }
        pending->completed = true;
        pending->timer.cancel();
        auto handler = std::move(pending->handler);
        if (handler) {
            handler(std::move(result));
        }
        if (pending->stream_closed) {
            pending_.erase(query_id);
        }
    }

    void fail_pending(std::uint16_t query_id, core::Error error) {
        const auto found = pending_.find(query_id);
        if (found == pending_.end() || found->second->completed) {
            return;
        }
        const auto pending = found->second;
        pending->completed = true;
        pending->timer.cancel();
        if (http2_session_ != nullptr && pending->stream_id > 0) {
            nghttp2_submit_rst_stream(http2_session_, NGHTTP2_FLAG_NONE, pending->stream_id,
                                      NGHTTP2_CANCEL);
        }
        auto handler = std::move(pending->handler);
        if (handler) {
            handler(core::fail(std::move(error)));
        }
    }

    void fail_all(const core::Error &error) {
        std::vector<Handler> handlers;
        handlers.reserve(pending_.size());
        for (auto &[stream_id, pending] : pending_) {
            pending->timer.cancel();
            if (!pending->completed && pending->handler) {
                pending->completed = true;
                handlers.push_back(std::move(pending->handler));
            }
        }
        pending_.clear();
        stream_queries_.clear();
        queued_queries_.clear();
        for (auto &handler : handlers) {
            handler(core::fail(error));
        }
    }

    void connection_failed(core::Error error, std::uint64_t generation) {
        if (generation != connection_generation_ || stopped_) {
            return;
        }
        retired_ = true;
        close_connection();
        close_http2();
        fail_all(error);
    }

    void close_http2() noexcept {
        if (http2_session_) {
            nghttp2_session_del(http2_session_);
            http2_session_ = nullptr;
        }
    }

    void close_connection() noexcept {
        ++connection_generation_;
        connecting_ = false;
        connected_ = false;
        write_in_progress_ = false;
        read_in_progress_ = false;
        boost::system::error_code ignored;
        if (ssl_stream_) {
            ssl_stream_->next_layer().close();
            ssl_stream_.reset();
        }
    }

    runtime::AsioRuntime &runtime_;
    boost::asio::ip::tcp::endpoint endpoint_;
    std::string server_name_;
    std::string authority_;
    std::string path_;
    bool verify_peer_;
    boost::asio::ssl::context ssl_context_;
    using SslStream = boost::asio::ssl::stream<StreamHandleAdapter>;
    std::shared_ptr<DnsUpstreamDialer> dialer_;
    std::unique_ptr<SslStream> ssl_stream_;
    nghttp2_session *http2_session_ = nullptr;
    std::unordered_map<std::uint16_t, PendingPtr> pending_;
    std::unordered_map<std::int32_t, std::uint16_t> stream_queries_;
    std::deque<std::uint16_t> queued_queries_;
    std::array<std::uint8_t, 16384> read_buffer_{};
    std::vector<std::uint8_t> pending_write_;
    std::uint64_t connection_generation_ = 0;
    bool connecting_ = false;
    bool connected_ = false;
    bool write_in_progress_ = false;
    bool read_in_progress_ = false;
    bool retired_ = false;
    bool stopped_ = false;
};

class Doh2DnsTransport::Operation final
    : public std::enable_shared_from_this<Doh2DnsTransport::Operation> {
  public:
    Operation(Doh2DnsTransport &owner, ExchangeId exchange_id, DnsExchangeRequest request,
              Handler handler)
        : owner_(owner), exchange_id_(exchange_id), request_(std::move(request)),
          handler_(std::move(handler)) {}

    void start() {
        if (std::chrono::steady_clock::now() >= request_.deadline) {
            finish(core::fail(timeout_error()));
            return;
        }
        const auto query_id = owner_.next_query_id();
        if (!query_id) {
            finish(core::fail({core::ErrorCode::configuration,
                               "DoH2 transport has no available transaction IDs"}));
            return;
        }
        query_id_ = *query_id;
        owner_.active_query_ids_.insert(query_id_);
        const auto encoded = DnsMessageCodec::rewrite_id(request_.query, query_id_);
        if (!encoded) {
            finish(core::fail(encoded.error()));
            return;
        }
        query_wire_ = encoded.value();
        session_ = owner_.session();
        if (!session_) {
            finish(core::fail(
                {core::ErrorCode::configuration, "DoH2 transport session is not available"}));
            return;
        }
        auto self = shared_from_this();
        session_->exchange(query_id_, query_wire_, request_.deadline,
                           [self](core::Result<std::vector<std::uint8_t>> result) {
                               self->session_finished(std::move(result));
                           });
        exchange_started_ = true;
    }

    void cancel() {
        if (completed_) {
            return;
        }
        completed_ = true;
        close_session_exchange();
        owner_.complete(exchange_id_, core::fail(cancelled_error()));
    }

    Handler take_handler() { return std::move(handler_); }
    std::uint16_t query_id() const noexcept { return query_id_; }

  private:
    void session_finished(core::Result<std::vector<std::uint8_t>> result) {
        exchange_started_ = false;
        if (completed_) {
            return;
        }
        if (!result) {
            finish(core::fail(result.error()));
            return;
        }
        const auto response = DnsMessageCodec::decode_packet(result.value(), query_id_);
        if (!response) {
            finish(core::fail(response.error()));
            return;
        }
        if (!matches_question(response.value())) {
            finish(core::fail({core::ErrorCode::protocol_framing,
                               "DoH2 response question does not match the query"}));
            return;
        }
        finish(response);
    }

    bool matches_question(const DnsPacket &response) const {
        if (!response.response() || response.questions.size() != request_.query.questions.size()) {
            return false;
        }
        return std::equal(response.questions.begin(), response.questions.end(),
                          request_.query.questions.begin(),
                          [](const DnsQuestion &actual, const DnsQuestion &expected) {
                              return normalize_name(actual.name) == normalize_name(expected.name) &&
                                     actual.type == expected.type &&
                                     actual.class_code == expected.class_code;
                          });
    }

    void close_session_exchange() noexcept {
        if (session_ && exchange_started_) {
            session_->cancel(query_id_);
            exchange_started_ = false;
        }
    }

    void finish(core::Result<DnsPacket> result) {
        if (completed_) {
            return;
        }
        completed_ = true;
        close_session_exchange();
        owner_.complete(exchange_id_, std::move(result));
    }

    Doh2DnsTransport &owner_;
    ExchangeId exchange_id_;
    DnsExchangeRequest request_;
    Handler handler_;
    std::shared_ptr<Session> session_;
    std::vector<std::uint8_t> query_wire_;
    std::uint16_t query_id_ = 0;
    bool exchange_started_ = false;
    bool completed_ = false;
};

std::optional<std::uint16_t> Doh2DnsTransport::next_query_id() noexcept {
    for (std::size_t attempt = 0; attempt < 0xffff; ++attempt) {
        const auto query_id = next_query_id_++;
        if (next_query_id_ == 0) {
            next_query_id_ = 1;
        }
        if (query_id != 0 && !active_query_ids_.contains(query_id)) {
            return query_id;
        }
    }
    return std::nullopt;
}

std::shared_ptr<Doh2DnsTransport::Session> Doh2DnsTransport::session() {
    if (stopped_) {
        return nullptr;
    }
    if (!session_ || session_->retired()) {
        const auto endpoint = config_.tcp_endpoint.value_or(boost::asio::ip::tcp::endpoint(
            config_.endpoint.address(),
            config_.endpoint.port() == 53 ? 443 : config_.endpoint.port()));
        const auto server_name =
            config_.server_name.empty() ? endpoint.address().to_string() : config_.server_name;
        const auto authority = config_.doh_authority.empty()
                                   ? (config_.server_name.empty() ? endpoint.address().to_string()
                                                                  : config_.server_name)
                                   : config_.doh_authority;
        session_ = std::make_shared<Session>(runtime_, endpoint, server_name, authority,
                                             config_.doh_path, config_.verify_peer, config_.dialer);
    }
    return session_;
}

DnsTransport::ExchangeId Doh2DnsTransport::exchange(DnsExchangeRequest request, Handler handler) {
    const auto exchange_id = next_exchange_id_++;
    auto operation =
        std::make_shared<Operation>(*this, exchange_id, std::move(request), std::move(handler));
    operations_.emplace(exchange_id, operation);
    if (stopped_) {
        operation->cancel();
    } else {
        operation->start();
    }
    return exchange_id;
}

void Doh2DnsTransport::cancel(ExchangeId exchange_id) noexcept {
    const auto operation = operations_.find(exchange_id);
    if (operation != operations_.end()) {
        operation->second->cancel();
    }
}

void Doh2DnsTransport::stop() noexcept {
    if (stopped_) {
        return;
    }
    stopped_ = true;
    if (session_) {
        session_->stop();
    }
    while (!operations_.empty()) {
        operations_.begin()->second->cancel();
    }
}

void Doh2DnsTransport::complete(ExchangeId exchange_id, core::Result<DnsPacket> result) {
    const auto operation = operations_.find(exchange_id);
    if (operation == operations_.end()) {
        return;
    }
    auto current = std::move(operation->second);
    operations_.erase(operation);
    active_query_ids_.erase(current->query_id());
    auto handler = current->take_handler();
    if (handler) {
        handler(std::move(result));
    }
}

std::shared_ptr<DnsTransport> make_doh2_dns_transport(runtime::AsioRuntime &runtime,
                                                      DnsUpstreamConfig config) {
    return std::make_shared<Doh2DnsTransport>(runtime, std::move(config));
}

} // namespace clash_native::dns
