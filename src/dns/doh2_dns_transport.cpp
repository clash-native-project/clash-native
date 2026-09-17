#include <clash_native/dns/dns_codec.hpp>
#include <clash_native/dns/dns_transport.hpp>

#include "builtin_ca_bundle.hpp"
#include "stream_handle_adapter.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/ssl.hpp>

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

std::string_view trim_ascii(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1);
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
        value.remove_suffix(1);
    }
    return value;
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

class Doh2DnsTransport::Session final : public std::enable_shared_from_this<Session> {
  public:
    using Handler = std::function<void(core::Result<std::vector<std::uint8_t>>)>;
    using SslStream = boost::asio::ssl::stream<StreamHandleAdapter>;

    Session(runtime::AsioRuntime &runtime, boost::asio::ip::tcp::endpoint endpoint,
            std::string server_name, std::string authority, std::string path, bool verify_peer,
            std::shared_ptr<DnsUpstreamDialer> dialer)
        : runtime_(runtime), endpoint_(std::move(endpoint)), server_name_(std::move(server_name)),
          authority_(std::move(authority)), path_(std::move(path)), verify_peer_(verify_peer),
          ssl_context_(boost::asio::ssl::context::tls_client), dialer_(std::move(dialer)) {}

    ~Session() { close_http2(); }

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
        if (path_.empty() || path_.front() != '/' ||
            std::any_of(path_.begin(), path_.end(),
                        [](unsigned char value) { return value <= 0x20 || value == 0x7f; })) {
            complete_immediately(std::move(handler),
                                 core::Error{core::ErrorCode::configuration,
                                             "DoH2 path is not a valid origin-form target"});
            return;
        }

        auto pending = std::make_shared<Pending>(runtime_.context());
        pending->query_id = query_id;
        pending->query_wire = std::move(query);
        pending->handler = std::move(handler);
        pending->timer.expires_at(deadline);
        const auto self = shared_from_this();
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
        std::string status;
        std::string content_type;
        Handler handler;
        boost::asio::steady_timer timer;
        std::size_t body_offset = 0;
        std::int32_t stream_id = -1;
        bool completed = false;
        bool response_too_large = false;
    };

    using PendingPtr = std::shared_ptr<Pending>;

    static Session *from_user_data(void *user_data) noexcept {
        return static_cast<Session *>(user_data);
    }

    static nghttp2_ssize read_request_body(nghttp2_session *, std::int32_t, std::uint8_t *buffer,
                                           std::size_t length, std::uint32_t *flags,
                                           nghttp2_data_source *source, void *) {
        auto *pending = static_cast<Pending *>(source->ptr);
        if (pending == nullptr || pending->completed ||
            pending->body_offset > pending->query_wire.size()) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        const auto remaining = pending->query_wire.size() - pending->body_offset;
        const auto amount = std::min(length, remaining);
        if (amount != 0) {
            std::memcpy(buffer, pending->query_wire.data() + pending->body_offset, amount);
            pending->body_offset += amount;
        }
        if (pending->body_offset == pending->query_wire.size()) {
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
        auto *self = from_user_data(user_data);
        const auto found = self->stream_queries_.find(frame->hd.stream_id);
        if (found == self->stream_queries_.end()) {
            return 0;
        }
        const auto pending_it = self->pending_.find(found->second);
        if (pending_it == self->pending_.end()) {
            return 0;
        }
        const std::string_view header_name(reinterpret_cast<const char *>(name), name_length);
        const std::string_view header_value(reinterpret_cast<const char *>(value), value_length);
        if (header_name == ":status") {
            pending_it->second->status.assign(header_value);
        } else if (header_name == "content-type") {
            pending_it->second->content_type = lower_copy(header_value);
        }
        return 0;
    }

    static int on_data_chunk(nghttp2_session *, std::uint8_t, std::int32_t stream_id,
                             const std::uint8_t *data, std::size_t length, void *user_data) {
        auto *self = from_user_data(user_data);
        const auto stream = self->stream_queries_.find(stream_id);
        if (stream == self->stream_queries_.end()) {
            return 0;
        }
        const auto pending = self->pending_.find(stream->second);
        if (pending == self->pending_.end()) {
            return 0;
        }
        if (pending->second->response_body.size() + length > 0xffff) {
            pending->second->response_too_large = true;
            return 0;
        }
        pending->second->response_body.insert(pending->second->response_body.end(), data,
                                              data + length);
        return 0;
    }

    static int on_frame_received(nghttp2_session *, const nghttp2_frame *frame, void *user_data) {
        if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) == 0) {
            return 0;
        }
        auto *self = from_user_data(user_data);
        const auto stream = self->stream_queries_.find(frame->hd.stream_id);
        if (stream != self->stream_queries_.end()) {
            self->finish_pending(stream->second);
        }
        return 0;
    }

    static int on_stream_closed(nghttp2_session *, std::int32_t stream_id, std::uint32_t error_code,
                                void *user_data) {
        auto *self = from_user_data(user_data);
        const auto stream = self->stream_queries_.find(stream_id);
        if (stream == self->stream_queries_.end()) {
            return 0;
        }
        const auto query_id = stream->second;
        self->stream_queries_.erase(stream);
        self->stream_pending_.erase(stream_id);
        const auto pending = self->pending_.find(query_id);
        if (pending != self->pending_.end() && !pending->second->completed &&
            error_code != NGHTTP2_NO_ERROR) {
            self->fail_pending(query_id,
                               protocol_error("DoH2 response stream closed with an HTTP/2 error"));
        } else if (pending != self->pending_.end() && !pending->second->completed) {
            self->fail_pending(query_id,
                               protocol_error("DoH2 response stream closed before END_STREAM"));
        }
        return 0;
    }

    void complete_immediately(Handler handler, core::Error error) {
        boost::asio::post(runtime_.context(),
                          [handler = std::move(handler), error = std::move(error)]() mutable {
                              if (handler) {
                                  handler(core::fail(std::move(error)));
                              }
                          });
    }

    bool configure_tls(std::uint64_t generation) {
        boost::system::error_code error;
        if (verify_peer_) {
            const auto roots = detail::builtin_ca_bundle_pem();
            ssl_context_.add_certificate_authority(boost::asio::buffer(roots.data(), roots.size()),
                                                   error);
            if (error) {
                connection_failed(io_error("failed to load embedded DoH2 trust roots", error),
                                  generation);
                return false;
            }
        }
        ssl_stream_->set_verify_mode(verify_peer_ ? boost::asio::ssl::verify_peer
                                                  : boost::asio::ssl::verify_none);
        if (!server_name_.empty() &&
            SSL_set_tlsext_host_name(ssl_stream_->native_handle(), server_name_.c_str()) != 1) {
            connection_failed(
                {core::ErrorCode::configuration, "failed to configure DoH2 server name"},
                generation);
            return false;
        }
        if (verify_peer_) {
            ssl_stream_->set_verify_callback(
                boost::asio::ssl::host_name_verification(server_name_));
        }
        static constexpr unsigned char alpn[] = {2, 'h', '2'};
        if (SSL_set_alpn_protos(ssl_stream_->native_handle(), alpn, sizeof(alpn)) != 0) {
            connection_failed({core::ErrorCode::configuration, "failed to configure DoH2 ALPN"},
                              generation);
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
        const auto self = shared_from_this();
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
                if (self->configure_tls(generation)) {
                    self->handshake(generation);
                }
            });
    }

    void handshake(std::uint64_t generation) {
        const auto self = shared_from_this();
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

    bool start_http2(std::uint64_t generation) {
        nghttp2_session_callbacks *callbacks = nullptr;
        if (nghttp2_session_callbacks_new(&callbacks) != 0) {
            connection_failed(protocol_error("failed to allocate nghttp2 callbacks"), generation);
            return false;
        }
        nghttp2_session_callbacks_set_on_header_callback(callbacks, &on_header);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, &on_data_chunk);
        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, &on_frame_received);
        nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, &on_stream_closed);
        const auto created = nghttp2_session_client_new2(&http2_session_, callbacks, this, nullptr);
        nghttp2_session_callbacks_del(callbacks);
        if (created != 0) {
            connection_failed(protocol_error("failed to create nghttp2 client session"),
                              generation);
            return false;
        }
        const int settings_result =
            nghttp2_submit_settings(http2_session_, NGHTTP2_FLAG_NONE, nullptr, 0);
        if (settings_result != 0) {
            connection_failed(protocol_error("failed to submit HTTP/2 client settings"),
                              generation);
            return false;
        }
        connecting_ = false;
        connected_ = true;
        submit_queued_requests();
        send_pending();
        read_response();
        return true;
    }

    static nghttp2_nv make_header(const char *name, const std::string &value) {
        return {reinterpret_cast<std::uint8_t *>(const_cast<char *>(name)),
                reinterpret_cast<std::uint8_t *>(const_cast<char *>(value.data())),
                std::strlen(name), value.size(), NGHTTP2_NV_FLAG_NONE};
    }

    static nghttp2_nv make_static_header(const char *name, const char *value) {
        return {reinterpret_cast<std::uint8_t *>(const_cast<char *>(name)),
                reinterpret_cast<std::uint8_t *>(const_cast<char *>(value)), std::strlen(name),
                std::strlen(value), NGHTTP2_NV_FLAG_NONE};
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
                found->second->stream_id >= 0) {
                continue;
            }
            const auto &pending = found->second;
            const auto content_length = std::to_string(pending->query_wire.size());
            std::array<nghttp2_nv, 7> headers{
                make_static_header(":method", "POST"),
                make_static_header(":scheme", "https"),
                make_header(":authority", authority_),
                make_header(":path", path_),
                make_static_header("accept", "application/dns-message"),
                make_static_header("content-type", "application/dns-message"),
                make_header("content-length", content_length),
            };
            nghttp2_data_provider2 provider{};
            provider.source.ptr = pending.get();
            provider.read_callback = &read_request_body;
            const auto stream_id = nghttp2_submit_request2(
                http2_session_, nullptr, headers.data(), headers.size(), &provider, pending.get());
            if (stream_id < 0) {
                fail_pending(query_id,
                             protocol_error("failed to submit DoH2 DNS request to nghttp2"));
                continue;
            }
            pending->stream_id = stream_id;
            stream_queries_.emplace(stream_id, query_id);
            stream_pending_.emplace(stream_id, pending);
        }
    }

    void send_pending() {
        if (stopped_ || retired_ || !connected_ || write_in_progress_ ||
            http2_session_ == nullptr) {
            return;
        }
        const std::uint8_t *data = nullptr;
        const auto length = nghttp2_session_mem_send2(http2_session_, &data);
        if (length < 0) {
            connection_failed(protocol_error("nghttp2 failed to serialize HTTP/2 frames"),
                              connection_generation_);
            return;
        }
        if (length == 0) {
            return;
        }
        pending_write_.assign(data, data + length);
        write_in_progress_ = true;
        const auto self = shared_from_this();
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
        const auto self = shared_from_this();
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
                if (consumed < 0 || static_cast<std::size_t>(consumed) != size) {
                    self->connection_failed(protocol_error("invalid DoH2 response frames"),
                                            self->connection_generation_);
                    return;
                }
                self->send_pending();
                self->read_response();
            });
    }

    void finish_pending(std::uint16_t query_id) {
        const auto found = pending_.find(query_id);
        if (found == pending_.end() || found->second->completed) {
            return;
        }
        const auto pending = found->second;
        core::Result<std::vector<std::uint8_t>> result =
            core::fail(protocol_error("DoH2 DNS exchange did not produce a valid response"));
        const auto content_type = trim_ascii(
            std::string_view(pending->content_type).substr(0, pending->content_type.find(';')));
        if (pending->response_too_large) {
            result = core::fail(protocol_error("DoH2 DNS response exceeds message capacity"));
        } else if (pending->status == "200" && content_type == "application/dns-message" &&
                   !pending->response_body.empty()) {
            result = std::move(pending->response_body);
        } else if (pending->status != "200") {
            result = core::fail(protocol_error("DoH2 upstream returned a non-success status"));
        } else if (content_type != "application/dns-message") {
            result = core::fail(protocol_error("DoH2 upstream returned an invalid content type"));
        } else {
            result = core::fail(protocol_error("DoH2 upstream returned an empty DNS message"));
        }
        pending->completed = true;
        pending->timer.cancel();
        pending_.erase(found);
        auto handler = std::move(pending->handler);
        if (handler) {
            handler(std::move(result));
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
        if (http2_session_ && pending->stream_id >= 0) {
            (void)nghttp2_submit_rst_stream(http2_session_, NGHTTP2_FLAG_NONE, pending->stream_id,
                                            NGHTTP2_CANCEL);
        } else if (pending->stream_id >= 0) {
            stream_queries_.erase(pending->stream_id);
            stream_pending_.erase(pending->stream_id);
        }
        pending_.erase(found);
        auto handler = std::move(pending->handler);
        if (handler) {
            handler(core::fail(std::move(error)));
        }
        send_pending();
    }

    void fail_all(const core::Error &error) {
        std::vector<Handler> handlers;
        handlers.reserve(pending_.size());
        for (auto &[query_id, pending] : pending_) {
            pending->timer.cancel();
            if (!pending->completed && pending->handler) {
                pending->completed = true;
                handlers.push_back(std::move(pending->handler));
            }
        }
        pending_.clear();
        stream_queries_.clear();
        stream_pending_.clear();
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
    std::shared_ptr<DnsUpstreamDialer> dialer_;
    std::unique_ptr<SslStream> ssl_stream_;
    nghttp2_session *http2_session_ = nullptr;
    std::unordered_map<std::uint16_t, PendingPtr> pending_;
    std::unordered_map<std::int32_t, std::uint16_t> stream_queries_;
    std::unordered_map<std::int32_t, PendingPtr> stream_pending_;
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
        const auto self = shared_from_this();
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
