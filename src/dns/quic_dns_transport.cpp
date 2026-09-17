#include <clash_native/dns/dns_codec.hpp>
#include <clash_native/dns/dns_transport.hpp>

#include "builtin_ca_bundle.hpp"

#include <boost/asio/bind_executor.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstring>
#include <deque>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace clash_native::dns {

namespace {

using Clock = std::chrono::steady_clock;
constexpr std::size_t kMaximumIdleQuicSessions = 4;
constexpr std::size_t kMaximumConcurrentExchangesPerSession = 64;
constexpr auto kMinimumQuicHandshakeTimeout = std::chrono::seconds(30);
constexpr std::uint64_t kDoqRequestCancelled = 0x3;
constexpr std::uint64_t kHttp3RequestCancelled = 0x10c;

core::Error transport_error(std::string context) {
    return {core::ErrorCode::transport_io, std::move(context)};
}

core::Error protocol_error(std::string context) {
    return {core::ErrorCode::protocol_framing, std::move(context)};
}

core::Error timeout_error() { return {core::ErrorCode::timeout, "QUIC DNS query timed out"}; }

core::Error cancelled_error() {
    return {core::ErrorCode::cancelled, "QUIC DNS query was cancelled"};
}

core::Error upstream_error(std::string context, const boost::system::error_code &error) {
    return {core::ErrorCode::transport_io, std::move(context),
            std::error_code(error.value(), std::system_category())};
}

std::string lower_copy(std::string_view value) {
    std::string result(value);
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}

bool same_question(const DnsPacket &response, const DnsPacket &query) {
    if (!response.response() || response.questions.size() != query.questions.size()) {
        return false;
    }
    return std::equal(response.questions.begin(), response.questions.end(), query.questions.begin(),
                      [](const DnsQuestion &left, const DnsQuestion &right) {
                          return normalize_name(left.name) == normalize_name(right.name) &&
                                 left.type == right.type && left.class_code == right.class_code;
                      });
}

std::uint64_t timestamp_now() noexcept {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch())
            .count());
}

std::uint16_t remote_port(const DnsUpstreamConfig &config) {
    if (config.endpoint.port() != 53) {
        return config.endpoint.port();
    }
    return config.mode == DnsTransportMode::doq ? std::uint16_t{853} : std::uint16_t{443};
}

std::string remote_name(const DnsUpstreamConfig &config) {
    if (!config.server_name.empty()) {
        return config.server_name;
    }
    if (!config.hostname.empty()) {
        return config.hostname;
    }
    return config.endpoint.address().to_string();
}

std::string authority(const DnsUpstreamConfig &config, std::string host, std::uint16_t port) {
    if (!config.doh_authority.empty()) {
        return config.doh_authority;
    }
    if (host.find(':') != std::string::npos && host.front() != '[') {
        host = '[' + host + ']';
    }
    if (port != 443) {
        host += ':' + std::to_string(port);
    }
    return host;
}

} // namespace

class QuicDnsTransport final : public DnsTransport,
                               public std::enable_shared_from_this<QuicDnsTransport> {
  private:
    class Operation;

  public:
    QuicDnsTransport(runtime::AsioRuntime &runtime, DnsUpstreamConfig config)
        : runtime_(runtime), config_(std::move(config)), strand_(runtime.context().get_executor()) {
        if (!config_.dialer) {
            config_.dialer = make_direct_dns_upstream_dialer(runtime_);
        }
    }

    ExchangeId exchange(DnsExchangeRequest request, Handler handler) override;
    void cancel(ExchangeId exchange_id) noexcept override;
    void stop() noexcept override;

  private:
    struct ExchangeRegistration {
        std::shared_ptr<Operation> operation;
        Handler handler;
    };

    void complete(ExchangeId exchange_id, core::Result<DnsPacket> result);
    void session_idle(const std::shared_ptr<Operation> &operation);
    void session_retired(const Operation *operation) noexcept;
    void add_new_exchange(ExchangeId id, DnsExchangeRequest request, Handler handler);

    runtime::AsioRuntime &runtime_;
    DnsUpstreamConfig config_;
    boost::asio::strand<boost::asio::io_context::executor_type> strand_;
    std::unordered_map<ExchangeId, ExchangeRegistration> exchanges_;
    std::vector<std::shared_ptr<Operation>> active_sessions_;
    std::vector<std::shared_ptr<Operation>> idle_sessions_;
    std::atomic<ExchangeId> next_exchange_id_ = 1;
    bool stopped_ = false;

    friend class Operation;
};

class QuicDnsTransport::Operation final : public std::enable_shared_from_this<Operation> {
  public:
    struct Exchange {
        Exchange(ExchangeId exchange_id, DnsExchangeRequest exchange_request,
                 boost::asio::io_context &context)
            : id(exchange_id), request(std::move(exchange_request)), deadline_timer(context) {}

        ExchangeId id;
        DnsExchangeRequest request;
        boost::asio::steady_timer deadline_timer;
        std::int64_t stream_id = -1;
        std::vector<std::uint8_t> doq_request;
        std::vector<std::uint8_t> doq_response;
        std::size_t doq_offset = 0;
        bool doq_fin_submitted = false;
        bool doq_write_queued = false;
        bool stream_closed = false;
        std::size_t http3_request_offset = 0;
        std::vector<std::uint8_t> response_body;
        std::string response_status;
        std::string response_content_type;
        std::optional<core::Result<DnsPacket>> result;
    };

    explicit Operation(QuicDnsTransport &owner)
        : owner_(owner), expiry_timer_(owner.runtime_.context()),
          idle_timer_(owner.runtime_.context()), mode_(owner.config_.mode),
          host_(remote_name(owner.config_)), port_(remote_port(owner.config_)),
          authority_(authority(owner.config_, host_, port_)),
          path_(owner.config_.doh_path.empty() ? "/dns-query" : owner.config_.doh_path) {
        connection_ref_.get_conn = &get_connection;
        connection_ref_.user_data = this;
    }

    ~Operation() {
        if (datagram_) {
            datagram_->cancel();
            datagram_->close();
        }
        release_protocol();
    }

    bool can_accept_exchange() const noexcept {
        return !retired_ && exchanges_.size() < kMaximumConcurrentExchangesPerSession;
    }

    std::size_t active_exchange_count() const noexcept { return exchanges_.size(); }
    void close_idle() noexcept { retire_idle(); }
    bool is_idle() const noexcept { return idle_ && !retired_; }

  private:
    friend class QuicDnsTransport;

    static ngtcp2_conn *get_connection(ngtcp2_crypto_conn_ref *ref) noexcept {
        auto *self = static_cast<Operation *>(ref->user_data);
        return self->connection_;
    }

    static void random_bytes(std::uint8_t *data, std::size_t length,
                             const ngtcp2_rand_ctx *) noexcept {
        if (RAND_bytes(data, static_cast<int>(length)) != 1) {
            std::abort();
        }
    }

    static int get_new_connection_id(ngtcp2_conn *, ngtcp2_cid *cid,
                                     ngtcp2_stateless_reset_token *token, std::size_t cid_length,
                                     void *) noexcept {
        cid->datalen = cid_length;
        if (RAND_bytes(cid->data, static_cast<int>(cid_length)) != 1 ||
            RAND_bytes(token->data, sizeof(token->data)) != 1) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    static int on_handshake_completed(ngtcp2_conn *, void *user_data) {
        auto *self = static_cast<Operation *>(user_data);
        if (!self->check_selected_alpn()) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        self->handshake_completed_ = true;
        self->open_pending_exchanges_ = true;
        return 0;
    }

    static int on_stream_data(ngtcp2_conn *, std::uint32_t flags, std::int64_t stream_id,
                              std::uint64_t, const std::uint8_t *data, std::size_t length,
                              void *user_data, void *) {
        auto *self = static_cast<Operation *>(user_data);
        if (self->mode_ == DnsTransportMode::doq) {
            self->receive_doq(flags, stream_id, data, length);
            return 0;
        }
        return self->receive_http3(flags, stream_id, data, length);
    }

    static int on_acked_stream_data(ngtcp2_conn *, std::int64_t stream_id, std::uint64_t,
                                    std::uint64_t length, void *user_data, void *) {
        auto *self = static_cast<Operation *>(user_data);
        if (self->http3_ != nullptr &&
            nghttp3_conn_add_ack_offset(self->http3_, stream_id, length) != 0) {
            self->set_session_error(
                protocol_error("nghttp3 failed to acknowledge QUIC stream data"));
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    static int on_extend_max_stream_data(ngtcp2_conn *, std::int64_t stream_id, std::uint64_t,
                                         void *user_data, void *) {
        auto *self = static_cast<Operation *>(user_data);
        if (self->http3_ != nullptr && nghttp3_conn_unblock_stream(self->http3_, stream_id) != 0) {
            self->set_session_error(
                protocol_error("nghttp3 failed to unblock a QUIC request stream"));
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        if (self->mode_ == DnsTransportMode::doq) {
            const auto found = self->stream_exchanges_.find(stream_id);
            if (found != self->stream_exchanges_.end()) {
                self->doq_blocked_streams_.erase(stream_id);
                self->queue_doq_write(*found->second);
            }
        }
        return 0;
    }

    static int on_extend_max_local_streams_bidi(ngtcp2_conn *, std::uint64_t, void *user_data) {
        static_cast<Operation *>(user_data)->open_pending_exchanges_ = true;
        return 0;
    }

    static int on_stream_closed(ngtcp2_conn *, std::uint32_t, std::int64_t stream_id,
                                std::uint64_t app_error, void *user_data, void *) {
        auto *self = static_cast<Operation *>(user_data);
        if (self->http3_ != nullptr) {
            const auto result = nghttp3_conn_close_stream(self->http3_, stream_id, app_error);
            if (result != 0 && result != NGHTTP3_ERR_STREAM_NOT_FOUND) {
                self->set_session_error(protocol_error("nghttp3 failed to close a QUIC stream"));
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
        }
        self->stream_closed(stream_id);
        return 0;
    }

    static int on_http3_body(nghttp3_conn *, std::int64_t stream_id, const std::uint8_t *data,
                             std::size_t length, void *conn_user_data, void *) {
        auto *self = static_cast<Operation *>(conn_user_data);
        auto *exchange = self->find_stream_exchange(stream_id);
        if (exchange == nullptr || exchange->result) {
            return 0;
        }
        if (exchange->response_body.size() + length > 0xffff) {
            self->set_exchange_error(
                *exchange, protocol_error("DoH/HTTP/3 DNS response exceeds message capacity"));
            return 0;
        }
        exchange->response_body.insert(exchange->response_body.end(), data, data + length);
        return 0;
    }

    static int on_http3_header(nghttp3_conn *, std::int64_t stream_id, std::int32_t,
                               nghttp3_rcbuf *name, nghttp3_rcbuf *value, std::uint8_t,
                               void *conn_user_data, void *) {
        auto *self = static_cast<Operation *>(conn_user_data);
        auto *exchange = self->find_stream_exchange(stream_id);
        if (exchange == nullptr || exchange->result) {
            return 0;
        }
        const auto header_name = nghttp3_rcbuf_get_buf(name);
        const auto header_value = nghttp3_rcbuf_get_buf(value);
        const std::string_view name_view(reinterpret_cast<const char *>(header_name.base),
                                         header_name.len);
        const std::string_view value_view(reinterpret_cast<const char *>(header_value.base),
                                          header_value.len);
        if (name_view == ":status") {
            exchange->response_status.assign(value_view);
        } else if (name_view == "content-type") {
            exchange->response_content_type = lower_copy(value_view);
        }
        return 0;
    }

    static int on_http3_end_stream(nghttp3_conn *, std::int64_t stream_id, void *conn_user_data,
                                   void *) {
        auto *self = static_cast<Operation *>(conn_user_data);
        auto *exchange = self->find_stream_exchange(stream_id);
        if (exchange == nullptr || exchange->result) {
            return 0;
        }
        if (exchange->response_status != "200") {
            self->set_exchange_error(
                *exchange, protocol_error("DoH/HTTP/3 upstream returned a non-success status"));
            return 0;
        }
        const auto content_type = std::string_view(exchange->response_content_type)
                                      .substr(0, exchange->response_content_type.find(';'));
        if (content_type != "application/dns-message") {
            self->set_exchange_error(
                *exchange, protocol_error("DoH/HTTP/3 response has an invalid content type"));
            return 0;
        }
        self->decode_dns_response(*exchange, exchange->response_body);
        return 0;
    }

    static int on_http3_deferred_consume(nghttp3_conn *, std::int64_t stream_id,
                                         std::size_t consumed, void *conn_user_data, void *) {
        auto *self = static_cast<Operation *>(conn_user_data);
        if (ngtcp2_conn_extend_max_stream_offset(self->connection_, stream_id, consumed) != 0) {
            self->set_session_error(protocol_error("failed to extend QUIC flow-control credit"));
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        ngtcp2_conn_extend_max_offset(self->connection_, consumed);
        return 0;
    }

    static nghttp3_ssize read_http3_request(nghttp3_conn *, std::int64_t, nghttp3_vec *vectors,
                                            std::size_t vector_count, std::uint32_t *flags, void *,
                                            void *stream_user_data) {
        auto *exchange = static_cast<Exchange *>(stream_user_data);
        if (exchange == nullptr || vector_count == 0 ||
            exchange->http3_request_offset > exchange->request.query.wire.size()) {
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        const auto remaining = exchange->request.query.wire.size() - exchange->http3_request_offset;
        if (remaining == 0) {
            *flags |= NGHTTP3_DATA_FLAG_EOF;
            vectors[0] = {nullptr, 0};
            return 1;
        }
        vectors[0] = {const_cast<std::uint8_t *>(exchange->request.query.wire.data() +
                                                 exchange->http3_request_offset),
                      remaining};
        exchange->http3_request_offset += remaining;
        *flags |= NGHTTP3_DATA_FLAG_EOF;
        return 1;
    }

    static int on_crypto_data(ngtcp2_conn *connection, ngtcp2_encryption_level level,
                              std::uint64_t offset, const std::uint8_t *data, std::size_t length,
                              void *user_data) {
        return ngtcp2_crypto_recv_crypto_data_cb(connection, level, offset, data, length,
                                                 user_data);
    }

    static int on_update_key(ngtcp2_conn *connection, std::uint8_t *rx_secret,
                             std::uint8_t *tx_secret, ngtcp2_crypto_aead_ctx *rx_aead,
                             std::uint8_t *rx_iv, ngtcp2_crypto_aead_ctx *tx_aead,
                             std::uint8_t *tx_iv, const std::uint8_t *current_rx_secret,
                             const std::uint8_t *current_tx_secret, std::size_t secret_length,
                             void *) {
        return ngtcp2_crypto_update_key_cb(connection, rx_secret, tx_secret, rx_aead, rx_iv,
                                           tx_aead, tx_iv, current_rx_secret, current_tx_secret,
                                           secret_length, nullptr);
    }

    static int on_receive_reset(ngtcp2_conn *, std::int64_t stream_id, std::uint64_t,
                                std::uint64_t app_error, void *user_data, void *) {
        auto *self = static_cast<Operation *>(user_data);
        if (self->http3_ != nullptr &&
            nghttp3_conn_shutdown_stream_read(self->http3_, stream_id) != 0) {
            self->set_session_error(protocol_error("nghttp3 failed to handle a reset QUIC stream"));
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        if (auto *exchange = self->find_stream_exchange(stream_id);
            exchange != nullptr && !exchange->result) {
            self->set_exchange_error(*exchange,
                                     transport_error("QUIC upstream reset DNS stream with code " +
                                                     std::to_string(app_error)));
        }
        return 0;
    }

    void start_on_strand() {
        if (started_ || retired_ || exchanges_.empty()) {
            return;
        }
        started_ = true;
        const auto self = shared_from_this();
        const auto destination =
            core::Destination::address(owner_.config_.endpoint.address(), port_);
        owner_.config_.dialer->open_datagram(
            {destination}, [self](core::DatagramOpenResult result) mutable {
                boost::asio::dispatch(self->owner_.strand_,
                                      [self, result = std::move(result)]() mutable {
                                          self->datagram_opened(std::move(result));
                                      });
            });
    }

    void add_exchange(ExchangeId id, DnsExchangeRequest request) {
        if (retired_) {
            owner_.complete(id, core::fail(transport_error("QUIC DNS session is retired")));
            return;
        }
        idle_timer_.cancel();
        idle_ = false;
        auto exchange =
            std::make_shared<Exchange>(id, std::move(request), owner_.runtime_.context());
        exchanges_.emplace(id, exchange);
        const auto &wire = exchange->request.query.wire;
        if (wire.size() < 12 || wire.size() > 0xffff) {
            set_exchange_error(*exchange,
                               protocol_error("QUIC DNS query has an invalid message length"));
            drain_exchange_results();
            return;
        }
        if (mode_ == DnsTransportMode::doh3 &&
            (path_.empty() || path_.front() != '/' ||
             std::any_of(path_.begin(), path_.end(),
                         [](unsigned char value) { return value <= 0x20 || value == 0x7f; }))) {
            set_exchange_error(*exchange,
                               core::Error{core::ErrorCode::configuration,
                                           "DoH/HTTP/3 path is not a valid origin-form target"});
            drain_exchange_results();
            return;
        }
        if (Clock::now() >= exchange->request.deadline) {
            set_exchange_error(*exchange, timeout_error());
            drain_exchange_results();
            return;
        }
        exchange->deadline_timer.expires_at(exchange->request.deadline);
        const auto self = shared_from_this();
        exchange->deadline_timer.async_wait(boost::asio::bind_executor(
            owner_.strand_, [self, id](const boost::system::error_code &error) {
                if (!error) {
                    self->cancel_exchange(id, timeout_error());
                }
            }));
        pending_exchanges_.push_back(id);
        if (handshake_completed_) {
            open_pending_exchanges_ = true;
            pump_open_pending_exchanges();
        }
        start_on_strand();
    }

    void cancel_exchange(ExchangeId id, core::Error error) {
        const auto found = exchanges_.find(id);
        if (found == exchanges_.end() || found->second->result) {
            return;
        }
        set_exchange_error(*found->second, std::move(error));
        drain_exchange_results();
    }

    void cancel_all() { fail_session(cancelled_error()); }

    void datagram_opened(core::DatagramOpenResult result) {
        if (retired_ || exchanges_.empty()) {
            if (result.handle) {
                result.handle->close();
            }
            if (!retired_) {
                retire_session();
            }
            return;
        }
        if (!result.succeeded()) {
            fail_session(result.error.value_or(
                core::Error{core::ErrorCode::endpoint_connection,
                            "QUIC DNS datagram dialer failed to open a handle"}));
            return;
        }
        datagram_ = std::move(result.handle);
        if (!initialize_protocol()) {
            fail_session(session_error_.value_or(core::Error{core::ErrorCode::carrier_handshake,
                                                             "failed to initialize QUIC DNS TLS"}));
            return;
        }
        receive_next();
        write_packets();
        schedule_expiry();
    }

    bool initialize_protocol() {
        ssl_context_ = SSL_CTX_new(TLS_client_method());
        if (ssl_context_ == nullptr ||
            ngtcp2_crypto_boringssl_configure_client_context(ssl_context_) != 0) {
            set_transport_failure("failed to initialize BoringSSL for QUIC");
            return false;
        }
        if (!load_trust_roots()) {
            return false;
        }
        ssl_ = SSL_new(ssl_context_);
        if (ssl_ == nullptr) {
            set_transport_failure("failed to allocate BoringSSL connection state");
            return false;
        }
        SSL_set_app_data(ssl_, &connection_ref_);
        SSL_set_connect_state(ssl_);
        if (!configure_tls_peer()) {
            return false;
        }

        ngtcp2_callbacks callbacks{};
        callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
        callbacks.recv_crypto_data = &on_crypto_data;
        callbacks.handshake_completed = &on_handshake_completed;
        callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
        callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
        callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
        callbacks.recv_stream_data = &on_stream_data;
        callbacks.acked_stream_data_offset = &on_acked_stream_data;
        callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
        callbacks.rand = &random_bytes;
        callbacks.update_key = &on_update_key;
        callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
        callbacks.get_new_connection_id2 = &get_new_connection_id;
        callbacks.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;
        callbacks.extend_max_stream_data = &on_extend_max_stream_data;
        callbacks.extend_max_local_streams_bidi = &on_extend_max_local_streams_bidi;
        callbacks.stream_close = &on_stream_closed;
        callbacks.stream_reset = &on_receive_reset;

        ngtcp2_cid destination_id{};
        destination_id.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
        ngtcp2_cid source_id{};
        source_id.datalen = 8;
        if (RAND_bytes(destination_id.data, static_cast<int>(destination_id.datalen)) != 1 ||
            RAND_bytes(source_id.data, static_cast<int>(source_id.datalen)) != 1) {
            set_transport_failure("failed to generate QUIC connection identifiers");
            return false;
        }

        const auto bind_address =
            owner_.config_.endpoint.address().is_v4()
                ? boost::asio::ip::address(boost::asio::ip::address_v4::any())
                : boost::asio::ip::address(boost::asio::ip::address_v6::any());
        local_endpoint_ = {bind_address, 0};
        remote_endpoint_ = {owner_.config_.endpoint.address(), port_};
        ngtcp2_path path{};
        ngtcp2_addr_init(&path.local,
                         const_cast<ngtcp2_sockaddr *>(
                             reinterpret_cast<const ngtcp2_sockaddr *>(local_endpoint_.data())),
                         static_cast<ngtcp2_socklen>(local_endpoint_.size()));
        ngtcp2_addr_init(&path.remote,
                         const_cast<ngtcp2_sockaddr *>(
                             reinterpret_cast<const ngtcp2_sockaddr *>(remote_endpoint_.data())),
                         static_cast<ngtcp2_socklen>(remote_endpoint_.size()));

        ngtcp2_settings settings;
        ngtcp2_settings_default(&settings);
        settings.initial_ts = timestamp_now();
        auto latest_deadline = Clock::time_point::min();
        for (const auto &[id, exchange] : exchanges_) {
            latest_deadline = std::max(latest_deadline, exchange->request.deadline);
        }
        const auto handshake_remaining = std::max(
            std::chrono::duration_cast<std::chrono::nanoseconds>(latest_deadline - Clock::now()),
            std::chrono::duration_cast<std::chrono::nanoseconds>(kMinimumQuicHandshakeTimeout));
        settings.handshake_timeout = static_cast<ngtcp2_duration>(handshake_remaining.count());

        ngtcp2_transport_params parameters;
        ngtcp2_transport_params_default(&parameters);
        parameters.initial_max_data = 1024 * 1024;
        parameters.initial_max_stream_data_bidi_local = 256 * 1024;
        parameters.initial_max_stream_data_bidi_remote = 256 * 1024;
        parameters.initial_max_stream_data_uni = 256 * 1024;
        parameters.initial_max_streams_bidi = 16;
        parameters.initial_max_streams_uni = 3;
        const int created = ngtcp2_conn_client_new(&connection_, &destination_id, &source_id, &path,
                                                   NGTCP2_PROTO_VER_V1, &callbacks, &settings,
                                                   &parameters, nullptr, this);
        if (created != 0) {
            set_transport_failure(std::string("ngtcp2 failed to create client connection: ") +
                                  ngtcp2_strerror(created));
            return false;
        }
        ngtcp2_conn_set_tls_native_handle(connection_, ssl_);
        return true;
    }

    bool load_trust_roots() {
        if (!owner_.config_.verify_peer) {
            SSL_CTX_set_verify(ssl_context_, SSL_VERIFY_NONE, nullptr);
            return true;
        }
        const auto pem = detail::builtin_ca_bundle_pem();
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(
            BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free);
        if (!bio) {
            set_authentication_failure("failed to read the embedded DNS CA bundle");
            return false;
        }
        auto *store = SSL_CTX_get_cert_store(ssl_context_);
        std::size_t roots = 0;
        while (X509 *certificate = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)) {
            if (X509_STORE_add_cert(store, certificate) != 1) {
                ERR_clear_error();
            }
            X509_free(certificate);
            ++roots;
        }
        ERR_clear_error();
        if (roots == 0) {
            set_authentication_failure("the embedded DNS CA bundle contains no certificates");
            return false;
        }
        SSL_CTX_set_verify(ssl_context_, SSL_VERIFY_PEER, nullptr);
        return true;
    }

    bool configure_tls_peer() {
        boost::system::error_code address_error;
        (void)boost::asio::ip::make_address(host_, address_error);
        if (address_error) {
            if (SSL_set_tlsext_host_name(ssl_, host_.c_str()) != 1) {
                set_authentication_failure("failed to set QUIC DNS server name");
                return false;
            }
        }
        if (owner_.config_.verify_peer) {
            auto *parameters = SSL_get0_param(ssl_);
            const int configured =
                address_error ? X509_VERIFY_PARAM_set1_host(parameters, host_.c_str(), host_.size())
                              : X509_VERIFY_PARAM_set1_ip_asc(parameters, host_.c_str());
            if (configured != 1) {
                set_authentication_failure("failed to configure QUIC DNS certificate validation");
                return false;
            }
        }
        if (mode_ == DnsTransportMode::doq) {
            static constexpr std::uint8_t alpn[] = {3, 'd', 'o', 'q'};
            if (SSL_set_alpn_protos(ssl_, alpn, sizeof(alpn)) != 0) {
                set_authentication_failure("failed to configure DoQ ALPN");
                return false;
            }
        } else {
            static constexpr std::uint8_t alpn[] = {2, 'h', '3'};
            if (SSL_set_alpn_protos(ssl_, alpn, sizeof(alpn)) != 0) {
                set_authentication_failure("failed to configure HTTP/3 ALPN");
                return false;
            }
        }
        return true;
    }

    bool check_selected_alpn() {
        const unsigned char *protocol = nullptr;
        unsigned int protocol_length = 0;
        SSL_get0_alpn_selected(ssl_, &protocol, &protocol_length);
        const std::string_view expected = mode_ == DnsTransportMode::doq ? "doq" : "h3";
        if (protocol_length != expected.size() ||
            !std::equal(protocol, protocol + protocol_length, expected.begin())) {
            set_authentication_failure("QUIC DNS upstream negotiated an unexpected ALPN");
            return false;
        }
        return true;
    }

    bool initialize_http3() {
        if (http3_ == nullptr) {
            nghttp3_callbacks callbacks{};
            callbacks.recv_data = &on_http3_body;
            callbacks.deferred_consume = &on_http3_deferred_consume;
            callbacks.recv_header = &on_http3_header;
            callbacks.end_stream = &on_http3_end_stream;
            nghttp3_settings settings;
            nghttp3_settings_default(&settings);
            if (nghttp3_conn_client_new(&http3_, &callbacks, &settings, nghttp3_mem_default(),
                                        this) != 0) {
                set_protocol_failure("failed to create nghttp3 client connection");
                return false;
            }

            std::int64_t control_stream = -1;
            std::int64_t encoder_stream = -1;
            std::int64_t decoder_stream = -1;
            if (ngtcp2_conn_open_uni_stream(connection_, &control_stream, nullptr) != 0 ||
                ngtcp2_conn_open_uni_stream(connection_, &encoder_stream, nullptr) != 0 ||
                ngtcp2_conn_open_uni_stream(connection_, &decoder_stream, nullptr) != 0 ||
                nghttp3_conn_bind_control_stream(http3_, control_stream) != 0 ||
                nghttp3_conn_bind_qpack_streams(http3_, encoder_stream, decoder_stream) != 0) {
                set_protocol_failure("failed to initialize HTTP/3 control and QPACK streams");
                return false;
            }
        }
        return true;
    }

    void pump_open_pending_exchanges() {
        if (!open_pending_exchanges_ || !handshake_completed_ || retired_ ||
            connection_ == nullptr) {
            return;
        }
        open_pending_exchanges_ = false;
        if (mode_ == DnsTransportMode::doh3 && !initialize_http3()) {
            fail_session(session_error_.value_or(
                core::Error{core::ErrorCode::protocol_framing,
                            "failed to initialize HTTP/3 connection state"}));
            return;
        }
        while (!pending_exchanges_.empty() && !retired_) {
            const auto id = pending_exchanges_.front();
            const auto active = exchanges_.find(id);
            if (active == exchanges_.end()) {
                pending_exchanges_.pop_front();
                continue;
            }
            const auto &exchange = active->second;
            if (exchange->stream_id >= 0) {
                pending_exchanges_.pop_front();
                continue;
            }
            std::int64_t stream_id = -1;
            const auto opened = ngtcp2_conn_open_bidi_stream(connection_, &stream_id, nullptr);
            if (opened == NGTCP2_ERR_STREAM_ID_BLOCKED) {
                return;
            }
            if (opened != 0) {
                fail_session(
                    transport_error(std::string("ngtcp2 could not open a DNS request stream: ") +
                                    ngtcp2_strerror(opened)));
                return;
            }
            pending_exchanges_.pop_front();
            exchange->stream_id = stream_id;
            stream_exchanges_.emplace(stream_id, exchange);
            if (mode_ == DnsTransportMode::doq) {
                const auto &wire = exchange->request.query.wire;
                exchange->doq_request.reserve(wire.size() + 2);
                exchange->doq_request.push_back(static_cast<std::uint8_t>(wire.size() >> 8));
                exchange->doq_request.push_back(static_cast<std::uint8_t>(wire.size() & 0xff));
                exchange->doq_request.insert(exchange->doq_request.end(), wire.begin(), wire.end());
                exchange->doq_request[2] = 0;
                exchange->doq_request[3] = 0;
                queue_doq_write(*exchange);
                continue;
            }

            const auto content_length = std::to_string(exchange->request.query.wire.size());
            std::array<nghttp3_nv, 7> headers{
                make_header(":method", "POST"),
                make_header(":scheme", "https"),
                make_header(":authority", authority_),
                make_header(":path", path_),
                make_header("accept", "application/dns-message"),
                make_header("content-type", "application/dns-message"),
                make_header("content-length", content_length),
            };
            nghttp3_data_reader reader{&read_http3_request};
            if (nghttp3_conn_submit_request(http3_, stream_id, headers.data(), headers.size(),
                                            &reader, exchange.get()) != 0) {
                set_exchange_error(*exchange,
                                   protocol_error("failed to submit DoH/HTTP/3 DNS request"));
            }
        }
        drain_exchange_results();
        if (!retired_) {
            write_packets();
            schedule_expiry();
        }
    }

    static nghttp3_nv make_header(std::string_view name, std::string_view value) {
        return {reinterpret_cast<const std::uint8_t *>(name.data()),
                reinterpret_cast<const std::uint8_t *>(value.data()), name.size(), value.size(),
                NGHTTP3_NV_FLAG_NONE};
    }

    int receive_http3(std::uint32_t flags, std::int64_t stream_id, const std::uint8_t *data,
                      std::size_t length) {
        if (http3_ == nullptr) {
            set_protocol_failure("received HTTP/3 stream data before session setup");
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        const auto consumed =
            nghttp3_conn_read_stream2(http3_, stream_id, data, length,
                                      (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0, timestamp_now());
        if (consumed < 0) {
            set_protocol_failure("nghttp3 rejected incoming HTTP/3 stream data");
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        if (ngtcp2_conn_extend_max_stream_offset(connection_, stream_id,
                                                 static_cast<std::uint64_t>(consumed)) != 0) {
            set_protocol_failure("failed to extend HTTP/3 QUIC flow-control credit");
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        ngtcp2_conn_extend_max_offset(connection_, static_cast<std::uint64_t>(consumed));
        return 0;
    }

    void queue_doq_write(Exchange &exchange) {
        if (!exchange.doq_fin_submitted && !exchange.doq_write_queued) {
            exchange.doq_write_queued = true;
            doq_pending_write_.push_back(exchange.stream_id);
        }
    }

    void resume_blocked_doq_streams() {
        const auto blocked = std::move(doq_blocked_streams_);
        doq_blocked_streams_.clear();
        for (const auto stream_id : blocked) {
            const auto found = stream_exchanges_.find(stream_id);
            if (found != stream_exchanges_.end() && !found->second->result) {
                queue_doq_write(*found->second);
            }
        }
    }

    void receive_doq(std::uint32_t flags, std::int64_t stream_id, const std::uint8_t *data,
                     std::size_t length) {
        auto *exchange = find_stream_exchange(stream_id);
        if (exchange == nullptr || exchange->result) {
            return;
        }
        if (exchange->doq_response.size() + length > 0xffff + 2) {
            set_exchange_error(*exchange,
                               protocol_error("DoQ response exceeds the DNS message limit"));
            return;
        }
        exchange->doq_response.insert(exchange->doq_response.end(), data, data + length);
        if ((flags & NGTCP2_STREAM_DATA_FLAG_FIN) == 0) {
            return;
        }
        if (exchange->doq_response.size() < 2) {
            set_exchange_error(*exchange,
                               protocol_error("DoQ response ended before its length prefix"));
            return;
        }
        const auto message_length =
            static_cast<std::size_t>(exchange->doq_response[0] << 8 | exchange->doq_response[1]);
        if (message_length == 0 || exchange->doq_response.size() != message_length + 2) {
            set_exchange_error(
                *exchange,
                protocol_error("DoQ response length prefix does not match the DNS message"));
            return;
        }
        const auto message = std::span<const std::uint8_t>(exchange->doq_response).subspan(2);
        if (message.size() < 2 || message[0] != 0 || message[1] != 0) {
            set_exchange_error(*exchange,
                               protocol_error("DoQ response DNS message ID is not zero"));
            return;
        }
        std::vector<std::uint8_t> restored(message.begin(), message.end());
        restored[0] = static_cast<std::uint8_t>(exchange->request.query.id >> 8);
        restored[1] = static_cast<std::uint8_t>(exchange->request.query.id & 0xff);
        decode_dns_response(*exchange, restored);
    }

    void decode_dns_response(Exchange &exchange, std::span<const std::uint8_t> wire) {
        const auto response = DnsMessageCodec::decode_packet(wire, exchange.request.query.id);
        if (!response) {
            set_exchange_error(exchange, response.error());
            return;
        }
        if (!same_question(response.value(), exchange.request.query)) {
            set_exchange_error(
                exchange, protocol_error("QUIC DNS response question does not match the query"));
            return;
        }
        if (!exchange.result) {
            exchange.result.emplace(response.value());
        }
    }

    Exchange *find_stream_exchange(std::int64_t stream_id) noexcept {
        const auto found = stream_exchanges_.find(stream_id);
        return found == stream_exchanges_.end() ? nullptr : found->second.get();
    }

    void set_session_error(core::Error error) {
        if (!session_error_) {
            session_error_.emplace(std::move(error));
        }
    }

    void set_transport_failure(std::string message) {
        set_session_error(transport_error(std::move(message)));
    }

    void set_protocol_failure(std::string message) {
        set_session_error(protocol_error(std::move(message)));
    }

    void set_authentication_failure(std::string message) {
        set_session_error(core::Error{core::ErrorCode::authentication, std::move(message)});
    }

    void set_exchange_error(Exchange &exchange, core::Error error) {
        if (!exchange.result) {
            exchange.result.emplace(core::fail(std::move(error)));
        }
    }

    void receive_next() {
        if (retired_ || !datagram_ || receiving_) {
            return;
        }
        receiving_ = true;
        auto buffer = std::make_shared<ReceiveBuffer>();
        const auto self = shared_from_this();
        datagram_->async_receive_from(
            boost::asio::buffer(buffer->bytes),
            [self, buffer](const boost::system::error_code &error, std::size_t length,
                           boost::asio::ip::udp::endpoint sender) {
                boost::asio::dispatch(self->owner_.strand_, [self, buffer, error, length,
                                                             sender = std::move(sender)] {
                    self->receiving_ = false;
                    if (self->retired_) {
                        return;
                    }
                    if (error) {
                        if (error != boost::asio::error::operation_aborted) {
                            self->fail_session(
                                upstream_error("failed to receive QUIC DNS datagram", error));
                        }
                        return;
                    }
                    if (sender == self->remote_endpoint_ && length != 0) {
                        self->process_datagram(buffer->bytes.data(), length, sender);
                    }
                    if (!self->retired_) {
                        self->receive_next();
                    }
                });
            });
    }

    void process_datagram(const std::uint8_t *data, std::size_t length,
                          const boost::asio::ip::udp::endpoint &sender) {
        ngtcp2_path path{};
        ngtcp2_addr_init(&path.local,
                         const_cast<ngtcp2_sockaddr *>(
                             reinterpret_cast<const ngtcp2_sockaddr *>(local_endpoint_.data())),
                         static_cast<ngtcp2_socklen>(local_endpoint_.size()));
        ngtcp2_addr_init(
            &path.remote,
            const_cast<ngtcp2_sockaddr *>(reinterpret_cast<const ngtcp2_sockaddr *>(sender.data())),
            static_cast<ngtcp2_socklen>(sender.size()));
        ngtcp2_pkt_info packet_info{};
        const auto result =
            ngtcp2_conn_read_pkt(connection_, &path, &packet_info, data, length, timestamp_now());
        if (result != 0) {
            const auto alert = ngtcp2_conn_get_tls_alert2(connection_);
            if (result == NGTCP2_ERR_CRYPTO) {
                set_authentication_failure("QUIC TLS handshake failed with alert " +
                                           std::to_string(alert));
            } else {
                set_transport_failure(std::string("ngtcp2 failed to process a packet: ") +
                                      ngtcp2_strerror(result));
            }
        }
        if (session_error_) {
            auto error = std::move(*session_error_);
            session_error_.reset();
            fail_session(std::move(error));
            return;
        }
        resume_blocked_doq_streams();
        pump_open_pending_exchanges();
        drain_exchange_results();
        if (retired_) {
            return;
        }
        write_packets();
        schedule_expiry();
    }

    void write_packets() {
        if (retired_ || connection_ == nullptr) {
            return;
        }
        for (std::size_t packet_count = 0; packet_count < 32; ++packet_count) {
            std::array<std::uint8_t, 1350> packet{};
            ngtcp2_path_storage path_storage{};
            ngtcp2_path_storage_zero(&path_storage);
            ngtcp2_pkt_info packet_info{};
            const auto now = timestamp_now();
            bool packet_ready = false;
            for (std::size_t frame_count = 0; frame_count < 128; ++frame_count) {
                std::int64_t stream_id = -1;
                int fin = 0;
                std::array<nghttp3_vec, 16> http3_vectors{};
                std::array<ngtcp2_vec, 16> stream_vectors{};
                std::size_t vector_count = 0;
                std::shared_ptr<Exchange> doq_exchange;

                if (mode_ == DnsTransportMode::doq &&
                    ngtcp2_conn_get_max_data_left2(connection_) != 0) {
                    while (!doq_pending_write_.empty()) {
                        const auto candidate_id = doq_pending_write_.front();
                        doq_pending_write_.pop_front();
                        const auto found = stream_exchanges_.find(candidate_id);
                        if (found == stream_exchanges_.end()) {
                            continue;
                        }
                        found->second->doq_write_queued = false;
                        if (found->second->result || found->second->doq_fin_submitted) {
                            continue;
                        }
                        doq_exchange = found->second;
                        break;
                    }
                }
                if (doq_exchange != nullptr) {
                    stream_id = doq_exchange->stream_id;
                    fin = 1;
                    if (doq_exchange->doq_offset < doq_exchange->doq_request.size()) {
                        stream_vectors[0] = {
                            doq_exchange->doq_request.data() + doq_exchange->doq_offset,
                            doq_exchange->doq_request.size() - doq_exchange->doq_offset};
                        vector_count = 1;
                    }
                } else if (mode_ == DnsTransportMode::doh3 && http3_ != nullptr &&
                           ngtcp2_conn_get_max_data_left2(connection_) != 0) {
                    const auto count = nghttp3_conn_writev_stream(
                        http3_, &stream_id, &fin, http3_vectors.data(), http3_vectors.size());
                    if (count < 0) {
                        set_protocol_failure("nghttp3 failed to generate HTTP/3 stream data");
                        break;
                    }
                    vector_count = static_cast<std::size_t>(count);
                    for (std::size_t index = 0; index < vector_count; ++index) {
                        stream_vectors[index] = {http3_vectors[index].base,
                                                 http3_vectors[index].len};
                    }
                }

                std::uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
                if (fin) {
                    flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
                }
                ngtcp2_ssize consumed = -1;
                const auto written = ngtcp2_conn_writev_stream(
                    connection_, &path_storage.path, &packet_info, packet.data(), packet.size(),
                    &consumed, flags, stream_id, stream_vectors.data(), vector_count, now);
                if (written == NGTCP2_ERR_WRITE_MORE) {
                    if (consumed < 0) {
                        set_transport_failure(
                            "ngtcp2 returned WRITE_MORE without consuming stream data");
                        break;
                    }
                    if (doq_exchange != nullptr) {
                        doq_exchange->doq_offset += static_cast<std::size_t>(consumed);
                        doq_exchange->doq_fin_submitted =
                            doq_exchange->doq_offset == doq_exchange->doq_request.size();
                        queue_doq_write(*doq_exchange);
                    } else if (http3_ != nullptr && stream_id >= 0 &&
                               nghttp3_conn_add_write_offset(
                                   http3_, stream_id, static_cast<std::uint64_t>(consumed)) != 0) {
                        set_protocol_failure("nghttp3 failed to advance HTTP/3 stream output");
                        break;
                    }
                    continue;
                }
                if (written == NGTCP2_ERR_STREAM_DATA_BLOCKED && stream_id >= 0) {
                    if (doq_exchange != nullptr) {
                        doq_blocked_streams_.insert(stream_id);
                    } else if (http3_ != nullptr &&
                               ngtcp2_conn_get_max_data_left2(connection_) != 0) {
                        nghttp3_conn_block_stream(http3_, stream_id);
                    }
                    continue;
                }
                if (written < 0) {
                    set_transport_failure(std::string("ngtcp2 failed to write a packet: ") +
                                          ngtcp2_strerror(static_cast<int>(written)));
                    break;
                }
                if (written == 0) {
                    if (doq_exchange != nullptr) {
                        queue_doq_write(*doq_exchange);
                    }
                    break;
                }
                if (consumed >= 0) {
                    if (doq_exchange != nullptr) {
                        doq_exchange->doq_offset += static_cast<std::size_t>(consumed);
                        doq_exchange->doq_fin_submitted =
                            doq_exchange->doq_offset == doq_exchange->doq_request.size();
                        queue_doq_write(*doq_exchange);
                    } else if (http3_ != nullptr && stream_id >= 0 &&
                               nghttp3_conn_add_write_offset(
                                   http3_, stream_id, static_cast<std::uint64_t>(consumed)) != 0) {
                        set_protocol_failure("nghttp3 failed to advance HTTP/3 stream output");
                        break;
                    }
                } else if (doq_exchange != nullptr) {
                    // QUIC may emit ACK or control frames without consuming the selected stream.
                    queue_doq_write(*doq_exchange);
                }
                ngtcp2_conn_update_pkt_tx_time(connection_, now);
                outgoing_.emplace_back(packet.begin(), packet.begin() + written);
                packet_ready = true;
                break;
            }
            if (session_error_ || retired_ || !packet_ready) {
                break;
            }
        }
        if (session_error_) {
            auto error = std::move(*session_error_);
            session_error_.reset();
            fail_session(std::move(error));
            return;
        }
        drain_exchange_results();
        if (retired_) {
            return;
        }
        send_next_packet();
        schedule_expiry();
    }

    void send_next_packet() {
        if (retired_ || sending_ || outgoing_.empty() || !datagram_) {
            return;
        }
        sending_ = true;
        auto packet = std::make_shared<std::vector<std::uint8_t>>(std::move(outgoing_.front()));
        outgoing_.pop_front();
        const auto self = shared_from_this();
        datagram_->async_send_to(
            boost::asio::buffer(*packet), remote_endpoint_,
            [self, packet](const boost::system::error_code &error, std::size_t length) {
                boost::asio::dispatch(self->owner_.strand_, [self, packet, error, length] {
                    self->sending_ = false;
                    if (self->retired_) {
                        return;
                    }
                    if (error || length != packet->size()) {
                        self->fail_session(
                            error ? upstream_error("failed to send QUIC DNS datagram", error)
                                  : transport_error("QUIC DNS datagram was only partially sent"));
                        return;
                    }
                    self->send_next_packet();
                });
            });
    }

    void schedule_expiry() {
        if (retired_ || connection_ == nullptr) {
            return;
        }
        const auto expiry = ngtcp2_conn_get_expiry2(connection_);
        if (expiry == std::numeric_limits<ngtcp2_tstamp>::max()) {
            return;
        }
        const auto now = timestamp_now();
        const auto wait = expiry > now ? expiry - now : 1;
        expiry_timer_.expires_after(std::chrono::nanoseconds(wait));
        const auto self = shared_from_this();
        expiry_timer_.async_wait(boost::asio::bind_executor(
            owner_.strand_, [self](const boost::system::error_code &error) {
                if (error || self->retired_ || self->connection_ == nullptr) {
                    return;
                }
                const auto result = ngtcp2_conn_handle_expiry(self->connection_, timestamp_now());
                if (result != 0) {
                    self->fail_session(transport_error(
                        std::string("ngtcp2 connection timer failed: ") + ngtcp2_strerror(result)));
                    return;
                }
                self->write_packets();
                self->schedule_expiry();
            }));
    }

    void stream_closed(std::int64_t stream_id) {
        const auto found = stream_exchanges_.find(stream_id);
        if (found == stream_exchanges_.end()) {
            return;
        }
        auto exchange = found->second;
        exchange->stream_closed = true;
        doq_blocked_streams_.erase(stream_id);
        stream_exchanges_.erase(found);
        if (!exchange->result && exchanges_.contains(exchange->id)) {
            set_exchange_error(
                *exchange, transport_error("QUIC DNS stream closed before a response completed"));
        }
    }

    void drain_exchange_results() {
        std::vector<std::pair<ExchangeId, core::Result<DnsPacket>>> completed;
        for (auto &[id, exchange] : exchanges_) {
            if (exchange->result) {
                completed.emplace_back(id, std::move(*exchange->result));
                exchange->result.reset();
            }
        }
        for (auto &[id, result] : completed) {
            complete_exchange(id, std::move(result));
        }
    }

    void complete_exchange(ExchangeId id, core::Result<DnsPacket> result) {
        const auto found = exchanges_.find(id);
        if (found == exchanges_.end()) {
            return;
        }
        const auto exchange = found->second;
        exchange->deadline_timer.cancel();
        if (!result && exchange->stream_id >= 0 && !exchange->stream_closed &&
            connection_ != nullptr) {
            if (http3_ != nullptr) {
                nghttp3_conn_shutdown_stream_read(http3_, exchange->stream_id);
                nghttp3_conn_shutdown_stream_write(http3_, exchange->stream_id);
            }
            const auto app_error =
                mode_ == DnsTransportMode::doq ? kDoqRequestCancelled : kHttp3RequestCancelled;
            (void)ngtcp2_conn_shutdown_stream(connection_, 0, exchange->stream_id, app_error);
        }
        exchanges_.erase(found);
        std::erase(doq_pending_write_, exchange->stream_id);
        doq_blocked_streams_.erase(exchange->stream_id);
        owner_.complete(id, std::move(result));
        if (exchanges_.empty()) {
            enter_idle_or_retire();
        }
    }

    void enter_idle_or_retire() {
        if (retired_) {
            return;
        }
        if (!handshake_completed_ || connection_ == nullptr || !datagram_) {
            retire_session();
            return;
        }
        idle_ = true;
        const auto self = shared_from_this();
        idle_timer_.expires_after(std::chrono::seconds(30));
        idle_timer_.async_wait(boost::asio::bind_executor(
            owner_.strand_, [self](const boost::system::error_code &error) {
                if (!error && self->exchanges_.empty()) {
                    self->retire_idle();
                }
            }));
        owner_.session_idle(self);
    }

    void retire_idle() noexcept {
        if (retired_ || !exchanges_.empty()) {
            return;
        }
        retire_session();
    }

    void retire_session() noexcept {
        if (retired_) {
            return;
        }
        retired_ = true;
        idle_ = false;
        idle_timer_.cancel();
        expiry_timer_.cancel();
        if (datagram_) {
            datagram_->cancel();
            datagram_->close();
            datagram_.reset();
        }
        release_protocol();
        exchanges_.clear();
        stream_exchanges_.clear();
        pending_exchanges_.clear();
        doq_pending_write_.clear();
        doq_blocked_streams_.clear();
        owner_.session_retired(this);
    }

    void fail_session(core::Error error) {
        if (retired_) {
            return;
        }
        std::vector<ExchangeId> exchange_ids;
        exchange_ids.reserve(exchanges_.size());
        for (const auto &[id, exchange] : exchanges_) {
            exchange_ids.push_back(id);
            exchange->deadline_timer.cancel();
        }
        retired_ = true;
        idle_ = false;
        idle_timer_.cancel();
        expiry_timer_.cancel();
        if (datagram_) {
            datagram_->cancel();
            datagram_->close();
            datagram_.reset();
        }
        release_protocol();
        exchanges_.clear();
        stream_exchanges_.clear();
        pending_exchanges_.clear();
        doq_pending_write_.clear();
        doq_blocked_streams_.clear();
        owner_.session_retired(this);
        for (const auto id : exchange_ids) {
            owner_.complete(id, core::fail(error));
        }
    }

    void release_protocol() noexcept {
        if (http3_ != nullptr) {
            nghttp3_conn_del(http3_);
            http3_ = nullptr;
        }
        if (connection_ != nullptr) {
            ngtcp2_conn_del(connection_);
            connection_ = nullptr;
        }
        if (ssl_ != nullptr) {
            SSL_free(ssl_);
            ssl_ = nullptr;
        }
        if (ssl_context_ != nullptr) {
            SSL_CTX_free(ssl_context_);
            ssl_context_ = nullptr;
        }
    }

    QuicDnsTransport &owner_;
    boost::asio::steady_timer expiry_timer_;
    boost::asio::steady_timer idle_timer_;
    DnsTransportMode mode_;
    std::string host_;
    std::uint16_t port_;
    std::string authority_;
    std::string path_;
    boost::asio::ip::udp::endpoint local_endpoint_;
    boost::asio::ip::udp::endpoint remote_endpoint_;
    std::shared_ptr<core::DatagramHandle> datagram_;
    ngtcp2_crypto_conn_ref connection_ref_{};
    SSL_CTX *ssl_context_ = nullptr;
    SSL *ssl_ = nullptr;
    ngtcp2_conn *connection_ = nullptr;
    nghttp3_conn *http3_ = nullptr;
    std::unordered_map<ExchangeId, std::shared_ptr<Exchange>> exchanges_;
    std::unordered_map<std::int64_t, std::shared_ptr<Exchange>> stream_exchanges_;
    std::deque<ExchangeId> pending_exchanges_;
    std::deque<std::int64_t> doq_pending_write_;
    std::unordered_set<std::int64_t> doq_blocked_streams_;
    std::deque<std::vector<std::uint8_t>> outgoing_;
    std::optional<core::Error> session_error_;
    bool started_ = false;
    bool handshake_completed_ = false;
    bool open_pending_exchanges_ = false;
    bool idle_ = false;
    bool retired_ = false;
    bool receiving_ = false;
    bool sending_ = false;

    struct ReceiveBuffer {
        std::array<std::uint8_t, 65536> bytes{};
    };
};

DnsTransport::ExchangeId QuicDnsTransport::exchange(DnsExchangeRequest request, Handler handler) {
    const auto id = next_exchange_id_.fetch_add(1, std::memory_order_relaxed);
    const auto self = shared_from_this();
    boost::asio::post(
        strand_, [self, id, request = std::move(request), handler = std::move(handler)]() mutable {
            self->add_new_exchange(id, std::move(request), std::move(handler));
        });
    return id;
}

void QuicDnsTransport::add_new_exchange(ExchangeId id, DnsExchangeRequest request,
                                        Handler handler) {
    if (stopped_) {
        if (handler) {
            handler(core::fail(cancelled_error()));
        }
        return;
    }

    std::shared_ptr<Operation> operation;
    for (const auto &candidate : active_sessions_) {
        if (candidate->can_accept_exchange() &&
            (!operation ||
             candidate->active_exchange_count() < operation->active_exchange_count())) {
            operation = candidate;
        }
    }
    if (!operation && !idle_sessions_.empty()) {
        operation = std::move(idle_sessions_.back());
        idle_sessions_.pop_back();
        active_sessions_.push_back(operation);
    }
    if (!operation) {
        operation = std::make_shared<Operation>(*this);
        active_sessions_.push_back(operation);
    }
    exchanges_.emplace(id, ExchangeRegistration{operation, std::move(handler)});
    operation->add_exchange(id, std::move(request));
}

void QuicDnsTransport::cancel(ExchangeId exchange_id) noexcept {
    try {
        const auto self = shared_from_this();
        boost::asio::post(strand_, [self, exchange_id] {
            const auto found = self->exchanges_.find(exchange_id);
            if (found != self->exchanges_.end()) {
                found->second.operation->cancel_exchange(exchange_id, cancelled_error());
            }
        });
    } catch (...) {
    }
}

void QuicDnsTransport::stop() noexcept {
    try {
        const auto self = shared_from_this();
        boost::asio::post(strand_, [self] {
            if (self->stopped_) {
                return;
            }
            self->stopped_ = true;
            const auto active = self->active_sessions_;
            for (const auto &operation : active) {
                operation->cancel_all();
            }
            const auto idle = std::move(self->idle_sessions_);
            self->idle_sessions_.clear();
            for (const auto &operation : idle) {
                operation->close_idle();
            }
        });
    } catch (...) {
    }
}

void QuicDnsTransport::session_idle(const std::shared_ptr<Operation> &operation) {
    std::erase_if(active_sessions_, [&operation](const auto &candidate) {
        return candidate.get() == operation.get();
    });
    if (stopped_ || !operation->is_idle()) {
        operation->close_idle();
        return;
    }
    const auto already_idle = std::any_of(
        idle_sessions_.begin(), idle_sessions_.end(),
        [&operation](const auto &candidate) { return candidate.get() == operation.get(); });
    if (!already_idle) {
        idle_sessions_.push_back(operation);
    }
    if (idle_sessions_.size() > kMaximumIdleQuicSessions) {
        auto oldest = std::move(idle_sessions_.front());
        idle_sessions_.erase(idle_sessions_.begin());
        oldest->close_idle();
    }
}

void QuicDnsTransport::session_retired(const Operation *operation) noexcept {
    std::erase_if(active_sessions_,
                  [operation](const auto &candidate) { return candidate.get() == operation; });
    std::erase_if(idle_sessions_,
                  [operation](const auto &candidate) { return candidate.get() == operation; });
}

void QuicDnsTransport::complete(ExchangeId exchange_id, core::Result<DnsPacket> result) {
    const auto found = exchanges_.find(exchange_id);
    if (found == exchanges_.end()) {
        return;
    }
    auto handler = std::move(found->second.handler);
    exchanges_.erase(found);
    if (handler) {
        handler(std::move(result));
    }
}

std::shared_ptr<DnsTransport> make_quic_dns_transport(runtime::AsioRuntime &runtime,
                                                      DnsUpstreamConfig config) {
    return std::make_shared<QuicDnsTransport>(runtime, std::move(config));
}

} // namespace clash_native::dns
