#include <clash_native/transport/quic_client.hpp>

#include "transport/builtin_ca_bundle.hpp"

#include <boost/asio/bind_executor.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

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
#include <chrono>
#include <deque>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>

namespace clash_native::transport {

namespace {

using Clock = std::chrono::steady_clock;

std::uint64_t timestamp_now() noexcept {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch())
            .count());
}

core::Error configuration_error(std::string context) {
    return {core::ErrorCode::configuration, std::move(context), {}};
}

core::Error authentication_error(std::string context) {
    return {core::ErrorCode::authentication, std::move(context), {}};
}

core::Error transport_error(std::string context, const boost::system::error_code &error) {
    return {core::ErrorCode::transport_io, std::move(context),
            std::error_code(error.value(), std::system_category())};
}

bool add_certificates(std::string_view pem, X509_STORE *store, std::size_t &count) {
    if (pem.empty()) {
        return true;
    }
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(
        BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free);
    if (!bio) {
        return false;
    }
    while (X509 *certificate = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)) {
        if (X509_STORE_add_cert(store, certificate) != 1) {
            // A certificate already present in the store is not a configuration error.
            ERR_clear_error();
        }
        X509_free(certificate);
        ++count;
    }
    ERR_clear_error();
    return true;
}

} // namespace

class QuicClientConnection::Impl final : public std::enable_shared_from_this<Impl> {
  public:
    Impl(boost::asio::any_io_executor executor, std::unique_ptr<core::DatagramHandle> datagram,
         boost::asio::ip::udp::endpoint remote_endpoint, QuicClientOptions options,
         QuicClientEvents events)
        : executor_(std::move(executor)), expiry_timer_(executor_), datagram_(std::move(datagram)),
          remote_endpoint_(std::move(remote_endpoint)), options_(std::move(options)),
          events_(std::move(events)) {
        connection_ref_.get_conn = &get_connection;
        connection_ref_.user_data = this;
    }

    ~Impl() { release_protocol(); }

    void start() {
        if (!validate_options()) {
            fail(*error_);
            return;
        }
        if (!initialize_protocol()) {
            fail(*error_);
            return;
        }
        receive_next();
        write_packets();
        schedule_expiry();
    }

    QuicOpenStreamResult open_stream(bool unidirectional) {
        if (retired_ || !ready_ || connection_ == nullptr) {
            return {QuicOpenStreamResult::State::failed, -1,
                    configuration_error("QUIC connection is not ready")};
        }
        std::int64_t stream_id = -1;
        const auto result = unidirectional
                                ? ngtcp2_conn_open_uni_stream(connection_, &stream_id, nullptr)
                                : ngtcp2_conn_open_bidi_stream(connection_, &stream_id, nullptr);
        if (result == NGTCP2_ERR_STREAM_ID_BLOCKED) {
            return {QuicOpenStreamResult::State::blocked, -1, std::nullopt};
        }
        if (result != 0) {
            const auto error = protocol_error(std::string("ngtcp2 could not open a QUIC stream: ") +
                                              ngtcp2_strerror(result));
            fail(error);
            return {QuicOpenStreamResult::State::failed, -1, error};
        }
        return {QuicOpenStreamResult::State::opened, stream_id, std::nullopt};
    }

    void write_stream_data(std::int64_t stream_id, std::vector<std::uint8_t> data, bool fin) {
        if (retired_ || stream_id < 0 || finished_streams_.contains(stream_id)) {
            return;
        }
        auto &writes = stream_writes_[stream_id];
        if (!writes.empty() && writes.back().fin) {
            fail(protocol_error("QUIC stream data was queued after FIN"));
            return;
        }
        writes.push_back(PendingWrite{std::move(data), 0, fin});
        if (fin) {
            finished_streams_.insert(stream_id);
        }
        queue_stream(stream_id);
        request_write();
    }

    void shutdown_stream(std::int64_t stream_id, std::uint64_t application_error) noexcept {
        if (retired_ || connection_ == nullptr || stream_id < 0) {
            return;
        }
        (void)ngtcp2_conn_shutdown_stream(connection_, 0, stream_id, application_error);
        stream_writes_.erase(stream_id);
        std::erase(ready_streams_, stream_id);
        scheduled_streams_.erase(stream_id);
        blocked_streams_.erase(stream_id);
        write_again_ = true;
        request_write();
    }

    core::Status extend_receive_credit(std::int64_t stream_id, std::size_t consumed) {
        if (retired_ || connection_ == nullptr || consumed == 0) {
            return {};
        }
        const auto amount = static_cast<std::uint64_t>(consumed);
        if (ngtcp2_conn_extend_max_stream_offset(connection_, stream_id, amount) != 0) {
            const auto error = protocol_error("failed to extend QUIC stream flow-control credit");
            fail(error);
            return core::fail(error);
        }
        ngtcp2_conn_extend_max_offset(connection_, amount);
        request_write();
        return {};
    }

    void close() noexcept {
        try {
            const auto self = shared_from_this();
            boost::asio::post(executor_, [self] { self->retire(); });
        } catch (...) {
            retire();
        }
    }

    bool ready() const noexcept { return ready_ && !retired_; }
    bool retired() const noexcept { return retired_; }
    boost::asio::any_io_executor executor() const noexcept { return executor_; }

    void set_events(QuicClientEvents events) {
        events_ = std::move(events);
        if (ready_ && events_.ready) {
            events_.ready(selected_alpn_);
        } else if (retired_ && error_ && events_.failed) {
            events_.failed(*error_);
        }
    }

  private:
    struct PendingWrite {
        std::vector<std::uint8_t> bytes;
        std::size_t offset = 0;
        bool fin = false;
    };

    struct ReceiveBuffer {
        std::array<std::uint8_t, 65536> bytes{};
    };

    static ngtcp2_conn *get_connection(ngtcp2_crypto_conn_ref *ref) noexcept {
        return static_cast<Impl *>(ref->user_data)->connection_;
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
        auto *self = static_cast<Impl *>(user_data);
        const auto alpn = self->selected_alpn();
        if (!alpn) {
            self->error_ = authentication_error("QUIC peer negotiated an unoffered ALPN");
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        self->ready_ = true;
        self->selected_alpn_ = *alpn;
        if (self->events_.ready) {
            self->events_.ready(*alpn);
        }
        return 0;
    }

    static int on_stream_data(ngtcp2_conn *, std::uint32_t flags, std::int64_t stream_id,
                              std::uint64_t, const std::uint8_t *data, std::size_t length,
                              void *user_data, void *) {
        auto *self = static_cast<Impl *>(user_data);
        if (self->events_.stream_data) {
            self->events_.stream_data(stream_id, data, length,
                                      (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0);
        }
        return 0;
    }

    static int on_acked_stream_data(ngtcp2_conn *, std::int64_t stream_id, std::uint64_t,
                                    std::uint64_t length, void *user_data, void *) {
        auto *self = static_cast<Impl *>(user_data);
        if (self->events_.stream_data_acked) {
            self->events_.stream_data_acked(stream_id, length);
        }
        return 0;
    }

    static int on_extend_max_stream_data(ngtcp2_conn *, std::int64_t stream_id, std::uint64_t,
                                         void *user_data, void *) {
        auto *self = static_cast<Impl *>(user_data);
        self->blocked_streams_.erase(stream_id);
        self->queue_stream(stream_id);
        if (self->events_.stream_writable) {
            self->events_.stream_writable(stream_id);
        }
        return 0;
    }

    static int on_extend_max_local_streams_bidi(ngtcp2_conn *, std::uint64_t, void *user_data) {
        auto *self = static_cast<Impl *>(user_data);
        self->stream_capacity_pending_ = true;
        return 0;
    }

    static int on_extend_max_local_streams_uni(ngtcp2_conn *, std::uint64_t, void *user_data) {
        auto *self = static_cast<Impl *>(user_data);
        self->stream_capacity_pending_ = true;
        return 0;
    }

    static int on_stream_closed(ngtcp2_conn *, std::uint32_t, std::int64_t stream_id,
                                std::uint64_t application_error, void *user_data, void *) {
        auto *self = static_cast<Impl *>(user_data);
        self->stream_writes_.erase(stream_id);
        self->finished_streams_.erase(stream_id);
        self->blocked_streams_.erase(stream_id);
        self->scheduled_streams_.erase(stream_id);
        std::erase(self->ready_streams_, stream_id);
        if (self->events_.stream_closed) {
            self->events_.stream_closed(stream_id, application_error);
        }
        return 0;
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
                                std::uint64_t application_error, void *user_data, void *) {
        auto *self = static_cast<Impl *>(user_data);
        if (self->events_.stream_reset) {
            self->events_.stream_reset(stream_id, application_error);
        }
        return 0;
    }

    bool validate_options() {
        if (!datagram_ || remote_endpoint_.port() == 0 || options_.alpn_protocols.empty()) {
            error_ = configuration_error(
                "QUIC client requires a datagram handle, remote port, and ALPN protocol");
            return false;
        }
        if (options_.verify_peer && options_.server_name.empty()) {
            error_ = configuration_error("QUIC peer verification requires a server name");
            return false;
        }
        if (options_.handshake_timeout <= Clock::duration::zero()) {
            error_ = configuration_error("QUIC handshake timeout must be positive");
            return false;
        }
        std::size_t alpn_size = 0;
        for (const auto &alpn : options_.alpn_protocols) {
            if (alpn.empty() || alpn.size() > 255 || alpn_size + alpn.size() + 1 > 65535) {
                error_ = configuration_error("QUIC ALPN protocol list is invalid");
                return false;
            }
            alpn_size += alpn.size() + 1;
        }
        return true;
    }

    bool initialize_protocol() {
        ssl_context_ = SSL_CTX_new(TLS_client_method());
        if (ssl_context_ == nullptr ||
            ngtcp2_crypto_boringssl_configure_client_context(ssl_context_) != 0) {
            error_ = transport_error("failed to initialize BoringSSL for QUIC", {});
            return false;
        }
        if (!load_trust_roots()) {
            return false;
        }
        ssl_ = SSL_new(ssl_context_);
        if (ssl_ == nullptr) {
            error_ = transport_error("failed to allocate QUIC TLS state", {});
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
        callbacks.extend_max_local_streams_uni = &on_extend_max_local_streams_uni;
        callbacks.stream_close = &on_stream_closed;
        callbacks.stream_reset = &on_receive_reset;

        ngtcp2_cid destination_id{};
        destination_id.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
        ngtcp2_cid source_id{};
        source_id.datalen = 8;
        if (RAND_bytes(destination_id.data, static_cast<int>(destination_id.datalen)) != 1 ||
            RAND_bytes(source_id.data, static_cast<int>(source_id.datalen)) != 1) {
            error_ = transport_error("failed to generate QUIC connection identifiers", {});
            return false;
        }

        const auto bind_address =
            remote_endpoint_.address().is_v4()
                ? boost::asio::ip::address(boost::asio::ip::address_v4::any())
                : boost::asio::ip::address(boost::asio::ip::address_v6::any());
        local_endpoint_ = {bind_address, 0};
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
        settings.handshake_timeout = static_cast<ngtcp2_duration>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(options_.handshake_timeout)
                .count());

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
            error_ = protocol_error(std::string("ngtcp2 failed to create client connection: ") +
                                    ngtcp2_strerror(created));
            return false;
        }
        ngtcp2_conn_set_tls_native_handle(connection_, ssl_);
        return true;
    }

    bool load_trust_roots() {
        if (!options_.verify_peer) {
            SSL_CTX_set_verify(ssl_context_, SSL_VERIFY_NONE, nullptr);
            return true;
        }
        const auto embedded = detail::builtin_ca_bundle_pem();
        auto *store = SSL_CTX_get_cert_store(ssl_context_);
        std::size_t roots = 0;
        if (!add_certificates(embedded, store, roots) ||
            !add_certificates(options_.trusted_ca_pem, store, roots) || roots == 0) {
            error_ = authentication_error("failed to load QUIC TLS trust roots");
            return false;
        }
        SSL_CTX_set_verify(ssl_context_, SSL_VERIFY_PEER, nullptr);
        return true;
    }

    bool configure_tls_peer() {
        boost::system::error_code address_error;
        (void)boost::asio::ip::make_address(options_.server_name, address_error);
        if (address_error && !options_.server_name.empty() &&
            SSL_set_tlsext_host_name(ssl_, options_.server_name.c_str()) != 1) {
            error_ = authentication_error("failed to set QUIC TLS server name");
            return false;
        }
        if (options_.verify_peer) {
            auto *parameters = SSL_get0_param(ssl_);
            const int configured =
                address_error
                    ? X509_VERIFY_PARAM_set1_host(parameters, options_.server_name.c_str(),
                                                  options_.server_name.size())
                    : X509_VERIFY_PARAM_set1_ip_asc(parameters, options_.server_name.c_str());
            if (configured != 1) {
                error_ = authentication_error("failed to configure QUIC certificate validation");
                return false;
            }
        }

        std::vector<unsigned char> alpn;
        for (const auto &protocol : options_.alpn_protocols) {
            alpn.push_back(static_cast<unsigned char>(protocol.size()));
            alpn.insert(alpn.end(), protocol.begin(), protocol.end());
        }
        if (SSL_set_alpn_protos(ssl_, alpn.data(), static_cast<unsigned int>(alpn.size())) != 0) {
            error_ = configuration_error("failed to configure QUIC ALPN");
            return false;
        }
        return true;
    }

    std::optional<std::string> selected_alpn() const {
        const unsigned char *protocol = nullptr;
        unsigned int protocol_length = 0;
        SSL_get0_alpn_selected(ssl_, &protocol, &protocol_length);
        if (protocol == nullptr || protocol_length == 0) {
            return std::nullopt;
        }
        const std::string_view selected(reinterpret_cast<const char *>(protocol), protocol_length);
        const auto offered =
            std::find(options_.alpn_protocols.begin(), options_.alpn_protocols.end(), selected);
        if (offered == options_.alpn_protocols.end()) {
            return std::nullopt;
        }
        return std::string(selected);
    }

    static core::Error protocol_error(std::string context) {
        return {core::ErrorCode::protocol_framing, std::move(context), {}};
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
                boost::asio::dispatch(self->executor_, [self, buffer, error, length,
                                                        sender = std::move(sender)] {
                    self->receiving_ = false;
                    if (self->retired_) {
                        return;
                    }
                    if (error) {
                        if (error != boost::asio::error::operation_aborted) {
                            self->fail(transport_error("failed to receive QUIC datagram", error));
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
        processing_datagram_ = true;
        const auto result =
            ngtcp2_conn_read_pkt(connection_, &path, &packet_info, data, length, timestamp_now());
        processing_datagram_ = false;
        if (stream_capacity_pending_) {
            stream_capacity_pending_ = false;
            if (events_.stream_capacity) {
                events_.stream_capacity();
            }
        }
        if (result != 0) {
            if (error_) {
                fail(*error_);
            } else if (result == NGTCP2_ERR_CRYPTO) {
                fail(authentication_error("QUIC TLS handshake failed with alert " +
                                          std::to_string(ngtcp2_conn_get_tls_alert2(connection_))));
            } else {
                fail(protocol_error(std::string("ngtcp2 failed to process a packet: ") +
                                    ngtcp2_strerror(result)));
            }
            return;
        }
        request_write();
        schedule_expiry();
    }

    void queue_stream(std::int64_t stream_id) {
        if (retired_ || blocked_streams_.contains(stream_id) ||
            scheduled_streams_.contains(stream_id)) {
            return;
        }
        const auto found = stream_writes_.find(stream_id);
        if (found == stream_writes_.end() || found->second.empty()) {
            return;
        }
        scheduled_streams_.insert(stream_id);
        ready_streams_.push_back(stream_id);
    }

    std::optional<std::int64_t> take_writable_stream() {
        while (!ready_streams_.empty()) {
            const auto stream_id = ready_streams_.front();
            ready_streams_.pop_front();
            scheduled_streams_.erase(stream_id);
            if (blocked_streams_.contains(stream_id)) {
                continue;
            }
            const auto found = stream_writes_.find(stream_id);
            if (found != stream_writes_.end() && !found->second.empty()) {
                return stream_id;
            }
        }
        return std::nullopt;
    }

    void advance_write(std::int64_t stream_id, std::size_t consumed, bool fin_flagged) {
        const auto found = stream_writes_.find(stream_id);
        if (found == stream_writes_.end() || found->second.empty()) {
            return;
        }
        auto &write = found->second.front();
        const auto remaining = write.bytes.size() - write.offset;
        const auto advanced = std::min(remaining, consumed);
        write.offset += advanced;
        const bool complete = write.offset == write.bytes.size();
        if (complete && (!write.fin || fin_flagged)) {
            const bool fin = write.fin;
            found->second.pop_front();
            if (fin) {
                stream_writes_.erase(found);
            } else {
                queue_stream(stream_id);
            }
            if (events_.stream_write_consumed) {
                if (advanced != 0) {
                    events_.stream_write_consumed(stream_id, advanced, false);
                }
                events_.stream_write_consumed(stream_id, 0, true);
            }
        } else {
            if (advanced != 0 && events_.stream_write_consumed) {
                events_.stream_write_consumed(stream_id, advanced, false);
            }
            queue_stream(stream_id);
        }
    }

    void request_write() {
        if (processing_datagram_ || writing_packets_ || retired_) {
            write_again_ = true;
            return;
        }
        write_packets();
    }

    void write_packets() {
        if (retired_ || connection_ == nullptr || writing_packets_) {
            write_again_ = true;
            return;
        }
        writing_packets_ = true;
        do {
            write_again_ = false;
            for (std::size_t packet_count = 0; packet_count < 32; ++packet_count) {
                std::array<std::uint8_t, 1350> packet{};
                ngtcp2_path_storage path_storage{};
                ngtcp2_path_storage_zero(&path_storage);
                ngtcp2_pkt_info packet_info{};
                const auto now = timestamp_now();
                bool packet_ready = false;
                for (std::size_t frame_count = 0; frame_count < 128; ++frame_count) {
                    std::int64_t stream_id = -1;
                    std::array<ngtcp2_vec, 1> vectors{};
                    std::size_t vector_count = 0;
                    bool fin = false;
                    if (ngtcp2_conn_get_max_data_left2(connection_) != 0) {
                        if (const auto writable = take_writable_stream()) {
                            stream_id = *writable;
                            auto &write = stream_writes_.at(stream_id).front();
                            const auto remaining = write.bytes.size() - write.offset;
                            if (remaining != 0) {
                                vectors[0] = {write.bytes.data() + write.offset, remaining};
                                vector_count = 1;
                            }
                            fin = write.fin;
                        }
                    }
                    std::uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
                    if (fin) {
                        flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
                    }
                    ngtcp2_ssize consumed = -1;
                    const auto written = ngtcp2_conn_writev_stream(
                        connection_, &path_storage.path, &packet_info, packet.data(), packet.size(),
                        &consumed, flags, stream_id, vectors.data(), vector_count, now);
                    if (written == NGTCP2_ERR_WRITE_MORE) {
                        if (stream_id >= 0) {
                            if (consumed < 0) {
                                fail(protocol_error(
                                    "ngtcp2 returned WRITE_MORE without consuming stream data"));
                                break;
                            }
                            advance_write(stream_id, static_cast<std::size_t>(consumed), fin);
                        }
                        continue;
                    }
                    if (written == NGTCP2_ERR_STREAM_DATA_BLOCKED && stream_id >= 0) {
                        blocked_streams_.insert(stream_id);
                        if (events_.stream_blocked) {
                            events_.stream_blocked(stream_id);
                        }
                        continue;
                    }
                    if (written < 0) {
                        fail(protocol_error(std::string("ngtcp2 failed to write a packet: ") +
                                            ngtcp2_strerror(static_cast<int>(written))));
                        break;
                    }
                    if (stream_id >= 0 && consumed >= 0) {
                        advance_write(stream_id, static_cast<std::size_t>(consumed), fin);
                    } else if (stream_id >= 0) {
                        // ngtcp2 may emit a control/ACK packet without consuming the selected
                        // application stream. Keep that stream eligible for the next send pass.
                        queue_stream(stream_id);
                    }
                    if (written == 0) {
                        break;
                    }
                    ngtcp2_conn_update_pkt_tx_time(connection_, now);
                    outgoing_.emplace_back(packet.begin(), packet.begin() + written);
                    packet_ready = true;
                    break;
                }
                if (retired_ || !packet_ready) {
                    break;
                }
            }
            send_next_packet();
        } while (write_again_ && !retired_);
        writing_packets_ = false;
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
                boost::asio::dispatch(self->executor_, [self, packet, error, length] {
                    self->sending_ = false;
                    if (self->retired_) {
                        return;
                    }
                    if (error || length != packet->size()) {
                        self->fail(error ? transport_error("failed to send QUIC datagram", error)
                                         : core::Error{core::ErrorCode::transport_io,
                                                       "QUIC datagram was only partially sent",
                                                       {}});
                        return;
                    }
                    self->send_next_packet();
                    if (self->outgoing_.empty()) {
                        self->request_write();
                    }
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
        expiry_timer_.async_wait(
            boost::asio::bind_executor(executor_, [self](const boost::system::error_code &error) {
                if (error || self->retired_ || self->connection_ == nullptr) {
                    return;
                }
                const auto result = ngtcp2_conn_handle_expiry(self->connection_, timestamp_now());
                if (result != 0) {
                    self->fail(protocol_error(std::string("ngtcp2 connection timer failed: ") +
                                              ngtcp2_strerror(result)));
                    return;
                }
                self->write_packets();
                self->schedule_expiry();
            }));
    }

    void fail(core::Error error) {
        if (retired_) {
            return;
        }
        error_ = error;
        retired_ = true;
        ready_ = false;
        expiry_timer_.cancel();
        if (datagram_) {
            datagram_->cancel();
            datagram_->close();
            datagram_.reset();
        }
        release_protocol();
        if (events_.failed) {
            events_.failed(std::move(error));
        }
    }

    void retire() noexcept {
        if (retired_) {
            return;
        }
        retired_ = true;
        ready_ = false;
        expiry_timer_.cancel();
        if (datagram_) {
            datagram_->cancel();
            datagram_->close();
            datagram_.reset();
        }
        release_protocol();
        stream_writes_.clear();
        outgoing_.clear();
    }

    void release_protocol() noexcept {
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

    boost::asio::any_io_executor executor_;
    boost::asio::steady_timer expiry_timer_;
    std::unique_ptr<core::DatagramHandle> datagram_;
    boost::asio::ip::udp::endpoint remote_endpoint_;
    boost::asio::ip::udp::endpoint local_endpoint_;
    QuicClientOptions options_;
    QuicClientEvents events_;
    std::string selected_alpn_;
    ngtcp2_crypto_conn_ref connection_ref_{};
    SSL_CTX *ssl_context_ = nullptr;
    SSL *ssl_ = nullptr;
    ngtcp2_conn *connection_ = nullptr;
    std::unordered_map<std::int64_t, std::deque<PendingWrite>> stream_writes_;
    std::set<std::int64_t> finished_streams_;
    std::set<std::int64_t> blocked_streams_;
    std::set<std::int64_t> scheduled_streams_;
    std::deque<std::int64_t> ready_streams_;
    std::deque<std::vector<std::uint8_t>> outgoing_;
    std::optional<core::Error> error_;
    bool ready_ = false;
    bool retired_ = false;
    bool receiving_ = false;
    bool sending_ = false;
    bool processing_datagram_ = false;
    bool writing_packets_ = false;
    bool write_again_ = false;
    bool stream_capacity_pending_ = false;
};

QuicClientConnection::QuicClientConnection(std::shared_ptr<Impl> impl) : impl_(std::move(impl)) {}

QuicClientConnection::~QuicClientConnection() { close(); }

QuicOpenStreamResult QuicClientConnection::open_bidirectional_stream() {
    return impl_->open_stream(false);
}

QuicOpenStreamResult QuicClientConnection::open_unidirectional_stream() {
    return impl_->open_stream(true);
}

void QuicClientConnection::write_stream_data(std::int64_t stream_id, std::vector<std::uint8_t> data,
                                             bool fin) {
    impl_->write_stream_data(stream_id, std::move(data), fin);
}

void QuicClientConnection::shutdown_stream(std::int64_t stream_id,
                                           std::uint64_t application_error) noexcept {
    impl_->shutdown_stream(stream_id, application_error);
}

core::Status QuicClientConnection::extend_receive_credit(std::int64_t stream_id,
                                                         std::size_t consumed) {
    return impl_->extend_receive_credit(stream_id, consumed);
}

bool QuicClientConnection::ready() const noexcept { return impl_->ready(); }

bool QuicClientConnection::retired() const noexcept { return impl_->retired(); }

boost::asio::any_io_executor QuicClientConnection::executor() const noexcept {
    return impl_->executor();
}

void QuicClientConnection::set_events(QuicClientEvents events) {
    impl_->set_events(std::move(events));
}

void QuicClientConnection::close() noexcept {
    if (impl_) {
        impl_->close();
    }
}

std::shared_ptr<QuicClientConnection>
make_quic_client_connection(boost::asio::any_io_executor executor,
                            std::unique_ptr<core::DatagramHandle> datagram,
                            boost::asio::ip::udp::endpoint remote_endpoint,
                            QuicClientOptions options, QuicClientEvents events) {
    if (!datagram) {
        if (datagram) {
            datagram->close();
        }
        return {};
    }
    auto impl = std::make_shared<QuicClientConnection::Impl>(
        std::move(executor), std::move(datagram), std::move(remote_endpoint), std::move(options),
        std::move(events));
    auto connection = std::shared_ptr<QuicClientConnection>(new QuicClientConnection(impl));
    impl->start();
    return connection;
}

} // namespace clash_native::transport
