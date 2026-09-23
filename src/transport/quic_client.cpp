#include <clash_native/transport/quic_client.hpp>

#include <clash_native/async/callback_sender.hpp>
#include <clash_native/async/oneshot.hpp>
#include <clash_native/io/sender.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>

#include "transport/builtin_ca_bundle.hpp"

#include <stdexec/execution.hpp>

#include <boost/asio/bind_executor.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/error.hpp>
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
#include <cstring>
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

constexpr std::size_t kQuicDatagramPayloadLimit = 1200;

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
    Impl(boost::asio::any_io_executor executor, std::unique_ptr<io::DatagramHandle> datagram,
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

    QuicClientConnection::ObserverId observe_stream(std::int64_t stream_id,
                                                    QuicStreamObserver observer) {
        const auto observer_id = next_observer_id_++;
        stream_observers_[stream_id].emplace(observer_id, std::move(observer));
        return observer_id;
    }

    void remove_stream_observer(std::int64_t stream_id,
                                QuicClientConnection::ObserverId observer_id) noexcept {
        const auto found = stream_observers_.find(stream_id);
        if (found == stream_observers_.end()) {
            return;
        }
        found->second.erase(observer_id);
        if (found->second.empty()) {
            stream_observers_.erase(found);
        }
    }

    QuicClientConnection::ObserverId observe_datagrams(QuicDatagramObserver observer) {
        const auto observer_id = next_observer_id_++;
        datagram_observers_.emplace(observer_id, std::move(observer));
        return observer_id;
    }

    void remove_datagram_observer(QuicClientConnection::ObserverId observer_id) noexcept {
        datagram_observers_.erase(observer_id);
    }

    void async_send_datagram(std::vector<std::uint8_t> data,
                             QuicClientConnection::DatagramWriteHandler handler) {
        auto fail_async = [executor = executor_, handler = std::move(handler)](
                              const boost::system::error_code &error) mutable {
            boost::asio::post(executor, [handler = std::move(handler), error]() mutable {
                if (handler) {
                    handler(error, 0);
                }
            });
        };
        if (retired_) {
            fail_async(boost::asio::error::operation_aborted);
            return;
        }
        const auto maximum = max_datagram_size();
        if (!ready_ || maximum == 0) {
            fail_async(boost::asio::error::operation_not_supported);
            return;
        }
        if (data.size() > maximum) {
            fail_async(boost::asio::error::message_size);
            return;
        }
        datagram_writes_.push_back(
            PendingDatagram{std::move(data), std::move(handler), next_datagram_id_++});
        request_write();
    }

    std::size_t max_datagram_size() const noexcept {
        if (connection_ == nullptr) {
            return 0;
        }
        const auto *parameters = ngtcp2_conn_get_remote_transport_params2(connection_);
        if (parameters == nullptr || parameters->max_datagram_frame_size == 0) {
            return 0;
        }
        return std::min<std::size_t>(static_cast<std::size_t>(parameters->max_datagram_frame_size),
                                     kQuicDatagramPayloadLimit);
    }

    boost::asio::ip::udp::endpoint remote_endpoint() const noexcept { return remote_endpoint_; }

    QuicClientConnection::StreamId track_multiplexed_stream(std::int64_t stream_id) {
        const auto operation_id = next_operation_id_++;
        multiplexed_streams_.emplace(operation_id, stream_id);
        active_streams_.insert(stream_id);
        return operation_id;
    }

    QuicClientConnection::StreamId next_operation_id() noexcept { return next_operation_id_++; }

    void cancel_multiplexed_stream(QuicClientConnection::StreamId operation_id) noexcept {
        const auto found = multiplexed_streams_.find(operation_id);
        if (found == multiplexed_streams_.end()) {
            return;
        }
        const auto stream_id = found->second;
        multiplexed_streams_.erase(found);
        active_streams_.erase(stream_id);
        shutdown_stream(stream_id, 0);
    }

    std::size_t active_streams() const noexcept { return active_streams_.size(); }

    std::optional<std::size_t> max_concurrent_streams() const noexcept {
        if (connection_ == nullptr) {
            return std::nullopt;
        }
        const auto *parameters = ngtcp2_conn_get_remote_transport_params2(connection_);
        if (parameters == nullptr || parameters->initial_max_streams_bidi == 0) {
            return std::nullopt;
        }
        return static_cast<std::size_t>(parameters->initial_max_streams_bidi);
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

    struct PendingDatagram {
        std::vector<std::uint8_t> bytes;
        QuicClientConnection::DatagramWriteHandler handler;
        std::uint64_t id = 0;
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

    void dispatch_stream_data(std::int64_t stream_id, const std::uint8_t *data, std::size_t length,
                              bool fin) {
        if (events_.stream_data) {
            events_.stream_data(stream_id, data, length, fin);
        }
        const auto found = stream_observers_.find(stream_id);
        if (found == stream_observers_.end()) {
            return;
        }
        std::vector<QuicStreamObserver> observers;
        observers.reserve(found->second.size());
        for (const auto &[observer_id, observer] : found->second) {
            (void)observer_id;
            observers.push_back(observer);
        }
        for (const auto &observer : observers) {
            if (observer.data) {
                observer.data(data, length, fin);
            }
        }
    }

    void dispatch_stream_write_consumed(std::int64_t stream_id, std::size_t length, bool complete) {
        if (events_.stream_write_consumed) {
            events_.stream_write_consumed(stream_id, length, complete);
        }
        const auto found = stream_observers_.find(stream_id);
        if (found == stream_observers_.end()) {
            return;
        }
        std::vector<QuicStreamObserver> observers;
        observers.reserve(found->second.size());
        for (const auto &[observer_id, observer] : found->second) {
            (void)observer_id;
            observers.push_back(observer);
        }
        for (const auto &observer : observers) {
            if (observer.write_consumed) {
                observer.write_consumed(length, complete);
            }
        }
    }

    void dispatch_stream_writable(std::int64_t stream_id) {
        if (events_.stream_writable) {
            events_.stream_writable(stream_id);
        }
        const auto found = stream_observers_.find(stream_id);
        if (found == stream_observers_.end()) {
            return;
        }
        std::vector<QuicStreamObserver> observers;
        observers.reserve(found->second.size());
        for (const auto &[observer_id, observer] : found->second) {
            (void)observer_id;
            observers.push_back(observer);
        }
        for (const auto &observer : observers) {
            if (observer.writable) {
                observer.writable();
            }
        }
    }

    void dispatch_stream_closed(std::int64_t stream_id, std::uint64_t application_error) {
        if (events_.stream_closed) {
            events_.stream_closed(stream_id, application_error);
        }
        active_streams_.erase(stream_id);
        for (auto iterator = multiplexed_streams_.begin();
             iterator != multiplexed_streams_.end();) {
            if (iterator->second == stream_id) {
                iterator = multiplexed_streams_.erase(iterator);
            } else {
                ++iterator;
            }
        }
        const auto found = stream_observers_.find(stream_id);
        if (found == stream_observers_.end()) {
            return;
        }
        std::vector<QuicStreamObserver> observers;
        observers.reserve(found->second.size());
        for (const auto &[observer_id, observer] : found->second) {
            (void)observer_id;
            observers.push_back(observer);
        }
        for (const auto &observer : observers) {
            if (observer.closed) {
                observer.closed(application_error);
            }
        }
    }

    void dispatch_stream_reset(std::int64_t stream_id, std::uint64_t application_error) {
        if (events_.stream_reset) {
            events_.stream_reset(stream_id, application_error);
        }
        active_streams_.erase(stream_id);
        for (auto iterator = multiplexed_streams_.begin();
             iterator != multiplexed_streams_.end();) {
            if (iterator->second == stream_id) {
                iterator = multiplexed_streams_.erase(iterator);
            } else {
                ++iterator;
            }
        }
        const auto found = stream_observers_.find(stream_id);
        if (found == stream_observers_.end()) {
            return;
        }
        std::vector<QuicStreamObserver> observers;
        observers.reserve(found->second.size());
        for (const auto &[observer_id, observer] : found->second) {
            (void)observer_id;
            observers.push_back(observer);
        }
        for (const auto &observer : observers) {
            if (observer.reset) {
                observer.reset(application_error);
            }
        }
    }

    void dispatch_datagram(const std::uint8_t *data, std::size_t length) {
        const auto observers = datagram_observers_;
        for (const auto &[observer_id, observer] : observers) {
            (void)observer_id;
            if (observer.data) {
                observer.data(data, length);
            }
        }
    }

    void dispatch_datagram_closed() {
        const auto observers = datagram_observers_;
        for (const auto &[observer_id, observer] : observers) {
            (void)observer_id;
            if (observer.closed) {
                observer.closed();
            }
        }
    }

    void dispatch_stream_observers_reset() {
        const auto observers = stream_observers_;
        for (const auto &[stream_id, stream_observer_map] : observers) {
            (void)stream_id;
            for (const auto &[observer_id, observer] : stream_observer_map) {
                (void)observer_id;
                if (observer.reset) {
                    observer.reset(0);
                }
            }
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
        self->dispatch_stream_data(stream_id, data, length,
                                   (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0);
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
        self->dispatch_stream_writable(stream_id);
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
        self->dispatch_stream_closed(stream_id, application_error);
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
        self->dispatch_stream_reset(stream_id, application_error);
        return 0;
    }

    static int on_recv_datagram(ngtcp2_conn *, std::uint32_t, const std::uint8_t *data,
                                std::size_t length, void *user_data) {
        auto *self = static_cast<Impl *>(user_data);
        self->dispatch_datagram(data, length);
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
        callbacks.recv_datagram = &on_recv_datagram;

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
        parameters.max_datagram_frame_size = kQuicDatagramPayloadLimit;
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
        struct ReceiveReceiver {
            using receiver_concept = stdexec::receiver_tag;
            std::shared_ptr<Impl> self;
            std::shared_ptr<ReceiveBuffer> buffer;
            void set_value(io::DatagramPacket packet) && noexcept {
                // Hoist before the move below: argument evaluation order
                // is unspecified, so reading self->executor_ next to
                // [self = std::move(self)] may observe the moved-from state.
                auto executor = self->executor_;
                boost::asio::dispatch(std::move(executor), [self = std::move(self),
                                                            buffer = std::move(buffer),
                                                            packet = std::move(packet)] {
                    self->receiving_ = false;
                    self->check_teardown();
                    if (self->retired_) {
                        return;
                    }
                    if (packet.address.is_address() &&
                        packet.address.address() == self->remote_endpoint_.address() &&
                        packet.address.port() == self->remote_endpoint_.port() &&
                        packet.size != 0) {
                        self->process_datagram(
                            buffer->bytes.data(), packet.size,
                            boost::asio::ip::udp::endpoint(packet.address.address(),
                                                           packet.address.port()));
                    }
                    if (!self->retired_) {
                        self->receive_next();
                    }
                    self->check_teardown();
                });
            }
            void set_error(std::exception_ptr error) && noexcept {
                const auto self = std::move(this->self);
                boost::asio::dispatch(self->executor_, [self, error = std::move(error)] {
                    self->receiving_ = false;
                    self->check_teardown();
                    if (self->retired_) {
                        return;
                    }
                    try {
                        std::rethrow_exception(std::move(error));
                    } catch (const boost::system::system_error &failure) {
                        if (failure.code() != boost::asio::error::operation_aborted) {
                            self->fail(
                                transport_error("failed to receive QUIC datagram", failure.code()));
                        }
                    } catch (const core::Error &failure) {
                        self->fail(failure);
                    } catch (...) {
                        self->fail(core::Error{
                            core::ErrorCode::transport_io, "failed to receive QUIC datagram", {}});
                    }
                    self->check_teardown();
                });
            }
            void set_stopped() && noexcept {
                const auto self = std::move(this->self);
                boost::asio::dispatch(self->executor_, [self] {
                    self->receiving_ = false;
                    self->check_teardown();
                });
            }
        };
        auto buffer = std::make_shared<ReceiveBuffer>();
        auto sender = datagram_->async_receive_from(boost::asio::buffer(buffer->bytes));
        async::start_with_receiver(std::move(sender), ReceiveReceiver{shared_from_this(), buffer});
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
            if (advanced != 0) {
                dispatch_stream_write_consumed(stream_id, advanced, false);
            }
            dispatch_stream_write_consumed(stream_id, 0, true);
        } else {
            if (advanced != 0) {
                dispatch_stream_write_consumed(stream_id, advanced, false);
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
                    if (!datagram_writes_.empty()) {
                        auto &datagram = datagram_writes_.front();
                        int accepted = 0;
                        const auto written = ngtcp2_conn_write_datagram(
                            connection_, &path_storage.path, &packet_info, packet.data(),
                            packet.size(), &accepted, NGTCP2_WRITE_DATAGRAM_FLAG_NONE, datagram.id,
                            datagram.bytes.data(), datagram.bytes.size(), now);
                        if (written < 0) {
                            auto handler = std::move(datagram.handler);
                            datagram_writes_.pop_front();
                            post_datagram_result(std::move(handler),
                                                 boost::asio::error::message_size, 0);
                            if (written == NGTCP2_ERR_INVALID_STATE ||
                                written == NGTCP2_ERR_INVALID_ARGUMENT) {
                                continue;
                            }
                            fail(protocol_error(
                                std::string("ngtcp2 failed to write a QUIC DATAGRAM: ") +
                                ngtcp2_strerror(static_cast<int>(written))));
                            break;
                        }
                        if (accepted == 0 || written == 0) {
                            break;
                        }
                        auto handler = std::move(datagram.handler);
                        const auto size = datagram.bytes.size();
                        datagram_writes_.pop_front();
                        post_datagram_result(std::move(handler), {}, size);
                        ngtcp2_conn_update_pkt_tx_time(connection_, now);
                        outgoing_.emplace_back(packet.begin(), packet.begin() + written);
                        packet_ready = true;
                        break;
                    }
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

    void post_datagram_result(QuicClientConnection::DatagramWriteHandler handler,
                              const boost::system::error_code &error, std::size_t size) {
        boost::asio::post(executor_, [handler = std::move(handler), error, size]() mutable {
            if (handler) {
                handler(error, size);
            }
        });
    }

    void send_next_packet() {
        if (retired_ || sending_ || outgoing_.empty() || !datagram_) {
            return;
        }
        sending_ = true;
        auto packet = std::make_shared<std::vector<std::uint8_t>>(std::move(outgoing_.front()));
        outgoing_.pop_front();
        struct SendReceiver {
            using receiver_concept = stdexec::receiver_tag;
            std::shared_ptr<Impl> self;
            std::shared_ptr<std::vector<std::uint8_t>> packet;
            void set_value(std::size_t length) && noexcept {
                // Hoist before the move below: argument evaluation order
                // is unspecified, so reading self->executor_ next to
                // [self = std::move(self)] may observe the moved-from state.
                auto executor = self->executor_;
                boost::asio::dispatch(std::move(executor), [self = std::move(self),
                                                            packet = std::move(packet), length] {
                    self->sending_ = false;
                    self->check_teardown();
                    if (self->retired_) {
                        return;
                    }
                    if (length != packet->size()) {
                        self->fail(core::Error{core::ErrorCode::transport_io,
                                               "QUIC datagram was only partially sent",
                                               {}});
                        return;
                    }
                    self->send_next_packet();
                    if (self->outgoing_.empty()) {
                        self->request_write();
                    }
                    self->check_teardown();
                });
            }
            void set_error(std::exception_ptr error) && noexcept {
                const auto self = std::move(this->self);
                boost::asio::dispatch(self->executor_, [self, error = std::move(error)] {
                    self->sending_ = false;
                    self->check_teardown();
                    if (self->retired_) {
                        return;
                    }
                    try {
                        std::rethrow_exception(std::move(error));
                    } catch (const core::Error &failure) {
                        self->fail(failure);
                    } catch (...) {
                        self->fail(core::Error{
                            core::ErrorCode::transport_io, "failed to send QUIC datagram", {}});
                    }
                    self->check_teardown();
                });
            }
            void set_stopped() && noexcept {
                const auto self = std::move(this->self);
                boost::asio::dispatch(self->executor_, [self] {
                    self->sending_ = false;
                    self->check_teardown();
                });
            }
        };
        auto sender = datagram_->async_send_to(
            boost::asio::buffer(*packet), io::DatagramAddress::from_endpoint(remote_endpoint_));
        async::start_with_receiver(std::move(sender),
                                   SendReceiver{shared_from_this(), std::move(packet)});
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
        for (auto &datagram : datagram_writes_) {
            post_datagram_result(std::move(datagram.handler), boost::asio::error::operation_aborted,
                                 0);
        }
        datagram_writes_.clear();
        dispatch_datagram_closed();
        dispatch_stream_observers_reset();
        stream_observers_.clear();
        multiplexed_streams_.clear();
        active_streams_.clear();
        if (datagram_) {
            // Cancel and close promptly, but do not release: sender ops
            // parked on the handle (receive_next/send_next_packet) keep
            // the Impl alive through their receivers and must still see
            // a live handle when they complete. The handle dies with the
            // Impl once they drain.
            datagram_->cancel();
            datagram_->close();
        }
        release_protocol();
        // Join the pump before reporting: parked sender ops still hold
        // receivers that dispatch back to this strand, so the failure
        // notification (and everything downstream of it, up to process
        // teardown) waits until they have drained. Reporting early lets
        // the caller stop the runtime while completions are still in
        // flight, which destroys queued strand work out from under them.
        check_teardown();
    }

    // Fires events_.failed once the pump has drained after fail(). Runs
    // on the strand; every receiving_/sending_ transition funnels here.
    void check_teardown() {
        if (!retired_ || teardown_notified_ || receiving_ || sending_ || !error_) {
            return;
        }
        teardown_notified_ = true;
        if (events_.failed) {
            events_.failed(std::move(*error_));
        }
    }

    void retire() noexcept {
        if (retired_) {
            return;
        }
        retired_ = true;
        ready_ = false;
        expiry_timer_.cancel();
        for (auto &datagram : datagram_writes_) {
            post_datagram_result(std::move(datagram.handler), boost::asio::error::operation_aborted,
                                 0);
        }
        datagram_writes_.clear();
        dispatch_datagram_closed();
        dispatch_stream_observers_reset();
        stream_observers_.clear();
        multiplexed_streams_.clear();
        active_streams_.clear();
        if (datagram_) {
            // Same lifetime rule as fail(): parked sender ops outlive
            // this call and complete against the handle.
            datagram_->cancel();
            datagram_->close();
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
    std::unique_ptr<io::DatagramHandle> datagram_;
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
    std::unordered_map<std::int64_t,
                       std::unordered_map<QuicClientConnection::ObserverId, QuicStreamObserver>>
        stream_observers_;
    std::unordered_map<QuicClientConnection::ObserverId, QuicDatagramObserver> datagram_observers_;
    std::unordered_map<QuicClientConnection::StreamId, std::int64_t> multiplexed_streams_;
    std::set<std::int64_t> active_streams_;
    std::set<std::int64_t> finished_streams_;
    std::set<std::int64_t> blocked_streams_;
    std::set<std::int64_t> scheduled_streams_;
    std::deque<std::int64_t> ready_streams_;
    std::deque<std::vector<std::uint8_t>> outgoing_;
    std::deque<PendingDatagram> datagram_writes_;
    std::optional<core::Error> error_;
    QuicClientConnection::ObserverId next_observer_id_ = 1;
    QuicClientConnection::StreamId next_operation_id_ = 1;
    std::uint64_t next_datagram_id_ = 1;
    bool ready_ = false;
    bool retired_ = false;
    bool receiving_ = false;
    bool sending_ = false;
    bool teardown_notified_ = false;
    bool processing_datagram_ = false;
    bool writing_packets_ = false;
    bool write_again_ = false;
    bool stream_capacity_pending_ = false;
};

namespace {

class QuicStreamHandle final : public io::StreamHandle {
  public:
    QuicStreamHandle(std::shared_ptr<QuicClientConnection> connection,
                     io::MultiplexedSession::StreamId operation_id, std::int64_t stream_id)
        : connection_(std::move(connection)), operation_id_(operation_id), stream_id_(stream_id),
          executor_(connection_->executor()) {
        observer_id_ = connection_->observe_stream(
            stream_id_, QuicStreamObserver{
                            [this](const std::uint8_t *data, std::size_t size, bool fin) {
                                on_data(data, size, fin);
                            },
                            [this](std::size_t, bool complete) {
                                if (complete) {
                                    on_write_complete();
                                }
                            },
                            [this] { pump_write(); },
                            [this](std::uint64_t) { on_stream_closed(); },
                            [this](std::uint64_t) { on_stream_reset(); },
                        });
    }

    ~QuicStreamHandle() override { close(); }

    io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override {
        using Signatures =
            stdexec::completion_signatures<stdexec::set_value_t(std::optional<std::size_t>),
                                           stdexec::set_error_t(std::exception_ptr),
                                           stdexec::set_stopped_t()>;
        return io::AnySender<std::optional<std::size_t>>{async::callback_sender<Signatures>(
            [self = this, buffer](auto terminal) mutable {
                self->read(buffer, std::move(terminal));
            },
            [](auto receiver, const boost::system::error_code &error, std::size_t size) {
                net::translate_read(std::move(receiver), error, size, "quic stream read");
            })};
    }

    io::AnySender<std::size_t> async_write(boost::asio::const_buffer buffer) override {
        using Signatures = stdexec::completion_signatures<stdexec::set_value_t(std::size_t),
                                                          stdexec::set_error_t(std::exception_ptr),
                                                          stdexec::set_stopped_t()>;
        return io::AnySender<std::size_t>{async::callback_sender<Signatures>(
            [self = this, buffer](auto terminal) mutable {
                self->write(buffer, std::move(terminal));
            },
            [](auto receiver, const boost::system::error_code &error, std::size_t size) {
                net::translate_write(std::move(receiver), error, size, "quic stream write");
            })};
    }

    // The observer machinery below stays callback-parked; each pull/write
    // bridges once through the shells above.
    using ReadHandler = std::function<void(const boost::system::error_code &, std::size_t)>;
    using WriteHandler = std::function<void(const boost::system::error_code &, std::size_t)>;

    void read(boost::asio::mutable_buffer buffer, ReadHandler handler) {
        if (read_pending_) {
            post_read(boost::asio::error::operation_aborted, 0, std::move(handler));
            return;
        }
        if (closed_) {
            post_read(boost::asio::error::operation_aborted, 0, std::move(handler));
            return;
        }
        read_pending_ = true;
        read_data_ = static_cast<std::uint8_t *>(buffer.data());
        read_size_ = buffer.size();
        read_handler_ = std::move(handler);
        fulfill_read();
    }

    void write(boost::asio::const_buffer buffer, WriteHandler handler) {
        if (closed_ || send_shutdown_) {
            post_write(boost::asio::error::operation_aborted, 0, std::move(handler));
            return;
        }
        const auto size = buffer.size();
        if (size == 0) {
            post_write({}, 0, std::move(handler));
            return;
        }
        PendingWrite pending;
        pending.bytes.resize(size);
        std::memcpy(pending.bytes.data(), buffer.data(), size);
        pending.handler = std::move(handler);
        writes_.push_back(std::move(pending));
        pump_write();
    }

    boost::asio::any_io_executor executor() noexcept override { return executor_; }

    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept override {
        error = boost::asio::error::operation_not_supported;
        return {};
    }

    void shutdown_send(boost::system::error_code &error) noexcept override {
        if (closed_ || send_shutdown_) {
            error = closed_ ? boost::asio::error::operation_aborted : boost::system::error_code{};
            return;
        }
        send_shutdown_ = true;
        connection_->write_stream_data(stream_id_, {}, true);
        error.clear();
    }

    void close() noexcept override {
        if (closed_) {
            return;
        }
        closed_ = true;
        connection_->remove_stream_observer(stream_id_, observer_id_);
        connection_->cancel(operation_id_);
        fail_pending(boost::asio::error::operation_aborted);
    }

  private:
    struct ReadChunk {
        std::vector<std::uint8_t> bytes;
        std::size_t offset = 0;
        bool fin = false;
    };

    struct PendingWrite {
        std::vector<std::uint8_t> bytes;
        WriteHandler handler;
    };

    void on_data(const std::uint8_t *data, std::size_t size, bool fin) {
        if (closed_) {
            return;
        }
        if (size != 0) {
            ReadChunk chunk;
            chunk.bytes.assign(data, data + size);
            chunk.fin = fin;
            read_queue_.push_back(std::move(chunk));
        } else if (fin) {
            eof_ = true;
        }
        if (fin && !read_queue_.empty()) {
            read_queue_.back().fin = true;
        }
        fulfill_read();
    }

    void on_stream_closed() {
        if (closed_) {
            return;
        }
        eof_ = true;
        fulfill_read();
    }

    void on_stream_reset() {
        if (closed_) {
            return;
        }
        terminal_error_ = boost::asio::error::connection_reset;
        fail_pending(*terminal_error_);
        connection_->remove_stream_observer(stream_id_, observer_id_);
        closed_ = true;
    }

    void fulfill_read() {
        if (!read_pending_ || closed_) {
            return;
        }
        if (terminal_error_) {
            auto handler = std::move(read_handler_);
            read_pending_ = false;
            post_read(*terminal_error_, 0, std::move(handler));
            return;
        }
        if (read_queue_.empty()) {
            if (eof_) {
                auto handler = std::move(read_handler_);
                read_pending_ = false;
                post_read(boost::asio::error::eof, 0, std::move(handler));
            }
            return;
        }

        auto &chunk = read_queue_.front();
        const auto available = chunk.bytes.size() - chunk.offset;
        const auto copied = std::min(read_size_, available);
        std::memcpy(read_data_, chunk.bytes.data() + chunk.offset, copied);
        chunk.offset += copied;
        if (chunk.offset == chunk.bytes.size()) {
            const bool fin = chunk.fin;
            read_queue_.pop_front();
            if (fin) {
                eof_ = true;
            }
        }
        const auto consumed = copied;
        const auto handler = std::move(read_handler_);
        read_pending_ = false;
        read_data_ = nullptr;
        read_size_ = 0;
        if (consumed != 0) {
            (void)connection_->extend_receive_credit(stream_id_, consumed);
        }
        post_read({}, consumed, handler);
    }

    void pump_write() {
        if (closed_ || write_in_flight_ || writes_.empty()) {
            return;
        }
        write_in_flight_ = true;
        connection_->write_stream_data(stream_id_, writes_.front().bytes, false);
    }

    void on_write_complete() {
        if (closed_ || !write_in_flight_ || writes_.empty()) {
            return;
        }
        auto handler = std::move(writes_.front().handler);
        const auto size = writes_.front().bytes.size();
        writes_.pop_front();
        write_in_flight_ = false;
        post_write({}, size, std::move(handler));
        pump_write();
    }

    void fail_pending(const boost::system::error_code &error) {
        if (read_pending_) {
            auto handler = std::move(read_handler_);
            read_pending_ = false;
            post_read(error, 0, std::move(handler));
        }
        if (write_in_flight_ && !writes_.empty()) {
            auto handler = std::move(writes_.front().handler);
            writes_.pop_front();
            write_in_flight_ = false;
            post_write(error, 0, std::move(handler));
        }
        while (!writes_.empty()) {
            auto handler = std::move(writes_.front().handler);
            writes_.pop_front();
            post_write(error, 0, std::move(handler));
        }
    }

    void post_read(const boost::system::error_code &error, std::size_t size, ReadHandler handler) {
        boost::asio::post(executor_, [handler = std::move(handler), error, size]() mutable {
            if (handler) {
                handler(error, size);
            }
        });
    }

    void post_write(const boost::system::error_code &error, std::size_t size,
                    WriteHandler handler) {
        boost::asio::post(executor_, [handler = std::move(handler), error, size]() mutable {
            if (handler) {
                handler(error, size);
            }
        });
    }

    std::shared_ptr<QuicClientConnection> connection_;
    io::MultiplexedSession::StreamId operation_id_;
    std::int64_t stream_id_;
    boost::asio::any_io_executor executor_;
    QuicClientConnection::ObserverId observer_id_ = 0;
    std::deque<ReadChunk> read_queue_;
    std::deque<PendingWrite> writes_;
    std::uint8_t *read_data_ = nullptr;
    std::size_t read_size_ = 0;
    ReadHandler read_handler_;
    std::optional<boost::system::error_code> terminal_error_;
    bool read_pending_ = false;
    bool write_in_flight_ = false;
    bool eof_ = false;
    bool send_shutdown_ = false;
    bool closed_ = false;
};

class QuicDatagramHandle final : public io::DatagramHandle {
  public:
    using ReadHandler =
        std::function<void(const boost::system::error_code &, std::size_t, io::DatagramAddress)>;
    using WriteHandler = std::function<void(const boost::system::error_code &, std::size_t)>;

    explicit QuicDatagramHandle(std::shared_ptr<QuicClientConnection> connection)
        : connection_(std::move(connection)), executor_(connection_->executor()) {
        observer_id_ = connection_->observe_datagrams(QuicDatagramObserver{
            [this](const std::uint8_t *data, std::size_t size) { on_data(data, size); },
            [this] { on_connection_closed(); }});
    }

    ~QuicDatagramHandle() override { close(); }

    io::AnySender<std::size_t> async_send_to(boost::asio::const_buffer buffer,
                                             io::DatagramAddress destination) override {
        using Signatures = stdexec::completion_signatures<stdexec::set_value_t(std::size_t),
                                                          stdexec::set_error_t(std::exception_ptr),
                                                          stdexec::set_stopped_t()>;
        return io::AnySender<std::size_t>{async::callback_sender<Signatures>(
            [self = this, buffer, destination](auto terminal) mutable {
                self->send(buffer, std::move(destination), std::move(terminal));
            },
            [](auto receiver, const boost::system::error_code &error, std::size_t size) {
                if (!error) {
                    stdexec::set_value(std::move(receiver), size);
                    return;
                }
                if (error == boost::asio::error::operation_aborted) {
                    stdexec::set_stopped(std::move(receiver));
                    return;
                }
                stdexec::set_error(std::move(receiver), std::make_exception_ptr(core::Error{
                                                            core::ErrorCode::transport_io,
                                                            "QUIC datagram send failed", error}));
            })};
    }

    io::AnySender<io::DatagramPacket>
    async_receive_from(boost::asio::mutable_buffer buffer) override {
        using Signatures = stdexec::completion_signatures<stdexec::set_value_t(io::DatagramPacket),
                                                          stdexec::set_error_t(std::exception_ptr),
                                                          stdexec::set_stopped_t()>;
        return io::AnySender<io::DatagramPacket>{async::callback_sender<Signatures>(
            [self = this, buffer](auto terminal) mutable {
                self->receive(buffer, [terminal = std::move(terminal)](
                                          const boost::system::error_code &error, std::size_t size,
                                          io::DatagramAddress source) mutable {
                    terminal(error, size, std::move(source));
                });
            },
            [](auto receiver, const boost::system::error_code &error, std::size_t size,
               io::DatagramAddress source) {
                if (!error) {
                    stdexec::set_value(std::move(receiver),
                                       io::DatagramPacket{size, std::move(source)});
                    return;
                }
                if (error == boost::asio::error::operation_aborted) {
                    stdexec::set_stopped(std::move(receiver));
                    return;
                }
                stdexec::set_error(
                    std::move(receiver),
                    std::make_exception_ptr(core::Error{core::ErrorCode::transport_io,
                                                        "QUIC datagram receive failed", error}));
            })};
    }

    void send(boost::asio::const_buffer buffer, io::DatagramAddress destination,
              WriteHandler handler) {
        if (closed_) {
            post_write(boost::asio::error::operation_aborted, 0, std::move(handler));
            return;
        }
        if (!destination.is_address() ||
            destination.address() != connection_->remote_endpoint().address() ||
            destination.port() != connection_->remote_endpoint().port()) {
            post_write(boost::asio::error::host_unreachable, 0, std::move(handler));
            return;
        }
        if (buffer.size() > max_datagram_size()) {
            post_write(boost::asio::error::message_size, 0, std::move(handler));
            return;
        }
        std::vector<std::uint8_t> bytes(buffer.size());
        if (!bytes.empty()) {
            std::memcpy(bytes.data(), buffer.data(), bytes.size());
        }
        connection_->async_send_datagram(std::move(bytes), std::move(handler));
    }

    void receive(boost::asio::mutable_buffer buffer, ReadHandler handler) {
        if (read_pending_) {
            post_read(boost::asio::error::operation_aborted, 0, {}, std::move(handler));
            return;
        }
        if (closed_) {
            post_read(boost::asio::error::operation_aborted, 0, {}, std::move(handler));
            return;
        }
        read_pending_ = true;
        read_data_ = static_cast<std::uint8_t *>(buffer.data());
        read_size_ = buffer.size();
        read_handler_ = std::move(handler);
        fulfill_read();
    }

    boost::asio::any_io_executor executor() noexcept override { return executor_; }

    std::size_t max_datagram_size() const noexcept override {
        return connection_->max_datagram_size();
    }

    void cancel() noexcept override {
        if (closed_) {
            return;
        }
        fail_read(boost::asio::error::operation_aborted);
    }

    void close() noexcept override {
        if (closed_) {
            return;
        }
        closed_ = true;
        connection_->remove_datagram_observer(observer_id_);
        fail_read(boost::asio::error::operation_aborted);
    }

  private:
    struct Datagram {
        std::vector<std::uint8_t> bytes;
    };

    void on_data(const std::uint8_t *data, std::size_t size) {
        if (closed_) {
            return;
        }
        Datagram datagram;
        datagram.bytes.assign(data, data + size);
        queue_.push_back(std::move(datagram));
        fulfill_read();
    }

    void fulfill_read() {
        if (!read_pending_ || closed_ || queue_.empty()) {
            return;
        }
        auto datagram = std::move(queue_.front());
        queue_.pop_front();
        if (datagram.bytes.size() > read_size_) {
            read_pending_ = false;
            post_read(boost::asio::error::message_size, 0,
                      io::DatagramAddress::from_endpoint(connection_->remote_endpoint()),
                      std::move(read_handler_));
            return;
        }
        if (!datagram.bytes.empty()) {
            std::memcpy(read_data_, datagram.bytes.data(), datagram.bytes.size());
        }
        read_pending_ = false;
        post_read({}, datagram.bytes.size(),
                  io::DatagramAddress::from_endpoint(connection_->remote_endpoint()),
                  std::move(read_handler_));
    }

    void fail_read(const boost::system::error_code &error) {
        if (!read_pending_) {
            return;
        }
        read_pending_ = false;
        post_read(error, 0, {}, std::move(read_handler_));
    }

    void on_connection_closed() {
        if (closed_) {
            return;
        }
        closed_ = true;
        fail_read(boost::asio::error::operation_aborted);
    }

    void post_read(const boost::system::error_code &error, std::size_t size,
                   io::DatagramAddress sender, ReadHandler handler) {
        boost::asio::post(executor_, [handler = std::move(handler), error, size, sender]() mutable {
            if (handler) {
                handler(error, size, sender);
            }
        });
    }

    void post_write(const boost::system::error_code &error, std::size_t size,
                    WriteHandler handler) {
        boost::asio::post(executor_, [handler = std::move(handler), error, size]() mutable {
            if (handler) {
                handler(error, size);
            }
        });
    }

    std::shared_ptr<QuicClientConnection> connection_;
    boost::asio::any_io_executor executor_;
    QuicClientConnection::ObserverId observer_id_ = 0;
    std::deque<Datagram> queue_;
    std::uint8_t *read_data_ = nullptr;
    std::size_t read_size_ = 0;
    ReadHandler read_handler_;
    bool read_pending_ = false;
    bool closed_ = false;
};

} // namespace

QuicClientConnection::QuicClientConnection(std::shared_ptr<Impl> impl) : impl_(std::move(impl)) {}

QuicClientConnection::~QuicClientConnection() { close(); }

QuicOpenStreamResult QuicClientConnection::open_bidirectional_stream() {
    return impl_->open_stream(false);
}

QuicOpenStreamResult QuicClientConnection::open_unidirectional_stream() {
    return impl_->open_stream(true);
}

namespace {

using QuicOpenTerminal = core::Result<std::unique_ptr<io::StreamHandle>>;

io::AnySender<std::unique_ptr<io::StreamHandle>>
wrap_quic_open(std::shared_ptr<QuicClientConnection> self,
               QuicClientConnection::StreamId operation_id,
               async::oneshot::Receiver<QuicOpenTerminal> receiver) {
    auto sender =
        std::move(receiver) |
        stdexec::then(
            [](std::optional<QuicOpenTerminal> terminal) -> std::unique_ptr<io::StreamHandle> {
                if (!terminal) {
                    throw core::Error{core::ErrorCode::cancelled, "QUIC stream open was abandoned"};
                }
                if (!*terminal) {
                    throw terminal->error();
                }
                return std::move(terminal->value());
            }) |
        stdexec::let_stopped([self = std::move(self), operation_id] {
            self->cancel(operation_id);
            return stdexec::just_stopped();
        });
    return io::AnySender<std::unique_ptr<io::StreamHandle>>{std::move(sender)};
}

} // namespace

io::AnySender<std::unique_ptr<io::StreamHandle>>
QuicClientConnection::open_stream(io::MultiplexedStreamRequest request,
                                  std::chrono::steady_clock::time_point deadline) {
    auto channel = async::oneshot::channel<QuicOpenTerminal>();
    const auto operation_id = impl_->next_operation_id();
    if (!request.bidirectional) {
        channel.sender.send(core::fail(core::Error{core::ErrorCode::unsupported,
                                                   "QUIC unidirectional streams are not "
                                                   "StreamHandle-compatible",
                                                   {}}));
        return wrap_quic_open(shared_from_this(), operation_id, std::move(channel.receiver));
    }
    if (deadline <= Clock::now()) {
        channel.sender.send(
            core::fail(core::Error{core::ErrorCode::timeout, "QUIC stream open timed out", {}}));
        return wrap_quic_open(shared_from_this(), operation_id, std::move(channel.receiver));
    }
    const auto opened = impl_->open_stream(false);
    if (opened.state != QuicOpenStreamResult::State::opened || opened.stream_id < 0) {
        channel.sender.send(core::fail(opened.error.value_or(
            core::Error{core::ErrorCode::transport_io, "QUIC stream could not be opened", {}})));
        return wrap_quic_open(shared_from_this(), operation_id, std::move(channel.receiver));
    }
    const auto tracked_id = impl_->track_multiplexed_stream(opened.stream_id);
    const auto connection = shared_from_this();
    std::unique_ptr<io::StreamHandle> stream =
        std::make_unique<QuicStreamHandle>(connection, tracked_id, opened.stream_id);
    channel.sender.send(QuicOpenTerminal{std::move(stream)});
    return wrap_quic_open(shared_from_this(), operation_id, std::move(channel.receiver));
}

void QuicClientConnection::cancel(StreamId stream_id) noexcept {
    impl_->cancel_multiplexed_stream(stream_id);
}

std::size_t QuicClientConnection::active_streams() const noexcept {
    return impl_->active_streams();
}

std::optional<std::size_t> QuicClientConnection::max_concurrent_streams() const noexcept {
    return impl_->max_concurrent_streams();
}

QuicClientConnection::ObserverId QuicClientConnection::observe_stream(std::int64_t stream_id,
                                                                      QuicStreamObserver observer) {
    return impl_->observe_stream(stream_id, std::move(observer));
}

void QuicClientConnection::remove_stream_observer(std::int64_t stream_id,
                                                  ObserverId observer_id) noexcept {
    impl_->remove_stream_observer(stream_id, observer_id);
}

QuicClientConnection::ObserverId
QuicClientConnection::observe_datagrams(QuicDatagramObserver observer) {
    return impl_->observe_datagrams(std::move(observer));
}

void QuicClientConnection::remove_datagram_observer(ObserverId observer_id) noexcept {
    impl_->remove_datagram_observer(observer_id);
}

void QuicClientConnection::async_send_datagram(std::vector<std::uint8_t> data,
                                               DatagramWriteHandler handler) {
    impl_->async_send_datagram(std::move(data), std::move(handler));
}

std::unique_ptr<io::DatagramHandle> QuicClientConnection::open_datagram() {
    return std::make_unique<QuicDatagramHandle>(shared_from_this());
}

std::size_t QuicClientConnection::max_datagram_size() const noexcept {
    return impl_->max_datagram_size();
}

boost::asio::ip::udp::endpoint QuicClientConnection::remote_endpoint() const noexcept {
    return impl_->remote_endpoint();
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
                            std::unique_ptr<io::DatagramHandle> datagram,
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
