#include <clash_native/dns/dns_codec.hpp>
#include <clash_native/dns/dns_transport.hpp>

#include "builtin_ca_bundle.hpp"
#include "stream_handle_adapter.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/write.hpp>

#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <deque>
#include <memory>
#include <optional>
#include <string>
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

core::Error handshake_error(const boost::system::error_code &error) {
    return {core::ErrorCode::carrier_handshake, "DoT TLS handshake failed",
            std::error_code(error.value(), std::system_category())};
}

core::Error timeout_error() { return {core::ErrorCode::timeout, "DoT DNS query timed out"}; }

core::Error cancelled_error() {
    return {core::ErrorCode::cancelled, "DoT DNS query was cancelled"};
}

} // namespace

class DotDnsTransport final : public DnsTransport {
  private:
    class Operation;
    class Session;

  public:
    DotDnsTransport(runtime::AsioRuntime &runtime, DnsUpstreamConfig config)
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

class DotDnsTransport::Session final
    : public std::enable_shared_from_this<DotDnsTransport::Session> {
  public:
    using Handler = std::function<void(core::Result<std::vector<std::uint8_t>>)>;

    Session(runtime::AsioRuntime &runtime, boost::asio::ip::tcp::endpoint endpoint,
            std::string server_name, bool verify_peer, std::shared_ptr<DnsUpstreamDialer> dialer)
        : runtime_(runtime), endpoint_(endpoint), server_name_(std::move(server_name)),
          verify_peer_(verify_peer), ssl_context_(boost::asio::ssl::context::tls_client),
          dialer_(std::move(dialer)) {}

    void exchange(std::uint16_t query_id, std::vector<std::uint8_t> query,
                  std::chrono::steady_clock::time_point deadline, Handler handler) {
        if (stopped_ || retired_) {
            complete_immediately(std::move(handler), cancelled_error());
            return;
        }
        if (query.empty() || query.size() > 0xffff) {
            complete_immediately(std::move(handler), {core::ErrorCode::protocol_framing,
                                                      "DoT DNS query length is invalid"});
            return;
        }
        if (pending_.contains(query_id)) {
            complete_immediately(std::move(handler),
                                 {core::ErrorCode::protocol_framing,
                                  "DoT DNS transaction ID is already in use on the session"});
            return;
        }

        auto pending = std::make_shared<Pending>(runtime_.context());
        pending->frame.reserve(2 + query.size());
        pending->frame.push_back(static_cast<std::uint8_t>(query.size() >> 8));
        pending->frame.push_back(static_cast<std::uint8_t>(query.size() & 0xff));
        pending->frame.insert(pending->frame.end(), query.begin(), query.end());
        pending->handler = std::move(handler);
        pending->timer.expires_at(deadline);
        auto self = shared_from_this();
        pending->timer.async_wait([self, query_id](const boost::system::error_code &error) {
            if (!error) {
                self->fail_request(query_id, timeout_error());
            }
        });
        pending_.emplace(query_id, pending);
        write_queue_.push_back(query_id);
        connect_if_needed();
        flush_writes();
    }

    void cancel(std::uint16_t query_id) noexcept { fail_request(query_id, cancelled_error()); }

    void stop() noexcept {
        if (stopped_) {
            return;
        }
        stopped_ = true;
        retired_ = true;
        close_connection();
        fail_all(cancelled_error());
    }

    bool retired() const noexcept { return retired_; }

  private:
    struct Pending {
        explicit Pending(boost::asio::io_context &context) : timer(context) {}

        std::vector<std::uint8_t> frame;
        Handler handler;
        boost::asio::steady_timer timer;
    };

    using PendingPtr = std::shared_ptr<Pending>;
    using ReadCompletion = std::function<void(const boost::system::error_code &)>;

    void complete_immediately(Handler handler, core::Error error) {
        boost::asio::post(runtime_.context(),
                          [handler = std::move(handler), error = std::move(error)]() mutable {
                              if (handler) {
                                  handler(core::fail(std::move(error)));
                              }
                          });
    }

    bool configure_tls() {
        boost::system::error_code error;
        if (verify_peer_) {
            const auto trust_roots = detail::builtin_ca_bundle_pem();
            ssl_context_.add_certificate_authority(
                boost::asio::buffer(trust_roots.data(), trust_roots.size()), error);
            if (error) {
                connection_failed(io_error("failed to load embedded DoT trust roots", error),
                                  connection_generation_);
                return false;
            }
        }
        ssl_stream_->set_verify_mode(verify_peer_ ? boost::asio::ssl::verify_peer
                                                  : boost::asio::ssl::verify_none);
        if (!server_name_.empty() &&
            SSL_set_tlsext_host_name(ssl_stream_->native_handle(), server_name_.c_str()) != 1) {
            connection_failed(
                {core::ErrorCode::configuration, "failed to configure DoT server name"},
                connection_generation_);
            return false;
        }
        if (verify_peer_) {
            ssl_stream_->set_verify_callback(
                boost::asio::ssl::host_name_verification(server_name_));
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
                                                          "DoT dialer failed to open a stream"}),
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
                self->connecting_ = false;
                self->connected_ = true;
                self->read_frame(generation);
                self->flush_writes(generation);
            });
    }

    void flush_writes(std::uint64_t generation = 0) {
        if (generation == 0) {
            generation = connection_generation_;
        }
        if (stopped_ || retired_ || generation != connection_generation_ || !connected_ ||
            write_in_progress_) {
            return;
        }
        while (!write_queue_.empty() && !pending_.contains(write_queue_.front())) {
            write_queue_.pop_front();
        }
        if (write_queue_.empty()) {
            return;
        }

        const auto query_id = write_queue_.front();
        const auto pending = pending_.at(query_id);
        write_in_progress_ = true;
        auto self = shared_from_this();
        boost::asio::async_write(
            *ssl_stream_, boost::asio::buffer(pending->frame),
            [self, pending, query_id, generation](const boost::system::error_code &error,
                                                  std::size_t) {
                if (generation != self->connection_generation_ || self->stopped_) {
                    return;
                }
                self->write_in_progress_ = false;
                if (error) {
                    self->connection_failed(io_error("failed to send DoT DNS query", error),
                                            generation);
                    return;
                }
                if (!self->write_queue_.empty() && self->write_queue_.front() == query_id) {
                    self->write_queue_.pop_front();
                }
                self->flush_writes(generation);
            });
    }

    void read_frame(std::uint64_t generation) {
        if (stopped_ || retired_ || generation != connection_generation_ || !connected_ ||
            read_in_progress_) {
            return;
        }
        read_in_progress_ = true;
        auto length = std::make_shared<std::vector<std::uint8_t>>(2);
        auto self = shared_from_this();
        read_exact(
            length, 0, generation,
            [self, length, generation](const boost::system::error_code &error) {
                self->read_in_progress_ = false;
                if (generation != self->connection_generation_ || self->stopped_) {
                    return;
                }
                if (error) {
                    self->connection_failed(io_error("failed to receive DoT DNS length", error),
                                            generation);
                    return;
                }
                const auto size = static_cast<std::size_t>((*length)[0] << 8 | (*length)[1]);
                if (size == 0 || size > 0xffff) {
                    self->connection_failed(
                        {core::ErrorCode::protocol_framing, "DoT DNS response length is invalid"},
                        generation);
                    return;
                }
                auto body = std::make_shared<std::vector<std::uint8_t>>(size);
                self->read_exact(
                    body, 0, generation,
                    [self, body, generation](const boost::system::error_code &error) {
                        if (generation != self->connection_generation_ || self->stopped_) {
                            return;
                        }
                        if (error) {
                            self->connection_failed(
                                io_error("failed to receive DoT DNS response", error), generation);
                            return;
                        }
                        self->dispatch_response(std::move(*body), generation);
                    });
            });
    }

    void read_exact(std::shared_ptr<std::vector<std::uint8_t>> buffer, std::size_t offset,
                    std::uint64_t generation, ReadCompletion handler) {
        if (stopped_ || retired_ || generation != connection_generation_ || !connected_ ||
            offset >= buffer->size()) {
            return;
        }
        auto self = shared_from_this();
        ssl_stream_->async_read_some(
            boost::asio::buffer(buffer->data() + offset, buffer->size() - offset),
            [self, buffer, offset, generation, handler = std::move(handler)](
                const boost::system::error_code &error, std::size_t size) mutable {
                if (generation != self->connection_generation_ || self->stopped_) {
                    return;
                }
                if (error) {
                    handler(error);
                    return;
                }
                if (size == 0) {
                    handler(boost::asio::error::eof);
                    return;
                }
                const auto next_offset = offset + size;
                if (next_offset >= buffer->size()) {
                    handler({});
                    return;
                }
                self->read_exact(buffer, next_offset, generation, std::move(handler));
            });
    }

    void dispatch_response(std::vector<std::uint8_t> response, std::uint64_t generation) {
        if (response.size() < 2) {
            connection_failed({core::ErrorCode::protocol_framing,
                               "DoT DNS response is shorter than its transaction ID"},
                              generation);
            return;
        }
        const auto query_id = static_cast<std::uint16_t>(response[0] << 8 | response[1]);
        Handler handler;
        if (const auto found = pending_.find(query_id); found != pending_.end()) {
            auto pending = std::move(found->second);
            pending_.erase(found);
            pending->timer.cancel();
            handler = std::move(pending->handler);
        }
        if (handler) {
            handler(std::move(response));
        }
        read_frame(generation);
    }

    void fail_request(std::uint16_t query_id, core::Error error) {
        const auto found = pending_.find(query_id);
        if (found == pending_.end()) {
            return;
        }
        auto pending = std::move(found->second);
        pending_.erase(found);
        write_queue_.erase(std::remove(write_queue_.begin(), write_queue_.end(), query_id),
                           write_queue_.end());
        pending->timer.cancel();
        if (pending->handler) {
            auto handler = std::move(pending->handler);
            handler(core::fail(std::move(error)));
        }
    }

    void fail_all(const core::Error &error) {
        std::vector<Handler> handlers;
        handlers.reserve(pending_.size());
        for (auto &[query_id, pending] : pending_) {
            pending->timer.cancel();
            if (pending->handler) {
                handlers.push_back(std::move(pending->handler));
            }
        }
        pending_.clear();
        write_queue_.clear();
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
        fail_all(error);
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
    bool verify_peer_;
    boost::asio::ssl::context ssl_context_;
    using SslStream = boost::asio::ssl::stream<StreamHandleAdapter>;
    std::shared_ptr<DnsUpstreamDialer> dialer_;
    std::unique_ptr<SslStream> ssl_stream_;
    std::unordered_map<std::uint16_t, PendingPtr> pending_;
    std::deque<std::uint16_t> write_queue_;
    std::uint64_t connection_generation_ = 0;
    bool connecting_ = false;
    bool connected_ = false;
    bool write_in_progress_ = false;
    bool read_in_progress_ = false;
    bool retired_ = false;
    bool stopped_ = false;
};

class DotDnsTransport::Operation final
    : public std::enable_shared_from_this<DotDnsTransport::Operation> {
  public:
    Operation(DotDnsTransport &owner, ExchangeId exchange_id, DnsExchangeRequest request,
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
                               "DoT transport has no available transaction IDs"}));
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
                {core::ErrorCode::configuration, "DoT transport session is not available"}));
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
                               "DoT DNS response question does not match the query"}));
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

    DotDnsTransport &owner_;
    ExchangeId exchange_id_;
    DnsExchangeRequest request_;
    Handler handler_;
    std::shared_ptr<Session> session_;
    std::vector<std::uint8_t> query_wire_;
    std::uint16_t query_id_ = 0;
    bool exchange_started_ = false;
    bool completed_ = false;
};

std::optional<std::uint16_t> DotDnsTransport::next_query_id() noexcept {
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

std::shared_ptr<DotDnsTransport::Session> DotDnsTransport::session() {
    if (stopped_) {
        return nullptr;
    }
    if (!session_ || session_->retired()) {
        const auto endpoint = config_.tcp_endpoint.value_or(boost::asio::ip::tcp::endpoint(
            config_.endpoint.address(),
            config_.endpoint.port() == 53 ? 853 : config_.endpoint.port()));
        const auto server_name =
            config_.server_name.empty() ? endpoint.address().to_string() : config_.server_name;
        session_ = std::make_shared<Session>(runtime_, endpoint, server_name, config_.verify_peer,
                                             config_.dialer);
    }
    return session_;
}

DnsTransport::ExchangeId DotDnsTransport::exchange(DnsExchangeRequest request, Handler handler) {
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

void DotDnsTransport::cancel(ExchangeId exchange_id) noexcept {
    const auto operation = operations_.find(exchange_id);
    if (operation != operations_.end()) {
        operation->second->cancel();
    }
}

void DotDnsTransport::stop() noexcept {
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

void DotDnsTransport::complete(ExchangeId exchange_id, core::Result<DnsPacket> result) {
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

std::shared_ptr<DnsTransport> make_dot_dns_transport(runtime::AsioRuntime &runtime,
                                                     DnsUpstreamConfig config) {
    return std::make_shared<DotDnsTransport>(runtime, std::move(config));
}

} // namespace clash_native::dns
