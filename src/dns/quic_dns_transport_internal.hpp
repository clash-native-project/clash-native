#pragma once

#include <clash_native/dns/dns_transport.hpp>
#include <clash_native/transport/exchange_session.hpp>
#include <clash_native/transport/quic_client.hpp>

#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace clash_native::dns {

namespace quic_dns_detail {

inline core::Error transport_error(std::string context) {
    return {core::ErrorCode::transport_io, std::move(context), {}};
}

inline core::Error protocol_error(std::string context) {
    return {core::ErrorCode::protocol_framing, std::move(context), {}};
}

} // namespace quic_dns_detail

class QuicDnsTransport final : public DnsTransport,
                               public std::enable_shared_from_this<QuicDnsTransport> {
  private:
    class Operation;

  public:
    QuicDnsTransport(runtime::AsioRuntime &runtime, DnsUpstreamConfig config);

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
                 boost::asio::any_io_executor executor)
            : id(exchange_id), request(std::move(exchange_request)),
              deadline_timer(std::move(executor)) {}

        ExchangeId id;
        DnsExchangeRequest request;
        boost::asio::steady_timer deadline_timer;
        std::int64_t stream_id = -1;
        std::optional<transport::ExchangeSession::ExchangeId> http_exchange_id;
        std::vector<std::uint8_t> doq_response;
        std::optional<core::Result<DnsPacket>> result;
    };

    explicit Operation(QuicDnsTransport &owner);

    bool can_accept_exchange() const noexcept;
    std::size_t active_exchange_count() const noexcept;
    void close_idle() noexcept;
    bool is_idle() const noexcept;

  private:
    friend class QuicDnsTransport;

    void start_on_strand();
    void add_exchange(ExchangeId id, DnsExchangeRequest request);
    void cancel_exchange(ExchangeId id, core::Error error);
    void cancel_all();
    // Sessions-plane edge: takes an already-adapted core:: handle plus the
    // open error, mirroring DatagramOpenResult without naming the io::
    // vocabulary this plane has not adopted yet.
    void datagram_opened(std::unique_ptr<core::DatagramHandle> handle,
                         std::optional<core::Error> error);

    transport::QuicClientEvents make_doq_events();
    void start_doh3_session();

    void on_quic_ready(std::string selected_alpn);
    void pump_open_pending_exchanges();
    void on_doq_stream_data(std::int64_t stream_id, const std::uint8_t *data, std::size_t length,
                            bool fin);
    void on_doq_stream_closed(std::int64_t stream_id);
    void on_doq_stream_reset(std::int64_t stream_id, std::uint64_t app_error);
    Exchange *find_stream_exchange(std::int64_t stream_id) noexcept;

    void open_pending_http3_exchanges();
    void submit_http3_exchange(const std::shared_ptr<Exchange> &exchange);
    void on_http3_result(ExchangeId id, core::Result<transport::ExchangeResponse> result);

    void decode_dns_response(Exchange &exchange, std::span<const std::uint8_t> wire);
    void set_exchange_error(Exchange &exchange, core::Error error);
    void drain_exchange_results();
    void complete_exchange(ExchangeId id, core::Result<DnsPacket> result);
    void enter_idle_or_retire();
    void retire_idle() noexcept;
    void retire_session() noexcept;
    void fail_session(core::Error error);

  private:
    QuicDnsTransport &owner_;
    boost::asio::steady_timer idle_timer_;
    DnsTransportMode mode_;
    std::string host_;
    std::uint16_t port_;
    boost::asio::ip::udp::endpoint remote_endpoint_;
    std::string authority_;
    std::string path_;
    std::shared_ptr<transport::QuicClientConnection> quic_;
    std::shared_ptr<transport::ExchangeSession> http3_;
    std::unordered_map<ExchangeId, std::shared_ptr<Exchange>> exchanges_;
    std::unordered_map<std::int64_t, std::shared_ptr<Exchange>> stream_exchanges_;
    std::deque<ExchangeId> pending_exchanges_;
    bool started_ = false;
    bool handshake_completed_ = false;
    bool idle_ = false;
    bool retired_ = false;
};

} // namespace clash_native::dns
