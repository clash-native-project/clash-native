#include "quic_dns_transport_internal.hpp"

#include <utility>

namespace clash_native::dns {
namespace {
using quic_dns_detail::protocol_error;
using quic_dns_detail::transport_error;
} // namespace

transport::QuicClientEvents QuicDnsTransport::Operation::make_doq_events() {
    transport::QuicClientEvents events;
    const auto weak = weak_from_this();
    events.ready = [weak](std::string alpn) {
        if (const auto self = weak.lock())
            self->on_quic_ready(std::move(alpn));
    };
    events.stream_data = [weak](std::int64_t stream_id, const std::uint8_t *data,
                                std::size_t length, bool fin) {
        if (const auto self = weak.lock())
            self->on_doq_stream_data(stream_id, data, length, fin);
    };
    events.stream_capacity = [weak] {
        if (const auto self = weak.lock())
            self->pump_open_pending_exchanges();
    };
    events.stream_closed = [weak](std::int64_t stream_id, std::uint64_t) {
        if (const auto self = weak.lock())
            self->on_doq_stream_closed(stream_id);
    };
    events.stream_reset = [weak](std::int64_t stream_id, std::uint64_t app_error) {
        if (const auto self = weak.lock())
            self->on_doq_stream_reset(stream_id, app_error);
    };
    events.failed = [weak](core::Error error) {
        if (const auto self = weak.lock())
            self->fail_session(std::move(error));
    };
    return events;
}

void QuicDnsTransport::Operation::on_quic_ready(std::string selected_alpn) {
    if (selected_alpn != "doq") {
        fail_session(core::Error{
            core::ErrorCode::authentication, "DoQ upstream negotiated an unexpected ALPN", {}});
        return;
    }
    handshake_completed_ = true;
    pump_open_pending_exchanges();
}

void QuicDnsTransport::Operation::pump_open_pending_exchanges() {
    if (mode_ != DnsTransportMode::doq || !handshake_completed_ || retired_ || quic_ == nullptr ||
        !quic_->ready()) {
        return;
    }
    while (!pending_exchanges_.empty() && !retired_) {
        const auto id = pending_exchanges_.front();
        const auto active = exchanges_.find(id);
        if (active == exchanges_.end() || active->second->result) {
            pending_exchanges_.pop_front();
            continue;
        }
        const auto exchange = active->second;
        if (exchange->stream_id >= 0) {
            pending_exchanges_.pop_front();
            continue;
        }
        const auto opened = quic_->open_bidirectional_stream();
        if (opened.state == transport::QuicOpenStreamResult::State::blocked) {
            return;
        }
        if (opened.state != transport::QuicOpenStreamResult::State::opened) {
            fail_session(opened.error.value_or(
                protocol_error("QUIC connection failed to open a DoQ request stream")));
            return;
        }
        pending_exchanges_.pop_front();
        exchange->stream_id = opened.stream_id;
        stream_exchanges_.emplace(opened.stream_id, exchange);

        const auto &wire = exchange->request.query.wire;
        std::vector<std::uint8_t> message;
        message.reserve(wire.size() + 2);
        message.push_back(static_cast<std::uint8_t>(wire.size() >> 8));
        message.push_back(static_cast<std::uint8_t>(wire.size() & 0xff));
        message.insert(message.end(), wire.begin(), wire.end());
        message[2] = 0;
        message[3] = 0;
        quic_->write_stream_data(opened.stream_id, std::move(message), true);
    }
}

void QuicDnsTransport::Operation::on_doq_stream_data(std::int64_t stream_id,
                                                     const std::uint8_t *data, std::size_t length,
                                                     bool fin) {
    auto *exchange = find_stream_exchange(stream_id);
    if (exchange == nullptr || exchange->result) {
        if (length != 0 && quic_) {
            (void)quic_->extend_receive_credit(stream_id, length);
        }
        return;
    }
    if (exchange->doq_response.size() + length > 0xffff + 2) {
        set_exchange_error(*exchange, protocol_error("DoQ response exceeds the DNS message limit"));
        drain_exchange_results();
        return;
    }
    if (length != 0) {
        exchange->doq_response.insert(exchange->doq_response.end(), data, data + length);
        if (quic_) {
            (void)quic_->extend_receive_credit(stream_id, length);
        }
    }
    if (!fin) {
        return;
    }
    if (exchange->doq_response.size() < 2) {
        set_exchange_error(*exchange,
                           protocol_error("DoQ response ended before its length prefix"));
        drain_exchange_results();
        return;
    }
    const auto message_length =
        static_cast<std::size_t>(exchange->doq_response[0] << 8 | exchange->doq_response[1]);
    if (message_length == 0 || exchange->doq_response.size() != message_length + 2) {
        set_exchange_error(
            *exchange, protocol_error("DoQ response length prefix does not match the DNS message"));
        drain_exchange_results();
        return;
    }
    const auto message = std::span<const std::uint8_t>(exchange->doq_response).subspan(2);
    if (message.size() < 2 || message[0] != 0 || message[1] != 0) {
        set_exchange_error(*exchange, protocol_error("DoQ response DNS message ID is not zero"));
        drain_exchange_results();
        return;
    }
    std::vector<std::uint8_t> restored(message.begin(), message.end());
    restored[0] = static_cast<std::uint8_t>(exchange->request.query.id >> 8);
    restored[1] = static_cast<std::uint8_t>(exchange->request.query.id & 0xff);
    decode_dns_response(*exchange, restored);
    drain_exchange_results();
}

void QuicDnsTransport::Operation::on_doq_stream_closed(std::int64_t stream_id) {
    const auto found = stream_exchanges_.find(stream_id);
    if (found == stream_exchanges_.end()) {
        return;
    }
    const auto exchange = found->second;
    exchange->stream_id = -1;
    stream_exchanges_.erase(found);
    if (!exchange->result && exchanges_.contains(exchange->id)) {
        set_exchange_error(*exchange,
                           transport_error("DoQ stream closed before a DNS response completed"));
        drain_exchange_results();
    }
}

void QuicDnsTransport::Operation::on_doq_stream_reset(std::int64_t stream_id,
                                                      std::uint64_t app_error) {
    auto *exchange = find_stream_exchange(stream_id);
    if (exchange == nullptr || exchange->result) {
        return;
    }
    set_exchange_error(*exchange, transport_error("DoQ upstream reset DNS stream with code " +
                                                  std::to_string(app_error)));
    drain_exchange_results();
}

QuicDnsTransport::Operation::Exchange *
QuicDnsTransport::Operation::find_stream_exchange(std::int64_t stream_id) noexcept {
    const auto found = stream_exchanges_.find(stream_id);
    return found == stream_exchanges_.end() ? nullptr : found->second.get();
}

} // namespace clash_native::dns
