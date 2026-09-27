#include "quic_dns_transport_internal.hpp"

#include <clash_native/io/exchange_session.hpp>
#include <clash_native/transport/http_sessions.hpp>

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>
#include <utility>

namespace clash_native::dns {
namespace {
using quic_dns_detail::protocol_error;
core::Error http3_cancelled_error() {
    return {core::ErrorCode::cancelled, "DoH3 exchange was cancelled"};
}
std::string lower_copy(std::string_view value) {
    std::string result(value);
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}
bool is_dns_message_content_type(std::string_view value) {
    const auto semicolon = value.find(';');
    auto media_type = value.substr(0, semicolon);
    while (!media_type.empty() && (media_type.front() == ' ' || media_type.front() == '\t'))
        media_type.remove_prefix(1);
    while (!media_type.empty() && (media_type.back() == ' ' || media_type.back() == '\t'))
        media_type.remove_suffix(1);
    return lower_copy(media_type) == "application/dns-message";
}
} // namespace

void QuicDnsTransport::Operation::start_doh3_session() {
    const auto weak = weak_from_this();
    const auto failure = [weak](core::Error error) {
        if (const auto self = weak.lock())
            self->fail_session(std::move(error));
    };
    auto session = transport::make_http3_exchange_session(quic_, failure);
    if (retired_) {
        if (session)
            session->stop();
        return;
    }
    if (!session) {
        fail_session(protocol_error("failed to create shared HTTP/3 session"));
        return;
    }
    http3_ = std::move(session);
    open_pending_http3_exchanges();
}

void QuicDnsTransport::Operation::open_pending_http3_exchanges() {
    if (!http3_ || retired_) {
        return;
    }
    while (!pending_exchanges_.empty()) {
        const auto id = pending_exchanges_.front();
        pending_exchanges_.pop_front();
        const auto found = exchanges_.find(id);
        if (found != exchanges_.end() && !found->second->result) {
            submit_http3_exchange(found->second);
        }
    }
    drain_exchange_results();
}

void QuicDnsTransport::Operation::submit_http3_exchange(const std::shared_ptr<Exchange> &exchange) {
    if (!http3_ || retired_ || exchange->result || exchange->http_exchange_started) {
        return;
    }
    io::ExchangeRequest request;
    request.method = "POST";
    request.scheme = "https";
    request.authority = authority_;
    request.target = path_;
    request.headers = {{"accept", "application/dns-message"},
                       {"content-type", "application/dns-message"}};
    request.body = exchange->request.query.wire;
    request.response_body_limit = 0xffff;

    exchange->http_exchange_started = true;
    // Guarded emission pump: one exchange task per request, co_awaiting
    // the io:: sender. The task always ends with a value; on_http3_result
    // drops late terminals when the exchange is already gone. Cancelled
    // via the session (close path shuts the stream down).
    scope_.spawn(run_http3_exchange(shared_from_this(), exchange->id, std::move(request),
                                    exchange->request.deadline));
}

exec::task<void>
QuicDnsTransport::Operation::run_http3_exchange(std::shared_ptr<Operation> self, DnsExchangeId id,
                                                io::ExchangeRequest request,
                                                std::chrono::steady_clock::time_point deadline) {
    core::Result<io::ExchangeResponse> result = core::fail(http3_cancelled_error());
    try {
        auto session = self->http3_;
        if (session == nullptr) {
            self->on_http3_result(id, core::fail(http3_cancelled_error()));
            co_return;
        }
        try {
            result = co_await session->exchange(std::move(request), deadline);
        } catch (const core::Error &failure) {
            self->on_http3_result(id, core::fail(failure));
            co_return;
        } catch (...) {
            self->on_http3_result(id, core::fail(core::Error{core::ErrorCode::endpoint_connection,
                                                             "DoH3 exchange failed"}));
            co_return;
        }
    } catch (...) {
        self->on_http3_result(id, core::fail(core::Error{core::ErrorCode::endpoint_connection,
                                                         "DoH3 exchange failed"}));
        co_return;
    }
    self->on_http3_result(id, std::move(result));
    co_return;
}

void QuicDnsTransport::Operation::on_http3_result(DnsExchangeId id,
                                                  core::Result<io::ExchangeResponse> result) {
    const auto found = exchanges_.find(id);
    if (found == exchanges_.end() || found->second->result) {
        return;
    }
    auto &exchange = *found->second;
    if (!result) {
        set_exchange_error(exchange, result.error());
        drain_exchange_results();
        return;
    }
    if (result->status != 200) {
        set_exchange_error(exchange,
                           protocol_error("DoH/HTTP/3 upstream returned a non-success status"));
        drain_exchange_results();
        return;
    }
    const auto content_type = std::find_if(
        result->headers.begin(), result->headers.end(),
        [](const io::ExchangeField &header) { return lower_copy(header.name) == "content-type"; });
    if (content_type == result->headers.end() ||
        !is_dns_message_content_type(content_type->value)) {
        set_exchange_error(exchange,
                           protocol_error("DoH/HTTP/3 response has an invalid content type"));
        drain_exchange_results();
        return;
    }
    decode_dns_response(exchange, result->body);
    drain_exchange_results();
}

} // namespace clash_native::dns
