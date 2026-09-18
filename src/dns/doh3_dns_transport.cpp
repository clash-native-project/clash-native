#include "quic_dns_transport_internal.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>
#include <utility>

namespace clash_native::dns {
namespace {
using quic_dns_detail::protocol_error;
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
    auto session = transport::make_http3_client_session(quic_, failure);
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
    if (!http3_ || retired_ || exchange->result || exchange->http_exchange_id) {
        return;
    }
    transport::HttpRequest request;
    request.method = "POST";
    request.scheme = "https";
    request.authority = authority_;
    request.target = path_;
    request.headers = {{"accept", "application/dns-message"},
                       {"content-type", "application/dns-message"}};
    request.body = exchange->request.query.wire;
    request.response_body_limit = 0xffff;

    const auto id = exchange->id;
    const auto weak = weak_from_this();
    exchange->http_exchange_id =
        http3_->exchange(std::move(request), exchange->request.deadline,
                         [weak, id](core::Result<transport::HttpResponse> result) mutable {
                             if (const auto self = weak.lock()) {
                                 self->on_http3_result(id, std::move(result));
                             }
                         });
}

void QuicDnsTransport::Operation::on_http3_result(ExchangeId id,
                                                  core::Result<transport::HttpResponse> result) {
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
    const auto content_type = std::find_if(result->headers.begin(), result->headers.end(),
                                           [](const transport::HttpHeader &header) {
                                               return lower_copy(header.name) == "content-type";
                                           });
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
