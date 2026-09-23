#include "proxy_session.hpp"

#include "http_proxy_utils.hpp"

#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>
#include <clash_native/transport/http_sessions.hpp>

#include <boost/asio/post.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/http.hpp>
#include <fmt/format.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <iterator>
#include <limits>
#include <utility>

namespace clash_native::proxy {

using namespace http_detail;
namespace http = boost::beast::http;

void ProxySession::read_http_headers() {
    http_request_parser_ = std::make_shared<ProxyRequestBodyStream::Parser>();
    http_request_parser_->header_limit(64 * 1024);
    http_request_parser_->body_limit((std::numeric_limits<std::uint64_t>::max)());
    http_request_parser_->merge_all_trailers(true);
    auto self = shared_from_this();
    http::async_read_header(
        client_, http_buffer_, *http_request_parser_,
        [self](const boost::system::error_code &error, std::size_t) {
            if (error) {
                const auto status = error == http::error::header_limit ? 431 : 400;
                self->send_http_forward_response(
                    status, status == 431 ? "Request Header Fields Too Large" : "Bad Request");
                return;
            }

            const auto &request = self->http_request_parser_->get();
            self->http_client_keep_alive_ = self->http_request_keep_alive(request);
            const auto authentication = self->authenticate_http_request(request);
            if (authentication != HttpAuthenticationResult::accepted) {
                self->send_http_auth_response(authentication == HttpAuthenticationResult::missing,
                                              self->http_client_keep_alive_ &&
                                                  self->http_request_parser_->is_done());
                return;
            }

            const auto method = copy_view(request.method_string());
            if (method != "CONNECT") {
                self->begin_http_forward();
                return;
            }
            if (request.version() != 10 && request.version() != 11) {
                self->send_http_forward_response(400, "Bad Request");
                return;
            }

            const auto authority = copy_view(request.target());
            const auto destination = parse_http_authority(authority);
            if (!destination) {
                self->send_http_forward_response(400, "Bad Request");
                return;
            }

            const auto buffered = self->http_buffer_.size();
            self->http_initial_data_.resize(buffered);
            if (buffered != 0) {
                boost::asio::buffer_copy(boost::asio::buffer(self->http_initial_data_),
                                         self->http_buffer_.data());
                self->http_buffer_.consume(buffered);
            }
            self->open_target(*destination);
        });
}

HttpAuthenticationResult
ProxySession::authenticate_http_request(const http::request<http::buffer_body> &request) const {
    if (owner_.http_username_.empty() && owner_.http_password_.empty()) {
        return HttpAuthenticationResult::accepted;
    }

    for (const auto &field : request.base()) {
        if (is_http_header(as_std_view(field.name_string()), "proxy-authorization")) {
            const auto value = trim_http_whitespace(as_std_view(field.value()));
            if (value.empty()) {
                return HttpAuthenticationResult::missing;
            }
            return basic_authorization_matches(value, owner_.http_username_, owner_.http_password_)
                       ? HttpAuthenticationResult::accepted
                       : HttpAuthenticationResult::rejected;
        }
    }
    return HttpAuthenticationResult::missing;
}

bool ProxySession::http_request_keep_alive(const http::request<http::buffer_body> &request) const {
    auto keep_alive = request.keep_alive();
    for (const auto &field : request.base()) {
        if (!is_http_header(as_std_view(field.name_string()), "proxy-connection")) {
            continue;
        }
        const auto value = lowercase_ascii(trim_http_whitespace(as_std_view(field.value())));
        if (value == "keep-alive") {
            keep_alive = true;
        } else if (value == "close") {
            keep_alive = false;
        }
    }
    return keep_alive;
}

void ProxySession::send_http_auth_response(bool missing, bool keep_alive) {
    if (closed_.load(std::memory_order_acquire)) {
        return;
    }
    const auto connection_headers =
        keep_alive ? "Connection: keep-alive\r\nProxy-Connection: keep-alive\r\n"
                     "Keep-Alive: timeout=4\r\n"
                   : "Connection: close\r\n";
    http_response_ =
        fmt::format("HTTP/1.1 {}\r\n{}{}Content-Length: 0\r\n"
                    "Proxy-Agent: clash-native\r\n\r\n",
                    missing ? "407 Proxy Authentication Required" : "403 Forbidden",
                    missing ? "Proxy-Authenticate: Basic\r\n" : "", connection_headers);
    auto self = shared_from_this();
    boost::asio::async_write(
        client_, boost::asio::buffer(http_response_),
        [self, keep_alive](const boost::system::error_code &error, std::size_t) {
            if (error) {
                self->close();
            } else if (keep_alive) {
                self->http_exchange_keep_alive_ = true;
                self->finish_http_forward();
            } else {
                self->close();
            }
        });
}

void ProxySession::begin_http_forward() {
    const auto &request = http_request_parser_->get();
    if (request.version() != 11) {
        send_http_forward_response(505, "HTTP Version Not Supported");
        return;
    }

    const auto target_text = copy_view(request.target());
    if (target_text == "*" && request.method() == http::verb::options) {
        http_exchange_keep_alive_ = http_client_keep_alive_;
        send_http_forward_response(200, "OK", "Allow: CONNECT, OPTIONS\r\n",
                                   http_client_keep_alive_);
        return;
    }
    const auto parsed_target = parse_http_absolute_target(target_text);
    if (!parsed_target) {
        const auto scheme_end = target_text.find("://");
        if (scheme_end != std::string::npos &&
            lowercase_ascii(std::string_view(target_text).substr(0, scheme_end)) != "http") {
            send_http_forward_response(501, "Not Implemented");
        } else {
            send_http_forward_response(400, "Bad Request");
        }
        return;
    }

    std::unordered_set<std::string> connection_options;
    if (!collect_connection_options(request.base(), connection_options)) {
        send_http_forward_response(400, "Bad Request");
        return;
    }
    for (const auto &option : connection_options) {
        if (option == "content-length" || option == "host" || option == "transfer-encoding") {
            send_http_forward_response(400, "Bad Request");
            return;
        }
    }

    std::string upgrade_protocol;
    bool has_upgrade_header = false;
    if (!collect_upgrade_protocol(request.base(), upgrade_protocol, has_upgrade_header)) {
        if (has_upgrade_header || connection_options.contains("upgrade")) {
            send_http_forward_response(400, "Bad Request");
            return;
        }
    }
    if (has_upgrade_header || connection_options.contains("upgrade")) {
        if (!has_upgrade_header || !connection_options.contains("upgrade")) {
            send_http_forward_response(400, "Bad Request");
            return;
        }
        if (request.method() != http::verb::get || !http_request_parser_->is_done()) {
            send_http_forward_response(501, "Not Implemented");
            return;
        }

        http_forward_ = true;
        http_upgrade_forward_ = true;
        http_upgrade_request_ = {};
        http_upgrade_request_.mode = io::StreamUpgradeMode::upgrade;
        http_upgrade_request_.scheme = "http";
        http_upgrade_request_.authority = parsed_target->authority;
        http_upgrade_request_.target = parsed_target->origin_target;
        http_upgrade_request_.protocol = std::move(upgrade_protocol);
        for (const auto &field : request.base()) {
            const auto name = as_std_view(field.name_string());
            if (is_http_header(name, "host") || is_http_header(name, "connection") ||
                is_http_header(name, "upgrade") || is_http_header(name, "proxy-connection") ||
                is_http_header(name, "proxy-authorization") || is_http_header(name, "keep-alive") ||
                is_http_header(name, "te") || is_http_header(name, "trailer") ||
                is_http_header(name, "transfer-encoding") ||
                is_http_header(name, "content-length")) {
                continue;
            }
            http_upgrade_request_.headers.push_back({std::string(name), copy_view(field.value())});
        }

        const auto buffered = http_buffer_.size();
        http_initial_data_.resize(buffered);
        if (buffered != 0) {
            boost::asio::buffer_copy(boost::asio::buffer(http_initial_data_), http_buffer_.data());
            http_buffer_.consume(buffered);
        }
        open_target(parsed_target->destination);
        return;
    }

    std::unordered_set<std::string> declared_trailers;
    std::vector<std::string> trailer_names;
    if (!collect_declared_trailers(request.base(), connection_options, declared_trailers,
                                   trailer_names)) {
        send_http_forward_response(400, "Bad Request");
        return;
    }

    bool expects_continue = false;
    for (const auto &field : request.base()) {
        if (is_http_header(as_std_view(field.name_string()), "expect")) {
            if (lowercase_ascii(trim_http_whitespace(as_std_view(field.value()))) !=
                "100-continue") {
                send_http_forward_response(417, "Expectation Failed");
                return;
            }
            expects_continue = true;
        }
    }

    http_forward_request_ = {};
    http_forward_request_.request.method = copy_view(request.method_string());
    http_forward_request_method_ = http_forward_request_.request.method;
    http_forward_request_.request.scheme = "http";
    http_forward_request_.request.authority = parsed_target->authority;
    http_forward_request_.request.target = parsed_target->origin_target;
    if (request.method() == http::verb::options && parsed_target->empty_path_and_query) {
        http_forward_request_.request.target = "*";
    }
    http_forward_request_.request.keep_alive = true;
    if (const auto content_length = http_request_parser_->content_length()) {
        http_forward_request_.content_length = *content_length;
    }
    if (http_request_parser_->is_done()) {
        http_forward_request_.content_length = 0;
    } else {
        const auto header_count =
            static_cast<std::size_t>(std::distance(request.base().begin(), request.base().end()));
        http_request_body_ = std::make_shared<ProxyRequestBodyStream>(
            client_, http_buffer_, http_request_parser_, header_count, std::move(declared_trailers),
            [this](std::size_t size) { http_forward_request_bytes_ += size; });
        http_forward_request_.body = http_request_body_;
    }

    for (const auto &field : request.base()) {
        const auto name = as_std_view(field.name_string());
        if (is_http_header(name, "host") || is_http_header(name, "content-length") ||
            is_http_header(name, "expect") || is_http_header(name, "trailer") ||
            is_hop_by_hop_or_proxy_header(name, connection_options)) {
            continue;
        }
        http_forward_request_.request.headers.push_back(
            {std::string(name), copy_view(field.value())});
    }
    http_forward_request_.request.headers.push_back({"Host", parsed_target->authority});

    if (http_forward_request_.body && !trailer_names.empty()) {
        std::string value;
        for (const auto &name : trailer_names) {
            if (!value.empty()) {
                value.append(", ");
            }
            value.append(name);
        }
        http_forward_request_.request.headers.push_back({"Trailer", std::move(value)});
    }

    if (expects_continue) {
        auto self = shared_from_this();
        interim_http_response_ = "HTTP/1.1 100 Continue\r\n\r\n";
        boost::asio::async_write(client_, boost::asio::buffer(interim_http_response_),
                                 [self, destination = parsed_target->destination](
                                     const boost::system::error_code &error, std::size_t) mutable {
                                     if (error) {
                                         self->close();
                                         return;
                                     }
                                     self->open_http_forward_target(std::move(destination));
                                 });
        return;
    }
    open_http_forward_target(parsed_target->destination);
}

void ProxySession::open_http_forward_target(core::Destination destination) {
    http_forward_ = true;
    open_target(std::move(destination));
}

void ProxySession::start_http_upgrade_exchange() {
    // Exchange-plane debt: the tunnel runs on io:: through the adapter;
    // the forward path still owns http_session_ until its upload body flips.
    http_tunnel_session_ = transport::make_http1_exchange_session(std::move(remote_));
    if (!http_tunnel_session_) {
        send_http_forward_response(502, "Bad Gateway");
        return;
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::minutes(5);
    struct UpgradeReceiver {
        using receiver_concept = stdexec::receiver_tag;
        std::shared_ptr<ProxySession> self;
        void set_value(io::StreamUpgradeResponse result) && noexcept {
            self->handle_http_upgrade_response(std::move(result));
        }
        void set_error(std::exception_ptr error) && noexcept {
            try {
                std::rethrow_exception(std::move(error));
            } catch (const core::Error &failure) {
                self->handle_http_upgrade_response(core::fail(failure));
            } catch (...) {
                self->handle_http_upgrade_response(core::fail(core::Error{
                    core::ErrorCode::endpoint_connection, "HTTP upgrade tunnel failed"}));
            }
        }
        void set_stopped() && noexcept {
            self->handle_http_upgrade_response(core::fail(
                core::Error{core::ErrorCode::cancelled, "HTTP upgrade tunnel was cancelled"}));
        }
    };
    auto self = shared_from_this();
    async::start_with_receiver(
        http_tunnel_session_->open_tunnel(std::move(http_upgrade_request_), deadline),
        UpgradeReceiver{self});
}

void ProxySession::start_http_forward_exchange() {
    http_session_ = transport::make_http1_exchange_session(std::move(remote_));
    if (!http_session_) {
        send_http_forward_response(502, "Bad Gateway");
        return;
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::minutes(5);
    struct ForwardReceiver {
        using receiver_concept = stdexec::receiver_tag;
        std::shared_ptr<ProxySession> self;
        void set_value(io::StreamingExchangeResponse result) && noexcept {
            self->handle_http_forward_response(std::move(result));
        }
        void set_error(std::exception_ptr error) && noexcept {
            try {
                std::rethrow_exception(std::move(error));
            } catch (const core::Error &failure) {
                self->handle_http_forward_response(core::fail(failure));
            } catch (...) {
                self->handle_http_forward_response(core::fail(core::Error{
                    core::ErrorCode::endpoint_connection, "HTTP forward exchange failed"}));
            }
        }
        void set_stopped() && noexcept {
            self->handle_http_forward_response(core::fail(
                core::Error{core::ErrorCode::cancelled, "HTTP forward exchange was cancelled"}));
        }
    };
    auto self = shared_from_this();
    async::start_with_receiver(
        http_session_->exchange_streaming(std::move(http_forward_request_), deadline),
        ForwardReceiver{self});
}

void ProxySession::handle_http_upgrade_response(core::Result<io::StreamUpgradeResponse> result) {
    if (closed_.load(std::memory_order_acquire)) {
        return;
    }
    if (!result) {
        send_http_forward_response(502, "Bad Gateway");
        return;
    }

    auto upgrade = std::move(result.value());
    if (!upgrade.stream || upgrade.response.status != 101) {
        const auto status = upgrade.response.status >= 400 && upgrade.response.status <= 599
                                ? static_cast<int>(upgrade.response.status)
                                : 502;
        const auto reason =
            status == 502 ? std::string_view("Bad Gateway")
                          : as_std_view(http::obsolete_reason(static_cast<http::status>(status)));
        send_http_forward_response(status, reason);
        return;
    }

    // The tunnel stream arrives as io:: from the exchange edge; no adaptation.
    remote_ = std::move(upgrade.stream);
    if (http_tunnel_session_) {
        http_tunnel_session_->stop();
        http_tunnel_session_.reset();
    }
    http_response_ = build_http_upgrade_response_headers(upgrade.response);
    auto self = shared_from_this();
    boost::asio::async_write(client_, boost::asio::buffer(http_response_),
                             [self](const boost::system::error_code &error, std::size_t size) {
                                 if (error) {
                                     self->close();
                                     return;
                                 }
                                 self->http_forward_response_bytes_ += size;
                                 self->start_relay();
                             });
}

void ProxySession::handle_http_forward_response(
    core::Result<io::StreamingExchangeResponse> result) {
    if (closed_.load(std::memory_order_acquire)) {
        return;
    }
    if (!result) {
        const auto status = result.error().code == core::ErrorCode::rejected ? 403 : 502;
        send_http_forward_response(status, status == 403 ? "Forbidden" : "Bad Gateway");
        return;
    }

    http_forward_response_ = std::move(result.value());
    const auto status = http_forward_response_.response.status;
    if (status < 200 || status == 101 || status > 599) {
        send_http_forward_response(502, "Bad Gateway");
        return;
    }

    const bool has_body = !http_forward_request_method_is("HEAD") && status != 204 &&
                          status != 205 && status != 304 &&
                          static_cast<bool>(http_forward_response_.body);
    http_exchange_keep_alive_ =
        http_client_keep_alive_ && http_forward_response_.response.keep_alive;
    http_response_ = build_http_forward_response_headers(http_forward_response_.response, has_body);
    auto self = shared_from_this();
    boost::asio::async_write(
        client_, boost::asio::buffer(http_response_),
        [self, has_body](const boost::system::error_code &error, std::size_t size) {
            if (error) {
                self->close();
                return;
            }
            self->http_forward_response_bytes_ += size;
            if (!has_body) {
                if (self->http_forward_response_.body) {
                    self->http_forward_response_.body->cancel();
                }
                self->finish_http_forward();
                return;
            }
            self->read_http_forward_response_body();
        });
}

bool ProxySession::http_forward_request_method_is(std::string_view method) const noexcept {
    return http_forward_request_method_ == method;
}

std::string
ProxySession::build_http_upgrade_response_headers(const io::ExchangeResponse &response) const {
    const auto reason = http::obsolete_reason(static_cast<http::status>(response.status));
    std::string output = fmt::format("HTTP/1.1 {} {}\r\n", response.status, copy_view(reason));
    for (const auto &header : response.headers) {
        if (is_http_header(header.name, "content-length") ||
            is_http_header(header.name, "transfer-encoding") ||
            is_http_header(header.name, "proxy-connection") ||
            is_http_header(header.name, "proxy-authenticate") ||
            is_http_header(header.name, "proxy-authorization")) {
            continue;
        }
        output.append(header.name);
        output.append(": ");
        output.append(header.value);
        output.append("\r\n");
    }
    output.append("Proxy-Agent: clash-native\r\n\r\n");
    return output;
}

std::string ProxySession::build_http_forward_response_headers(const io::ExchangeResponse &response,
                                                              bool has_body) {
    std::unordered_set<std::string> connection_options;
    for (const auto &header : response.headers) {
        if (!is_http_header(header.name, "connection")) {
            continue;
        }
        std::string_view value(header.value);
        while (true) {
            const auto comma = value.find(',');
            const auto option = trim_http_whitespace(value.substr(0, comma));
            if (is_http_token(option)) {
                connection_options.emplace(lowercase_ascii(option));
            }
            if (comma == std::string_view::npos) {
                break;
            }
            value.remove_prefix(comma + 1);
        }
    }

    const auto reason = http::obsolete_reason(static_cast<http::status>(response.status));
    std::string output = fmt::format("HTTP/1.1 {} {}\r\n", response.status, copy_view(reason));
    const bool preserve_content_length =
        http_forward_request_method_is("HEAD") || response.status == 304;
    for (const auto &header : response.headers) {
        if (is_hop_by_hop_or_proxy_header(header.name, connection_options) ||
            (is_http_header(header.name, "content-length") && !preserve_content_length)) {
            continue;
        }
        output.append(header.name);
        output.append(": ");
        output.append(header.value);
        output.append("\r\n");
    }
    if (has_body) {
        output.append("Transfer-Encoding: chunked\r\n");
    }
    if (http_exchange_keep_alive_) {
        output.append("Connection: keep-alive\r\nProxy-Connection: keep-alive\r\n"
                      "Keep-Alive: timeout=4\r\n");
    } else {
        output.append("Connection: close\r\n");
    }
    output.append("Proxy-Agent: clash-native\r\n\r\n");
    return output;
}

void ProxySession::read_http_forward_response_body() {
    if (closed_.load(std::memory_order_acquire) || !http_forward_response_.body) {
        finish_http_forward();
        return;
    }
    struct ForwardBodyReceiver {
        using receiver_concept = stdexec::receiver_tag;
        std::shared_ptr<ProxySession> self;
        void set_value(std::optional<std::size_t> size) && noexcept {
            if (size) {
                self->on_http_forward_response_read({}, *size);
                return;
            }
            self->on_http_forward_response_read(boost::asio::error::eof, 0);
        }
        void set_error(std::exception_ptr error) && noexcept {
            self->on_http_forward_response_read(net::unpack_error(std::move(error)), 0);
        }
        void set_stopped() && noexcept {
            self->on_http_forward_response_read(boost::asio::error::operation_aborted, 0);
        }
    };
    auto self = shared_from_this();
    async::start_with_receiver(http_forward_response_.body->async_read_some(
                                   boost::asio::buffer(http_forward_response_buffer_)),
                               ForwardBodyReceiver{self});
}

void ProxySession::on_http_forward_response_read(const boost::system::error_code &error,
                                                 std::size_t size) {
    const auto self = shared_from_this();
    if (self->closed_.load(std::memory_order_acquire)) {
        return;
    }
    if (error == boost::asio::error::eof) {
        self->write_http_forward_response_trailers();
        return;
    }
    if (error) {
        spdlog::warn("HTTP forward proxy upstream response body read failed: {}", error.message());
        self->close();
        return;
    }
    if (size == 0) {
        boost::asio::post(self->client_.get_executor(),
                          [self] { self->read_http_forward_response_body(); });
        return;
    }

    auto framed = std::make_shared<std::vector<std::uint8_t>>();
    const auto chunk_size = fmt::format("{:x}\r\n", size);
    framed->reserve(chunk_size.size() + size + 2);
    framed->insert(framed->end(), chunk_size.begin(), chunk_size.end());
    framed->insert(framed->end(), self->http_forward_response_buffer_.begin(),
                   self->http_forward_response_buffer_.begin() + size);
    framed->insert(framed->end(), {'\r', '\n'});
    boost::asio::async_write(
        self->client_, boost::asio::buffer(*framed),
        [self, framed](const boost::system::error_code &write_error, std::size_t written) {
            if (write_error) {
                self->close();
                return;
            }
            self->http_forward_response_bytes_ += written;
            self->read_http_forward_response_body();
        });
}

void ProxySession::write_http_forward_response_trailers() {
    std::string final_chunk = "0\r\n";
    if (http_forward_response_.body) {
        std::unordered_set<std::string> no_connection_options;
        for (const auto &trailer : http_forward_response_.body->trailers()) {
            if (!is_http_token(trailer.name) ||
                is_hop_by_hop_or_proxy_header(trailer.name, no_connection_options) ||
                is_http_header(trailer.name, "content-length") ||
                is_http_header(trailer.name, "host")) {
                continue;
            }
            final_chunk.append(trailer.name);
            final_chunk.append(": ");
            final_chunk.append(trailer.value);
            final_chunk.append("\r\n");
        }
    }
    final_chunk.append("\r\n");
    http_response_ = std::move(final_chunk);
    auto self = shared_from_this();
    boost::asio::async_write(client_, boost::asio::buffer(http_response_),
                             [self](const boost::system::error_code &error, std::size_t size) {
                                 if (error) {
                                     self->close();
                                     return;
                                 }
                                 self->http_forward_response_bytes_ += size;
                                 self->finish_http_forward();
                             });
}

void ProxySession::reset_http_forward_exchange() {
    if (http_request_body_) {
        http_request_body_->cancel();
        http_request_body_.reset();
    }
    if (http_forward_response_.body) {
        http_forward_response_.body->cancel();
        http_forward_response_.body.reset();
    }
    if (http_session_) {
        http_session_->stop();
        http_session_.reset();
    }
    if (remote_) {
        remote_->close();
        remote_.reset();
    }
    if (connection_id_ && owner_.connection_registry_) {
        owner_.connection_registry_->remove(*connection_id_);
        connection_id_.reset();
    }

    http_forward_ = false;
    http_upgrade_forward_ = false;
    http_forward_request_ = {};
    http_upgrade_request_ = {};
    http_forward_response_ = {};
    http_request_parser_.reset();
    http_response_.clear();
    http_initial_data_.clear();
    http_forward_request_method_.clear();
    http_client_keep_alive_ = false;
    http_exchange_keep_alive_ = false;
    http_forward_request_bytes_ = 0;
    http_forward_response_bytes_ = 0;
}

void ProxySession::finish_http_forward() {
    if (connection_id_ && owner_.connection_registry_) {
        owner_.connection_registry_->update_stats(*connection_id_, http_forward_request_bytes_,
                                                  http_forward_response_bytes_);
    }
    const bool keep_alive = http_client_keep_alive_ && http_exchange_keep_alive_;
    reset_http_forward_exchange();
    if (!keep_alive || closed_.load(std::memory_order_acquire)) {
        close();
        return;
    }
    reset_handshake_timer();
    read_http_headers();
}

void ProxySession::send_http_forward_response(int status, std::string_view reason,
                                              std::string_view extra_headers, bool keep_alive) {
    if (closed_.load(std::memory_order_acquire)) {
        return;
    }
    const auto connection_headers =
        keep_alive ? "Connection: keep-alive\r\nProxy-Connection: keep-alive\r\n"
                     "Keep-Alive: timeout=4\r\n"
                   : "Connection: close\r\n";
    http_response_ = fmt::format("HTTP/1.1 {} {}\r\n{}Content-Length: 0\r\n{}"
                                 "Proxy-Agent: clash-native\r\n\r\n",
                                 status, reason, extra_headers, connection_headers);
    auto self = shared_from_this();
    boost::asio::async_write(
        client_, boost::asio::buffer(http_response_),
        [self, keep_alive](const boost::system::error_code &error, std::size_t) {
            if (error) {
                self->close();
            } else if (keep_alive) {
                self->finish_http_forward();
            } else {
                self->close();
            }
        });
}

void ProxySession::send_http_response(int status, std::string_view reason, bool start_relay) {
    if (closed_.load(std::memory_order_acquire)) {
        return;
    }
    http_response_ =
        fmt::format("HTTP/1.1 {} {}\r\nProxy-Agent: clash-native\r\n\r\n", status, reason);
    auto self = shared_from_this();
    boost::asio::async_write(
        client_, boost::asio::buffer(http_response_),
        [self, start_relay](const boost::system::error_code &error, std::size_t) {
            if (error || !start_relay) {
                self->close();
                return;
            }
            self->start_relay();
        });
}

} // namespace clash_native::proxy
