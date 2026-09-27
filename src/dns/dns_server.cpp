#include <clash_native/dns/dns_codec.hpp>
#include <clash_native/dns/dns_server.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <exec/asio/use_sender.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <semaphore>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace clash_native::dns {

namespace {

core::Error listener_error(std::string operation, const boost::system::error_code &error) {
    return {core::ErrorCode::transport_io, "failed to " + std::move(operation),
            std::error_code(error.value(), std::system_category())};
}

// Logs a wire I/O failure at the awaiting coroutine site. use_sender
// surfaces Asio errors as exception_ptr (system_error); stopped (abort)
// arrives here too and is logged the same way before the loop bails to
// close(). Kept at debug: shutdown/EOF races are routine, not warnings.
void log_wire_error(std::string_view operation, const std::exception_ptr &error) {
    try {
        std::rethrow_exception(error);
    } catch (const core::Error &failure) {
        spdlog::debug("DNS TCP connection {} failed: {}", operation, failure.context);
    } catch (const std::exception &failure) {
        spdlog::debug("DNS TCP connection {} failed: {}", operation, failure.what());
    } catch (...) {
        spdlog::debug("DNS TCP connection {} failed with unknown error", operation);
    }
}

std::size_t udp_payload_limit(const DnsPacket &query) {
    const auto opt = std::find_if(
        query.additionals.begin(), query.additionals.end(), [](const DnsResourceRecord &record) {
            return record.type == static_cast<std::uint16_t>(DnsRecordType::opt);
        });
    if (opt == query.additionals.end()) {
        return 512;
    }
    return std::max<std::size_t>(512, opt->class_code);
}

core::Result<std::vector<std::uint8_t>>
limit_udp_response(const DnsPacket &query, core::Result<std::vector<std::uint8_t>> response) {
    if (!response) {
        return core::fail(response.error());
    }
    return DnsMessageCodec::truncate_udp_response(response.value(), udp_payload_limit(query));
}

std::optional<core::Result<std::vector<std::uint8_t>>>
fake_ip_response(const DnsPacket &query, const std::shared_ptr<FakeIpStore> &store,
                 const std::function<bool(std::string_view)> &filter) {
    if (!store || !filter || query.response() || query.questions.size() != 1 ||
        query.questions.front().type != DnsRecordType::a || !filter(query.questions.front().name)) {
        return std::nullopt;
    }

    const auto address = store->resolve(query.questions.front().name);
    if (!address) {
        return DnsMessageCodec::encode_error_response(query, 2);
    }

    DnsAnswer answer;
    answer.question = query.questions.front();
    answer.addresses.push_back(address.value());
    answer.ttl_seconds = 60;
    return DnsMessageCodec::encode_response(query, answer);
}

} // namespace

DnsServer::DnsServer(runtime::AsioRuntime &runtime, ResolverService &resolver,
                     boost::asio::ip::udp::endpoint udp_endpoint,
                     boost::asio::ip::tcp::endpoint tcp_endpoint)
    : DnsServer(runtime, resolver.query_service(), udp_endpoint, tcp_endpoint) {}

DnsServer::DnsServer(runtime::AsioRuntime &runtime, DnsQueryService &query_service,
                     boost::asio::ip::udp::endpoint udp_endpoint,
                     boost::asio::ip::tcp::endpoint tcp_endpoint)
    : runtime_(runtime), query_service_(&query_service), udp_socket_(runtime.serialized_executor()),
      tcp_acceptor_(runtime.serialized_executor()), udp_endpoint_(udp_endpoint),
      tcp_endpoint_(tcp_endpoint) {}

DnsServer::DnsServer(runtime::AsioRuntime &runtime,
                     std::shared_ptr<runtime::RuntimeSnapshotStore> snapshot_store,
                     boost::asio::ip::udp::endpoint udp_endpoint,
                     boost::asio::ip::tcp::endpoint tcp_endpoint)
    : runtime_(runtime), snapshot_store_(std::move(snapshot_store)),
      udp_socket_(runtime.serialized_executor()), tcp_acceptor_(runtime.serialized_executor()),
      udp_endpoint_(udp_endpoint), tcp_endpoint_(tcp_endpoint) {
    if (!snapshot_store_) {
        throw std::invalid_argument("DNS server requires a runtime snapshot store");
    }
}

DnsServer::~DnsServer() { stop(); }

core::Status DnsServer::start() {
    if (running_.load(std::memory_order_acquire)) {
        return {};
    }

    boost::system::error_code error;
    udp_socket_.open(udp_endpoint_.protocol(), error);
    if (!error) {
        udp_socket_.set_option(boost::asio::socket_base::reuse_address(true), error);
    }
    if (!error) {
        udp_socket_.bind(udp_endpoint_, error);
    }
    if (!error) {
        tcp_acceptor_.open(tcp_endpoint_.protocol(), error);
    }
    if (!error) {
        tcp_acceptor_.set_option(boost::asio::socket_base::reuse_address(true), error);
    }
    if (!error) {
        tcp_acceptor_.bind(tcp_endpoint_, error);
    }
    if (!error) {
        tcp_acceptor_.listen(boost::asio::socket_base::max_listen_connections, error);
    }
    if (error) {
        spdlog::error("DNS server failed to open local listeners: {}", error.message());
        boost::system::error_code ignored;
        udp_socket_.close();
        tcp_acceptor_.close(ignored);
        return core::fail(listener_error("open the local DNS server", error));
    }

    udp_endpoint_ = udp_socket_.local_endpoint(error);
    if (!error) {
        tcp_endpoint_ = tcp_acceptor_.local_endpoint(error);
    }
    if (error) {
        spdlog::error("DNS server failed to query local listener endpoints: {}", error.message());
        boost::system::error_code ignored;
        udp_socket_.close();
        tcp_acceptor_.close(ignored);
        return core::fail(listener_error("query the local DNS server endpoint", error));
    }

    running_.store(true, std::memory_order_release);
    spdlog::info("DNS server listening on UDP {}:{} and TCP {}:{}",
                 udp_endpoint_.address().to_string(), udp_endpoint_.port(),
                 tcp_endpoint_.address().to_string(), tcp_endpoint_.port());
    receive_udp();
    accept_tcp();
    return {};
}

void DnsServer::stop() noexcept {
    if (!running_.exchange(false, std::memory_order_acq_rel)) {
        spdlog::debug("DNS server stop requested while already stopped");
        return;
    }
    spdlog::debug("Stopping DNS server");

    if (!runtime_.running()) {
        stop_on_owner();
        return;
    }

    std::binary_semaphore completed(0);
    boost::asio::dispatch(runtime_.serialized_executor(), [this, &completed] {
        stop_on_owner();
        completed.release();
    });
    completed.acquire();
}

void DnsServer::set_fake_ip_store(std::shared_ptr<FakeIpStore> store,
                                  std::function<bool(std::string_view)> filter) {
    if (running()) {
        throw std::logic_error("Cannot change FakeIP configuration on a running DNS server");
    }
    fake_ip_store_ = std::move(store);
    fake_ip_filter_ = std::move(filter);
}

void DnsServer::stop_on_owner() noexcept {
    // Stop the UDP and accept loops first: the in-flight receive/accept
    // completes stopped and the loops exit without re-arming. In-flight
    // UDP resolves abort through query_sender stop; socket close below is
    // retained as the I/O-level abort.
    try {
        udp_scope_.request_stop();
    } catch (...) {
    }
    try {
        accept_scope_.request_stop();
    } catch (...) {
    }

    boost::system::error_code ignored;
    udp_socket_.close();
    tcp_acceptor_.cancel(ignored);
    tcp_acceptor_.close(ignored);
    // Abort each connection: closes its socket (the in-flight read/write
    // completes aborted) and funnels its loop task to close(). close()
    // erases from the set, so copy first.
    std::vector<std::shared_ptr<TcpConnection>> connections(tcp_connections_.begin(),
                                                            tcp_connections_.end());
    for (const auto &connection : connections) {
        connection->abort();
    }
    tcp_connections_.clear();
    spdlog::debug("DNS server stopped");
}

bool DnsServer::running() const noexcept { return running_.load(std::memory_order_acquire); }

boost::asio::ip::udp::endpoint DnsServer::udp_endpoint() const noexcept { return udp_endpoint_; }

boost::asio::ip::tcp::endpoint DnsServer::tcp_endpoint() const noexcept { return tcp_endpoint_; }

runtime::RuntimeSnapshotPtr DnsServer::current_snapshot() const noexcept {
    return snapshot_store_ ? snapshot_store_->load() : nullptr;
}

void DnsServer::receive_udp() {
    // Single-outstanding-pull UDP pump as a task loop: one co_awaited
    // receive at a time, each answer fanned out to its own resolve task.
    // Socket close aborts the in-flight receive (stopped) and the loop
    // exits; the task always ends with a value so the scope never fails.
    udp_scope_.spawn(run_udp_loop(this));
}

exec::task<void> DnsServer::run_udp_loop(DnsServer *server) {
    while (server->running_.load(std::memory_order_acquire)) {
        io::DatagramPacket received;
        try {
            auto sender =
                server->udp_socket_.async_receive_from(boost::asio::buffer(server->udp_buffer_));
            received = co_await std::move(sender);
        } catch (...) {
            // Stopped (shutdown close) or receive failure: stop owns
            // teardown, so just exit the loop without re-arming.
            co_return;
        }
        if (!server->running_.load(std::memory_order_acquire)) {
            co_return;
        }
        if (!received.address.is_address()) {
            continue;
        }
        const auto query = DnsMessageCodec::decode_packet(
            std::span<const std::uint8_t>(server->udp_buffer_.data(), received.size));
        if (!query) {
            continue;
        }
        const auto sender_endpoint =
            boost::asio::ip::udp::endpoint(received.address.address(), received.address.port());
        server->udp_scope_.spawn(
            run_udp_resolve(server, std::move(query.value()), sender_endpoint));
    }
    co_return;
}

exec::task<void> DnsServer::run_udp_resolve(DnsServer *server, DnsPacket query,
                                            boost::asio::ip::udp::endpoint sender) {
    const auto snapshot = server->current_snapshot();
    const auto &fake_store = snapshot ? snapshot->fake_ip_store : server->fake_ip_store_;
    const auto &fake_filter = snapshot ? snapshot->fake_ip_filter : server->fake_ip_filter_;
    if (const auto fake_response = fake_ip_response(query, fake_store, fake_filter)) {
        const auto response = limit_udp_response(query, *fake_response);
        if (response && response.value().size() <= 0xffff) {
            auto payload = std::make_shared<std::vector<std::uint8_t>>(response.value());
            server->send_udp_response(sender, std::move(payload));
        }
        co_return;
    }
    auto resolver_owner = snapshot ? snapshot->resolver : server->resolver_owner_;
    auto *query_service = snapshot && resolver_owner != nullptr ? &resolver_owner->query_service()
                                                                : server->query_service_;
    if (query_service == nullptr) {
        const auto response =
            limit_udp_response(query, DnsMessageCodec::encode_error_response(query, 2));
        if (response) {
            auto payload = std::make_shared<std::vector<std::uint8_t>>(response.value());
            server->send_udp_response(sender, std::move(payload));
        }
        co_return;
    }
    const auto error_response = [&]() -> core::Result<DnsPacket> {
        const auto encoded = DnsMessageCodec::encode_error_response(query, 2);
        if (encoded) {
            return DnsMessageCodec::decode_packet(encoded.value(), query.id);
        }
        return core::fail(core::Error{core::ErrorCode::transport_io, "DNS UDP query failed"});
    };
    core::Result<DnsPacket> answered = error_response();
    try {
        // Composable wait: server stop aborts the query await through the
        // scope, so the task never leaks until the upstream answers.
        // NOTE: query_sender takes the packet by value; the limit/encode
        // below still need the original, so move a copy.
        answered = co_await query_service->query_sender(query);
    } catch (...) {
        answered = error_response();
    }
    if (!answered) {
        answered = error_response();
    }
    const auto response =
        limit_udp_response(query, core::Result<std::vector<std::uint8_t>>(answered.value().wire));
    if (!response || response.value().size() > 0xffff) {
        co_return;
    }
    auto payload = std::make_shared<std::vector<std::uint8_t>>(response.value());
    server->send_udp_response(sender, std::move(payload));
    co_return;
}

void DnsServer::send_udp_response(boost::asio::ip::udp::endpoint recipient,
                                  std::shared_ptr<std::vector<std::uint8_t>> payload) {
    // Fire-and-forget send task: completion (sent, failed, stopped) is
    // terminal by itself, so the task always ends with a value.
    udp_scope_.spawn(run_udp_send(this, recipient, std::move(payload)));
}

exec::task<void> DnsServer::run_udp_send(DnsServer *server,
                                         boost::asio::ip::udp::endpoint recipient,
                                         std::shared_ptr<std::vector<std::uint8_t>> payload) {
    try {
        auto sender = server->udp_socket_.async_send_to(
            boost::asio::buffer(*payload), io::DatagramAddress::from_endpoint(recipient));
        co_await (std::move(sender) | stdexec::then([](std::size_t) {}));
    } catch (...) {
    }
    co_return;
}

void DnsServer::accept_tcp() {
    // The accept loop is a task, not a self-rearming callback: stop (via
    // accept_scope_ request_stop on shutdown) completes the in-flight
    // accept as stopped and the loop exits without re-arming. No gate
    // check is needed: stop owns teardown through the scope.
    accept_scope_.spawn(run_accept_loop(this));
}

exec::task<void> DnsServer::run_accept_loop(DnsServer *server) {
    while (server->running_.load(std::memory_order_acquire)) {
        auto socket =
            std::make_shared<boost::asio::ip::tcp::socket>(server->runtime_.serialized_executor());
        try {
            co_await server->tcp_acceptor_.async_accept(*socket, exec::asio::use_sender);
        } catch (...) {
            // Stopped (shutdown cancel/close) or accept failure: stop owns
            // teardown, so just exit the loop without re-arming.
            co_return;
        }
        if (!server->running_.load(std::memory_order_acquire)) {
            co_return;
        }
        auto connection = std::make_shared<DnsServer::TcpConnection>(*server, socket);
        server->tcp_connections_.insert(connection);
        connection->start();
    }
    co_return;
}

DnsServer::TcpConnection::TcpConnection(DnsServer &server,
                                        std::shared_ptr<boost::asio::ip::tcp::socket> socket)
    : server(server), socket(std::move(socket)) {}

void DnsServer::TcpConnection::start() { scope.spawn(run(shared_from_this())); }

void DnsServer::TcpConnection::abort() noexcept {
    // Idempotent with close(): mark completed so the loop task bails at
    // its next guard, close the socket so the in-flight read/write
    // completes aborted promptly. The task then funnels to close().
    completed_ = true;
    if (socket) {
        boost::system::error_code ignored;
        socket->cancel(ignored);
        socket->close(ignored);
    }
}

void DnsServer::TcpConnection::close() noexcept {
    completed_ = true;
    if (socket) {
        boost::system::error_code ignored;
        socket->cancel(ignored);
        socket->close(ignored);
    }
    server.tcp_connections_.erase(shared_from_this());
}

exec::task<void> DnsServer::TcpConnection::run(std::shared_ptr<TcpConnection> self) {
    // Query loop: length, body, resolve, write back, repeat. Reads and
    // writes are use_sender awaits composed with the query_sender await:
    // connection stop (socket close) aborts the wire wait, and query stop
    // aborts the upstream wait. Every terminal funnels to close(), so the
    // task always ends with a value and the scope never fails.
    try {
        while (!self->completed_) {
            std::array<std::uint8_t, 2> length{};
            try {
                co_await (boost::asio::async_read(*self->socket, boost::asio::buffer(length),
                                                  exec::asio::use_sender) |
                          stdexec::then([](std::size_t) {}));
            } catch (...) {
                log_wire_error("read length", std::current_exception());
                break;
            }
            if (self->completed_) {
                break;
            }
            const auto size = static_cast<std::size_t>(length[0] << 8 | length[1]);
            if (size == 0 || size > self->server.udp_buffer_.size()) {
                break;
            }
            std::vector<std::uint8_t> payload(size);
            try {
                co_await (boost::asio::async_read(*self->socket, boost::asio::buffer(payload),
                                                  exec::asio::use_sender) |
                          stdexec::then([](std::size_t) {}));
            } catch (...) {
                log_wire_error("read body", std::current_exception());
                break;
            }
            if (self->completed_) {
                break;
            }
            const auto query = DnsMessageCodec::decode_packet(payload);
            if (!query) {
                break;
            }
            const auto response = co_await resolve(self, std::move(query.value()));
            if (self->completed_) {
                break;
            }
            if (!response || response.value().size() > 0xffff) {
                break;
            }
            auto frame = std::make_shared<std::vector<std::uint8_t>>();
            frame->reserve(2 + response.value().size());
            frame->push_back(static_cast<std::uint8_t>(response.value().size() >> 8));
            frame->push_back(static_cast<std::uint8_t>(response.value().size() & 0xff));
            frame->insert(frame->end(), response.value().begin(), response.value().end());
            try {
                co_await (boost::asio::async_write(*self->socket, boost::asio::buffer(*frame),
                                                   exec::asio::use_sender) |
                          stdexec::then([](std::size_t) {}));
            } catch (...) {
                log_wire_error("write response", std::current_exception());
                break;
            }
        }
    } catch (...) {
        log_wire_error("run loop", std::current_exception());
    }
    self->close();
    co_return;
}

exec::task<core::Result<std::vector<std::uint8_t>>>
DnsServer::TcpConnection::resolve(std::shared_ptr<TcpConnection> self, DnsPacket query) {
    auto &server = self->server;
    const auto snapshot = server.current_snapshot();
    const auto &fake_store = snapshot ? snapshot->fake_ip_store : server.fake_ip_store_;
    const auto &fake_filter = snapshot ? snapshot->fake_ip_filter : server.fake_ip_filter_;
    if (const auto fake_response = fake_ip_response(query, fake_store, fake_filter)) {
        co_return *fake_response;
    }
    auto resolver_owner = snapshot ? snapshot->resolver : server.resolver_owner_;
    auto *query_service = snapshot && resolver_owner != nullptr ? &resolver_owner->query_service()
                                                                : server.query_service_;
    if (query_service == nullptr) {
        co_return DnsMessageCodec::encode_error_response(query, 2);
    }
    core::Result<DnsPacket> answered;
    try {
        // Composable wait: connection stop aborts the socket, query stop
        // aborts this await; either way the loop bails at completed_.
        answered = co_await query_service->query_sender(std::move(query));
    } catch (const core::Error &failure) {
        co_return core::Result<std::vector<std::uint8_t>>(core::fail(failure));
    } catch (...) {
        co_return core::Result<std::vector<std::uint8_t>>(
            core::fail(core::Error{core::ErrorCode::transport_io, "DNS TCP query failed", {}}));
    }
    if (self->completed_) {
        co_return core::Result<std::vector<std::uint8_t>>(
            core::fail(core::Error{core::ErrorCode::cancelled, "DNS TCP connection closed", {}}));
    }
    if (!answered) {
        co_return DnsMessageCodec::encode_error_response(query, 2);
    }
    co_return core::Result<std::vector<std::uint8_t>>(answered.value().wire);
}

} // namespace clash_native::dns
