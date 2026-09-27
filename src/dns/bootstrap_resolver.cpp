#include <clash_native/async/oneshot.hpp>
#include <clash_native/async/timer.hpp>
#include <clash_native/dns/bootstrap_resolver.hpp>
#include <clash_native/dns/dns_codec.hpp>

#include <exec/asio/use_sender.hpp>
#include <exec/async_scope.hpp>
#include <exec/task.hpp>

#include <stdexec/execution.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <memory>
#include <optional>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

namespace clash_native::dns {

namespace {

using DnsServerEndpoint = boost::asio::ip::udp::endpoint;
using Address = boost::asio::ip::address;
using AddressResult = core::Result<std::vector<Address>>;

core::Error resolution_error(std::string hostname, const boost::system::error_code &error) {
    return {core::ErrorCode::resolution, "bootstrap resolution failed for " + std::move(hostname),
            std::error_code(error.value(), std::system_category())};
}

core::Error timeout_error() { return {core::ErrorCode::timeout, "bootstrap resolution timed out"}; }

core::Error cancelled_error() {
    return {core::ErrorCode::cancelled, "bootstrap resolution was cancelled"};
}

// System resolver as a straight-line task: the resolve await races a
// sleep_until deadline task. First-wins via map lookup in complete(): the
// loser finds no entry and drops. Resolver cancel() aborts in-flight
// use_sender awaits (operation_aborted -> set_stopped), so the task ends
// promptly and its late terminal drops the same way.
class SystemBootstrapResolver final : public BootstrapResolver,
                                      public std::enable_shared_from_this<SystemBootstrapResolver> {
  public:
    explicit SystemBootstrapResolver(runtime::AsioRuntime &runtime)
        : runtime_(runtime), resolver_(runtime.serialized_executor()) {}

    RequestId resolve(std::string hostname, std::chrono::steady_clock::time_point deadline,
                      Handler handler) override {
        const auto request_id = next_request_id_++;
        auto request = std::make_shared<Request>();
        request->hostname = std::move(hostname);
        request->handler = std::move(handler);
        requests_.emplace(request_id, request);
        if (stopped_) {
            complete(request_id, core::fail(cancelled_error()));
            return request_id;
        }
        auto self = shared_from_this();
        scope_.spawn(run(self, request_id));
        scope_.spawn(run_deadline(self, request_id, deadline));
        return request_id;
    }

    void cancel(RequestId request_id) noexcept override {
        complete(request_id, core::fail(cancelled_error()));
    }

    void stop() noexcept override {
        if (stopped_) {
            return;
        }
        stopped_ = true;
        resolver_.cancel();
        std::vector<RequestId> request_ids;
        request_ids.reserve(requests_.size());
        for (const auto &[request_id, request] : requests_) {
            (void)request;
            request_ids.push_back(request_id);
        }
        for (const auto request_id : request_ids) {
            complete(request_id, core::fail(cancelled_error()));
        }
    }

  private:
    struct Request {
        std::string hostname;
        Handler handler;
    };

    // Straight-line resolve chain. Always ends with a value: every terminal
    // funnels through complete(), and a stop-cancelled await ends the task
    // silently after stop() already delivered the terminal.
    static exec::task<void> run(std::shared_ptr<SystemBootstrapResolver> self,
                                RequestId request_id) {
        std::string hostname;
        {
            const auto found = self->requests_.find(request_id);
            if (found == self->requests_.end()) {
                co_return;
            }
            hostname = found->second->hostname;
        }
        try {
            auto results =
                co_await self->resolver_.async_resolve(hostname, "0", exec::asio::use_sender);
            std::vector<Address> addresses;
            for (const auto &entry : results) {
                const auto address = entry.endpoint().address();
                if (std::find(addresses.begin(), addresses.end(), address) == addresses.end()) {
                    addresses.push_back(address);
                }
            }
            if (addresses.empty()) {
                self->complete(request_id,
                               core::fail({core::ErrorCode::resolution,
                                           "bootstrap resolution returned no addresses"}));
            } else {
                self->complete(request_id, std::move(addresses));
            }
        } catch (const boost::system::system_error &failure) {
            self->complete(request_id, core::fail(resolution_error(hostname, failure.code())));
        } catch (...) {
            self->complete(request_id,
                           core::fail(resolution_error(hostname, boost::system::error_code{})));
        }
        co_return;
    }

    // Deadline task: fires once at the deadline; the map lookup drops it
    // when the resolve already won. Bounded by the deadline, so no stop is
    // ever requested.
    static exec::task<void> run_deadline(std::shared_ptr<SystemBootstrapResolver> self,
                                         RequestId request_id,
                                         std::chrono::steady_clock::time_point deadline) {
        try {
            co_await async::sleep_until(self->runtime_.serialized_executor(), deadline);
        } catch (...) {
            co_return;
        }
        self->complete(request_id, core::fail(timeout_error()));
        co_return;
    }

    void complete(RequestId request_id, AddressResult result) {
        const auto found = requests_.find(request_id);
        if (found == requests_.end()) {
            return;
        }
        auto request = std::move(found->second);
        requests_.erase(found);
        if (request->handler) {
            auto handler = std::move(request->handler);
            runtime_.scheduler().post(
                [handler = std::move(handler), result = std::move(result)]() mutable {
                    handler(std::move(result));
                });
        }
    }

    runtime::AsioRuntime &runtime_;
    boost::asio::ip::tcp::resolver resolver_;
    exec::async_scope scope_;
    std::unordered_map<RequestId, std::shared_ptr<Request>> requests_;
    RequestId next_request_id_ = 1;
    bool stopped_ = false;
};

bool same_endpoint(const DnsServerEndpoint &left, const DnsServerEndpoint &right) {
    return left.address() == right.address() && left.port() == right.port();
}

std::vector<DnsServerEndpoint>
merge_servers(const std::vector<DnsServerEndpoint> &configured_servers) {
    std::vector<DnsServerEndpoint> servers;
    const auto append_unique = [&servers](const DnsServerEndpoint &endpoint) {
        if (endpoint.port() == 0 || endpoint.address().is_unspecified()) {
            return;
        }
        if (std::none_of(servers.begin(), servers.end(),
                         [&](const auto &existing) { return same_endpoint(existing, endpoint); })) {
            servers.push_back(endpoint);
        }
    };
    for (const auto &endpoint : configured_servers) {
        append_unique(endpoint);
    }
    for (const auto &endpoint : default_bootstrap_dns_servers()) {
        append_unique(endpoint);
    }
    return servers;
}

enum class ServerStep : unsigned char {
    completed,
    next_server,
};

class DnsBootstrapResolver final : public BootstrapResolver,
                                   public std::enable_shared_from_this<DnsBootstrapResolver> {
  public:
    DnsBootstrapResolver(runtime::AsioRuntime &runtime,
                         std::vector<DnsServerEndpoint> configured_servers,
                         std::shared_ptr<BootstrapResolver> system_resolver)
        : runtime_(runtime), configured_servers_(std::move(configured_servers)),
          system_resolver_(system_resolver ? std::move(system_resolver)
                                           : make_system_bootstrap_resolver(runtime_)) {}

    RequestId resolve(std::string hostname, std::chrono::steady_clock::time_point deadline,
                      Handler handler) override {
        const auto request_id = next_request_id_++;
        if (stopped_) {
            runtime_.scheduler().post([handler = std::move(handler)]() mutable {
                if (handler) {
                    handler(core::fail(cancelled_error()));
                }
            });
            return request_id;
        }
        auto request = std::make_shared<Request>();
        request->hostname = std::move(hostname);
        request->deadline = deadline;
        request->handler = std::move(handler);
        request->servers = merge_servers(configured_servers_);
        requests_.emplace(request_id, request);
        auto self = shared_from_this();
        scope_.spawn(run(self, request_id));
        scope_.spawn(run_deadline(self, request_id, request));
        return request_id;
    }

    void cancel(RequestId request_id) noexcept override {
        const auto found = requests_.find(request_id);
        if (found == requests_.end()) {
            return;
        }
        auto request = found->second;
        if (request->system_request_id != 0) {
            system_resolver_->cancel(request->system_request_id);
            request->system_request_id = 0;
        }
        close_socket(*request);
        complete(request_id, core::fail(cancelled_error()));
    }

    void stop() noexcept override {
        if (stopped_) {
            return;
        }
        stopped_ = true;
        system_resolver_->stop();
        std::vector<RequestId> request_ids;
        request_ids.reserve(requests_.size());
        for (const auto &[request_id, request] : requests_) {
            (void)request;
            request_ids.push_back(request_id);
        }
        for (const auto request_id : request_ids) {
            const auto found = requests_.find(request_id);
            if (found != requests_.end()) {
                close_socket(*found->second);
            }
            complete(request_id, core::fail(cancelled_error()));
        }
    }

  private:
    struct Request {
        std::string hostname;
        std::chrono::steady_clock::time_point deadline;
        Handler handler;
        std::vector<DnsServerEndpoint> servers;
        std::size_t server_index = 0;
        std::uint64_t server_attempt = 0;
        std::vector<Address> addresses;
        std::shared_ptr<boost::asio::ip::udp::socket> socket;
        boost::asio::ip::udp::endpoint sender;
        std::array<std::uint8_t, 65535> response_buffer{};
        std::vector<std::uint8_t> query_wire;
        RequestId system_request_id = 0;
        bool completed = false;
        bool server_expired = false;
        bool deadline_exceeded = false;
        bool in_system = false;
    };

    void close_socket(Request &request) {
        if (request.socket) {
            boost::system::error_code ignored;
            request.socket->cancel(ignored);
            request.socket->close(ignored);
            request.socket.reset();
        }
    }

    // Driver task: UDP servers in order, then the system fallback. Progression
    // stays in this one task; the deadline tasks only set flags and close the
    // socket to wake it. Always ends with a value.
    static exec::task<void> run(std::shared_ptr<DnsBootstrapResolver> self, RequestId request_id) {
        const auto found = self->requests_.find(request_id);
        if (found == self->requests_.end()) {
            co_return;
        }
        const auto request = found->second;
        while (request->server_index < request->servers.size()) {
            if (request->completed || self->stopped_) {
                co_return;
            }
            if (request->deadline_exceeded ||
                std::chrono::steady_clock::now() >= request->deadline) {
                break;
            }
            const auto endpoint = request->servers[request->server_index];
            const auto step = co_await run_server(self, request_id, request, endpoint);
            if (request->completed || step == ServerStep::completed || self->stopped_) {
                co_return;
            }
            if (request->deadline_exceeded ||
                std::chrono::steady_clock::now() >= request->deadline) {
                break;
            }
            self->close_socket(*request);
            ++request->server_index;
        }
        if (request->completed || self->stopped_) {
            co_return;
        }
        co_await run_system(self, request_id, request);
        co_return;
    }

    // One server: A then AAAA, accumulating addresses. Any failure or expiry
    // moves to the next server; a completed request (or stop) ends the drive.
    static exec::task<ServerStep> run_server(std::shared_ptr<DnsBootstrapResolver> self,
                                             RequestId request_id, std::shared_ptr<Request> request,
                                             DnsServerEndpoint endpoint) {
        auto socket =
            std::make_shared<boost::asio::ip::udp::socket>(self->runtime_.serialized_executor());
        boost::system::error_code error;
        socket->open(endpoint.protocol(), error);
        if (!error) {
            socket->bind({endpoint.address().is_v4() ? Address(boost::asio::ip::address_v4::any())
                                                     : Address(boost::asio::ip::address_v6::any()),
                          0},
                         error);
        }
        if (error) {
            co_return ServerStep::next_server;
        }
        request->socket = socket;
        request->server_expired = false;
        const auto attempt = ++request->server_attempt;

        const auto now = std::chrono::steady_clock::now();
        const auto remaining_servers = request->servers.size() - request->server_index;
        const auto server_budget =
            (request->deadline - now) /
            static_cast<std::int64_t>(remaining_servers > 0 ? remaining_servers : 1);
        const auto server_deadline = std::min(request->deadline, now + server_budget);
        self->scope_.spawn(
            run_server_deadline(self, request_id, request, socket, attempt, server_deadline));

        for (int query_index = 0; query_index < 2; ++query_index) {
            if (request->completed || self->stopped_ || request->server_expired ||
                request->deadline_exceeded ||
                std::chrono::steady_clock::now() >= request->deadline) {
                co_return ServerStep::next_server;
            }
            const auto type = query_index == 0 ? DnsRecordType::a : DnsRecordType::aaaa;
            const DnsQuestion question{request->hostname, type, 1};
            const auto query_id = self->next_query_id();
            auto wire = DnsMessageCodec::encode_query_packet(question, query_id);
            if (!wire) {
                co_return ServerStep::next_server;
            }
            request->query_wire = std::move(wire.value());
            // A closed socket aborts the await with set_stopped; map that to
            // an empty outcome so the drive survives to the next server.
            std::optional<std::size_t> sent;
            try {
                sent = co_await (socket->async_send_to(boost::asio::buffer(request->query_wire),
                                                       endpoint, exec::asio::use_sender) |
                                 stdexec::then([](std::size_t size) {
                                     return std::optional<std::size_t>(size);
                                 }) |
                                 stdexec::let_stopped(
                                     [] { return stdexec::just(std::optional<std::size_t>()); }));
            } catch (...) {
                co_return ServerStep::next_server;
            }
            if (!sent || request->completed || self->stopped_ || request->server_expired) {
                co_return ServerStep::next_server;
            }
            bool answered = false;
            while (!answered) {
                if (request->completed || self->stopped_ || request->server_expired) {
                    co_return ServerStep::next_server;
                }
                std::optional<std::size_t> received;
                try {
                    received = co_await (
                        socket->async_receive_from(boost::asio::buffer(request->response_buffer),
                                                   request->sender, exec::asio::use_sender) |
                        stdexec::then(
                            [](std::size_t size) { return std::optional<std::size_t>(size); }) |
                        stdexec::let_stopped(
                            [] { return stdexec::just(std::optional<std::size_t>()); }));
                } catch (...) {
                    co_return ServerStep::next_server;
                }
                if (!received || request->completed || self->stopped_ || request->server_expired) {
                    co_return ServerStep::next_server;
                }
                const auto size = *received;
                if (request->sender != endpoint || size < 2 ||
                    static_cast<std::uint16_t>(request->response_buffer[0] << 8 |
                                               request->response_buffer[1]) != query_id) {
                    continue;
                }
                const auto response = DnsMessageCodec::decode_packet(
                    std::span<const std::uint8_t>(request->response_buffer.data(), size), query_id);
                if (!response) {
                    co_return ServerStep::next_server;
                }
                const auto answer = DnsMessageCodec::to_address_answer(response.value());
                if (answer && !answer.value().addresses.empty()) {
                    for (const auto &address : answer.value().addresses) {
                        if (std::find(request->addresses.begin(), request->addresses.end(),
                                      address) == request->addresses.end()) {
                            request->addresses.push_back(address);
                        }
                    }
                }
                answered = true;
            }
        }
        if (!request->addresses.empty()) {
            self->complete(request_id, std::move(request->addresses));
            co_return ServerStep::completed;
        }
        co_return ServerStep::next_server;
    }

    // System fallback: the Handler-style call is awaited through a oneshot
    // channel (the sender is shared so the copyable Handler can hold it).
    // The system resolver's own deadline bounds the wait; cancel() aborts it
    // and its send wakes this task to drop.
    static exec::task<void> run_system(std::shared_ptr<DnsBootstrapResolver> self,
                                       RequestId request_id, std::shared_ptr<Request> request) {
        request->in_system = true;
        if (request->completed || self->stopped_) {
            co_return;
        }
        auto channel = async::oneshot::channel<AddressResult>();
        auto sender =
            std::make_shared<async::oneshot::Sender<AddressResult>>(std::move(channel.sender));
        request->system_request_id = self->system_resolver_->resolve(
            request->hostname, request->deadline,
            [sender](AddressResult result) mutable { sender->send(std::move(result)); });
        if (request->completed || self->stopped_) {
            co_return;
        }
        auto outcome = co_await std::move(channel.receiver);
        request->system_request_id = 0;
        if (request->completed || self->stopped_) {
            co_return;
        }
        if (!outcome) {
            self->complete(request_id, core::fail(cancelled_error()));
            co_return;
        }
        self->complete(request_id, std::move(*outcome));
        co_return;
    }

    // Per-server budget task: marks the server expired and closes its socket
    // to wake the driver. Stale firings (a newer attempt is driving) drop via
    // the attempt check. Bounded by the server deadline; never stopped.
    static exec::task<void>
    run_server_deadline(std::shared_ptr<DnsBootstrapResolver> self, RequestId request_id,
                        std::shared_ptr<Request> request,
                        std::shared_ptr<boost::asio::ip::udp::socket> socket, std::uint64_t attempt,
                        std::chrono::steady_clock::time_point deadline) {
        (void)request_id;
        try {
            co_await async::sleep_until(self->runtime_.serialized_executor(), deadline);
        } catch (...) {
            co_return;
        }
        if (request->completed || self->stopped_ || request->server_attempt != attempt) {
            co_return;
        }
        request->server_expired = true;
        boost::system::error_code ignored;
        socket->cancel(ignored);
        socket->close(ignored);
        co_return;
    }

    // Overall deadline task: pushes the driver into the system phase. When the
    // driver is already there, the system resolver's own deadline owns the
    // wait, so this only wakes it. Bounded by the deadline; never stopped.
    static exec::task<void> run_deadline(std::shared_ptr<DnsBootstrapResolver> self,
                                         RequestId request_id, std::shared_ptr<Request> request) {
        try {
            co_await async::sleep_until(self->runtime_.serialized_executor(), request->deadline);
        } catch (...) {
            co_return;
        }
        if (request->completed || self->stopped_ || request->in_system) {
            co_return;
        }
        request->deadline_exceeded = true;
        self->close_socket(*request);
        (void)request_id;
        co_return;
    }

    std::uint16_t next_query_id() noexcept {
        auto query_id = next_query_id_++;
        if (query_id == 0) {
            query_id = next_query_id_++;
        }
        return query_id;
    }

    void complete(RequestId request_id, AddressResult result) {
        const auto found = requests_.find(request_id);
        if (found == requests_.end()) {
            return;
        }
        auto request = std::move(found->second);
        requests_.erase(found);
        request->completed = true;
        close_socket(*request);
        if (request->handler) {
            auto handler = std::move(request->handler);
            runtime_.scheduler().post(
                [handler = std::move(handler), result = std::move(result)]() mutable {
                    handler(std::move(result));
                });
        }
    }

    runtime::AsioRuntime &runtime_;
    std::vector<DnsServerEndpoint> configured_servers_;
    std::shared_ptr<BootstrapResolver> system_resolver_;
    exec::async_scope scope_;
    std::unordered_map<RequestId, std::shared_ptr<Request>> requests_;
    RequestId next_request_id_ = 1;
    std::uint16_t next_query_id_ = 1;
    bool stopped_ = false;
};

} // namespace

std::shared_ptr<BootstrapResolver> make_system_bootstrap_resolver(runtime::AsioRuntime &runtime) {
    return std::make_shared<SystemBootstrapResolver>(runtime);
}

std::vector<boost::asio::ip::udp::endpoint> default_bootstrap_dns_servers() {
    return {
        {boost::asio::ip::make_address_v4("223.5.5.5"), 53},
        {boost::asio::ip::make_address_v4("223.6.6.6"), 53},
        {boost::asio::ip::make_address_v4("1.1.1.1"), 53},
        {boost::asio::ip::make_address_v4("1.0.0.1"), 53},
        {boost::asio::ip::make_address_v4("8.8.8.8"), 53},
        {boost::asio::ip::make_address_v4("8.8.4.4"), 53},
    };
}

std::shared_ptr<BootstrapResolver>
make_bootstrap_resolver(runtime::AsioRuntime &runtime,
                        std::vector<boost::asio::ip::udp::endpoint> configured_servers,
                        std::shared_ptr<BootstrapResolver> system_resolver) {
    return std::make_shared<DnsBootstrapResolver>(runtime, std::move(configured_servers),
                                                  std::move(system_resolver));
}

} // namespace clash_native::dns
