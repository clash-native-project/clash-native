#include <clash_native/dns/bootstrap_resolver.hpp>
#include <clash_native/dns/dns_codec.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

namespace clash_native::dns {

namespace {

using DnsServerEndpoint = boost::asio::ip::udp::endpoint;
using Address = boost::asio::ip::address;

core::Error resolution_error(std::string hostname, const boost::system::error_code &error) {
    return {core::ErrorCode::resolution, "bootstrap resolution failed for " + std::move(hostname),
            std::error_code(error.value(), std::system_category())};
}

core::Error timeout_error() { return {core::ErrorCode::timeout, "bootstrap resolution timed out"}; }

core::Error cancelled_error() {
    return {core::ErrorCode::cancelled, "bootstrap resolution was cancelled"};
}

class SystemBootstrapResolver final : public BootstrapResolver,
                                      public std::enable_shared_from_this<SystemBootstrapResolver> {
  public:
    explicit SystemBootstrapResolver(runtime::AsioRuntime &runtime)
        : runtime_(runtime), resolver_(runtime.serialized_executor()) {}

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
        auto request = std::make_shared<Request>(runtime_.serialized_executor());
        request->hostname = std::move(hostname);
        request->handler = std::move(handler);
        request->timer.expires_at(deadline);
        requests_.emplace(request_id, request);

        const auto self = shared_from_this();
        request->timer.async_wait([self, request_id](const boost::system::error_code &error) {
            if (!error) {
                self->complete(request_id, core::fail(timeout_error()));
            }
        });
        resolver_.async_resolve(
            request->hostname, "0",
            [self, request_id](const boost::system::error_code &error,
                               const boost::asio::ip::tcp::resolver::results_type &results) {
                const auto found = self->requests_.find(request_id);
                if (found == self->requests_.end()) {
                    return;
                }
                if (error) {
                    self->complete(request_id,
                                   core::fail(resolution_error(found->second->hostname, error)));
                    return;
                }

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
                    return;
                }
                self->complete(request_id, std::move(addresses));
            });
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
        explicit Request(boost::asio::any_io_executor executor) : timer(std::move(executor)) {}

        std::string hostname;
        Handler handler;
        boost::asio::steady_timer timer;
    };

    void complete(RequestId request_id, core::Result<std::vector<Address>> result) {
        const auto found = requests_.find(request_id);
        if (found == requests_.end()) {
            return;
        }
        auto request = std::move(found->second);
        requests_.erase(found);
        request->timer.cancel();
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
        auto request = std::make_shared<Request>(runtime_.serialized_executor());
        request->hostname = std::move(hostname);
        request->deadline = deadline;
        request->handler = std::move(handler);
        request->servers = merge_servers(configured_servers_);
        requests_.emplace(request_id, request);
        start_server(request_id);
        return request_id;
    }

    void cancel(RequestId request_id) noexcept override {
        const auto found = requests_.find(request_id);
        if (found == requests_.end()) {
            return;
        }
        auto request = std::move(found->second);
        requests_.erase(found);
        ++request->generation;
        if (request->system_request_id != 0) {
            system_resolver_->cancel(request->system_request_id);
        }
        close_socket(*request);
        if (request->handler) {
            auto handler = std::move(request->handler);
            runtime_.scheduler().post([handler = std::move(handler)]() mutable {
                handler(core::fail(cancelled_error()));
            });
        }
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
            complete(request_id, core::fail(cancelled_error()));
        }
    }

  private:
    struct Request {
        explicit Request(boost::asio::any_io_executor executor) : timer(std::move(executor)) {}

        std::string hostname;
        std::chrono::steady_clock::time_point deadline;
        Handler handler;
        std::vector<DnsServerEndpoint> servers;
        std::size_t server_index = 0;
        int query_index = 0;
        std::uint16_t query_id = 0;
        std::uint64_t generation = 0;
        std::chrono::steady_clock::time_point server_deadline;
        std::vector<Address> addresses;
        std::shared_ptr<boost::asio::ip::udp::socket> socket;
        boost::asio::ip::udp::endpoint sender;
        boost::asio::steady_timer timer;
        std::array<std::uint8_t, 65535> response_buffer{};
        std::vector<std::uint8_t> query_wire;
        RequestId system_request_id = 0;
    };

    void close_socket(Request &request) {
        request.timer.cancel();
        if (request.socket) {
            boost::system::error_code ignored;
            request.socket->cancel(ignored);
            request.socket->close(ignored);
            request.socket.reset();
        }
    }

    void start_server(RequestId request_id) {
        const auto found = requests_.find(request_id);
        if (found == requests_.end() || stopped_) {
            return;
        }
        const auto request = found->second;
        if (std::chrono::steady_clock::now() >= request->deadline ||
            request->server_index >= request->servers.size()) {
            start_system(request_id);
            return;
        }

        request->socket =
            std::make_shared<boost::asio::ip::udp::socket>(runtime_.serialized_executor());
        boost::system::error_code error;
        const auto endpoint = request->servers[request->server_index];
        request->socket->open(endpoint.protocol(), error);
        if (!error) {
            request->socket->bind(
                {endpoint.address().is_v4()
                     ? boost::asio::ip::address(boost::asio::ip::address_v4::any())
                     : boost::asio::ip::address(boost::asio::ip::address_v6::any()),
                 0},
                error);
        }
        if (error) {
            finish_server(request_id);
            return;
        }

        const auto now = std::chrono::steady_clock::now();
        const auto remaining = request->deadline - now;
        const auto remaining_servers = request->servers.size() - request->server_index;
        const auto server_budget = remaining / static_cast<std::int64_t>(remaining_servers);
        request->server_deadline = std::min(request->deadline, now + server_budget);
        request->timer.expires_at(request->server_deadline);
        const auto self = shared_from_this();
        request->timer.async_wait([self, request_id](const boost::system::error_code &timer_error) {
            if (!timer_error) {
                const auto found = self->requests_.find(request_id);
                if (found == self->requests_.end() || self->stopped_) {
                    return;
                }
                if (!found->second->addresses.empty()) {
                    self->complete(request_id, std::move(found->second->addresses));
                } else if (std::chrono::steady_clock::now() >= found->second->deadline) {
                    self->start_system(request_id);
                } else {
                    self->finish_server(request_id);
                }
            }
        });
        request->query_index = 0;
        request->addresses.clear();
        start_query(request_id);
    }

    void start_query(RequestId request_id) {
        const auto found = requests_.find(request_id);
        if (found == requests_.end() || stopped_) {
            return;
        }
        const auto request = found->second;
        if (std::chrono::steady_clock::now() >= request->deadline) {
            start_system(request_id);
            return;
        }
        const auto endpoint = request->servers[request->server_index];
        const auto type = request->query_index == 0 ? DnsRecordType::a : DnsRecordType::aaaa;
        const DnsQuestion question{request->hostname, type, 1};
        request->query_id = next_query_id();
        auto wire = DnsMessageCodec::encode_query_packet(question, request->query_id);
        if (!wire) {
            finish_server(request_id);
            return;
        }
        request->query_wire = std::move(wire.value());
        const auto generation = ++request->generation;
        const auto socket = request->socket;
        socket->async_send_to(boost::asio::buffer(request->query_wire), endpoint,
                              [self = shared_from_this(), request_id,
                               generation](const boost::system::error_code &error, std::size_t) {
                                  const auto found = self->requests_.find(request_id);
                                  if (found == self->requests_.end() ||
                                      found->second->generation != generation || self->stopped_) {
                                      return;
                                  }
                                  if (error) {
                                      self->finish_server(request_id);
                                      return;
                                  }
                                  self->receive_query(request_id, generation);
                              });
    }

    void receive_query(RequestId request_id, std::uint64_t generation) {
        const auto found = requests_.find(request_id);
        if (found == requests_.end() || found->second->generation != generation || stopped_) {
            return;
        }
        const auto request = found->second;
        const auto socket = request->socket;
        socket->async_receive_from(
            boost::asio::buffer(request->response_buffer), request->sender,
            [self = shared_from_this(), request_id,
             generation](const boost::system::error_code &error, std::size_t size) {
                const auto found = self->requests_.find(request_id);
                if (found == self->requests_.end() || found->second->generation != generation ||
                    self->stopped_) {
                    return;
                }
                const auto request = found->second;
                if (error) {
                    self->finish_server(request_id);
                    return;
                }
                const auto endpoint = request->servers[request->server_index];
                if (request->sender != endpoint || size < 2 ||
                    static_cast<std::uint16_t>(request->response_buffer[0] << 8 |
                                               request->response_buffer[1]) != request->query_id) {
                    self->receive_query(request_id, generation);
                    return;
                }
                const auto response = DnsMessageCodec::decode_packet(
                    std::span<const std::uint8_t>(request->response_buffer.data(), size),
                    request->query_id);
                if (!response) {
                    self->finish_server(request_id);
                    return;
                }
                self->query_completed(request_id, generation, response);
            });
    }

    void query_completed(RequestId request_id, std::uint64_t generation,
                         core::Result<DnsPacket> result) {
        const auto found = requests_.find(request_id);
        if (found == requests_.end() || found->second->generation != generation || stopped_) {
            return;
        }
        const auto request = found->second;
        if (result) {
            const auto answer = DnsMessageCodec::to_address_answer(result.value());
            if (answer && !answer.value().addresses.empty()) {
                for (const auto &address : answer.value().addresses) {
                    if (std::find(request->addresses.begin(), request->addresses.end(), address) ==
                        request->addresses.end()) {
                        request->addresses.push_back(address);
                    }
                }
            }
        }
        if (request->query_index == 0) {
            request->query_index = 1;
            start_query(request_id);
            return;
        }
        if (!request->addresses.empty()) {
            complete(request_id, std::move(request->addresses));
            return;
        }
        finish_server(request_id);
    }

    void finish_server(RequestId request_id) {
        const auto found = requests_.find(request_id);
        if (found == requests_.end() || stopped_) {
            return;
        }
        const auto request = found->second;
        close_socket(*request);
        ++request->server_index;
        start_server(request_id);
    }

    void start_system(RequestId request_id) {
        const auto found = requests_.find(request_id);
        if (found == requests_.end() || stopped_) {
            return;
        }
        const auto request = found->second;
        close_socket(*request);
        if (request->system_request_id != 0) {
            return;
        }
        request->system_request_id = system_resolver_->resolve(
            request->hostname, request->deadline,
            [self = shared_from_this(), request_id](core::Result<std::vector<Address>> result) {
                self->system_completed(request_id, std::move(result));
            });
    }

    void system_completed(RequestId request_id, core::Result<std::vector<Address>> result) {
        const auto found = requests_.find(request_id);
        if (found == requests_.end() || stopped_) {
            return;
        }
        found->second->system_request_id = 0;
        complete(request_id, std::move(result));
    }

    std::uint16_t next_query_id() noexcept {
        auto query_id = next_query_id_++;
        if (query_id == 0) {
            query_id = next_query_id_++;
        }
        return query_id;
    }

    void complete(RequestId request_id, core::Result<std::vector<Address>> result) {
        const auto found = requests_.find(request_id);
        if (found == requests_.end()) {
            return;
        }
        auto request = std::move(found->second);
        requests_.erase(found);
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
