#include <clash_native/dns/bootstrap_resolver.hpp>
#include <clash_native/dns/dns_transport.hpp>

#include <boost/asio/post.hpp>

#include <algorithm>
#include <unordered_map>
#include <utility>
#include <vector>

namespace clash_native::dns {

namespace {

core::Error cancelled_error() {
    return {core::ErrorCode::cancelled, "DNS bootstrap transport was cancelled"};
}

core::Error resolution_error() {
    return {core::ErrorCode::resolution, "DNS bootstrap transport returned no usable address"};
}

bool address_matches_endpoint_family(const boost::asio::ip::address &address,
                                     const boost::asio::ip::address &endpoint_address) {
    if (endpoint_address.is_unspecified()) {
        return address.is_v4() == endpoint_address.is_v4();
    }
    return address == endpoint_address;
}

class BootstrapDnsTransport final : public DnsTransport,
                                    public std::enable_shared_from_this<BootstrapDnsTransport> {
  public:
    BootstrapDnsTransport(runtime::AsioRuntime &runtime, DnsUpstreamConfig config)
        : runtime_(runtime), config_(std::move(config)),
          bootstrap_(config_.bootstrap_resolver
                         ? config_.bootstrap_resolver
                         : make_bootstrap_resolver(runtime_, config_.bootstrap_dns_servers)) {}

    ExchangeId exchange(DnsExchangeRequest request, Handler handler) override {
        const auto exchange_id = next_exchange_id_++;
        auto pending = std::make_shared<Pending>();
        pending->request = std::move(request);
        pending->handler = std::move(handler);
        pending_.emplace(exchange_id, pending);
        if (stopped_) {
            complete(exchange_id, core::fail(cancelled_error()));
            return exchange_id;
        }

        const auto self = shared_from_this();
        pending->bootstrap_id = bootstrap_->resolve(
            config_.hostname, pending->request.deadline,
            [self, exchange_id](core::Result<std::vector<boost::asio::ip::address>> result) {
                self->bootstrap_completed(exchange_id, std::move(result));
            });
        return exchange_id;
    }

    void cancel(ExchangeId exchange_id) noexcept override {
        const auto found = pending_.find(exchange_id);
        if (found == pending_.end()) {
            return;
        }
        const auto pending = found->second;
        if (pending->bootstrap_id != 0) {
            bootstrap_->cancel(pending->bootstrap_id);
        }
        if (pending->inner_id != 0 && inner_) {
            inner_->cancel(pending->inner_id);
        }
        complete(exchange_id, core::fail(cancelled_error()));
    }

    void stop() noexcept override {
        if (stopped_) {
            return;
        }
        stopped_ = true;
        bootstrap_->stop();
        if (inner_) {
            inner_->stop();
        }

        std::vector<ExchangeId> exchange_ids;
        exchange_ids.reserve(pending_.size());
        for (const auto &[exchange_id, pending] : pending_) {
            exchange_ids.push_back(exchange_id);
        }
        for (const auto exchange_id : exchange_ids) {
            complete(exchange_id, core::fail(cancelled_error()));
        }
    }

  private:
    struct Pending {
        DnsExchangeRequest request;
        Handler handler;
        BootstrapResolver::RequestId bootstrap_id = 0;
        DnsTransport::ExchangeId inner_id = 0;
    };

    void bootstrap_completed(ExchangeId exchange_id,
                             core::Result<std::vector<boost::asio::ip::address>> result) {
        const auto found = pending_.find(exchange_id);
        if (found == pending_.end() || stopped_) {
            return;
        }
        const auto pending = found->second;
        pending->bootstrap_id = 0;
        if (!result) {
            complete(exchange_id, core::fail(result.error()));
            return;
        }

        const auto endpoint_address = config_.endpoint.address();
        const auto selected =
            std::find_if(result.value().begin(), result.value().end(), [&](const auto &address) {
                return address_matches_endpoint_family(address, endpoint_address);
            });
        if (selected == result.value().end()) {
            complete(exchange_id, core::fail(resolution_error()));
            return;
        }

        if (!inner_) {
            auto resolved_config = config_;
            resolved_config.hostname.clear();
            resolved_config.bootstrap_resolver.reset();
            resolved_config.endpoint =
                boost::asio::ip::udp::endpoint(*selected, config_.endpoint.port());
            if (resolved_config.tcp_endpoint &&
                resolved_config.tcp_endpoint->address().is_unspecified()) {
                resolved_config.tcp_endpoint =
                    boost::asio::ip::tcp::endpoint(*selected, resolved_config.tcp_endpoint->port());
            }
            if (resolved_config.fallback_endpoint &&
                resolved_config.fallback_endpoint->address().is_unspecified()) {
                resolved_config.fallback_endpoint = boost::asio::ip::udp::endpoint(
                    *selected, resolved_config.fallback_endpoint->port());
            }
            if (resolved_config.fallback_tcp_endpoint &&
                resolved_config.fallback_tcp_endpoint->address().is_unspecified()) {
                resolved_config.fallback_tcp_endpoint = boost::asio::ip::tcp::endpoint(
                    *selected, resolved_config.fallback_tcp_endpoint->port());
            }
            inner_ = make_asio_dns_transport(runtime_, std::move(resolved_config));
        }

        const auto self = shared_from_this();
        pending->inner_id = inner_->exchange(
            std::move(pending->request), [self, exchange_id](core::Result<DnsPacket> inner_result) {
                self->complete(exchange_id, std::move(inner_result));
            });
    }

    void complete(ExchangeId exchange_id, core::Result<DnsPacket> result) {
        const auto found = pending_.find(exchange_id);
        if (found == pending_.end()) {
            return;
        }
        auto pending = std::move(found->second);
        pending_.erase(found);
        if (pending->handler) {
            auto handler = std::move(pending->handler);
            boost::asio::post(runtime_.context(),
                              [handler = std::move(handler), result = std::move(result)]() mutable {
                                  handler(std::move(result));
                              });
        }
    }

    runtime::AsioRuntime &runtime_;
    DnsUpstreamConfig config_;
    std::shared_ptr<BootstrapResolver> bootstrap_;
    std::shared_ptr<DnsTransport> inner_;
    std::unordered_map<ExchangeId, std::shared_ptr<Pending>> pending_;
    ExchangeId next_exchange_id_ = 1;
    bool stopped_ = false;
};

} // namespace

std::shared_ptr<DnsTransport> make_bootstrap_dns_transport(runtime::AsioRuntime &runtime,
                                                           DnsUpstreamConfig config) {
    return std::make_shared<BootstrapDnsTransport>(runtime, std::move(config));
}

} // namespace clash_native::dns
