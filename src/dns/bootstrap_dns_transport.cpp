#include <clash_native/async/bridge.hpp>
#include <clash_native/async/held_operation.hpp>
#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/dns/bootstrap_resolver.hpp>
#include <clash_native/dns/dns_transport.hpp>
#include <clash_native/io/sender.hpp>

#include <stdexec/execution.hpp>

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

    io::AnySender<DnsExchangeResult> exchange(DnsExchangeRequest request) override {
        auto box = std::make_shared<std::optional<DnsExchangeRequest>>(std::move(request));
        auto self = shared_from_this();
        return async::bridge_sender<DnsExchangeResult>(
            [self, box](async::BridgeSender<DnsExchangeResult>::Handler done) mutable {
                if (!box || !*box) {
                    done(core::fail(cancelled_error()));
                    using AbortFn = async::BridgeSender<DnsExchangeResult>::AbortFn;
                    return AbortFn{[] {}};
                }
                const auto exchange_id = self->open_exchange(std::move(**box), std::move(done));
                box->reset();
                using AbortFn = async::BridgeSender<DnsExchangeResult>::AbortFn;
                return AbortFn{[self, exchange_id] { self->cancel_exchange(exchange_id); }};
            });
    }

    DnsExchangeId open_exchange(DnsExchangeRequest request,
                                async::BridgeSender<DnsExchangeResult>::Handler handler) {
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

    void cancel_exchange(DnsExchangeId exchange_id) noexcept {
        const auto found = pending_.find(exchange_id);
        if (found == pending_.end()) {
            return;
        }
        const auto pending = found->second;
        if (pending->bootstrap_id != 0) {
            bootstrap_->cancel(pending->bootstrap_id);
        }
        // Complete first so the late inner terminal drops by map lookup,
        // then destroy the op (its abort runs outside its own terminal).
        complete(exchange_id, core::fail(cancelled_error()));
        abort_inner(exchange_id);
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

        std::vector<DnsExchangeId> exchange_ids;
        exchange_ids.reserve(pending_.size());
        for (const auto &[exchange_id, pending] : pending_) {
            exchange_ids.push_back(exchange_id);
        }
        for (const auto exchange_id : exchange_ids) {
            complete(exchange_id, core::fail(cancelled_error()));
        }
        inner_ops_.clear();
    }

  private:
    // Inner drive state, held apart from Pending so terminal delivery
    // never destroys its own operation state: the receiver completes the
    // pending entry, and the op entry is erased (or aborted) separately.
    struct InnerReceiver {
        using receiver_concept = stdexec::receiver_tag;
        std::weak_ptr<BootstrapDnsTransport> transport;
        DnsExchangeId exchange_id;
        void set_value(DnsExchangeResult result) noexcept {
            if (auto self = transport.lock()) {
                self->inner_finished(exchange_id, std::move(result));
            }
        }
        void set_error(std::exception_ptr error) noexcept {
            if (auto self = transport.lock()) {
                try {
                    std::rethrow_exception(std::move(error));
                } catch (const core::Error &failure) {
                    self->inner_finished(exchange_id, core::fail(failure));
                    return;
                } catch (...) {
                }
                self->inner_finished(exchange_id,
                                     core::fail(core::Error{core::ErrorCode::transport_io,
                                                            "bootstrap inner exchange failed"}));
            }
        }
        void set_stopped() noexcept {
            if (auto self = transport.lock()) {
                self->inner_finished(exchange_id, core::fail(cancelled_error()));
            }
        }
    };
    // Connected inner op, heap-held and never moved; destroying it
    // aborts the inner exchange.
    using InnerDrive = async::HeldOperation<io::AnySender<DnsExchangeResult>, InnerReceiver>;

    struct Pending {
        DnsExchangeRequest request;
        async::BridgeSender<DnsExchangeResult>::Handler handler;
        BootstrapResolver::RequestId bootstrap_id = 0;
    };

    void abort_inner(DnsExchangeId exchange_id) {
        const auto found = inner_ops_.find(exchange_id);
        if (found == inner_ops_.end()) {
            return;
        }
        // Erasing destroys the op state outside its own terminal, which
        // runs the bridge aborter and cancels the inner exchange.
        inner_ops_.erase(found);
    }

    void inner_finished(DnsExchangeId exchange_id, DnsExchangeResult result) {
        const auto found = pending_.find(exchange_id);
        if (found == pending_.end()) {
            return;
        }
        // Schedule the op-state cleanup after delivery: complete() may run
        // inside this terminal, so the entry must outlive this call.
        const auto self = shared_from_this();
        runtime_.scheduler().post([self, exchange_id] { self->inner_ops_.erase(exchange_id); });
        complete(exchange_id, std::move(result));
    }

    void bootstrap_completed(DnsExchangeId exchange_id,
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

        // Drive the inner sender with a held op state so cancel aborts
        // exactly this exchange; the terminal routes through
        // inner_finished, which drops late results by map lookup.
        const auto self = shared_from_this();
        // NOTE: name the sender first; argument order is unspecified.
        auto sender = inner_->exchange(std::move(pending->request));
        auto drive = async::hold_operation(std::move(sender), InnerReceiver{self, exchange_id});
        inner_ops_.emplace(exchange_id, std::move(drive));
        inner_ops_[exchange_id]->start();
    }

    void complete(DnsExchangeId exchange_id, core::Result<DnsPacket> result) {
        const auto found = pending_.find(exchange_id);
        if (found == pending_.end()) {
            return;
        }
        auto pending = std::move(found->second);
        pending_.erase(found);
        if (pending->handler) {
            auto handler = std::move(pending->handler);
            runtime_.scheduler().post(
                [handler = std::move(handler), result = std::move(result)]() mutable {
                    handler(std::move(result));
                });
        }
    }

    runtime::AsioRuntime &runtime_;
    DnsUpstreamConfig config_;
    std::shared_ptr<BootstrapResolver> bootstrap_;
    std::shared_ptr<DnsTransport> inner_;
    std::unordered_map<DnsExchangeId, std::shared_ptr<Pending>> pending_;
    std::unordered_map<DnsExchangeId, std::shared_ptr<InnerDrive>> inner_ops_;
    DnsExchangeId next_exchange_id_ = 1;
    bool stopped_ = false;
};

} // namespace

std::shared_ptr<DnsTransport> make_bootstrap_dns_transport(runtime::AsioRuntime &runtime,
                                                           DnsUpstreamConfig config) {
    return std::make_shared<BootstrapDnsTransport>(runtime, std::move(config));
}

} // namespace clash_native::dns
