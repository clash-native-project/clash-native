#include <clash_native/async/detached.hpp>
#include <clash_native/async/oneshot.hpp>
#include <clash_native/dns/bootstrap_resolver.hpp>
#include <clash_native/dns/dns_transport.hpp>
#include <clash_native/io/sender.hpp>

#include <stdexec/execution.hpp>

#include <algorithm>
#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
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

using AddressResult = core::Result<std::vector<boost::asio::ip::address>>;

class BootstrapDnsTransport final : public DnsTransport,
                                    public std::enable_shared_from_this<BootstrapDnsTransport> {
  public:
    struct DriveTerminal {
        DnsExchangeResult result;
    };

    class Operation;

    BootstrapDnsTransport(runtime::AsioRuntime &runtime, DnsUpstreamConfig config);

    io::AnySender<DnsExchangeResult> exchange(DnsExchangeRequest request) override;

    void stop() noexcept override;

  private:
    io::AnySender<DnsExchangeResult> wrap(std::shared_ptr<Operation> operation,
                                          async::oneshot::Receiver<DriveTerminal> receiver);

    void erase(DnsExchangeId exchange_id);

    std::shared_ptr<DnsTransport> inner_for(const boost::asio::ip::address &selected);

    runtime::AsioRuntime &runtime_;
    DnsUpstreamConfig config_;
    std::shared_ptr<BootstrapResolver> bootstrap_;
    std::mutex mutex_;
    std::shared_ptr<DnsTransport> inner_;
    std::unordered_map<DnsExchangeId, std::shared_ptr<Operation>> operations_;
    DnsExchangeId next_exchange_id_ = 1;
    bool stopped_ = false;
};

class BootstrapDnsTransport::Operation final
    : public std::enable_shared_from_this<BootstrapDnsTransport::Operation> {
  public:
    Operation(BootstrapDnsTransport &owner, DnsExchangeId exchange_id, DnsExchangeRequest request,
              async::oneshot::Sender<DriveTerminal> terminal)
        : owner_(owner), exchange_id_(exchange_id), request_(std::move(request)),
          terminal_(std::move(terminal)) {}

    ~Operation() {
        // Best effort: an abandoned operation (receiver destroyed without
        // stop) still aborts its bootstrap resolve and wakes its awaits.
        // Detached task: no stop to request; the late terminal drops on
        // the completed_ guard.
        cancel_bootstrap();
    }

    void start() { async::spawn_detached(run(shared_from_this())); }

    void cancel() {
        if (completed_.exchange(true, std::memory_order_acq_rel)) {
            return;
        }
        cancel_bootstrap();
        terminal_.send(DriveTerminal{core::fail(cancelled_error())});
    }

  private:
    // Straight-line chain: bootstrap resolve, address select, inner exchange.
    // Every terminal funnels through finish(), so the spawned task always
    // ends with a value.
    static stdexec::task<void> run(std::shared_ptr<Operation> self) {
        auto channel = async::oneshot::channel<AddressResult>();
        auto sender =
            std::make_shared<async::oneshot::Sender<AddressResult>>(std::move(channel.sender));
        BootstrapResolver::RequestId bootstrap_id = 0;
        try {
            bootstrap_id = self->owner_.bootstrap_->resolve(
                self->owner_.config_.hostname, self->request_.deadline,
                [sender](AddressResult result) mutable { sender->send(std::move(result)); });
        } catch (...) {
            self->finish(core::fail(
                core::Error{core::ErrorCode::transport_io, "DNS bootstrap resolution failed"}));
            co_return;
        }
        self->bootstrap_id_.store(bootstrap_id, std::memory_order_release);
        if (self->completed_.load(std::memory_order_acquire)) {
            co_return;
        }
        auto outcome = co_await (
            std::move(channel.receiver) |
            stdexec::then([](std::optional<AddressResult> terminal) { return terminal; }) |
            stdexec::let_stopped([] { return stdexec::just(std::optional<AddressResult>()); }));
        self->bootstrap_id_.store(0, std::memory_order_release);
        if (!outcome || self->completed_.load(std::memory_order_acquire)) {
            co_return;
        }
        if (!*outcome) {
            self->finish(core::fail(outcome->error()));
            co_return;
        }
        const auto endpoint_address = self->owner_.config_.endpoint.address();
        const auto selected = std::find_if(
            outcome->value().begin(), outcome->value().end(), [&](const auto &address) {
                return address_matches_endpoint_family(address, endpoint_address);
            });
        if (selected == outcome->value().end()) {
            self->finish(core::fail(resolution_error()));
            co_return;
        }
        auto inner = self->owner_.inner_for(*selected);
        if (self->completed_.load(std::memory_order_acquire)) {
            co_return;
        }
        std::optional<DnsExchangeResult> inner_result;
        try {
            inner_result = co_await (inner->exchange(std::move(self->request_)) |
                                     stdexec::then([](DnsExchangeResult result) {
                                         return std::optional<DnsExchangeResult>(std::move(result));
                                     }) |
                                     stdexec::let_stopped([] {
                                         return stdexec::just(std::optional<DnsExchangeResult>());
                                     }));
        } catch (const core::Error &failure) {
            self->finish(core::fail(failure));
            co_return;
        } catch (...) {
            self->finish(core::fail(
                core::Error{core::ErrorCode::transport_io, "DNS bootstrap inner exchange failed"}));
            co_return;
        }
        if (!inner_result || self->completed_.load(std::memory_order_acquire)) {
            co_return;
        }
        self->finish(std::move(*inner_result));
        co_return;
    }

    void finish(DnsExchangeResult result) {
        if (completed_.exchange(true, std::memory_order_acq_rel)) {
            return;
        }
        cancel_bootstrap();
        owner_.erase(exchange_id_);
        terminal_.send(DriveTerminal{std::move(result)});
    }

    void cancel_bootstrap() noexcept {
        const auto bootstrap_id = bootstrap_id_.exchange(0, std::memory_order_acq_rel);
        if (bootstrap_id != 0) {
            try {
                owner_.bootstrap_->cancel(bootstrap_id);
            } catch (...) {
            }
        }
    }

    BootstrapDnsTransport &owner_;
    DnsExchangeId exchange_id_;
    DnsExchangeRequest request_;
    async::oneshot::Sender<DriveTerminal> terminal_;
    std::atomic_bool completed_{false};
    std::atomic<BootstrapResolver::RequestId> bootstrap_id_{0};
    // Detached resolve/exchange chain task, which always ends with a value.
};

BootstrapDnsTransport::BootstrapDnsTransport(runtime::AsioRuntime &runtime,
                                             DnsUpstreamConfig config)
    : runtime_(runtime), config_(std::move(config)),
      bootstrap_(config_.bootstrap_resolver
                     ? config_.bootstrap_resolver
                     : make_bootstrap_resolver(runtime_, config_.bootstrap_dns_servers)) {}

io::AnySender<DnsExchangeResult> BootstrapDnsTransport::exchange(DnsExchangeRequest request) {
    std::lock_guard lock(mutex_);
    if (stopped_) {
        return io::AnySender<DnsExchangeResult>{stdexec::just(core::fail(cancelled_error()))};
    }
    const auto exchange_id = next_exchange_id_++;
    auto channel = async::oneshot::channel<DriveTerminal>();
    auto operation = std::make_shared<Operation>(*this, exchange_id, std::move(request),
                                                 std::move(channel.sender));
    operations_.emplace(exchange_id, operation);
    // NOTE: name the sender first; argument order is unspecified.
    auto sender = wrap(operation, std::move(channel.receiver));
    operation->start();
    return sender;
}

void BootstrapDnsTransport::stop() noexcept {
    std::vector<std::shared_ptr<Operation>> operations;
    {
        std::lock_guard lock(mutex_);
        if (stopped_) {
            return;
        }
        stopped_ = true;
        operations.reserve(operations_.size());
        for (const auto &[exchange_id, operation] : operations_) {
            (void)exchange_id;
            operations.push_back(operation);
        }
    }
    bootstrap_->stop();
    std::shared_ptr<DnsTransport> inner;
    {
        std::lock_guard lock(mutex_);
        inner = inner_;
    }
    if (inner) {
        inner->stop();
    }
    for (const auto &operation : operations) {
        operation->cancel();
    }
}

io::AnySender<DnsExchangeResult>
BootstrapDnsTransport::wrap(std::shared_ptr<Operation> operation,
                            async::oneshot::Receiver<DriveTerminal> receiver) {
    auto sender = std::move(receiver) |
                  stdexec::then([](std::optional<DriveTerminal> terminal) -> DnsExchangeResult {
                      if (!terminal) {
                          throw core::Error{core::ErrorCode::cancelled,
                                            "DNS bootstrap exchange was abandoned"};
                      }
                      return std::move(terminal->result);
                  }) |
                  stdexec::let_stopped([operation] {
                      operation->cancel();
                      return stdexec::just_stopped();
                  });
    return io::AnySender<DnsExchangeResult>{std::move(sender)};
}

void BootstrapDnsTransport::erase(DnsExchangeId exchange_id) {
    std::lock_guard lock(mutex_);
    operations_.erase(exchange_id);
}

std::shared_ptr<DnsTransport>
BootstrapDnsTransport::inner_for(const boost::asio::ip::address &selected) {
    std::lock_guard lock(mutex_);
    if (!inner_) {
        auto resolved_config = config_;
        resolved_config.hostname.clear();
        resolved_config.bootstrap_resolver.reset();
        resolved_config.endpoint =
            boost::asio::ip::udp::endpoint(selected, config_.endpoint.port());
        if (resolved_config.tcp_endpoint &&
            resolved_config.tcp_endpoint->address().is_unspecified()) {
            resolved_config.tcp_endpoint =
                boost::asio::ip::tcp::endpoint(selected, resolved_config.tcp_endpoint->port());
        }
        if (resolved_config.fallback_endpoint &&
            resolved_config.fallback_endpoint->address().is_unspecified()) {
            resolved_config.fallback_endpoint =
                boost::asio::ip::udp::endpoint(selected, resolved_config.fallback_endpoint->port());
        }
        if (resolved_config.fallback_tcp_endpoint &&
            resolved_config.fallback_tcp_endpoint->address().is_unspecified()) {
            resolved_config.fallback_tcp_endpoint = boost::asio::ip::tcp::endpoint(
                selected, resolved_config.fallback_tcp_endpoint->port());
        }
        inner_ = make_asio_dns_transport(runtime_, std::move(resolved_config));
    }
    return inner_;
}

} // namespace

std::shared_ptr<DnsTransport> make_bootstrap_dns_transport(runtime::AsioRuntime &runtime,
                                                           DnsUpstreamConfig config) {
    return std::make_shared<BootstrapDnsTransport>(runtime, std::move(config));
}

} // namespace clash_native::dns
