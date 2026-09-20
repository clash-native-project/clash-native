#include <clash_native/dns/dns_upstream.hpp>

#include <boost/asio/post.hpp>

#include <algorithm>
#include <utility>

namespace clash_native::dns {

namespace {

constexpr auto kHealthBackoffBase = std::chrono::milliseconds(250);
constexpr auto kHealthBackoffMaximum = std::chrono::seconds(30);

core::Error configuration_error() {
    return {core::ErrorCode::configuration, "DNS upstream transport is not available"};
}

bool should_retry_response(const DnsPacket &packet) noexcept {
    return packet.response_code() == 2 || packet.response_code() == 5;
}

} // namespace

DnsUpstream::DnsUpstream(runtime::AsioRuntime &runtime, DnsUpstreamConfig config,
                         DnsTransportFactory transport_factory)
    : runtime_(runtime), timeout_(config.timeout) {
    if (transport_factory) {
        transport_ = transport_factory(runtime_, std::move(config));
    }
}

std::chrono::milliseconds DnsUpstream::timeout() const noexcept { return timeout_; }

DnsUpstream::~DnsUpstream() { stop(); }

DnsTransport::ExchangeId DnsUpstream::exchange(DnsPacket query,
                                               std::chrono::steady_clock::time_point deadline,
                                               DnsTransport::Handler handler) {
    if (!transport_) {
        boost::asio::post(runtime_.context(), [handler = std::move(handler)]() mutable {
            handler(core::fail(configuration_error()));
        });
        return 0;
    }
    return transport_->exchange({std::move(query), deadline}, std::move(handler));
}

void DnsUpstream::cancel(DnsTransport::ExchangeId exchange_id) noexcept {
    if (transport_) {
        transport_->cancel(exchange_id);
    }
}

void DnsUpstream::stop() noexcept {
    if (transport_) {
        transport_->stop();
    }
}

class DnsUpstreamGroup::Operation final
    : public std::enable_shared_from_this<DnsUpstreamGroup::Operation> {
  public:
    Operation(DnsUpstreamGroup &owner, DnsTransport::ExchangeId exchange_id, DnsPacket query,
              std::chrono::steady_clock::time_point deadline, DnsTransport::Handler handler)
        : owner_(owner), exchange_id_(exchange_id), query_(std::move(query)), deadline_(deadline),
          handler_(std::move(handler)) {}

    void start() {
        if (owner_.members_.empty()) {
            finish(core::fail(
                {core::ErrorCode::configuration, "DNS upstream group has no configured members"}));
            return;
        }
        attempted_.assign(owner_.members_.size(), false);
        start_member(owner_.next_start_index());
    }

    void cancel() {
        if (completed_) {
            return;
        }
        completed_ = true;
        if (current_member_ && current_exchange_started_) {
            current_member_->cancel(current_exchange_id_);
        }
        owner_.complete(exchange_id_, core::fail({core::ErrorCode::cancelled,
                                                  "DNS upstream group exchange was cancelled"}));
    }

    DnsTransport::Handler take_handler() { return std::move(handler_); }

  private:
    void start_member(std::size_t index) {
        if (completed_) {
            return;
        }
        if (std::chrono::steady_clock::now() >= deadline_) {
            finish(core::fail({core::ErrorCode::timeout, "DNS upstream group timed out"}));
            return;
        }

        const auto selected = owner_.select_member(index, attempted_);
        if (!selected) {
            if (last_error_) {
                finish(core::fail(*last_error_));
            } else {
                finish(core::fail({core::ErrorCode::configuration,
                                   "DNS upstream group has no available members"}));
            }
            return;
        }

        current_index_ = *selected;
        attempted_[current_index_] = true;
        current_member_ = owner_.members_[current_index_];
        current_exchange_started_ = false;
        const auto now = std::chrono::steady_clock::now();
        const auto remaining = deadline_ - now;
        const auto remaining_members = std::count(attempted_.begin(), attempted_.end(), false);
        auto member_deadline = deadline_;
        const auto remaining_attempts = remaining_members + 1;
        if (remaining_attempts > 1 && remaining > std::chrono::steady_clock::duration::zero()) {
            member_deadline = now + remaining / remaining_attempts;
        }
        auto self = shared_from_this();
        current_exchange_id_ = current_member_->exchange(
            query_, member_deadline,
            [self, member_index = current_index_](core::Result<DnsPacket> result) {
                self->member_finished(member_index, std::move(result));
            });
        current_exchange_started_ = true;
        if (completed_) {
            current_member_->cancel(current_exchange_id_);
        }
    }

    void member_finished(std::size_t index, core::Result<DnsPacket> result) {
        if (completed_ || index != current_index_) {
            return;
        }
        current_exchange_started_ = false;
        if (result) {
            if (!should_retry_response(result.value())) {
                owner_.record_success(index);
                finish(std::move(result));
                return;
            }
            last_error_ = core::Error{core::ErrorCode::resolution,
                                      "DNS upstream returned a retryable response"};
            owner_.record_failure(index, *last_error_);
            const auto next = (index + 1) % owner_.members_.size();
            if (std::chrono::steady_clock::now() < deadline_ &&
                std::any_of(attempted_.begin(), attempted_.end(),
                            [](bool attempted) { return !attempted; })) {
                start_member(next);
                return;
            }
            finish(std::move(result));
            return;
        }
        last_error_ = result.error();
        if (result.error().code != core::ErrorCode::cancelled) {
            owner_.record_failure(index, result.error());
        }
        const auto next = (index + 1) % owner_.members_.size();
        if (std::chrono::steady_clock::now() < deadline_) {
            start_member(next);
            return;
        }
        finish(std::move(result));
    }

    void finish(core::Result<DnsPacket> result) {
        if (completed_) {
            return;
        }
        completed_ = true;
        owner_.complete(exchange_id_, std::move(result));
    }

    DnsUpstreamGroup &owner_;
    DnsTransport::ExchangeId exchange_id_;
    DnsPacket query_;
    std::chrono::steady_clock::time_point deadline_;
    DnsTransport::Handler handler_;
    std::shared_ptr<DnsUpstream> current_member_;
    DnsTransport::ExchangeId current_exchange_id_ = 0;
    std::size_t current_index_ = 0;
    bool current_exchange_started_ = false;
    bool completed_ = false;
    std::vector<bool> attempted_;
    std::optional<core::Error> last_error_;
};

DnsUpstreamGroup::DnsUpstreamGroup(runtime::AsioRuntime &runtime, DnsUpstreamGroupConfig config,
                                   DnsTransportFactory transport_factory)
    : runtime_(runtime), selection_(config.selection), timeout_(config.timeout) {
    if (config.members.empty()) {
        return;
    }
    std::vector<DnsUpstreamConfig> expanded_members;
    expanded_members.reserve(config.members.size() * 2);
    for (auto &member : config.members) {
        const auto fallback_endpoint = member.fallback_endpoint;
        const auto fallback_tcp_endpoint = member.fallback_tcp_endpoint;
        member.fallback_endpoint.reset();
        member.fallback_tcp_endpoint.reset();
        expanded_members.push_back(member);
        if (fallback_endpoint) {
            DnsUpstreamConfig fallback;
            fallback.endpoint = *fallback_endpoint;
            fallback.timeout = member.timeout;
            fallback.tcp_endpoint = fallback_tcp_endpoint;
            fallback.prefer_tcp = member.prefer_tcp;
            fallback.mode = member.mode;
            fallback.server_name = member.server_name;
            fallback.verify_peer = member.verify_peer;
            fallback.doh_path = member.doh_path;
            fallback.doh_authority = member.doh_authority;
            fallback.dial_policy = member.dial_policy;
            fallback.dialer = member.dialer;
            fallback.bootstrap_dns_servers = member.bootstrap_dns_servers;
            expanded_members.push_back(std::move(fallback));
        }
    }
    if (timeout_.count() <= 0) {
        timeout_ = std::max_element(expanded_members.begin(), expanded_members.end(),
                                    [](const auto &left, const auto &right) {
                                        return left.timeout < right.timeout;
                                    })
                       ->timeout;
    }
    members_.reserve(expanded_members.size());
    for (auto &member : expanded_members) {
        members_.push_back(
            std::make_shared<DnsUpstream>(runtime_, std::move(member), transport_factory));
    }
    member_health_.resize(members_.size());
}

DnsUpstreamGroup::~DnsUpstreamGroup() { stop(); }

std::chrono::milliseconds DnsUpstreamGroup::timeout() const noexcept { return timeout_; }

std::size_t DnsUpstreamGroup::next_start_index() noexcept {
    if (selection_ != DnsUpstreamSelection::round_robin || members_.empty()) {
        return 0;
    }
    return next_member_.fetch_add(1, std::memory_order_relaxed) % members_.size();
}

std::optional<std::size_t>
DnsUpstreamGroup::select_member(std::size_t start_index, const std::vector<bool> &attempted) const {
    if (members_.empty()) {
        return std::nullopt;
    }

    const auto now = std::chrono::steady_clock::now();
    const auto normalized_start = start_index % members_.size();
    for (std::size_t offset = 0; offset < members_.size(); ++offset) {
        const auto index = (normalized_start + offset) % members_.size();
        if (!attempted[index] && member_health_[index].unhealthy_until <= now) {
            return index;
        }
    }

    // If every non-attempted member is in backoff, probe one member instead of
    // turning a temporary outage into a permanent failure.
    for (std::size_t offset = 0; offset < members_.size(); ++offset) {
        const auto index = (normalized_start + offset) % members_.size();
        if (!attempted[index]) {
            return index;
        }
    }
    return std::nullopt;
}

void DnsUpstreamGroup::record_failure(std::size_t member_index, const core::Error &error) {
    if (member_index >= member_health_.size() || error.code == core::ErrorCode::cancelled) {
        return;
    }

    auto &health = member_health_[member_index];
    health.consecutive_failures = std::min<std::size_t>(health.consecutive_failures + 1, 8);
    const auto multiplier = std::size_t{1} << (health.consecutive_failures - 1);
    const auto maximum =
        std::chrono::duration_cast<std::chrono::milliseconds>(kHealthBackoffMaximum);
    const auto backoff = std::min(maximum, kHealthBackoffBase * static_cast<int>(multiplier));
    health.unhealthy_until = std::chrono::steady_clock::now() + backoff;
}

void DnsUpstreamGroup::record_success(std::size_t member_index) noexcept {
    if (member_index >= member_health_.size()) {
        return;
    }
    member_health_[member_index] = {};
}

DnsTransport::ExchangeId DnsUpstreamGroup::exchange(DnsPacket query,
                                                    std::chrono::steady_clock::time_point deadline,
                                                    DnsTransport::Handler handler) {
    const auto exchange_id = next_exchange_id_++;
    auto operation = std::make_shared<Operation>(*this, exchange_id, std::move(query), deadline,
                                                 std::move(handler));
    operations_.emplace(exchange_id, operation);
    if (stopped_) {
        operation->cancel();
    } else {
        operation->start();
    }
    return exchange_id;
}

void DnsUpstreamGroup::cancel(DnsTransport::ExchangeId exchange_id) noexcept {
    const auto operation = operations_.find(exchange_id);
    if (operation != operations_.end()) {
        operation->second->cancel();
    }
}

void DnsUpstreamGroup::stop() noexcept {
    if (stopped_) {
        return;
    }
    stopped_ = true;
    while (!operations_.empty()) {
        operations_.begin()->second->cancel();
    }
    for (const auto &member : members_) {
        member->stop();
    }
}

void DnsUpstreamGroup::complete(DnsTransport::ExchangeId exchange_id,
                                core::Result<DnsPacket> result) {
    const auto operation = operations_.find(exchange_id);
    if (operation == operations_.end()) {
        return;
    }
    auto current = std::move(operation->second);
    operations_.erase(operation);
    auto handler = current->take_handler();
    if (handler) {
        handler(std::move(result));
    }
}

} // namespace clash_native::dns
