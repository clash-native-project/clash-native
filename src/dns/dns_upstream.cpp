#include <clash_native/async/bridge.hpp>
#include <clash_native/async/held_operation.hpp>
#include <clash_native/dns/dns_upstream.hpp>
#include <clash_native/io/sender.hpp>

#include <stdexec/execution.hpp>

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

// Drives one transport sender behind the upstream sender edge, hopping
// the terminal onto the runtime scheduler like the old contract. The
// held drive is destroyed on abort, cancelling exactly this exchange.
struct DriveReceiver {
    using receiver_concept = stdexec::receiver_tag;
    runtime::AsioRuntime *runtime;
    async::BridgeSender<DnsExchangeResult>::Handler done;
    void set_value(DnsExchangeResult result) noexcept {
        auto terminal = std::move(done);
        runtime->scheduler().post(
            [terminal = std::move(terminal), result = std::move(result)]() mutable {
                terminal(std::move(result));
            });
    }
    void set_error(std::exception_ptr error) noexcept {
        auto terminal = std::move(done);
        DnsExchangeResult result;
        try {
            std::rethrow_exception(std::move(error));
        } catch (const core::Error &failure) {
            result = core::fail(failure);
        } catch (...) {
            result = core::fail(
                core::Error{core::ErrorCode::transport_io, "DNS upstream exchange failed"});
        }
        runtime->scheduler().post(
            [terminal = std::move(terminal), result = std::move(result)]() mutable {
                terminal(std::move(result));
            });
    }
    void set_stopped() noexcept {
        auto terminal = std::move(done);
        runtime->scheduler().post([terminal = std::move(terminal)]() mutable {
            terminal(core::fail(
                core::Error{core::ErrorCode::cancelled, "DNS upstream exchange cancelled"}));
        });
    }
};

io::AnySender<DnsExchangeResult>
DnsUpstream::exchange(DnsPacket query, std::chrono::steady_clock::time_point deadline) {
    if (!transport_) {
        return io::AnySender<DnsExchangeResult>{stdexec::just(core::fail(configuration_error()))};
    }
    struct Shared {
        std::shared_ptr<async::HeldOperation<io::AnySender<DnsExchangeResult>, DriveReceiver>>
            drive;
    };
    auto shared = std::make_shared<Shared>();
    auto transport = transport_;
    auto *runtime = &runtime_;
    return async::bridge_sender<DnsExchangeResult>(
        [shared, transport, runtime, query = std::move(query),
         deadline](async::BridgeSender<DnsExchangeResult>::Handler done) mutable {
            // NOTE: name the sender first; argument order is unspecified.
            auto sender = transport->exchange({std::move(query), deadline});
            shared->drive =
                async::hold_operation(std::move(sender), DriveReceiver{runtime, std::move(done)});
            shared->drive->start();
            using AbortFn = async::BridgeSender<DnsExchangeResult>::AbortFn;
            return AbortFn{[shared] { shared->drive.reset(); }};
        });
}

void DnsUpstream::stop() noexcept {
    if (transport_) {
        transport_->stop();
    }
}

class DnsUpstreamGroup::Operation final
    : public std::enable_shared_from_this<DnsUpstreamGroup::Operation> {
  public:
    using MemberTerminal = async::BridgeSender<DnsExchangeResult>::Handler;
    struct MemberReceiver {
        using receiver_concept = stdexec::receiver_tag;
        std::shared_ptr<Operation> operation;
        std::size_t member_index;
        void set_value(DnsExchangeResult result) noexcept {
            auto self = std::move(operation);
            self->member_finished(member_index, std::move(result));
        }
        void set_error(std::exception_ptr error) noexcept {
            auto self = std::move(operation);
            try {
                std::rethrow_exception(std::move(error));
            } catch (const core::Error &failure) {
                self->member_finished(member_index, core::fail(failure));
                return;
            } catch (...) {
            }
            self->member_finished(member_index,
                                  core::fail(core::Error{core::ErrorCode::transport_io,
                                                         "DNS group member exchange failed"}));
        }
        void set_stopped() noexcept {
            auto self = std::move(operation);
            self->member_finished(member_index,
                                  core::fail(core::Error{core::ErrorCode::cancelled,
                                                         "DNS group member exchange cancelled"}));
        }
    };
    using MemberDrive = async::HeldOperation<io::AnySender<DnsExchangeResult>, MemberReceiver>;
    Operation(DnsUpstreamGroup &owner, DnsPacket query,
              std::chrono::steady_clock::time_point deadline, MemberTerminal handler)
        : owner_(owner), query_(std::move(query)), deadline_(deadline),
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
        // Destroying the drive aborts exactly the in-flight member
        // exchange; its late terminal drops on the completed_ guard.
        // finish() below marks completed, leaves the set, and delivers.
        drive_.reset();
        current_member_.reset();
        finish(
            core::fail({core::ErrorCode::cancelled, "DNS upstream group exchange was cancelled"}));
    }

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
        // NOTE: name the sender first; argument order is unspecified.
        auto sender = current_member_->exchange(query_, member_deadline);
        drive_ = async::hold_operation(std::move(sender), MemberReceiver{self, current_index_});
        drive_->start();
        current_exchange_started_ = true;
        if (completed_) {
            drive_.reset();
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
        // Drop the member drive first so no late terminal can reenter,
        // then leave the owner set and deliver.
        drive_.reset();
        current_member_.reset();
        auto handler = std::move(handler_);
        owner_.forget(this);
        if (handler) {
            handler(std::move(result));
        }
    }

    DnsUpstreamGroup &owner_;
    DnsPacket query_;
    std::chrono::steady_clock::time_point deadline_;
    MemberTerminal handler_;
    std::shared_ptr<DnsUpstream> current_member_;
    std::shared_ptr<MemberDrive> drive_;
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

io::AnySender<DnsExchangeResult>
DnsUpstreamGroup::exchange(DnsPacket query, std::chrono::steady_clock::time_point deadline) {
    auto self = shared_from_this();
    return async::bridge_sender<DnsExchangeResult>(
        [self, query = std::move(query),
         deadline](async::BridgeSender<DnsExchangeResult>::Handler done) mutable {
            auto operation =
                std::make_shared<Operation>(*self, std::move(query), deadline, std::move(done));
            self->operations_.insert(operation);
            if (self->stopped_) {
                operation->cancel();
            } else {
                operation->start();
            }
            using AbortFn = async::BridgeSender<DnsExchangeResult>::AbortFn;
            return AbortFn{[self, operation] {
                self->operations_.erase(operation);
                operation->cancel();
            }};
        });
}

void DnsUpstreamGroup::forget(Operation *operation) noexcept {
    for (auto it = operations_.begin(); it != operations_.end(); ++it) {
        if (it->get() == operation) {
            operations_.erase(it);
            return;
        }
    }
}

void DnsUpstreamGroup::stop() noexcept {
    if (stopped_) {
        return;
    }
    stopped_ = true;
    std::vector<std::shared_ptr<Operation>> operations;
    operations.reserve(operations_.size());
    for (const auto &operation : operations_) {
        operations.push_back(operation);
    }
    operations_.clear();
    for (const auto &operation : operations) {
        operation->cancel();
    }
    for (const auto &member : members_) {
        member->stop();
    }
}

} // namespace clash_native::dns
