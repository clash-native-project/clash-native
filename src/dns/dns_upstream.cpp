#include <clash_native/async/callback_sender.hpp>
#include <clash_native/dns/dns_upstream.hpp>
#include <clash_native/io/sender.hpp>

#include <exec/async_scope.hpp>
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

// Drives one transport sender behind the upstream sender edge through a
// scope-owned task: co_await the transport sender, then hop the terminal
// onto the runtime scheduler like the old contract. The scope (on the
// shared abort state) is request_stop()ed on abort, cancelling exactly
// this exchange; the late task terminal drops on the settled guard.
struct DriveShared : public std::enable_shared_from_this<DriveShared> {
    runtime::AsioRuntime *runtime = nullptr;
    std::optional<io::AnySender<DnsExchangeResult>> sender;
    async::BridgeHandler<DnsExchangeResult> done;
    exec::async_scope scope;
    std::atomic_bool settled{false};

    static stdexec::task<void> run(std::shared_ptr<DriveShared> self) {
        DnsExchangeResult result =
            core::fail(core::Error{core::ErrorCode::cancelled, "DNS upstream exchange cancelled"});
        try {
            auto sender = std::move(*self->sender) | stdexec::stopped_as_optional();
            auto outcome = co_await std::move(sender);
            if (outcome) {
                result = std::move(*outcome);
            }
        } catch (const core::Error &failure) {
            result = core::fail(failure);
        } catch (...) {
            try {
                std::rethrow_exception(std::current_exception());
            } catch (const core::Error &failure) {
                result = core::fail(failure);
            } catch (...) {
                result = core::fail(
                    core::Error{core::ErrorCode::transport_io, "DNS upstream exchange failed"});
            }
        }
        if (self->settled.exchange(true, std::memory_order_acq_rel)) {
            co_return;
        }
        auto *runtime = self->runtime;
        auto terminal = std::move(self->done);
        runtime->scheduler().post(
            [terminal = std::move(terminal), result = std::move(result)]() mutable {
                terminal(std::move(result));
            });
        co_return;
    }
};

io::AnySender<DnsExchangeResult>
DnsUpstream::exchange(DnsPacket query, std::chrono::steady_clock::time_point deadline) {
    if (!transport_) {
        return io::AnySender<DnsExchangeResult>{stdexec::just(core::fail(configuration_error()))};
    }
    using Signatures = async::BridgeSignatures<DnsExchangeResult>;
    auto shared = std::make_shared<DriveShared>();
    shared->runtime = &runtime_;
    shared->sender = transport_->exchange({std::move(query), deadline});
    return async::callback_sender<Signatures>(
        [shared](auto terminal) mutable -> async::CallbackAbortFn {
            shared->done = [terminal = std::move(terminal)](DnsExchangeResult result) mutable {
                terminal(std::move(result));
            };
            shared->scope.spawn(DriveShared::run(shared));
            return async::CallbackAbortFn{[shared] {
                if (!shared->settled.exchange(true, std::memory_order_acq_rel)) {
                    try {
                        shared->scope.request_stop();
                    } catch (...) {
                    }
                }
            }};
        },
        async::BridgeTranslate<DnsExchangeResult>{});
}

void DnsUpstream::stop() noexcept {
    if (transport_) {
        transport_->stop();
    }
}

class DnsUpstreamGroup::Operation final
    : public std::enable_shared_from_this<DnsUpstreamGroup::Operation> {
  public:
    using MemberTerminal = async::BridgeHandler<DnsExchangeResult>;
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
        // Sequential member retry as one task: co_await each member
        // sender in turn, falling through to the next member on failure
        // or retryable response. Stop aborts the in-flight await via the
        // scope; the task always ends with a value and finish() drops
        // late terminals on the completed_ guard.
        member_scope_.spawn(run(shared_from_this(), owner_.next_start_index()));
    }

    void cancel() {
        if (completed_) {
            return;
        }
        // Requesting stop aborts the in-flight member await; its late
        // terminal drops on the completed_ guard. finish() below marks
        // completed, leaves the set, and delivers.
        try {
            member_scope_.request_stop();
        } catch (...) {
        }
        current_member_.reset();
        finish(
            core::fail({core::ErrorCode::cancelled, "DNS upstream group exchange was cancelled"}));
    }

  private:
    // Sequential retry loop as a named task (no inline-capture coroutine):
    // co_await each selected member sender, record health, and continue to
    // the next member while the deadline holds. Every path funnels through
    // member_finished()/finish(), so the task always ends with a value.
    static stdexec::task<void> run(std::shared_ptr<Operation> self, std::size_t start_index) {
        auto index = start_index;
        while (!self->completed_) {
            if (std::chrono::steady_clock::now() >= self->deadline_) {
                self->member_finished(
                    self->current_index_,
                    core::fail({core::ErrorCode::timeout, "DNS upstream group timed out"}));
                if (self->completed_) {
                    co_return;
                }
                // member_finished with no selection funnels to finish.
                co_return;
            }
            const auto selected = self->owner_.select_member(index, self->attempted_);
            if (!selected) {
                if (self->last_error_) {
                    self->finish(core::fail(*self->last_error_));
                } else {
                    self->finish(core::fail({core::ErrorCode::configuration,
                                             "DNS upstream group has no available members"}));
                }
                co_return;
            }
            self->current_index_ = *selected;
            self->attempted_[self->current_index_] = true;
            self->current_member_ = self->owner_.members_[self->current_index_];
            const auto now = std::chrono::steady_clock::now();
            const auto remaining = self->deadline_ - now;
            const auto remaining_members =
                std::count(self->attempted_.begin(), self->attempted_.end(), false);
            auto member_deadline = self->deadline_;
            const auto remaining_attempts = remaining_members + 1;
            if (remaining_attempts > 1 && remaining > std::chrono::steady_clock::duration::zero()) {
                member_deadline = now + remaining / remaining_attempts;
            }
            DnsExchangeResult result = core::fail(
                core::Error{core::ErrorCode::cancelled, "DNS group member exchange cancelled"});
            try {
                // Stop from member_scope_ maps to a member failure inline:
                // request_stop unwinds the await as stopped, and the loop
                // must record it and move on instead of dying silently.
                auto sender = self->current_member_->exchange(self->query_, member_deadline) |
                              stdexec::stopped_as_optional();
                auto outcome = co_await std::move(sender);
                if (outcome) {
                    result = std::move(*outcome);
                }
            } catch (const core::Error &failure) {
                result = core::fail(failure);
            } catch (...) {
                try {
                    std::rethrow_exception(std::current_exception());
                } catch (const core::Error &failure) {
                    result = core::fail(failure);
                } catch (...) {
                    result = core::fail(core::Error{core::ErrorCode::transport_io,
                                                    "DNS group member exchange failed"});
                }
            }
            if (self->completed_) {
                co_return;
            }
            if (!result && result.error().code == core::ErrorCode::cancelled) {
                // Stop unwound the member await: the outer cancel already
                // delivered, so bail instead of retrying siblings.
                co_return;
            }
            const auto member_index = self->current_index_;
            if (result) {
                if (!should_retry_response(result.value())) {
                    self->owner_.record_success(member_index);
                    self->finish(std::move(result));
                    co_return;
                }
                self->last_error_ = core::Error{core::ErrorCode::resolution,
                                                "DNS upstream returned a retryable response"};
                self->owner_.record_failure(member_index, *self->last_error_);
                const auto next = (member_index + 1) % self->owner_.members_.size();
                if (std::chrono::steady_clock::now() < self->deadline_ &&
                    std::any_of(self->attempted_.begin(), self->attempted_.end(),
                                [](bool attempted) { return !attempted; })) {
                    index = next;
                    continue;
                }
                self->finish(std::move(result));
                co_return;
            }
            self->last_error_ = result.error();
            if (result.error().code != core::ErrorCode::cancelled) {
                self->owner_.record_failure(member_index, result.error());
            }
            // Cancelled member results still advance: stop owns teardown
            // via completed_, and the loop bails at its head.
            if (self->completed_) {
                co_return;
            }
            const auto next = (member_index + 1) % self->owner_.members_.size();
            if (std::chrono::steady_clock::now() < self->deadline_) {
                index = next;
                continue;
            }
            self->finish(std::move(result));
            co_return;
        }
        co_return;
    }

    void member_finished(std::size_t index, core::Result<DnsPacket> result) {
        if (completed_ || index != current_index_) {
            return;
        }
        if (result) {
            if (!should_retry_response(result.value())) {
                owner_.record_success(index);
                finish(std::move(result));
                return;
            }
            last_error_ = core::Error{core::ErrorCode::resolution,
                                      "DNS upstream returned a retryable response"};
            owner_.record_failure(index, *last_error_);
            finish(std::move(result));
            return;
        }
        last_error_ = result.error();
        if (result.error().code != core::ErrorCode::cancelled) {
            owner_.record_failure(index, result.error());
        }
        if (last_error_) {
            finish(core::fail(*last_error_));
        } else {
            finish(core::fail(
                {core::ErrorCode::configuration, "DNS upstream group has no available members"}));
        }
    }

    void finish(core::Result<DnsPacket> result) {
        if (completed_) {
            return;
        }
        completed_ = true;
        // The member task aborts through member_scope_ stop; late finish
        // drops on completed_. Leave the owner set, then deliver.
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
    exec::async_scope member_scope_;
    std::size_t current_index_ = 0;
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
    using Signatures = async::BridgeSignatures<DnsExchangeResult>;
    return async::callback_sender<Signatures>(
        [self, query = std::move(query),
         deadline](auto terminal) mutable -> async::CallbackAbortFn {
            auto done = std::make_shared<async::BridgeHandler<DnsExchangeResult>>(
                [terminal = std::move(terminal)](DnsExchangeResult result) mutable {
                    terminal(std::move(result));
                });
            auto operation = std::make_shared<Operation>(
                *self, std::move(query), deadline,
                [done](DnsExchangeResult result) mutable { (*done)(std::move(result)); });
            self->operations_.insert(operation);
            if (self->stopped_) {
                operation->cancel();
            } else {
                operation->start();
            }
            return async::CallbackAbortFn{[self, operation] {
                self->operations_.erase(operation);
                operation->cancel();
            }};
        },
        async::BridgeTranslate<DnsExchangeResult>{});
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
