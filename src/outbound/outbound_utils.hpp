#pragma once

#include <boost/asio/ip/address.hpp>
#include <boost/asio/post.hpp>
#include <boost/system/error_code.hpp>
#include <clash_native/async/callback_sender.hpp>
#include <clash_native/async/timer.hpp>
#include <clash_native/core/result.hpp>
#include <clash_native/dns/dns_types.hpp>
#include <clash_native/dns/resolver_service.hpp>
#include <clash_native/io/sender.hpp>
#include <clash_native/runtime/asio_runtime.hpp>

#include <exec/async_scope.hpp>
#include <exec/task.hpp>

#include <stdexec/execution.hpp>

#include <algorithm>
#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>
#include <vector>

namespace clash_native::outbound::detail {

using AddressList = std::vector<boost::asio::ip::address>;
using ResolveHandler = std::function<void(core::Result<AddressList>)>;

inline std::error_code to_std_error(const boost::system::error_code &error) {
    return {error.value(), std::system_category()};
}

// Task-driven hostname resolution shared by the outbounds. The A/AAAA loop
// is a single exec::task co_awaiting one callback_sender leaf per query
// (registry-pattern resolver stays callback-shaped on purpose); the deadline
// is a sleep_after task racing it, winner via the completed_ guard. No
// steady_timer member, no async_wait, no bridge_sender.
class HostResolveState final : public std::enable_shared_from_this<HostResolveState> {
  public:
    using Result = core::Result<AddressList>;

    HostResolveState(runtime::AsioRuntime &runtime, std::shared_ptr<dns::ResolverService> resolver,
                     std::string host)
        : runtime_(runtime), resolver_(std::move(resolver)), host_(std::move(host)) {}

    void set_handler(ResolveHandler handler) noexcept { handler_ = std::move(handler); }

    void start() {
        boost::system::error_code address_error;
        const auto address = boost::asio::ip::make_address(host_, address_error);
        if (!address_error) {
            finish(Result{AddressList{address}});
            return;
        }
        if (!resolver_) {
            finish(core::fail({core::ErrorCode::configuration,
                               "a DNS resolver is required for outbound server hostnames"}));
            return;
        }
        auto self = shared_from_this();
        // Deadline task races the resolve loop; teardown stays guard-driven,
        // so no stop is ever requested.
        scope_.spawn(run_resolve(self));
        scope_.spawn(run_deadline(self));
    }

    // Abort for sender-driven cancellation: idempotent with finish().
    // Cancels any in-flight resolver request; the late terminal then drops
    // at the completed_ guard or the empty handler.
    void abort() noexcept {
        auto self = shared_from_this();
        try {
            boost::asio::post(runtime_.serialized_executor(), [self] {
                if (self->completed_) {
                    return;
                }
                self->completed_ = true;
                if (self->resolver_ && self->request_id_) {
                    self->resolver_->cancel(*self->request_id_);
                    self->request_id_.reset();
                }
            });
        } catch (...) {
        }
    }

  private:
    // Single-call bridged leaf over the registry-pattern resolver: kept
    // callback-shaped deliberately, cancellation via the returned aborter.
    static io::AnySender<core::Result<dns::DnsAnswer>>
    resolve_one(std::shared_ptr<HostResolveState> self, dns::DnsRecordType type) {
        using Signatures =
            stdexec::completion_signatures<stdexec::set_value_t(core::Result<dns::DnsAnswer>),
                                           stdexec::set_error_t(std::exception_ptr),
                                           stdexec::set_stopped_t()>;
        return io::AnySender<core::Result<dns::DnsAnswer>>{async::callback_sender<Signatures>(
            [self, type](auto terminal) mutable -> async::CallbackAbortFn {
                dns::DnsQuestion question{self->host_, type, 1};
                auto id = self->resolver_->resolve(
                    std::move(question),
                    [self,
                     terminal = std::move(terminal)](core::Result<dns::DnsAnswer> result) mutable {
                        self->request_id_.reset();
                        terminal(std::move(result));
                    },
                    self->runtime_.scheduler());
                self->request_id_ = id;
                return async::CallbackAbortFn{[self] {
                    if (self->request_id_) {
                        self->resolver_->cancel(*self->request_id_);
                    }
                }};
            },
            [](stdexec::receiver auto &&receiver, core::Result<dns::DnsAnswer> result) {
                stdexec::set_value(std::forward<decltype(receiver)>(receiver), std::move(result));
            })};
    }

    // The A/AAAA loop as one straight-line task. Every terminal funnels
    // through finish(), so the spawned task always ends with a value unless
    // an outer stop ends it early (whose terminal the erasure delivers).
    static exec::task<void> run_resolve(std::shared_ptr<HostResolveState> self) {
        for (const auto type : {dns::DnsRecordType::a, dns::DnsRecordType::aaaa}) {
            core::Result<dns::DnsAnswer> answer;
            try {
                answer = co_await resolve_one(self, type);
            } catch (...) {
                self->finish(core::fail(
                    {core::ErrorCode::resolution, "failed to resolve outbound server hostname"}));
                co_return;
            }
            if (self->completed_) {
                co_return;
            }
            if (answer) {
                for (const auto &address : answer.value().addresses) {
                    if (std::find(self->addresses_.begin(), self->addresses_.end(), address) ==
                        self->addresses_.end()) {
                        self->addresses_.push_back(address);
                    }
                }
            } else if (!self->first_error_) {
                self->first_error_ = answer.error();
            }
        }
        if (self->addresses_.empty()) {
            self->finish(self->first_error_
                             ? Result(core::fail(*self->first_error_))
                             : Result(core::fail({core::ErrorCode::resolution,
                                                  "outbound server hostname resolved to no "
                                                  "addresses"})));
            co_return;
        }
        self->finish(Result{std::move(self->addresses_)});
    }

    static exec::task<void> run_deadline(std::shared_ptr<HostResolveState> self) {
        try {
            co_await async::sleep_after(self->runtime_.serialized_executor(),
                                        std::chrono::seconds(10));
        } catch (...) {
            co_return;
        }
        self->finish(
            core::fail({core::ErrorCode::timeout, "timed out resolving outbound server hostname"}));
    }

    void finish(Result result) {
        if (completed_) {
            return;
        }
        completed_ = true;
        if (resolver_ && request_id_) {
            resolver_->cancel(*request_id_);
            request_id_.reset();
        }
        auto handler = std::move(handler_);
        // Aborted operations park an empty handler: drop the terminal.
        if (!handler) {
            return;
        }
        handler(std::move(result));
    }

    runtime::AsioRuntime &runtime_;
    std::shared_ptr<dns::ResolverService> resolver_;
    std::string host_;
    // Owns the resolve/deadline chain tasks, which always end with a value.
    exec::async_scope scope_;
    ResolveHandler handler_;
    std::optional<dns::ResolverService::RequestId> request_id_;
    AddressList addresses_;
    std::optional<core::Error> first_error_;
    bool completed_ = false;
};

// Sender-native resolve with real cancellation: the aborter aborts the
// shared state (in-flight resolver request), so caller stop preempts the DNS
// wait instead of leaking until timeout.
inline io::AnySender<core::Result<AddressList>>
resolve_host_sender(runtime::AsioRuntime &runtime, std::shared_ptr<dns::ResolverService> resolver,
                    std::string host) {
    using Signatures =
        stdexec::completion_signatures<stdexec::set_value_t(core::Result<AddressList>),
                                       stdexec::set_error_t(std::exception_ptr),
                                       stdexec::set_stopped_t()>;
    return io::AnySender<core::Result<AddressList>>{async::callback_sender<Signatures>(
        [&runtime, resolver = std::move(resolver),
         host = std::move(host)](auto terminal) mutable -> async::CallbackAbortFn {
            auto state =
                std::make_shared<HostResolveState>(runtime, std::move(resolver), std::move(host));
            state->set_handler(ResolveHandler{std::move(terminal)});
            state->start();
            return async::CallbackAbortFn{[state] { state->abort(); }};
        },
        [](stdexec::receiver auto &&receiver, core::Result<AddressList> result) {
            stdexec::set_value(std::forward<decltype(receiver)>(receiver), std::move(result));
        })};
}

} // namespace clash_native::outbound::detail
