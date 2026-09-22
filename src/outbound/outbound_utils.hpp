#pragma once

#include <clash_native/core/result.hpp>
#include <clash_native/dns/dns_types.hpp>
#include <clash_native/dns/resolver_service.hpp>
#include <clash_native/runtime/asio_runtime.hpp>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>

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

class HostResolveOperation final : public std::enable_shared_from_this<HostResolveOperation> {
  public:
    HostResolveOperation(runtime::AsioRuntime &runtime,
                         std::shared_ptr<dns::ResolverService> resolver, std::string host,
                         ResolveHandler handler)
        : runtime_(runtime), resolver_(std::move(resolver)), host_(std::move(host)),
          timer_(runtime.serialized_executor()), handler_(std::move(handler)) {}

    void start() {
        boost::system::error_code address_error;
        const auto address = boost::asio::ip::make_address(host_, address_error);
        if (!address_error) {
            runtime_.scheduler().post(
                [self = shared_from_this(), address] { self->finish(AddressList{address}); });
            return;
        }
        if (!resolver_) {
            finish(core::fail({core::ErrorCode::configuration,
                               "a DNS resolver is required for outbound server hostnames"}));
            return;
        }

        timer_.expires_after(std::chrono::seconds(10));
        timer_.async_wait([self = shared_from_this()](const boost::system::error_code &error) {
            if (!error) {
                if (self->request_id_) {
                    self->resolver_->cancel(*self->request_id_);
                    self->request_id_.reset();
                }
                self->finish(core::fail(
                    {core::ErrorCode::timeout, "timed out resolving outbound server hostname"}));
            }
        });
        resolve(dns::DnsRecordType::a);
    }

  private:
    void resolve(dns::DnsRecordType type) {
        auto self = shared_from_this();
        request_id_ = resolver_->resolve(
            {host_, type, 1},
            [self, type](core::Result<dns::DnsAnswer> result) mutable {
                self->request_id_.reset();
                if (result) {
                    for (const auto &address : result.value().addresses) {
                        if (std::find(self->addresses_.begin(), self->addresses_.end(), address) ==
                            self->addresses_.end()) {
                            self->addresses_.push_back(address);
                        }
                    }
                } else if (!self->first_error_) {
                    self->first_error_ = result.error();
                }

                if (type == dns::DnsRecordType::a) {
                    self->resolve(dns::DnsRecordType::aaaa);
                    return;
                }
                if (self->addresses_.empty()) {
                    self->finish(self->first_error_
                                     ? core::Result<AddressList>(core::fail(*self->first_error_))
                                     : core::Result<AddressList>(core::fail(
                                           {core::ErrorCode::resolution,
                                            "outbound server hostname resolved to no addresses"})));
                    return;
                }
                self->finish(std::move(self->addresses_));
            },
            runtime_.scheduler());
    }

    void finish(core::Result<AddressList> result) {
        if (completed_) {
            return;
        }
        completed_ = true;
        timer_.cancel();
        if (resolver_ && request_id_) {
            resolver_->cancel(*request_id_);
            request_id_.reset();
        }
        auto handler = std::move(handler_);
        handler(std::move(result));
    }

    runtime::AsioRuntime &runtime_;
    std::shared_ptr<dns::ResolverService> resolver_;
    std::string host_;
    boost::asio::steady_timer timer_;
    ResolveHandler handler_;
    std::optional<dns::ResolverService::RequestId> request_id_;
    AddressList addresses_;
    std::optional<core::Error> first_error_;
    bool completed_ = false;
};

inline void resolve_host(runtime::AsioRuntime &runtime,
                         std::shared_ptr<dns::ResolverService> resolver, std::string host,
                         ResolveHandler handler) {
    auto operation = std::make_shared<HostResolveOperation>(runtime, std::move(resolver),
                                                            std::move(host), std::move(handler));
    operation->start();
}

} // namespace clash_native::outbound::detail
