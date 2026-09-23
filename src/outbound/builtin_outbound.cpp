#include <clash_native/async/bridge.hpp>
#include <clash_native/net/tcp_stream.hpp>
#include <clash_native/net/udp_stream.hpp>
#include <clash_native/outbound/builtin_outbound.hpp>

#include <boost/asio/connect.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

#include <fmt/format.h>

#include <chrono>
#include <exception>
#include <memory>
#include <system_error>
#include <utility>
#include <vector>

namespace clash_native::outbound {

namespace {

std::error_code to_std_error(const boost::system::error_code &error) {
    return {error.value(), std::system_category()};
}

std::string destination_text(const core::Destination &destination) {
    if (destination.is_domain()) {
        return fmt::format("{}:{}", destination.domain(), destination.port());
    }
    return fmt::format("{}:{}", destination.address().to_string(), destination.port());
}

core::Error connection_error(core::ErrorCode code, std::string context,
                             const boost::system::error_code &error) {
    return {code, std::move(context), to_std_error(error)};
}

class DirectConnectOperation final : public std::enable_shared_from_this<DirectConnectOperation> {
  public:
    DirectConnectOperation(boost::asio::any_io_executor executor, core::StreamRequest request,
                           std::shared_ptr<dns::ResolverService> resolver,
                           core::StreamOpenHandler handler)
        : request_(std::move(request)), resolver_(std::move(resolver)),
          socket_(std::move(executor)), connect_timer_(socket_.get_executor()),
          handler_(std::move(handler)) {}

    void start() {
        connect_timer_.expires_after(std::chrono::seconds(10));
        auto self = shared_from_this();
        connect_timer_.async_wait([self](const boost::system::error_code &error) {
            if (!error) {
                if (self->resolver_ && self->resolver_request_id_) {
                    self->resolver_->cancel(*self->resolver_request_id_);
                }
                boost::system::error_code ignored;
                self->socket_.cancel(ignored);
                self->complete(
                    core::Error{core::ErrorCode::timeout,
                                fmt::format("timed out connecting direct target {}",
                                            destination_text(self->request_.destination))});
            }
        });

        if (request_.resolved_address) {
            connect(std::vector<boost::asio::ip::address>{*request_.resolved_address});
            return;
        }
        if (request_.destination.is_address()) {
            connect(std::vector<boost::asio::ip::address>{request_.destination.address()});
            return;
        }

        if (!resolver_) {
            complete(core::Error{core::ErrorCode::configuration,
                                 "direct outbound requires a configured DNS resolver"});
            return;
        }

        resolve_domain(dns::DnsRecordType::a);
    }

    // Abort for sender-driven cancellation: runs on the strand (fully
    // ordered with complete()), best-effort and idempotent. The bridge drops
    // the late terminal through its settled flag.
    void abort() noexcept {
        auto self = shared_from_this();
        try {
            boost::asio::post(socket_.get_executor(), [self]() {
                if (self->completed_) {
                    return;
                }
                self->connect_timer_.cancel();
                if (self->resolver_ && self->resolver_request_id_) {
                    self->resolver_->cancel(*self->resolver_request_id_);
                    self->resolver_request_id_.reset();
                }
                boost::system::error_code ignored;
                self->socket_.close(ignored);
            });
        } catch (...) {
        }
    }

  private:
    void resolve_domain(dns::DnsRecordType type) {
        auto self = shared_from_this();
        resolver_request_id_ = resolver_->resolve(
            {request_.destination.domain(), type, 1},
            [self, type](core::Result<dns::DnsAnswer> result) {
                self->resolver_request_id_.reset();
                if (result) {
                    self->resolved_addresses_.insert(self->resolved_addresses_.end(),
                                                     result.value().addresses.begin(),
                                                     result.value().addresses.end());
                } else if (!self->first_resolution_error_) {
                    self->first_resolution_error_ = result.error();
                }

                if (type == dns::DnsRecordType::a) {
                    self->resolve_domain(dns::DnsRecordType::aaaa);
                    return;
                }
                if (self->resolved_addresses_.empty()) {
                    if (self->first_resolution_error_) {
                        self->complete(*self->first_resolution_error_);
                    } else {
                        self->complete(
                            core::Error{core::ErrorCode::resolution,
                                        fmt::format("direct target {} has no resolved addresses",
                                                    destination_text(self->request_.destination))});
                    }
                    return;
                }
                self->connect(self->resolved_addresses_);
            },
            std::nullopt);
    }

    void connect(const std::vector<boost::asio::ip::address> &addresses) {
        auto endpoints = std::make_shared<std::vector<boost::asio::ip::tcp::endpoint>>();
        endpoints->reserve(addresses.size());
        for (const auto &address : addresses) {
            endpoints->emplace_back(address, request_.destination.port());
        }
        auto self = shared_from_this();
        boost::asio::async_connect(
            socket_, *endpoints,
            [self, endpoints](const boost::system::error_code &error,
                              const boost::asio::ip::tcp::endpoint &) {
                self->complete(error
                                   ? connection_error(
                                         core::ErrorCode::endpoint_connection,
                                         fmt::format("failed to connect direct target {}",
                                                     destination_text(self->request_.destination)),
                                         error)
                                   : std::optional<core::Error>{});
            });
    }

    void complete(std::optional<core::Error> error) {
        if (completed_) {
            return;
        }
        completed_ = true;
        boost::system::error_code ignored;
        connect_timer_.cancel();
        if (error) {
            if (resolver_ && resolver_request_id_) {
                resolver_->cancel(*resolver_request_id_);
                resolver_request_id_.reset();
            }
            socket_.close(ignored);
            handler_(core::StreamOpenResult::failed(std::move(*error)));
            return;
        }

        handler_(
            core::StreamOpenResult::opened(std::make_unique<net::TcpStream>(std::move(socket_))));
    }

    core::StreamRequest request_;
    std::shared_ptr<dns::ResolverService> resolver_;
    std::optional<dns::ResolverService::RequestId> resolver_request_id_;
    std::vector<boost::asio::ip::address> resolved_addresses_;
    std::optional<core::Error> first_resolution_error_;
    boost::asio::ip::tcp::socket socket_;
    boost::asio::steady_timer connect_timer_;
    core::StreamOpenHandler handler_;
    bool completed_ = false;
};

core::StreamOpenResult rejected_stream() {
    return core::StreamOpenResult::failed(
        {core::ErrorCode::rejected, "connection rejected by the reject outbound"});
}

} // namespace

DirectOutbound::DirectOutbound(runtime::AsioRuntime &runtime,
                               std::shared_ptr<dns::ResolverService> resolver)
    : runtime_(runtime), resolver_(std::move(resolver)) {}

void DirectOutbound::set_resolver(std::shared_ptr<dns::ResolverService> resolver) {
    resolver_ = std::move(resolver);
}

const core::OutboundDescriptor &DirectOutbound::descriptor() const noexcept { return descriptor_; }

core::OutboundCapabilities DirectOutbound::capabilities() const noexcept { return capabilities_; }

io::AnySender<core::StreamOpenResult> DirectOutbound::connect_stream(core::StreamRequest request) {
    auto executor = runtime_.serialized_executor();
    auto resolver = resolver_;
    return async::bridge_sender<core::StreamOpenResult>(
        [executor, request = std::move(request), resolver = std::move(resolver)](
            async::BridgeSender<core::StreamOpenResult>::Handler terminal) mutable {
            auto operation = std::make_shared<DirectConnectOperation>(
                executor, std::move(request), std::move(resolver), std::move(terminal));
            operation->start();
            return [operation] { operation->abort(); };
        });
}

io::AnySender<core::DatagramOpenResult>
DirectOutbound::open_datagram(core::DatagramRequest request) {
    using ResultSender = io::AnySender<core::DatagramOpenResult>;
    if (!request.initial_destination || !request.initial_destination->is_address()) {
        return ResultSender{stdexec::just(core::DatagramOpenResult::failed(
            {core::ErrorCode::configuration,
             "direct outbound datagram dialing requires an IP address"}))};
    }

    const auto address = request.initial_destination->address();
    auto socket = std::make_unique<net::UdpStream>(runtime_.serialized_executor());
    boost::system::error_code error;
    socket->open(address.is_v4() ? boost::asio::ip::udp::v4() : boost::asio::ip::udp::v6(), error);
    if (!error) {
        const auto local_address =
            address.is_v4() ? boost::asio::ip::address(boost::asio::ip::address_v4::any())
                            : boost::asio::ip::address(boost::asio::ip::address_v6::any());
        socket->bind({local_address, 0}, error);
    }
    if (error) {
        return ResultSender{stdexec::just(core::DatagramOpenResult::failed(
            {core::ErrorCode::transport_io, "failed to open direct outbound datagram", error}))};
    }

    return ResultSender{stdexec::just(core::DatagramOpenResult::opened(
        std::move(socket), core::DatagramSemantics::fixed_destination))};
}

RejectOutbound::RejectOutbound(runtime::AsioRuntime &runtime) : runtime_(runtime) {}

const core::OutboundDescriptor &RejectOutbound::descriptor() const noexcept { return descriptor_; }

core::OutboundCapabilities RejectOutbound::capabilities() const noexcept { return capabilities_; }

io::AnySender<core::StreamOpenResult> RejectOutbound::connect_stream(core::StreamRequest) {
    return io::AnySender<core::StreamOpenResult>{stdexec::just(rejected_stream())};
}

io::AnySender<core::DatagramOpenResult> RejectOutbound::open_datagram(core::DatagramRequest) {
    return io::AnySender<core::DatagramOpenResult>{
        stdexec::just(core::DatagramOpenResult::unsupported())};
}

} // namespace clash_native::outbound
