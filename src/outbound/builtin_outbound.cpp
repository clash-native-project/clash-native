#include <clash_native/async/async.hpp>
#include <clash_native/async/callback_sender.hpp>
#include <clash_native/async/timer.hpp>
#include <clash_native/net/tcp_stream.hpp>
#include <clash_native/net/udp_stream.hpp>
#include <clash_native/outbound/builtin_outbound.hpp>

#include "outbound_utils.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/post.hpp>

#include <exec/asio/use_sender.hpp>
#include <exec/task.hpp>

#include <stdexec/execution.hpp>

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

class DirectConnectState final : public std::enable_shared_from_this<DirectConnectState> {
  public:
    DirectConnectState(runtime::AsioRuntime &runtime, core::StreamRequest request,
                       std::shared_ptr<dns::ResolverService> resolver,
                       core::StreamOpenHandler handler)
        : runtime_(runtime), request_(std::move(request)), resolver_(std::move(resolver)),
          socket_(runtime.serialized_executor()), handler_(std::move(handler)) {}

    void start() {
        auto self = shared_from_this();
        // Deadline task races the open chain; both run detached (immortal
        // heap scope): either task holds the last state reference at
        // completion, which would free a member scope_ before __complete
        // touches scope->__active_ (ASan #194, async_scope.hpp:162 --
        // same shape as ProxySession UDP tasks and Socks5UdpListener).
        async::spawn_detached(run_open(self));
        async::spawn_detached(run_deadline(self));
    }

    // Abort for sender-driven cancellation: idempotent with finish().
    // Stops the chain tasks (stop propagates into the resolve/connect
    // awaits) and closes the socket; the late terminal drops at the
    // completed_ guard or the claimed callback_sender settlement.
    void abort() noexcept {
        auto self = shared_from_this();
        try {
            boost::asio::post(runtime_.serialized_executor(), [self] {
                if (self->completed_) {
                    return;
                }
                self->completed_ = true;
                // No request_stop: detached tasks have no shared scope to
                // stop; closing the socket aborts the open chain, and the
                // deadline task drops at its completed_ guard.
                boost::system::error_code ignored;
                self->socket_.close(ignored);
            });
        } catch (...) {
        }
    }

  private:
    // Straight-line open chain: resolve (A/AAAA loop inside the shared
    // sender, kept as in-band Result), then TCP connect. Every terminal
    // funnels through finish(), so the spawned task always ends with a
    // value unless an outer stop ends it early.
    static exec::task<void> run_open(std::shared_ptr<DirectConnectState> self) {
        if (self->request_.resolved_address) {
            co_await connect_addresses(
                self, std::vector<boost::asio::ip::address>{*self->request_.resolved_address});
            co_return;
        }
        if (self->request_.destination.is_address()) {
            co_await connect_addresses(
                self, std::vector<boost::asio::ip::address>{self->request_.destination.address()});
            co_return;
        }
        if (!self->resolver_) {
            self->finish(core::StreamOpenResult::failed(
                {core::ErrorCode::configuration,
                 "direct outbound requires a configured DNS resolver"}));
            co_return;
        }
        core::Result<detail::AddressList> resolved;
        try {
            resolved = co_await detail::resolve_host_sender(self->runtime_, self->resolver_,
                                                            self->request_.destination.domain());
        } catch (...) {
            self->finish(core::StreamOpenResult::failed(
                {core::ErrorCode::resolution,
                 fmt::format("failed to resolve direct target {}",
                             destination_text(self->request_.destination))}));
            co_return;
        }
        if (self->completed_) {
            co_return;
        }
        if (!resolved || resolved.value().empty()) {
            self->finish(core::StreamOpenResult::failed(
                resolved ? core::Error{core::ErrorCode::resolution,
                                       fmt::format("direct target {} has no resolved addresses",
                                                   destination_text(self->request_.destination))}
                         : resolved.error()));
            co_return;
        }
        co_await connect_addresses(self, std::move(resolved.value()));
    }

    static exec::task<void> connect_addresses(std::shared_ptr<DirectConnectState> self,
                                              std::vector<boost::asio::ip::address> addresses) {
        auto endpoints = std::make_shared<std::vector<boost::asio::ip::tcp::endpoint>>();
        endpoints->reserve(addresses.size());
        for (const auto &address : addresses) {
            endpoints->emplace_back(address, self->request_.destination.port());
        }
        try {
            co_await (
                boost::asio::async_connect(self->socket_, *endpoints, exec::asio::use_sender) |
                stdexec::then([](const boost::asio::ip::tcp::endpoint &) {}) |
                stdexec::let_error([self](std::exception_ptr error) {
                    try {
                        std::rethrow_exception(std::move(error));
                    } catch (const boost::system::system_error &failure) {
                        return stdexec::just_error(std::make_exception_ptr(connection_error(
                            core::ErrorCode::endpoint_connection,
                            fmt::format("failed to connect direct target {}",
                                        destination_text(self->request_.destination)),
                            failure.code())));
                    }
                    std::rethrow_exception(std::current_exception());
                }));
        } catch (const core::Error &failure) {
            self->finish(core::StreamOpenResult::failed(failure));
            co_return;
        } catch (...) {
            self->finish(core::StreamOpenResult::failed(
                connection_error(core::ErrorCode::endpoint_connection,
                                 fmt::format("failed to connect direct target {}",
                                             destination_text(self->request_.destination)),
                                 boost::asio::error::fault)));
            co_return;
        }
        if (!self->completed_) {
            self->finish(core::StreamOpenResult::opened(
                std::make_unique<net::TcpStream>(std::move(self->socket_))));
        }
    }

    static exec::task<void> run_deadline(std::shared_ptr<DirectConnectState> self) {
        try {
            co_await async::sleep_after(self->runtime_.serialized_executor(),
                                        std::chrono::seconds(10));
        } catch (...) {
            co_return;
        }
        self->finish(core::StreamOpenResult::failed(
            {core::ErrorCode::timeout, fmt::format("timed out connecting direct target {}",
                                                   destination_text(self->request_.destination))}));
    }

    void finish(core::StreamOpenResult result) {
        if (completed_) {
            if (result.handle) {
                result.handle->close();
            }
            return;
        }
        completed_ = true;
        if (!result.succeeded()) {
            boost::system::error_code ignored;
            socket_.close(ignored);
        }
        auto handler = std::move(handler_);
        if (handler) {
            handler(std::move(result));
        }
    }

    runtime::AsioRuntime &runtime_;
    core::StreamRequest request_;
    std::shared_ptr<dns::ResolverService> resolver_;
    boost::asio::ip::tcp::socket socket_;
    core::StreamOpenHandler handler_;
    bool completed_ = false;
    // No member scope: open/deadline tasks run detached (immortal heap
    // scope) so the last state reference cannot free their scope (#194).
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
    using Signatures = stdexec::completion_signatures<stdexec::set_value_t(core::StreamOpenResult),
                                                      stdexec::set_error_t(std::exception_ptr),
                                                      stdexec::set_stopped_t()>;
    return io::AnySender<core::StreamOpenResult>{async::callback_sender<Signatures>(
        [&runtime = runtime_, resolver = resolver_,
         request = std::move(request)](auto terminal) mutable -> async::CallbackAbortFn {
            auto state = std::make_shared<DirectConnectState>(
                runtime, std::move(request), std::move(resolver),
                core::StreamOpenHandler{std::move(terminal)});
            state->start();
            return async::CallbackAbortFn{[state] { state->abort(); }};
        },
        [](stdexec::receiver auto &&receiver, core::StreamOpenResult result) {
            stdexec::set_value(std::forward<decltype(receiver)>(receiver), std::move(result));
        })};
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
