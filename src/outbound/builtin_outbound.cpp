#include <clash_native/net/tcp_stream.hpp>
#include <clash_native/outbound/builtin_outbound.hpp>

#include <boost/asio/connect.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

#include <fmt/format.h>

#include <chrono>
#include <memory>
#include <system_error>
#include <utility>

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
    DirectConnectOperation(boost::asio::io_context &context, core::StreamRequest request,
                           core::StreamOpenHandler handler)
        : request_(std::move(request)), resolver_(context), socket_(context),
          connect_timer_(context), handler_(std::move(handler)) {}

    void start() {
        connect_timer_.expires_after(std::chrono::seconds(10));
        auto self = shared_from_this();
        connect_timer_.async_wait([self](const boost::system::error_code &error) {
            if (!error) {
                self->resolver_.cancel();
                boost::system::error_code ignored;
                self->socket_.cancel(ignored);
                self->complete(
                    core::Error{core::ErrorCode::timeout,
                                fmt::format("timed out connecting direct target {}",
                                            destination_text(self->request_.destination))});
            }
        });

        if (request_.destination.is_address()) {
            connect(request_.destination.address());
            return;
        }

        resolver_.async_resolve(
            request_.destination.domain(), std::to_string(request_.destination.port()),
            [self](const boost::system::error_code &error,
                   const boost::asio::ip::tcp::resolver::results_type &results) {
                if (error) {
                    self->complete(
                        connection_error(core::ErrorCode::resolution,
                                         fmt::format("failed to resolve direct target {}",
                                                     destination_text(self->request_.destination)),
                                         error));
                    return;
                }

                auto endpoints =
                    std::make_shared<boost::asio::ip::tcp::resolver::results_type>(results);
                self->connect(*endpoints);
            });
    }

  private:
    void connect(const boost::asio::ip::address &address) {
        auto self = shared_from_this();
        socket_.async_connect(
            {address, request_.destination.port()}, [self](const boost::system::error_code &error) {
                self->complete(error
                                   ? connection_error(
                                         core::ErrorCode::endpoint_connection,
                                         fmt::format("failed to connect direct target {}",
                                                     destination_text(self->request_.destination)),
                                         error)
                                   : std::optional<core::Error>{});
            });
    }

    void connect(const boost::asio::ip::tcp::resolver::results_type &endpoints) {
        auto self = shared_from_this();
        boost::asio::async_connect(
            socket_, endpoints,
            [self](const boost::system::error_code &error, const boost::asio::ip::tcp::endpoint &) {
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
            resolver_.cancel();
            socket_.close(ignored);
            handler_(core::StreamOpenResult::failed(std::move(*error)));
            return;
        }

        handler_(
            core::StreamOpenResult::opened(std::make_unique<net::TcpStream>(std::move(socket_))));
    }

    core::StreamRequest request_;
    boost::asio::ip::tcp::resolver resolver_;
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

DirectOutbound::DirectOutbound(runtime::AsioRuntime &runtime) : runtime_(runtime) {}

const core::OutboundDescriptor &DirectOutbound::descriptor() const noexcept { return descriptor_; }

core::OutboundCapabilities DirectOutbound::capabilities() const noexcept { return capabilities_; }

void DirectOutbound::connect_stream(core::StreamRequest request, core::StreamOpenHandler handler) {
    auto operation = std::make_shared<DirectConnectOperation>(
        runtime_.context(), std::move(request), std::move(handler));
    operation->start();
}

void DirectOutbound::open_datagram(core::DatagramRequest, core::DatagramOpenHandler handler) {
    boost::asio::post(runtime_.context(), [handler = std::move(handler)]() mutable {
        handler(core::DatagramOpenResult::unsupported());
    });
}

RejectOutbound::RejectOutbound(runtime::AsioRuntime &runtime) : runtime_(runtime) {}

const core::OutboundDescriptor &RejectOutbound::descriptor() const noexcept { return descriptor_; }

core::OutboundCapabilities RejectOutbound::capabilities() const noexcept { return capabilities_; }

void RejectOutbound::connect_stream(core::StreamRequest, core::StreamOpenHandler handler) {
    boost::asio::post(runtime_.context(),
                      [handler = std::move(handler)]() mutable { handler(rejected_stream()); });
}

void RejectOutbound::open_datagram(core::DatagramRequest, core::DatagramOpenHandler handler) {
    boost::asio::post(runtime_.context(), [handler = std::move(handler)]() mutable {
        handler(core::DatagramOpenResult::unsupported());
    });
}

} // namespace clash_native::outbound
