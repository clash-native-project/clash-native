#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/io/datagram_handle.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>
#include <boost/system/error_code.hpp>

#include <cstddef>
#include <memory>
#include <utility>

namespace clash_native::net {

// Datagram-plane debt: converts an io:: destination into the core::
// vocabulary for helpers (proxy address codecs) that still speak core::.
// Delete with those helpers.
inline core::Destination to_core_destination(const io::Destination &destination) {
    return destination.is_domain()
               ? core::Destination::domain(destination.domain(), destination.port())
               : core::Destination::address(destination.address(), destination.port());
}

// Datagram-plane debt: exposes a core:: handle as io::DatagramHandle for
// callers that already run on senders (Shadowsocks direct/legacy/AEAD
// datagram construction still produces core:: handles and flips
// separately). Delete when the producers hand out io:: handles directly.
class CoreToIoDatagram final : public io::DatagramHandle {
  public:
    using ReadSignatures = stdexec::completion_signatures<stdexec::set_value_t(io::DatagramPacket),
                                                          stdexec::set_error_t(std::exception_ptr),
                                                          stdexec::set_stopped_t()>;
    using WriteSignatures = stdexec::completion_signatures<stdexec::set_value_t(std::size_t),
                                                           stdexec::set_error_t(std::exception_ptr),
                                                           stdexec::set_stopped_t()>;

    explicit CoreToIoDatagram(std::unique_ptr<core::DatagramHandle> inner)
        : executor_(inner->executor()), inner_(std::move(inner)) {}

    io::AnySender<std::size_t> async_send_to(boost::asio::const_buffer buffer,
                                             io::DatagramAddress destination) override {
        return io::AnySender<std::size_t>{async::callback_sender<WriteSignatures>(
            [this, buffer, destination = std::move(destination)](auto terminal) mutable {
                const core::DatagramAddress target =
                    destination.is_domain()
                        ? core::DatagramAddress::domain(destination.domain(), destination.port())
                        : core::DatagramAddress::address(destination.address(), destination.port());
                inner_->async_send_to(buffer, std::move(target),
                                      [terminal = std::move(terminal)](
                                          const boost::system::error_code &error,
                                          std::size_t size) mutable { terminal(error, size); });
            },
            [](auto &&receiver, const boost::system::error_code &error, std::size_t size) {
                if (!error) {
                    stdexec::set_value(std::move(receiver), size);
                } else {
                    stdexec::set_error(
                        std::move(receiver),
                        std::make_exception_ptr(
                            core::Error{core::ErrorCode::transport_io, "core handle send",
                                        std::error_code(error.value(), std::system_category())}));
                }
            })};
    }

    io::AnySender<io::DatagramPacket>
    async_receive_from(boost::asio::mutable_buffer buffer) override {
        return io::AnySender<io::DatagramPacket>{async::callback_sender<ReadSignatures>(
            [this, buffer](auto terminal) mutable {
                inner_->async_receive_from(
                    buffer, [terminal = std::move(terminal)](const boost::system::error_code &error,
                                                             std::size_t size,
                                                             core::DatagramAddress sender) mutable {
                        terminal(error, size, std::move(sender));
                    });
            },
            [](auto &&receiver, const boost::system::error_code &error, std::size_t size,
               core::DatagramAddress sender) {
                if (!error) {
                    const io::DatagramAddress source =
                        sender.is_domain()
                            ? io::DatagramAddress::domain(sender.domain(), sender.port())
                            : io::DatagramAddress::address(sender.address(), sender.port());
                    stdexec::set_value(std::move(receiver),
                                       io::DatagramPacket{size, std::move(source)});
                } else {
                    stdexec::set_error(
                        std::move(receiver),
                        std::make_exception_ptr(
                            core::Error{core::ErrorCode::transport_io, "core handle receive",
                                        std::error_code(error.value(), std::system_category())}));
                }
            })};
    }

    boost::asio::any_io_executor executor() noexcept override { return executor_; }

    std::size_t max_datagram_size() const noexcept override {
        return inner_ ? inner_->max_datagram_size() : 65507;
    }

    void cancel() noexcept override {
        if (inner_) {
            inner_->cancel();
        }
    }

    // Close without releasing: outstanding pulls may still complete; the
    // inner handle dies with the adapter after they drain.
    void close() noexcept override {
        if (inner_) {
            inner_->close();
        }
    }

  private:
    boost::asio::any_io_executor executor_;
    std::unique_ptr<core::DatagramHandle> inner_;
};

inline std::unique_ptr<io::DatagramHandle>
adapt_core_to_io_datagram(std::unique_ptr<core::DatagramHandle> datagram) {
    return std::make_unique<CoreToIoDatagram>(std::move(datagram));
}

} // namespace clash_native::net
