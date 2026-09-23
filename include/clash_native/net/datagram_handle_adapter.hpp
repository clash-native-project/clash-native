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

// Datagram-plane debt: exposes an io:: carrier as core::DatagramHandle
// for planes that still speak core:: (the DNS query operation and the
// legacy QUIC plane flip separately). Delete with those planes.
class IoToCoreDatagram final : public core::DatagramHandle {
  public:
    explicit IoToCoreDatagram(std::unique_ptr<io::DatagramHandle> inner)
        : executor_(inner->executor()), inner_(std::move(inner)) {}

    void async_send_to(boost::asio::const_buffer buffer, core::DatagramAddress destination,
                       WriteHandler handler) override {
        if (!inner_) {
            post_error(std::move(handler), boost::asio::error::bad_descriptor);
            return;
        }
        const io::DatagramAddress target =
            destination.is_domain()
                ? io::DatagramAddress::domain(destination.domain(), destination.port())
                : io::DatagramAddress::address(destination.address(), destination.port());
        struct Receiver {
            using receiver_concept = stdexec::receiver_tag;
            WriteHandler handler;

            void set_value(std::size_t size) && noexcept {
                auto callback = std::move(handler);
                callback(boost::system::error_code{}, size);
            }

            void set_error(std::exception_ptr error) && noexcept {
                auto callback = std::move(handler);
                callback(unpack_error(error), 0);
            }

            void set_stopped() && noexcept {
                auto callback = std::move(handler);
                callback(boost::asio::error::operation_aborted, 0);
            }
        };
        async::start_with_receiver(inner_->async_send_to(buffer, std::move(target)),
                                   Receiver{std::move(handler)});
    }

    void async_receive_from(boost::asio::mutable_buffer buffer, ReadHandler handler) override {
        if (!inner_) {
            boost::asio::post(executor_, [handler = std::move(handler)]() mutable {
                handler(boost::asio::error::bad_descriptor, 0, core::DatagramAddress{});
            });
            return;
        }
        struct Receiver {
            using receiver_concept = stdexec::receiver_tag;
            ReadHandler handler;

            void set_value(io::DatagramPacket packet) && noexcept {
                auto callback = std::move(handler);
                const core::DatagramAddress source =
                    packet.address.is_domain()
                        ? core::DatagramAddress::domain(packet.address.domain(),
                                                        packet.address.port())
                        : core::DatagramAddress::address(packet.address.address(),
                                                         packet.address.port());
                callback(boost::system::error_code{}, packet.size, std::move(source));
            }

            void set_error(std::exception_ptr error) && noexcept {
                auto callback = std::move(handler);
                callback(unpack_error(error), 0, core::DatagramAddress{});
            }

            void set_stopped() && noexcept {
                auto callback = std::move(handler);
                callback(boost::asio::error::operation_aborted, 0, core::DatagramAddress{});
            }
        };
        async::start_with_receiver(inner_->async_receive_from(buffer),
                                   Receiver{std::move(handler)});
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

    void close() noexcept override {
        if (inner_) {
            inner_->close();
        }
    }

  private:
    void post_error(core::DatagramHandle::WriteHandler handler,
                    boost::system::error_code error) const {
        boost::asio::post(executor_, [handler = std::move(handler), error]() mutable {
            handler(error, std::size_t{0});
        });
    }

    boost::asio::any_io_executor executor_;
    std::unique_ptr<io::DatagramHandle> inner_;
};

inline std::unique_ptr<core::DatagramHandle>
adapt_io_to_core_datagram(std::unique_ptr<io::DatagramHandle> datagram) {
    return std::make_unique<IoToCoreDatagram>(std::move(datagram));
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
