#include <clash_native/transport/shadowsocks/udp_over_tcp.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/post.hpp>
#include <boost/system/errc.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace clash_native::transport::shadowsocks {

namespace {

constexpr std::size_t kMaxDatagramSize = 65507;
constexpr std::uint8_t kIpv4Family = 0x00;
constexpr std::uint8_t kIpv6Family = 0x01;
constexpr std::uint8_t kDomainFamily = 0x02;
constexpr std::uint8_t kSocksIpv4Family = 0x01;
constexpr std::uint8_t kSocksIpv6Family = 0x04;
constexpr std::uint8_t kSocksDomainFamily = 0x03;

boost::system::error_code protocol_error() {
    return boost::system::errc::make_error_code(boost::system::errc::protocol_error);
}

boost::system::error_code message_size_error() {
    return boost::system::errc::make_error_code(boost::system::errc::message_size);
}

core::Result<std::vector<std::uint8_t>> encode_destination(const core::Destination &destination) {
    std::vector<std::uint8_t> result;
    if (destination.is_address()) {
        const auto address = destination.address();
        if (address.is_v4()) {
            result.reserve(1 + 4 + 2);
            result.push_back(kIpv4Family);
            const auto bytes = address.to_v4().to_bytes();
            result.insert(result.end(), bytes.begin(), bytes.end());
        } else if (address.is_v6()) {
            result.reserve(1 + 16 + 2);
            result.push_back(kIpv6Family);
            const auto bytes = address.to_v6().to_bytes();
            result.insert(result.end(), bytes.begin(), bytes.end());
        } else {
            return core::fail({core::ErrorCode::configuration,
                               "UDP-over-TCP destination address family is unsupported",
                               {}});
        }
    } else {
        if (destination.domain().empty() || destination.domain().size() > 255) {
            return core::fail(
                {core::ErrorCode::configuration, "UDP-over-TCP domain length is invalid", {}});
        }
        result.reserve(2 + destination.domain().size() + 2);
        result.push_back(kDomainFamily);
        result.push_back(static_cast<std::uint8_t>(destination.domain().size()));
        result.insert(result.end(), destination.domain().begin(), destination.domain().end());
    }
    result.push_back(static_cast<std::uint8_t>(destination.port() >> 8));
    result.push_back(static_cast<std::uint8_t>(destination.port() & 0xff));
    return result;
}

core::Result<std::vector<std::uint8_t>>
encode_request_destination(const core::Destination &destination) {
    std::vector<std::uint8_t> result;
    if (destination.is_address()) {
        const auto address = destination.address();
        if (address.is_v4()) {
            result.reserve(1 + 4 + 2);
            result.push_back(kSocksIpv4Family);
            const auto bytes = address.to_v4().to_bytes();
            result.insert(result.end(), bytes.begin(), bytes.end());
        } else if (address.is_v6()) {
            result.reserve(1 + 16 + 2);
            result.push_back(kSocksIpv6Family);
            const auto bytes = address.to_v6().to_bytes();
            result.insert(result.end(), bytes.begin(), bytes.end());
        } else {
            return core::fail({core::ErrorCode::configuration,
                               "UDP-over-TCP request address family is unsupported",
                               {}});
        }
    } else {
        if (destination.domain().empty() || destination.domain().size() > 255) {
            return core::fail({core::ErrorCode::configuration,
                               "UDP-over-TCP request domain length is invalid",
                               {}});
        }
        result.reserve(2 + destination.domain().size() + 2);
        result.push_back(kSocksDomainFamily);
        result.push_back(static_cast<std::uint8_t>(destination.domain().size()));
        result.insert(result.end(), destination.domain().begin(), destination.domain().end());
    }
    result.push_back(static_cast<std::uint8_t>(destination.port() >> 8));
    result.push_back(static_cast<std::uint8_t>(destination.port() & 0xff));
    return result;
}

class UdpOverTcpState final : public std::enable_shared_from_this<UdpOverTcpState> {
  public:
    UdpOverTcpState(std::unique_ptr<core::StreamHandle> stream, UdpOverTcpOptions options)
        : stream_(std::move(stream)), options_(std::move(options)) {}

    void send(boost::asio::const_buffer buffer, boost::asio::ip::udp::endpoint destination,
              core::DatagramHandle::WriteHandler handler) {
        if (closed_) {
            post_write_result(std::move(handler), boost::asio::error::operation_aborted, 0);
            return;
        }
        if (buffer.size() > std::numeric_limits<std::uint16_t>::max()) {
            post_write_result(std::move(handler), message_size_error(), 0);
            return;
        }

        auto address = encode_destination(
            core::Destination::address(destination.address(), destination.port()));
        if (!address) {
            post_write_result(std::move(handler), protocol_error(), 0);
            return;
        }
        std::vector<std::uint8_t> wire;
        bool includes_request = false;
        if (!request_written_ && !request_pending_ &&
            options_.version == UdpOverTcpVersion::version2) {
            if (!options_.request_destination) {
                post_write_result(std::move(handler), protocol_error(), 0);
                return;
            }
            auto request_address = encode_request_destination(*options_.request_destination);
            if (!request_address) {
                post_write_result(std::move(handler), protocol_error(), 0);
                return;
            }
            // false means packet mode; every frame carries its destination.
            wire.reserve(1 + request_address.value().size() + address.value().size() + 2 +
                         buffer.size());
            wire.push_back(0);
            wire.insert(wire.end(), request_address.value().begin(), request_address.value().end());
            includes_request = true;
            request_pending_ = true;
        } else {
            wire.reserve(address.value().size() + 2 + buffer.size());
        }
        wire.insert(wire.end(), address.value().begin(), address.value().end());
        wire.push_back(static_cast<std::uint8_t>(buffer.size() >> 8));
        wire.push_back(static_cast<std::uint8_t>(buffer.size() & 0xff));
        const auto *data = static_cast<const std::uint8_t *>(buffer.data());
        wire.insert(wire.end(), data, data + buffer.size());

        writes_.push_back({std::make_shared<std::vector<std::uint8_t>>(std::move(wire)),
                           std::move(handler), buffer.size(), includes_request});
        pump_write();
    }

    void pump_write() {
        if (closed_ || write_in_progress_ || writes_.empty()) {
            return;
        }
        auto pending = std::move(writes_.front());
        writes_.pop_front();
        if (options_.version == UdpOverTcpVersion::version2 && !request_written_ &&
            !pending.includes_request) {
            if (!options_.request_destination) {
                auto handler = std::move(pending.handler);
                post_write_result(std::move(handler), protocol_error(), 0);
                pump_write();
                return;
            }
            auto request_address = encode_request_destination(*options_.request_destination);
            if (!request_address) {
                auto handler = std::move(pending.handler);
                post_write_result(std::move(handler), protocol_error(), 0);
                pump_write();
                return;
            }
            pending.packet->insert(pending.packet->begin(), request_address.value().begin(),
                                   request_address.value().end());
            pending.packet->insert(pending.packet->begin(), 0);
            pending.includes_request = true;
            request_pending_ = true;
        }

        write_in_progress_ = true;
        auto self = shared_from_this();
        auto packet = std::move(pending.packet);
        auto handler = std::move(pending.handler);
        const auto size = pending.size;
        const auto includes_request = pending.includes_request;
        stream_->async_write(boost::asio::buffer(*packet),
                             [self, packet, handler = std::move(handler), size, includes_request](
                                 const boost::system::error_code &error, std::size_t) mutable {
                                 self->write_in_progress_ = false;
                                 if (includes_request) {
                                     self->request_pending_ = false;
                                     self->request_written_ = !error;
                                 }
                                 if (error) {
                                     handler(error, 0);
                                 } else {
                                     handler({}, size);
                                 }
                                 self->pump_write();
                             });
    }

    void receive(boost::asio::mutable_buffer buffer, core::DatagramHandle::ReadHandler handler) {
        if (closed_) {
            post_read_result(std::move(handler), boost::asio::error::operation_aborted, 0, {});
            return;
        }
        if (read_in_progress_) {
            post_read_result(std::move(handler), boost::asio::error::already_started, 0, {});
            return;
        }
        if (buffer.size() == 0) {
            post_read_result(std::move(handler), {}, 0, {});
            return;
        }
        read_in_progress_ = true;
        output_buffer_ = buffer;
        receive_handler_ = std::move(handler);
        if (connect_mode_) {
            read_length();
        } else {
            auto self = shared_from_this();
            boost::asio::post(stream_->executor(), [self]() { self->read_family(); });
        }
    }

    boost::asio::any_io_executor executor() noexcept { return stream_->executor(); }

    void close() noexcept {
        if (closed_) {
            return;
        }
        closed_ = true;
        if (stream_) {
            stream_->close();
            auto executor = stream_->executor();
            if (read_in_progress_) {
                read_in_progress_ = false;
                auto handler = std::move(receive_handler_);
                boost::asio::post(executor, [handler = std::move(handler)]() mutable {
                    handler(boost::asio::error::operation_aborted, 0, {});
                });
            }
            while (!writes_.empty()) {
                auto handler = std::move(writes_.front().handler);
                writes_.pop_front();
                boost::asio::post(executor, [handler = std::move(handler)]() mutable {
                    handler(boost::asio::error::operation_aborted, 0);
                });
            }
        }
    }

  private:
    using Completion = std::function<void(const boost::system::error_code &)>;

    struct PendingWrite {
        std::shared_ptr<std::vector<std::uint8_t>> packet;
        core::DatagramHandle::WriteHandler handler;
        std::size_t size = 0;
        bool includes_request = false;
    };

    void post_write_result(core::DatagramHandle::WriteHandler handler,
                           const boost::system::error_code &error, std::size_t size) {
        boost::asio::post(stream_->executor(), [handler = std::move(handler), error,
                                                size]() mutable { handler(error, size); });
    }

    void post_read_result(core::DatagramHandle::ReadHandler handler,
                          const boost::system::error_code &error, std::size_t size,
                          boost::asio::ip::udp::endpoint source) {
        boost::asio::post(stream_->executor(),
                          [handler = std::move(handler), error, size, source]() mutable {
                              handler(error, size, source);
                          });
    }

    void read_exact(std::shared_ptr<std::vector<std::uint8_t>> buffer, std::size_t offset,
                    Completion completion) {
        auto self = shared_from_this();
        auto read_buffer =
            boost::asio::mutable_buffer(buffer->data() + offset, buffer->size() - offset);
        stream_->async_read_some(
            read_buffer,
            [self, buffer = std::move(buffer), offset, completion = std::move(completion)](
                const boost::system::error_code &error, std::size_t size) mutable {
                if (error) {
                    completion(error);
                    return;
                }
                if (size == 0) {
                    completion(boost::asio::error::eof);
                    return;
                }
                const auto next = offset + size;
                if (next == buffer->size()) {
                    completion({});
                    return;
                }
                self->read_exact(std::move(buffer), next, std::move(completion));
            });
    }

    void read_family() {
        auto family = std::make_shared<std::vector<std::uint8_t>>(1);
        auto self = shared_from_this();
        read_exact(family, 0, [self, family](const boost::system::error_code &error) {
            if (error) {
                self->finish_receive(error, 0, {});
                return;
            }
            const auto value = (*family)[0];
            std::size_t address_size = 0;
            if (value == kIpv4Family) {
                address_size = 4;
            } else if (value == kIpv6Family) {
                address_size = 16;
            } else if (value == kDomainFamily) {
                self->read_domain_length();
                return;
            } else {
                self->finish_receive(protocol_error(), 0, {});
                return;
            }
            self->read_numeric_address(value, address_size);
        });
    }

    void read_domain_length() {
        auto length = std::make_shared<std::vector<std::uint8_t>>(1);
        auto self = shared_from_this();
        read_exact(length, 0, [self, length](const boost::system::error_code &error) {
            if (error) {
                self->finish_receive(error, 0, {});
                return;
            }
            // DatagramHandle exposes an IP endpoint. A domain in a response
            // cannot be represented without a resolver, so reject it clearly.
            self->finish_receive(protocol_error(), 0, {});
        });
    }

    void read_numeric_address(std::uint8_t family, std::size_t address_size) {
        auto address = std::make_shared<std::vector<std::uint8_t>>(address_size);
        auto self = shared_from_this();
        read_exact(address, 0, [self, family, address](const boost::system::error_code &error) {
            if (error) {
                self->finish_receive(error, 0, {});
                return;
            }
            self->read_port(family, address);
        });
    }

    void read_port(std::uint8_t family, std::shared_ptr<std::vector<std::uint8_t>> address) {
        auto port = std::make_shared<std::vector<std::uint8_t>>(2);
        auto self = shared_from_this();
        read_exact(port, 0, [self, family, address, port](const boost::system::error_code &error) {
            if (error) {
                self->finish_receive(error, 0, {});
                return;
            }
            boost::asio::ip::address parsed_address;
            if (family == kIpv4Family) {
                boost::asio::ip::address_v4::bytes_type bytes{};
                std::copy(address->begin(), address->end(), bytes.begin());
                parsed_address = boost::asio::ip::address_v4(bytes);
            } else {
                boost::asio::ip::address_v6::bytes_type bytes{};
                std::copy(address->begin(), address->end(), bytes.begin());
                parsed_address = boost::asio::ip::address_v6(bytes);
            }
            const auto port_value = static_cast<std::uint16_t>((*port)[0] << 8 | (*port)[1]);
            self->read_payload_length({parsed_address, port_value});
        });
    }

    void read_length() {
        auto length = std::make_shared<std::vector<std::uint8_t>>(2);
        auto self = shared_from_this();
        read_exact(length, 0, [self, length](const boost::system::error_code &error) {
            if (error) {
                self->finish_receive(error, 0, {});
                return;
            }
            const auto size = static_cast<std::size_t>((*length)[0] << 8 | (*length)[1]);
            self->read_payload_bytes({}, size);
        });
    }

    void read_payload_length(boost::asio::ip::udp::endpoint source) {
        auto length = std::make_shared<std::vector<std::uint8_t>>(2);
        auto self = shared_from_this();
        read_exact(length, 0, [self, length, source](const boost::system::error_code &error) {
            if (error) {
                self->finish_receive(error, 0, {});
                return;
            }
            const auto size = static_cast<std::size_t>((*length)[0] << 8 | (*length)[1]);
            self->read_payload_bytes(source, size);
        });
    }

    void read_payload_bytes(boost::asio::ip::udp::endpoint source, std::size_t size) {
        auto payload = std::make_shared<std::vector<std::uint8_t>>(size);
        auto self = shared_from_this();
        read_exact(payload, 0, [self, payload, source](const boost::system::error_code &error) {
            if (error) {
                self->finish_receive(error, 0, {});
                return;
            }
            if (payload->size() > self->output_buffer_.size()) {
                self->finish_receive(message_size_error(), 0, {});
                return;
            }
            if (!payload->empty()) {
                std::memcpy(self->output_buffer_.data(), payload->data(), payload->size());
            }
            self->finish_receive({}, payload->size(), source);
        });
    }

    void finish_receive(const boost::system::error_code &error, std::size_t size,
                        boost::asio::ip::udp::endpoint source) {
        read_in_progress_ = false;
        auto handler = std::move(receive_handler_);
        if (handler) {
            handler(error, size, source);
        }
    }

    std::unique_ptr<core::StreamHandle> stream_;
    UdpOverTcpOptions options_;
    std::deque<PendingWrite> writes_;
    boost::asio::mutable_buffer output_buffer_;
    core::DatagramHandle::ReadHandler receive_handler_;
    bool request_written_ = false;
    bool request_pending_ = false;
    bool connect_mode_ = false;
    bool write_in_progress_ = false;
    bool read_in_progress_ = false;
    bool closed_ = false;
};

class UdpOverTcpHandle final : public core::DatagramHandle {
  public:
    explicit UdpOverTcpHandle(std::shared_ptr<UdpOverTcpState> state) : state_(std::move(state)) {}

    void async_send_to(boost::asio::const_buffer buffer, boost::asio::ip::udp::endpoint destination,
                       WriteHandler handler) override {
        state_->send(buffer, std::move(destination), std::move(handler));
    }

    void async_receive_from(boost::asio::mutable_buffer buffer, ReadHandler handler) override {
        state_->receive(buffer, std::move(handler));
    }

    boost::asio::any_io_executor executor() noexcept override { return state_->executor(); }

    std::size_t max_datagram_size() const noexcept override { return kMaxDatagramSize; }

    void cancel() noexcept override { state_->close(); }
    void close() noexcept override { state_->close(); }

  private:
    std::shared_ptr<UdpOverTcpState> state_;
};

} // namespace

core::Result<std::unique_ptr<core::DatagramHandle>>
make_udp_over_tcp_datagram_handle(std::unique_ptr<core::StreamHandle> stream,
                                  UdpOverTcpOptions options) {
    if (!stream) {
        return core::fail(
            {core::ErrorCode::configuration, "UDP-over-TCP requires an established stream", {}});
    }
    if (options.version != UdpOverTcpVersion::legacy &&
        options.version != UdpOverTcpVersion::version2) {
        return core::fail({core::ErrorCode::configuration, "unsupported UDP-over-TCP version", {}});
    }
    auto state = std::make_shared<UdpOverTcpState>(std::move(stream), std::move(options));
    return std::unique_ptr<core::DatagramHandle>(
        std::make_unique<UdpOverTcpHandle>(std::move(state)));
}

} // namespace clash_native::transport::shadowsocks
