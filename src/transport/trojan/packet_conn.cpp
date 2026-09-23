#include <clash_native/transport/trojan/packet_conn.hpp>

#include <clash_native/async/callback_sender.hpp>
#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/io/sender.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>

#include <stdexec/execution.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/post.hpp>
#include <boost/system/errc.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace clash_native::transport::trojan {

namespace {

// Bridges one stream push/pull back into a legacy (error, size) handler.
struct StreamWriteBridge {
    using receiver_concept = stdexec::receiver_tag;
    std::function<void(const boost::system::error_code &, std::size_t)> handler;
    void set_value(std::size_t size) && noexcept {
        auto callback = std::move(handler);
        callback({}, size);
    }
    void set_error(std::exception_ptr error) && noexcept {
        auto callback = std::move(handler);
        callback(net::unpack_error(std::move(error)), 0);
    }
    void set_stopped() && noexcept {
        auto callback = std::move(handler);
        callback(boost::asio::error::operation_aborted, 0);
    }
};

struct StreamReadBridge {
    using receiver_concept = stdexec::receiver_tag;
    std::function<void(const boost::system::error_code &, std::size_t)> handler;
    void set_value(std::optional<std::size_t> size) && noexcept {
        auto callback = std::move(handler);
        if (size) {
            callback({}, *size);
        } else {
            callback(boost::asio::error::eof, 0);
        }
    }
    void set_error(std::exception_ptr error) && noexcept {
        auto callback = std::move(handler);
        callback(net::unpack_error(std::move(error)), 0);
    }
    void set_stopped() && noexcept {
        auto callback = std::move(handler);
        callback(boost::asio::error::operation_aborted, 0);
    }
};

constexpr std::uint8_t kSocksIpv4 = 0x01;
constexpr std::uint8_t kSocksIpv6 = 0x04;
constexpr std::uint8_t kSocksDomain = 0x03;

boost::system::error_code protocol_error() {
    return boost::system::errc::make_error_code(boost::system::errc::protocol_error);
}

boost::system::error_code message_size_error() {
    return boost::system::errc::make_error_code(boost::system::errc::message_size);
}

core::Result<std::vector<std::uint8_t>> encode_address(const io::DatagramAddress &destination) {
    std::vector<std::uint8_t> result;
    if (destination.is_address()) {
        const auto address = destination.address();
        if (address.is_v4()) {
            result.reserve(1 + 4 + 2);
            result.push_back(kSocksIpv4);
            const auto bytes = address.to_v4().to_bytes();
            result.insert(result.end(), bytes.begin(), bytes.end());
        } else if (address.is_v6()) {
            result.reserve(1 + 16 + 2);
            result.push_back(kSocksIpv6);
            const auto bytes = address.to_v6().to_bytes();
            result.insert(result.end(), bytes.begin(), bytes.end());
        } else {
            return core::fail({core::ErrorCode::configuration,
                               "Trojan packet destination address family is unsupported"});
        }
    } else {
        if (destination.domain().empty() || destination.domain().size() > 255) {
            return core::fail(
                {core::ErrorCode::configuration, "Trojan packet domain length is invalid"});
        }
        result.reserve(2 + destination.domain().size() + 2);
        result.push_back(kSocksDomain);
        result.push_back(static_cast<std::uint8_t>(destination.domain().size()));
        result.insert(result.end(), destination.domain().begin(), destination.domain().end());
    }
    result.push_back(static_cast<std::uint8_t>(destination.port() >> 8));
    result.push_back(static_cast<std::uint8_t>(destination.port() & 0xff));
    return result;
}

class TrojanPacketState final : public std::enable_shared_from_this<TrojanPacketState> {
  public:
    using ReadHandler =
        std::function<void(const boost::system::error_code &, std::size_t, io::DatagramAddress)>;
    using WriteHandler = std::function<void(const boost::system::error_code &, std::size_t)>;

    explicit TrojanPacketState(std::unique_ptr<io::StreamHandle> stream)
        : stream_(std::move(stream)) {}

    boost::asio::any_io_executor executor() noexcept { return stream_->executor(); }

    void send(boost::asio::const_buffer buffer, io::DatagramAddress destination,
              WriteHandler handler) {
        if (closed_) {
            post_write_result(std::move(handler), boost::asio::error::operation_aborted, 0);
            return;
        }
        if (buffer.size() > std::numeric_limits<std::uint16_t>::max()) {
            post_write_result(std::move(handler), message_size_error(), 0);
            return;
        }
        auto address = encode_address(destination);
        if (!address) {
            post_write_result(std::move(handler), protocol_error(), 0);
            return;
        }
        const auto *data = static_cast<const std::uint8_t *>(buffer.data());
        std::size_t offset = 0;
        // Mihomo splits payloads larger than kMaxPacketPayload into
        // multiple addr|len|CRLF|payload frames.
        do {
            const auto chunk = std::min<std::size_t>(buffer.size() - offset, kMaxPacketPayload);
            auto wire = std::make_shared<std::vector<std::uint8_t>>();
            wire->reserve(address.value().size() + 2 + 2 + chunk);
            wire->insert(wire->end(), address.value().begin(), address.value().end());
            wire->push_back(static_cast<std::uint8_t>(chunk >> 8));
            wire->push_back(static_cast<std::uint8_t>(chunk & 0xff));
            wire->push_back('\r');
            wire->push_back('\n');
            wire->insert(wire->end(), data + offset, data + offset + chunk);
            writes_.push_back({std::move(wire), nullptr, 0});
            offset += chunk;
        } while (offset < buffer.size());
        // The terminal delivery rides on the last frame; earlier frames
        // only pump the queue.
        writes_.back().handler = std::move(handler);
        writes_.back().size = buffer.size();
        pump_write();
    }

    void receive(boost::asio::mutable_buffer buffer, ReadHandler handler) {
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
        auto self = shared_from_this();
        boost::asio::post(stream_->executor(), [self]() { self->read_family(); });
    }

    void close() {
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
                if (handler) {
                    boost::asio::post(executor, [handler = std::move(handler)]() mutable {
                        handler(boost::asio::error::operation_aborted, 0);
                    });
                }
            }
        }
    }

  private:
    using Completion = std::function<void(const boost::system::error_code &)>;

    struct PendingWrite {
        std::shared_ptr<std::vector<std::uint8_t>> packet;
        WriteHandler handler;
        std::size_t size = 0;
    };

    void post_write_result(WriteHandler handler, const boost::system::error_code &error,
                           std::size_t size) {
        boost::asio::post(stream_->executor(), [handler = std::move(handler), error,
                                                size]() mutable { handler(error, size); });
    }

    void post_read_result(ReadHandler handler, const boost::system::error_code &error,
                          std::size_t size, io::DatagramAddress source) {
        boost::asio::post(stream_->executor(),
                          [handler = std::move(handler), error, size, source]() mutable {
                              handler(error, size, source);
                          });
    }

    void pump_write() {
        if (closed_ || write_in_progress_ || writes_.empty()) {
            return;
        }
        auto pending = std::move(writes_.front());
        writes_.pop_front();
        write_in_progress_ = true;
        auto self = shared_from_this();
        auto packet = std::move(pending.packet);
        auto handler = std::move(pending.handler);
        const auto size = pending.size;
        std::function<void(const boost::system::error_code &, std::size_t)> completion =
            [self, packet, handler = std::move(handler),
             size](const boost::system::error_code &error, std::size_t) mutable {
                self->write_in_progress_ = false;
                if (handler) {
                    if (error) {
                        handler(error, 0);
                    } else {
                        handler({}, size);
                    }
                }
                self->pump_write();
            };
        // NOTE: name the sender first; argument order is unspecified.
        auto sender = stream_->async_write(boost::asio::buffer(*packet));
        async::start_with_receiver(std::move(sender), StreamWriteBridge{std::move(completion)});
    }

    void read_exact(std::shared_ptr<std::vector<std::uint8_t>> buffer, std::size_t offset,
                    Completion completion) {
        auto self = shared_from_this();
        auto read_buffer =
            boost::asio::mutable_buffer(buffer->data() + offset, buffer->size() - offset);
        std::function<void(const boost::system::error_code &, std::size_t)> pull =
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
            };
        // NOTE: name the sender first; argument order is unspecified.
        auto sender = stream_->async_read_some(read_buffer);
        async::start_with_receiver(std::move(sender), StreamReadBridge{std::move(pull)});
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
            if (value == kSocksIpv4) {
                address_size = 4;
            } else if (value == kSocksIpv6) {
                address_size = 16;
            } else if (value == kSocksDomain) {
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
            const auto size = static_cast<std::size_t>((*length)[0]);
            if (size == 0) {
                self->finish_receive(protocol_error(), 0, {});
                return;
            }
            self->read_domain_name(size);
        });
    }

    void read_domain_name(std::size_t size) {
        auto domain = std::make_shared<std::vector<std::uint8_t>>(size);
        auto self = shared_from_this();
        read_exact(domain, 0, [self, domain](const boost::system::error_code &error) {
            if (error) {
                self->finish_receive(error, 0, {});
                return;
            }
            self->read_domain_port(std::string(domain->begin(), domain->end()));
        });
    }

    void read_domain_port(std::string domain) {
        auto port = std::make_shared<std::vector<std::uint8_t>>(2);
        auto self = shared_from_this();
        read_exact(port, 0,
                   [self, domain = std::move(domain),
                    port](const boost::system::error_code &error) mutable {
                       if (error) {
                           self->finish_receive(error, 0, {});
                           return;
                       }
                       const auto port_value =
                           static_cast<std::uint16_t>((*port)[0] << 8 | (*port)[1]);
                       self->read_payload_length(
                           io::DatagramAddress::domain(std::move(domain), port_value));
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
            if (family == kSocksIpv4) {
                boost::asio::ip::address_v4::bytes_type bytes{};
                std::copy(address->begin(), address->end(), bytes.begin());
                parsed_address = boost::asio::ip::address_v4(bytes);
            } else {
                boost::asio::ip::address_v6::bytes_type bytes{};
                std::copy(address->begin(), address->end(), bytes.begin());
                parsed_address = boost::asio::ip::address_v6(bytes);
            }
            const auto port_value = static_cast<std::uint16_t>((*port)[0] << 8 | (*port)[1]);
            self->read_payload_length(io::DatagramAddress::address(parsed_address, port_value));
        });
    }

    void read_payload_length(io::DatagramAddress source) {
        auto length = std::make_shared<std::vector<std::uint8_t>>(2 + 2);
        auto self = shared_from_this();
        // Length prefix plus the CRLF terminator arrive as one unit.
        read_exact(length, 0, [self, length, source](const boost::system::error_code &error) {
            if (error) {
                self->finish_receive(error, 0, {});
                return;
            }
            const auto size = static_cast<std::size_t>((*length)[0] << 8 | (*length)[1]);
            if ((*length)[2] != '\r' || (*length)[3] != '\n') {
                self->finish_receive(protocol_error(), 0, {});
                return;
            }
            if (size > kMaxPacketPayload) {
                self->finish_receive(protocol_error(), 0, {});
                return;
            }
            self->read_payload_bytes(source, size);
        });
    }

    void read_payload_bytes(io::DatagramAddress source, std::size_t size) {
        if (size == 0) {
            finish_receive({}, 0, source);
            return;
        }
        // The io::DatagramHandle contract reports truncation as a
        // message_size error rather than Mihomo's partial-delivery with
        // parked remainder.
        if (size > output_buffer_.size()) {
            finish_receive(message_size_error(), 0, {});
            return;
        }
        auto payload = std::make_shared<std::vector<std::uint8_t>>(size);
        auto self = shared_from_this();
        read_exact(payload, 0, [self, payload, source](const boost::system::error_code &error) {
            if (error) {
                self->finish_receive(error, 0, {});
                return;
            }
            std::memcpy(self->output_buffer_.data(), payload->data(), payload->size());
            self->finish_receive({}, payload->size(), source);
        });
    }

    void finish_receive(const boost::system::error_code &error, std::size_t size,
                        io::DatagramAddress source) {
        read_in_progress_ = false;
        auto handler = std::move(receive_handler_);
        if (handler) {
            handler(error, size, source);
        }
    }

    std::unique_ptr<io::StreamHandle> stream_;
    std::deque<PendingWrite> writes_;
    boost::asio::mutable_buffer output_buffer_;
    ReadHandler receive_handler_;
    bool write_in_progress_ = false;
    bool read_in_progress_ = false;
    bool closed_ = false;
};

class TrojanPacketHandle final : public io::DatagramHandle {
  public:
    explicit TrojanPacketHandle(std::shared_ptr<TrojanPacketState> state)
        : state_(std::move(state)) {}

    io::AnySender<std::size_t> async_send_to(boost::asio::const_buffer buffer,
                                             io::DatagramAddress destination) override {
        using Signatures = stdexec::completion_signatures<stdexec::set_value_t(std::size_t),
                                                          stdexec::set_error_t(std::exception_ptr),
                                                          stdexec::set_stopped_t()>;
        return io::AnySender<std::size_t>{async::callback_sender<Signatures>(
            [state = state_, buffer, destination](auto terminal) mutable {
                state->send(buffer, std::move(destination), std::move(terminal));
            },
            [](auto receiver, const boost::system::error_code &error, std::size_t size) {
                if (!error) {
                    stdexec::set_value(std::move(receiver), size);
                    return;
                }
                if (error == boost::asio::error::operation_aborted) {
                    stdexec::set_stopped(std::move(receiver));
                    return;
                }
                stdexec::set_error(std::move(receiver), std::make_exception_ptr(core::Error{
                                                            core::ErrorCode::transport_io,
                                                            "Trojan packet send failed", error}));
            })};
    }

    io::AnySender<io::DatagramPacket>
    async_receive_from(boost::asio::mutable_buffer buffer) override {
        using Signatures = stdexec::completion_signatures<stdexec::set_value_t(io::DatagramPacket),
                                                          stdexec::set_error_t(std::exception_ptr),
                                                          stdexec::set_stopped_t()>;
        return io::AnySender<io::DatagramPacket>{async::callback_sender<Signatures>(
            [state = state_, buffer](auto terminal) mutable {
                state->receive(buffer, [terminal = std::move(terminal)](
                                           const boost::system::error_code &error, std::size_t size,
                                           io::DatagramAddress source) mutable {
                    terminal(error, size, std::move(source));
                });
            },
            [](auto receiver, const boost::system::error_code &error, std::size_t size,
               io::DatagramAddress source) {
                if (!error) {
                    stdexec::set_value(std::move(receiver),
                                       io::DatagramPacket{size, std::move(source)});
                    return;
                }
                if (error == boost::asio::error::operation_aborted) {
                    stdexec::set_stopped(std::move(receiver));
                    return;
                }
                stdexec::set_error(
                    std::move(receiver),
                    std::make_exception_ptr(core::Error{core::ErrorCode::transport_io,
                                                        "Trojan packet receive failed", error}));
            })};
    }

    boost::asio::any_io_executor executor() noexcept override { return state_->executor(); }

    void cancel() noexcept override { state_->close(); }
    void close() noexcept override { state_->close(); }

  private:
    std::shared_ptr<TrojanPacketState> state_;
};

} // namespace

core::Result<std::unique_ptr<io::DatagramHandle>>
make_trojan_packet_conn(std::unique_ptr<io::StreamHandle> stream) {
    if (!stream) {
        return core::fail(
            {core::ErrorCode::configuration, "Trojan UDP requires an established stream"});
    }
    auto state = std::make_shared<TrojanPacketState>(std::move(stream));
    return std::unique_ptr<io::DatagramHandle>(
        std::make_unique<TrojanPacketHandle>(std::move(state)));
}

} // namespace clash_native::transport::trojan
