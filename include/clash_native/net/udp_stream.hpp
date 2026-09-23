#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/io/datagram_handle.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/ip/udp.hpp>

#include <cstddef>
#include <memory>
#include <optional>

namespace clash_native::net {

// UDP socket over an owned socket: the leaf datagram implementation.
// Sender completions are value / core::Error / stopped.
class UdpStream final : public io::DatagramHandle {
  public:
    explicit UdpStream(boost::asio::any_io_executor executor);
    ~UdpStream() override;

    UdpStream(const UdpStream &) = delete;
    UdpStream &operator=(const UdpStream &) = delete;
    UdpStream(UdpStream &&) = delete;
    UdpStream &operator=(UdpStream &&) = delete;

    void open(boost::asio::ip::udp protocol, boost::system::error_code &error);
    void bind(boost::asio::ip::udp::endpoint endpoint, boost::system::error_code &error);
    void set_buffer_size(int bytes, boost::system::error_code &error);
    void set_dscp(int dscp, boost::system::error_code &error);
    template <typename SettableSocketOption>
    void set_option(const SettableSocketOption &option, boost::system::error_code &error) {
        socket_->set_option(option, error);
    }

    io::AnySender<std::size_t> async_send_to(boost::asio::const_buffer buffer,
                                             io::DatagramAddress destination) override;
    io::AnySender<io::DatagramPacket>
    async_receive_from(boost::asio::mutable_buffer buffer) override;
    boost::asio::any_io_executor executor() noexcept override;
    boost::asio::ip::udp::endpoint local_endpoint(boost::system::error_code &error) const noexcept;
    void cancel() noexcept override;
    void close() noexcept override;

  private:
    std::shared_ptr<boost::asio::ip::udp::socket> socket_;
};

} // namespace clash_native::net
