#pragma once

#include <clash_native/net/udp_stream.hpp>
#include <clash_native/runtime/runtime_snapshot.hpp>

#include <boost/asio/ip/udp.hpp>

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace clash_native::proxy {

class ProxyServer;

class Socks5UdpListener final : public std::enable_shared_from_this<Socks5UdpListener> {
  public:
    explicit Socks5UdpListener(ProxyServer &owner);

    core::Status start(boost::asio::ip::udp::endpoint endpoint);
    void stop() noexcept;
    std::optional<boost::asio::ip::udp::endpoint> endpoint() const noexcept;

  private:
    struct Path {
        std::string key;
        std::shared_ptr<core::DatagramHandle> handle;
        boost::asio::ip::udp::endpoint target;
        boost::asio::ip::udp::endpoint client;
        std::vector<std::uint8_t> receive_buffer;
    };

    void receive();
    void process(std::size_t size, boost::asio::ip::udp::endpoint client);
    void send_payload(const std::shared_ptr<Path> &path,
                      std::shared_ptr<std::vector<std::uint8_t>> payload);
    void receive_response(const std::shared_ptr<Path> &path);
    void send_response(const std::shared_ptr<Path> &path, core::DatagramAddress source,
                       std::span<const std::uint8_t> payload);
    static std::string path_key(const boost::asio::ip::udp::endpoint &client,
                                const core::Destination &destination);

    ProxyServer &owner_;
    std::shared_ptr<net::UdpStream> socket_;
    runtime::RuntimeSnapshotPtr snapshot_;
    std::optional<boost::asio::ip::udp::endpoint> endpoint_;
    std::array<std::uint8_t, 65507> receive_buffer_{};
    std::unordered_map<std::string, std::shared_ptr<Path>> paths_;
    std::unordered_map<std::string, std::vector<std::shared_ptr<std::vector<std::uint8_t>>>>
        pending_;
    bool stopped_ = true;
};

} // namespace clash_native::proxy
