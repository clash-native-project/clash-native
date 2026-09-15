#include <clash_native/dns/dns_codec.hpp>
#include <clash_native/dns/dns_server.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <algorithm>
#include <array>
#include <system_error>
#include <utility>

namespace clash_native::dns {

namespace {

core::Error listener_error(std::string operation, const boost::system::error_code &error) {
    return {core::ErrorCode::transport_io, "failed to " + std::move(operation),
            std::error_code(error.value(), std::system_category())};
}

DnsAnswer error_answer(const DnsQuestion &question) {
    DnsAnswer answer;
    answer.question = question;
    answer.response_code = 2;
    return answer;
}

} // namespace

DnsServer::DnsServer(runtime::AsioRuntime &runtime, ResolverService &resolver,
                     boost::asio::ip::udp::endpoint udp_endpoint,
                     boost::asio::ip::tcp::endpoint tcp_endpoint)
    : runtime_(runtime), resolver_(resolver), udp_socket_(runtime.context()),
      tcp_acceptor_(runtime.context()), udp_endpoint_(udp_endpoint), tcp_endpoint_(tcp_endpoint) {}

DnsServer::~DnsServer() { stop(); }

core::Status DnsServer::start() {
    if (running_) {
        return {};
    }

    boost::system::error_code error;
    udp_socket_.open(udp_endpoint_.protocol(), error);
    if (!error) {
        udp_socket_.set_option(boost::asio::socket_base::reuse_address(true), error);
    }
    if (!error) {
        udp_socket_.bind(udp_endpoint_, error);
    }
    if (!error) {
        tcp_acceptor_.open(tcp_endpoint_.protocol(), error);
    }
    if (!error) {
        tcp_acceptor_.set_option(boost::asio::socket_base::reuse_address(true), error);
    }
    if (!error) {
        tcp_acceptor_.bind(tcp_endpoint_, error);
    }
    if (!error) {
        tcp_acceptor_.listen(boost::asio::socket_base::max_listen_connections, error);
    }
    if (error) {
        boost::system::error_code ignored;
        udp_socket_.close(ignored);
        tcp_acceptor_.close(ignored);
        return core::fail(listener_error("open the local DNS server", error));
    }

    udp_endpoint_ = udp_socket_.local_endpoint(error);
    if (!error) {
        tcp_endpoint_ = tcp_acceptor_.local_endpoint(error);
    }
    if (error) {
        boost::system::error_code ignored;
        udp_socket_.close(ignored);
        tcp_acceptor_.close(ignored);
        return core::fail(listener_error("query the local DNS server endpoint", error));
    }

    running_ = true;
    receive_udp();
    accept_tcp();
    return {};
}

void DnsServer::stop() noexcept {
    running_ = false;
    boost::system::error_code ignored;
    udp_socket_.cancel(ignored);
    udp_socket_.close(ignored);
    tcp_acceptor_.cancel(ignored);
    tcp_acceptor_.close(ignored);
}

bool DnsServer::running() const noexcept { return running_; }

boost::asio::ip::udp::endpoint DnsServer::udp_endpoint() const noexcept { return udp_endpoint_; }

boost::asio::ip::tcp::endpoint DnsServer::tcp_endpoint() const noexcept { return tcp_endpoint_; }

void DnsServer::receive_udp() {
    if (!running_) {
        return;
    }
    udp_socket_.async_receive_from(
        boost::asio::buffer(udp_buffer_), udp_sender_,
        [this](const boost::system::error_code &error, std::size_t size) {
            if (!error) {
                const auto query = DnsMessageCodec::decode_query(
                    std::span<const std::uint8_t>(udp_buffer_.data(), size));
                if (query) {
                    resolve_udp(std::move(query.value()), udp_sender_);
                }
            }
            if (running_) {
                receive_udp();
            }
        });
}

void DnsServer::accept_tcp() {
    if (!running_) {
        return;
    }
    auto socket = std::make_shared<boost::asio::ip::tcp::socket>(runtime_.context());
    tcp_acceptor_.async_accept(*socket, [this, socket](const boost::system::error_code &error) {
        if (!error && running_) {
            read_tcp_query(socket);
        }
        if (running_) {
            accept_tcp();
        }
    });
}

void DnsServer::read_tcp_query(std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
    auto length = std::make_shared<std::array<std::uint8_t, 2>>();
    boost::asio::async_read(
        *socket, boost::asio::buffer(*length),
        [this, socket, length](const boost::system::error_code &error, std::size_t) {
            if (error) {
                return;
            }
            const auto size = static_cast<std::size_t>((*length)[0] << 8 | (*length)[1]);
            if (size == 0 || size > udp_buffer_.size()) {
                boost::system::error_code ignored;
                socket->close(ignored);
                return;
            }
            auto payload = std::make_shared<std::vector<std::uint8_t>>(size);
            boost::asio::async_read(
                *socket, boost::asio::buffer(*payload),
                [this, socket, payload](const boost::system::error_code &read_error, std::size_t) {
                    if (read_error) {
                        return;
                    }
                    const auto query = DnsMessageCodec::decode_query(*payload);
                    if (query) {
                        resolve_tcp(socket, std::move(query.value()));
                        return;
                    }
                    boost::system::error_code ignored;
                    socket->close(ignored);
                });
        });
}

void DnsServer::resolve_udp(DnsQuery query, boost::asio::ip::udp::endpoint sender) {
    resolver_.resolve(query.question, [this, query = std::move(query),
                                       sender](core::Result<DnsAnswer> result) mutable {
        if (!running_) {
            return;
        }
        const auto answer = result ? result.value() : error_answer(query.question);
        const auto response = DnsMessageCodec::encode_response(query, answer);
        if (!response) {
            return;
        }
        auto payload = std::make_shared<std::vector<std::uint8_t>>(response.value());
        udp_socket_.async_send_to(boost::asio::buffer(*payload), sender,
                                  [payload](const boost::system::error_code &, std::size_t) {});
    });
}

void DnsServer::resolve_tcp(std::shared_ptr<boost::asio::ip::tcp::socket> socket, DnsQuery query) {
    resolver_.resolve(query.question, [this, socket = std::move(socket), query = std::move(query)](
                                          core::Result<DnsAnswer> result) mutable {
        if (!running_) {
            return;
        }
        const auto answer = result ? result.value() : error_answer(query.question);
        const auto response = DnsMessageCodec::encode_response(query, answer);
        if (!response || response.value().size() > 0xffff) {
            boost::system::error_code ignored;
            socket->close(ignored);
            return;
        }
        auto frame = std::make_shared<std::vector<std::uint8_t>>();
        frame->reserve(2 + response.value().size());
        frame->push_back(static_cast<std::uint8_t>(response.value().size() >> 8));
        frame->push_back(static_cast<std::uint8_t>(response.value().size() & 0xff));
        frame->insert(frame->end(), response.value().begin(), response.value().end());
        boost::asio::async_write(*socket, boost::asio::buffer(*frame),
                                 [socket, frame](const boost::system::error_code &, std::size_t) {
                                     boost::system::error_code ignored;
                                     socket->close(ignored);
                                 });
    });
}

} // namespace clash_native::dns
