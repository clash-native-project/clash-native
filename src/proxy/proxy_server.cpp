#include <clash_native/proxy/proxy_server.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace clash_native::proxy {

namespace {

constexpr std::uint8_t kSocksVersion = 0x05;
constexpr std::uint8_t kNoAuthentication = 0x00;
constexpr std::uint8_t kNoAcceptableMethods = 0xff;
constexpr std::uint8_t kConnectCommand = 0x01;

} // namespace

class ProxyServer::Session : public std::enable_shared_from_this<Session> {
  public:
    using CloseHandler = std::function<void(const std::shared_ptr<Session> &)>;

    Session(boost::asio::ip::tcp::socket client, CloseHandler close_handler)
        : client_(std::move(client)), remote_(client_.get_executor()),
          resolver_(client_.get_executor()), close_handler_(std::move(close_handler)) {}

    void start() { read_method_header(); }

    void stop() noexcept { close(); }

  private:
    void read_method_header() {
        auto self = shared_from_this();
        boost::asio::async_read(client_, boost::asio::buffer(method_header_),
                                [self](const boost::system::error_code &error, std::size_t) {
                                    if (error || self->method_header_[0] != kSocksVersion) {
                                        self->close();
                                        return;
                                    }

                                    self->methods_.resize(self->method_header_[1]);
                                    if (self->methods_.empty()) {
                                        self->send_method_response(kNoAcceptableMethods);
                                        return;
                                    }

                                    self->read_methods();
                                });
    }

    void read_methods() {
        auto self = shared_from_this();
        boost::asio::async_read(
            client_, boost::asio::buffer(methods_),
            [self](const boost::system::error_code &error, std::size_t) {
                if (error) {
                    self->close();
                    return;
                }

                const auto method =
                    std::find(self->methods_.begin(), self->methods_.end(), kNoAuthentication);
                self->send_method_response(method == self->methods_.end() ? kNoAcceptableMethods
                                                                          : kNoAuthentication);
            });
    }

    void send_method_response(std::uint8_t method) {
        method_response_ = {kSocksVersion, method};

        auto self = shared_from_this();
        boost::asio::async_write(
            client_, boost::asio::buffer(method_response_),
            [self, method](const boost::system::error_code &error, std::size_t) {
                if (error || method != kNoAuthentication) {
                    self->close();
                    return;
                }

                self->read_request_header();
            });
    }

    void read_request_header() {
        auto self = shared_from_this();
        boost::asio::async_read(client_, boost::asio::buffer(request_header_),
                                [self](const boost::system::error_code &error, std::size_t) {
                                    if (error || self->request_header_[0] != kSocksVersion) {
                                        self->close();
                                        return;
                                    }

                                    if (self->request_header_[1] != kConnectCommand) {
                                        self->send_reply(0x07, false);
                                        return;
                                    }

                                    switch (self->request_header_[3]) {
                                    case 0x01:
                                        self->request_body_.resize(6);
                                        self->read_request_body();
                                        break;
                                    case 0x03:
                                        self->read_domain_length();
                                        break;
                                    case 0x04:
                                        self->request_body_.resize(18);
                                        self->read_request_body();
                                        break;
                                    default:
                                        self->send_reply(0x08, false);
                                        break;
                                    }
                                });
    }

    void read_domain_length() {
        auto self = shared_from_this();
        boost::asio::async_read(client_, boost::asio::buffer(domain_length_),
                                [self](const boost::system::error_code &error, std::size_t) {
                                    if (error || self->domain_length_[0] == 0) {
                                        self->close();
                                        return;
                                    }

                                    self->request_body_.resize(self->domain_length_[0] + 2);
                                    self->read_request_body();
                                });
    }

    void read_request_body() {
        auto self = shared_from_this();
        boost::asio::async_read(client_, boost::asio::buffer(request_body_),
                                [self](const boost::system::error_code &error, std::size_t) {
                                    if (error) {
                                        self->close();
                                        return;
                                    }

                                    self->connect_target();
                                });
    }

    std::uint16_t request_port() const noexcept {
        const auto size = request_body_.size();
        return static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(request_body_[size - 2]) << 8) | request_body_[size - 1]);
    }

    void connect_target() {
        const auto port = request_port();
        switch (request_header_[3]) {
        case 0x01: {
            boost::asio::ip::address_v4::bytes_type bytes{};
            std::copy_n(request_body_.begin(), bytes.size(), bytes.begin());
            connect_target({boost::asio::ip::address_v4(bytes), port});
            return;
        }
        case 0x04: {
            boost::asio::ip::address_v6::bytes_type bytes{};
            std::copy_n(request_body_.begin(), bytes.size(), bytes.begin());
            connect_target({boost::asio::ip::address_v6(bytes), port});
            return;
        }
        case 0x03: {
            const auto host_size = request_body_.size() - 2;
            std::string host(request_body_.begin(), request_body_.begin() + host_size);
            resolve_target(std::move(host), port);
            return;
        }
        default:
            send_reply(0x08, false);
            return;
        }
    }

    void resolve_target(std::string host, std::uint16_t port) {
        auto self = shared_from_this();
        resolver_.async_resolve(
            host, std::to_string(port),
            [self](const boost::system::error_code &error,
                   const boost::asio::ip::tcp::resolver::results_type &results) {
                if (error) {
                    self->send_reply(0x04, false);
                    return;
                }

                auto endpoints =
                    std::make_shared<boost::asio::ip::tcp::resolver::results_type>(results);
                self->connect_target(std::move(endpoints));
            });
    }

    void connect_target(boost::asio::ip::tcp::endpoint endpoint) {
        auto self = shared_from_this();
        remote_.async_connect(endpoint, [self](const boost::system::error_code &error) {
            self->send_reply(error ? 0x05 : 0x00, !error);
        });
    }

    void connect_target(std::shared_ptr<boost::asio::ip::tcp::resolver::results_type> endpoints) {
        auto self = shared_from_this();
        boost::asio::async_connect(remote_, *endpoints,
                                   [self, endpoints](const boost::system::error_code &error,
                                                     const boost::asio::ip::tcp::endpoint &) {
                                       self->send_reply(error ? 0x05 : 0x00, !error);
                                   });
    }

    void send_reply(std::uint8_t reply, bool start_relay) {
        std::size_t reply_size = 10;
        reply_[0] = kSocksVersion;
        reply_[1] = reply;
        reply_[2] = 0x00;
        reply_[3] = 0x01;
        std::fill(reply_.begin() + 4, reply_.begin() + 10, 0);

        if (reply == 0x00) {
            boost::system::error_code error;
            const auto endpoint = remote_.local_endpoint(error);
            if (!error && endpoint.address().is_v6()) {
                reply_[3] = 0x04;
                const auto bytes = endpoint.address().to_v6().to_bytes();
                std::copy(bytes.begin(), bytes.end(), reply_.begin() + 4);
                reply_[20] = static_cast<std::uint8_t>(endpoint.port() >> 8);
                reply_[21] = static_cast<std::uint8_t>(endpoint.port() & 0xff);
                reply_size = 22;
            } else if (!error) {
                const auto bytes = endpoint.address().to_v4().to_bytes();
                std::copy(bytes.begin(), bytes.end(), reply_.begin() + 4);
                reply_[8] = static_cast<std::uint8_t>(endpoint.port() >> 8);
                reply_[9] = static_cast<std::uint8_t>(endpoint.port() & 0xff);
            }
        }

        auto self = shared_from_this();
        boost::asio::async_write(
            client_, boost::asio::buffer(reply_.data(), reply_size),
            [self, start_relay](const boost::system::error_code &error, std::size_t) {
                if (error || !start_relay) {
                    self->close();
                    return;
                }

                self->relay_from_client();
                self->relay_from_remote();
            });
    }

    void relay_from_client() {
        auto self = shared_from_this();
        client_.async_read_some(
            boost::asio::buffer(client_buffer_),
            [self](const boost::system::error_code &error, std::size_t size) {
                if (error) {
                    self->close();
                    return;
                }

                boost::asio::async_write(
                    self->remote_, boost::asio::buffer(self->client_buffer_, size),
                    [self](const boost::system::error_code &write_error, std::size_t) {
                        if (write_error) {
                            self->close();
                            return;
                        }

                        self->relay_from_client();
                    });
            });
    }

    void relay_from_remote() {
        auto self = shared_from_this();
        remote_.async_read_some(
            boost::asio::buffer(remote_buffer_),
            [self](const boost::system::error_code &error, std::size_t size) {
                if (error) {
                    self->close();
                    return;
                }

                boost::asio::async_write(
                    self->client_, boost::asio::buffer(self->remote_buffer_, size),
                    [self](const boost::system::error_code &write_error, std::size_t) {
                        if (write_error) {
                            self->close();
                            return;
                        }

                        self->relay_from_remote();
                    });
            });
    }

    void close() noexcept {
        if (closed_.exchange(true)) {
            return;
        }

        boost::system::error_code ignored;
        resolver_.cancel();
        client_.cancel(ignored);
        client_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored);
        client_.close(ignored);
        remote_.cancel(ignored);
        remote_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored);
        remote_.close(ignored);

        if (close_handler_) {
            close_handler_(shared_from_this());
        }
    }

    boost::asio::ip::tcp::socket client_;
    boost::asio::ip::tcp::socket remote_;
    boost::asio::ip::tcp::resolver resolver_;
    CloseHandler close_handler_;
    std::atomic_bool closed_{false};

    std::array<std::uint8_t, 2> method_header_{};
    std::array<std::uint8_t, 2> method_response_{};
    std::vector<std::uint8_t> methods_;
    std::array<std::uint8_t, 4> request_header_{};
    std::array<std::uint8_t, 1> domain_length_{};
    std::vector<std::uint8_t> request_body_;
    std::array<std::uint8_t, 22> reply_{};
    std::array<std::uint8_t, 8192> client_buffer_{};
    std::array<std::uint8_t, 8192> remote_buffer_{};
};

ProxyServer::ProxyServer(runtime::AsioRuntime &runtime, boost::asio::ip::tcp::endpoint endpoint)
    : runtime_(runtime), acceptor_(runtime.context()), endpoint_(endpoint) {}

ProxyServer::~ProxyServer() { stop(); }

void ProxyServer::set_endpoint(boost::asio::ip::tcp::endpoint endpoint) {
    if (running()) {
        throw std::logic_error("Cannot change a running proxy endpoint");
    }

    endpoint_ = endpoint;
}

void ProxyServer::start() {
    if (running_.exchange(true)) {
        return;
    }

    boost::system::error_code error;
    acceptor_.open(endpoint_.protocol(), error);
    if (!error) {
        acceptor_.set_option(boost::asio::socket_base::reuse_address(true), error);
    }
    if (!error) {
        acceptor_.bind(endpoint_, error);
    }
    if (!error) {
        acceptor_.listen(boost::asio::socket_base::max_listen_connections, error);
    }

    if (error) {
        running_ = false;
        acceptor_.close();
        throw boost::system::system_error(error);
    }

    endpoint_ = acceptor_.local_endpoint(error);
    if (error) {
        running_ = false;
        acceptor_.close();
        throw boost::system::system_error(error);
    }

    accept();
}

void ProxyServer::stop() noexcept {
    if (!running_.exchange(false)) {
        return;
    }

    boost::system::error_code ignored;
    acceptor_.cancel(ignored);
    acceptor_.close(ignored);

    std::vector<SessionPtr> sessions;
    {
        std::lock_guard lock(sessions_mutex_);
        sessions.reserve(sessions_.size());
        for (const auto &session : sessions_) {
            sessions.push_back(session);
        }
        sessions_.clear();
    }

    for (const auto &session : sessions) {
        session->stop();
    }
}

bool ProxyServer::running() const noexcept { return running_.load(); }

boost::asio::ip::tcp::endpoint ProxyServer::endpoint() const noexcept { return endpoint_; }

void ProxyServer::accept() {
    if (!running()) {
        return;
    }

    auto client = std::make_shared<boost::asio::ip::tcp::socket>(runtime_.context());
    acceptor_.async_accept(*client, [this, client](const boost::system::error_code &error) {
        if (!error && running()) {
            auto session = std::make_shared<Session>(
                std::move(*client),
                [this](const SessionPtr &closed_session) { remove_session(closed_session); });
            bool accepted_session = false;
            {
                std::lock_guard lock(sessions_mutex_);
                if (running()) {
                    sessions_.insert(session);
                    accepted_session = true;
                }
            }
            if (accepted_session) {
                session->start();
            } else {
                session->stop();
            }
        }

        if (running()) {
            accept();
        }
    });
}

void ProxyServer::remove_session(const SessionPtr &session) noexcept {
    std::lock_guard lock(sessions_mutex_);
    sessions_.erase(session);
}

} // namespace clash_native::proxy
