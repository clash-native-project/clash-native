#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/io/exchange_session.hpp>
#include <clash_native/io/stream_handle.hpp>
#include <clash_native/net/udp_stream.hpp>
#include <clash_native/proxy/proxy_server.hpp>
#include <clash_native/proxy/tcp_relay.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http.hpp>

#include <exec/async_scope.hpp>
#include <exec/task.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace clash_native::proxy {

inline constexpr std::uint8_t kSocksVersion = 0x05;
inline constexpr std::uint8_t kNoAuthentication = 0x00;
inline constexpr std::uint8_t kUsernamePasswordAuthentication = 0x02;
inline constexpr std::uint8_t kNoAcceptableMethods = 0xff;
inline constexpr std::uint8_t kSocksAuthVersion = 0x01;
inline constexpr std::uint8_t kConnectCommand = 0x01;
inline constexpr std::uint8_t kUdpAssociateCommand = 0x03;
inline constexpr auto kHandshakeTimeout = std::chrono::seconds(10);
inline constexpr std::size_t kMaxUdpPathsPerAssociation = 128;

enum class HttpAuthenticationResult {
    accepted,
    missing,
    rejected,
};

std::uint8_t socks_error_code(const std::optional<core::Error> &error);

class ProxyStream : public io::StreamHandle {
  public:
    using executor_type = boost::asio::any_io_executor;
    using Socket = boost::asio::ip::tcp::socket;
    using TlsSocket = boost::asio::ssl::stream<Socket>;
    using Stream = std::variant<std::unique_ptr<Socket>, std::unique_ptr<TlsSocket>>;
    using ReadHandler = std::function<void(const boost::system::error_code &, std::size_t)>;
    using WriteHandler = std::function<void(const boost::system::error_code &, std::size_t)>;

    ProxyStream(Socket socket, std::shared_ptr<boost::asio::ssl::context> tls_context);

    void async_server_handshake(std::function<void(const boost::system::error_code &)> handler);
    bool tls_enabled() const noexcept;
    // Handler-style reads/writes stay for the Asio composed operations
    // and Beast parsers that drive the proxy handshakes structurally.
    void async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler);
    template <typename Handler>
    void async_read_some(boost::asio::mutable_buffer buffer, Handler &&handler) {
        std::visit(
            [buffer, &handler](auto &stream) {
                stream->async_read_some(buffer, std::forward<Handler>(handler));
            },
            stream_);
    }
    void async_write(boost::asio::const_buffer buffer, WriteHandler handler);
    io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override;
    io::AnySender<std::size_t> async_write(boost::asio::const_buffer buffer) override;
    template <typename Handler>
    void async_write_some(boost::asio::const_buffer buffer, Handler &&handler) {
        std::visit(
            [buffer, &handler](auto &stream) {
                stream->async_write_some(buffer, std::forward<Handler>(handler));
            },
            stream_);
    }
    boost::asio::any_io_executor executor() noexcept override;
    boost::asio::any_io_executor get_executor() const noexcept;
    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept override;
    boost::asio::ip::tcp::endpoint remote_endpoint(boost::system::error_code &error) const noexcept;
    void shutdown_send(boost::system::error_code &error) noexcept override;
    void shutdown_receive(boost::system::error_code &error) noexcept;
    void cancel(boost::system::error_code &error) noexcept;
    void close() noexcept override;
    std::unique_ptr<io::StreamHandle> detach();

  private:
    ProxyStream(Stream stream, boost::asio::any_io_executor executor,
                std::shared_ptr<boost::asio::ssl::context> tls_context);

    template <typename Function>
    boost::asio::ip::tcp::endpoint endpoint(Function function,
                                            boost::system::error_code &error) const noexcept;
    template <typename Function> void visit_socket(Function function) noexcept;
    void shutdown(Socket::shutdown_type direction, boost::system::error_code &error) noexcept;

    Stream stream_;
    boost::asio::any_io_executor executor_;
    std::shared_ptr<boost::asio::ssl::context> tls_context_;
    bool detached_ = false;
};

class ProxyRequestBodyStream final : public io::ExchangeBodyStream,
                                     public std::enable_shared_from_this<ProxyRequestBodyStream> {
  public:
    using Parser = boost::beast::http::request_parser<boost::beast::http::buffer_body>;
    using ByteHandler = std::function<void(std::size_t)>;
    using ReadHandler = std::function<void(const boost::system::error_code &, std::size_t)>;

    ProxyRequestBodyStream(ProxyStream &socket, boost::beast::flat_buffer &buffer,
                           std::shared_ptr<Parser> parser, std::size_t initial_header_count,
                           std::unordered_set<std::string> declared_trailers,
                           ByteHandler byte_handler);
    io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override;
    std::vector<io::ExchangeField> trailers() const override;
    void cancel() noexcept override;

  private:
    void read_some(boost::asio::mutable_buffer buffer, ReadHandler handler);
    void retry_read(boost::asio::mutable_buffer buffer, ReadHandler handler);
    void post_read(ReadHandler handler, boost::system::error_code error, std::size_t size);

    ProxyStream &socket_;
    boost::beast::flat_buffer &buffer_;
    std::shared_ptr<Parser> parser_;
    boost::asio::any_io_executor executor_;
    std::size_t initial_header_count_ = 0;
    std::unordered_set<std::string> declared_trailers_;
    ByteHandler byte_handler_;
    bool reading_ = false;
    bool cancelled_ = false;
};

class ProxySession final : public std::enable_shared_from_this<ProxySession> {
  public:
    using CloseHandler = std::function<void(const std::shared_ptr<ProxySession> &)>;

    ProxySession(ProxyServer &owner, boost::asio::ip::tcp::socket client,
                 CloseHandler close_handler);
    void start();
    void stop() noexcept;

  private:
    struct UdpPath {
        std::string key;
        std::shared_ptr<io::DatagramHandle> handle;
        boost::asio::ip::udp::endpoint target;
        boost::asio::ip::udp::endpoint response_source;
        std::vector<std::uint8_t> receive_buffer;
    };

    enum class Protocol {
        socks4,
        socks5,
        http,
    };

    void reset_handshake_timer();
    void cancel_handshake_timer() noexcept;
    void read_protocol_byte();
    void read_socks4_request();
    void read_socks4_user_id();
    void read_socks4_domain();
    void open_socks4_target();
    void open_target(core::Destination destination);
    void handle_open_result(core::StreamOpenResult result);
    void start_relay();
    void close() noexcept;

    static exec::task<void> read_handshake_exact(std::shared_ptr<ProxySession> self,
                                                 boost::asio::mutable_buffer buffer);
    static exec::task<void> write_handshake_all(std::shared_ptr<ProxySession> self,
                                                boost::asio::const_buffer buffer);
    static exec::task<void> run_socks5_handshake(std::shared_ptr<ProxySession> self);
    std::uint16_t request_port() const noexcept;
    void open_socks_target();
    void open_socks_udp_association();
    void send_socks_udp_associate_reply(const boost::asio::ip::udp::endpoint &endpoint);
    void read_udp_control();
    void read_socks_udp_packet();
    bool accept_udp_sender(const boost::asio::ip::udp::endpoint &sender);
    void process_socks_udp_packet(std::size_t size);
    void send_udp_payload(const std::shared_ptr<UdpPath> &path,
                          std::shared_ptr<std::vector<std::uint8_t>> payload);
    // Single-pull response loop, re-armed per completion; no task needed.
    void receive_udp_response(const std::shared_ptr<UdpPath> &path);
    void send_socks_udp_response(io::DatagramAddress source, std::span<const std::uint8_t> payload);
    void send_socks4_reply(std::uint8_t status, bool start_relay);
    void send_socks_reply(std::uint8_t reply, bool start_relay);

    void read_http_headers();
    HttpAuthenticationResult authenticate_http_request(
        const boost::beast::http::request<boost::beast::http::buffer_body> &request) const;
    bool http_request_keep_alive(
        const boost::beast::http::request<boost::beast::http::buffer_body> &request) const;
    void send_http_auth_response(bool missing, bool keep_alive);
    void begin_http_forward();
    void open_http_forward_target(core::Destination destination);
    void start_http_upgrade_exchange();
    void start_http_forward_exchange();
    void handle_http_upgrade_response(core::Result<io::StreamUpgradeResponse> result);
    void handle_http_forward_response(core::Result<io::StreamingExchangeResponse> result);
    bool http_forward_request_method_is(std::string_view method) const noexcept;
    std::string build_http_upgrade_response_headers(const io::ExchangeResponse &response) const;
    std::string build_http_forward_response_headers(const io::ExchangeResponse &response,
                                                    bool has_body);
    void read_http_forward_response_body();
    void on_http_forward_response_read(const boost::system::error_code &error, std::size_t size);
    void write_http_forward_response_trailers();
    void reset_http_forward_exchange();
    void finish_http_forward();
    void send_http_forward_response(int status, std::string_view reason,
                                    std::string_view extra_headers = {}, bool keep_alive = false);
    void send_http_response(int status, std::string_view reason, bool start_relay);

    ProxyServer &owner_;
    ProxyStream client_;
    boost::asio::steady_timer handshake_timer_;
    // Owns handshake chain tasks; teardown stays guard-driven, so no
    // stop is ever requested.
    exec::async_scope scope_;
    std::unique_ptr<io::StreamHandle> remote_;
    std::shared_ptr<TcpRelay> relay_;
    CloseHandler close_handler_;
    std::optional<observability::ConnectionRegistry::ConnectionId> connection_id_;
    std::atomic_bool closed_{false};
    Protocol protocol_ = Protocol::socks5;
    bool http_forward_ = false;
    bool http_upgrade_forward_ = false;

    std::array<std::uint8_t, 1> protocol_byte_{};
    std::array<std::uint8_t, 8> socks4_request_{};
    std::array<std::uint8_t, 1024> socks4_read_buffer_{};
    std::vector<std::uint8_t> socks4_payload_;
    std::vector<std::uint8_t> socks4_user_id_;
    std::vector<std::uint8_t> socks4_domain_;
    std::array<std::uint8_t, 2> method_header_{};
    std::array<std::uint8_t, 2> method_response_{};
    std::vector<std::uint8_t> methods_;
    std::array<std::uint8_t, 2> auth_header_{};
    std::array<std::uint8_t, 1> auth_password_length_{};
    std::vector<std::uint8_t> auth_username_;
    std::vector<std::uint8_t> auth_password_;
    std::array<std::uint8_t, 2> auth_response_{};
    std::optional<std::string> authenticated_user_;
    std::array<std::uint8_t, 8> socks4_reply_{};
    std::array<std::uint8_t, 4> request_header_{};
    std::array<std::uint8_t, 1> domain_length_{};
    std::vector<std::uint8_t> request_body_;
    std::array<std::uint8_t, 22> reply_{};
    boost::beast::flat_buffer http_buffer_;
    std::shared_ptr<ProxyRequestBodyStream::Parser> http_request_parser_;
    std::shared_ptr<ProxyRequestBodyStream> http_request_body_;
    io::StreamingExchangeRequest http_forward_request_;
    std::string http_forward_request_method_;
    // Single-use forward session: stop() alone tears it down, so no
    // per-exchange id is kept (the io:: vocabulary cancels via stop).
    std::shared_ptr<io::ExchangeSession> http_session_;
    // Separate session for the upgrade (CONNECT tunnel) path; the forward
    // path uses http_session_ above.
    std::shared_ptr<io::ExchangeSession> http_tunnel_session_;
    io::StreamUpgradeRequest http_upgrade_request_;
    io::StreamingExchangeResponse http_forward_response_;
    bool http_client_keep_alive_ = false;
    bool http_exchange_keep_alive_ = false;
    std::array<std::uint8_t, 16 * 1024> http_forward_response_buffer_{};
    std::uint64_t http_forward_request_bytes_ = 0;
    std::uint64_t http_forward_response_bytes_ = 0;
    std::string interim_http_response_;
    std::vector<std::uint8_t> http_initial_data_;
    std::string http_response_;
    std::shared_ptr<net::UdpStream> udp_relay_socket_;
    boost::asio::ip::address udp_control_peer_ = boost::asio::ip::address_v4::any();
    std::optional<boost::asio::ip::udp::endpoint> udp_client_endpoint_;
    std::uint16_t expected_udp_client_port_ = 0;
    std::array<std::uint8_t, 1> udp_control_probe_{};
    std::array<std::uint8_t, 65507> udp_receive_buffer_{};
    runtime::RuntimeSnapshotPtr udp_snapshot_;
    std::unordered_map<std::string, std::shared_ptr<UdpPath>> udp_paths_;
    std::unordered_map<std::string, std::vector<std::shared_ptr<std::vector<std::uint8_t>>>>
        pending_udp_packets_;
    // Guards udp_paths_/pending_udp_packets_: receiver terminals race
    // close() from owner threads during teardown.
    std::mutex udp_paths_mutex_;
};

} // namespace clash_native::proxy
