#pragma once

#include <clash_native/core/result.hpp>

#include <boost/asio/ip/tcp.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace clash_native::transport::shadowsocks {

enum class ObfsMode {
    none,
    http,
    tls,
};

struct ObfsClientOptions {
    ObfsMode mode = ObfsMode::none;
    std::string host;
    std::uint16_t port = 0;
};

struct HttpObfsClientOptions {
    std::string host;
    std::uint16_t port = 0;
};

using HttpObfsRequestHandler = std::function<void(core::Status)>;
using HttpObfsResponseHandler = std::function<void(core::Result<std::vector<std::uint8_t>>)>;

// Sends the HTTP simple-obfs request with the first Shadowsocks wire bytes as
// its body. The request completes after the bytes are written; the server's
// 101 response is read lazily by the first Shadowsocks read operation.
void async_write_http_obfs_request(std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                                   std::vector<std::uint8_t> initial_payload,
                                   HttpObfsClientOptions options, HttpObfsRequestHandler handler);

// Consumes the HTTP simple-obfs 101 response. Any bytes received after the
// response headers are returned for the Shadowsocks stream decoder.
void async_read_http_obfs_response(std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                                   HttpObfsResponseHandler handler);

using TlsObfsRequestHandler = std::function<void(core::Status)>;
using TlsObfsResponseHandler = std::function<void(core::Result<std::vector<std::uint8_t>>)>;

// Sends a simple-obfs TLS-shaped ClientHello with the first Shadowsocks wire
// bytes embedded in the session-ticket extension.
void async_write_tls_obfs_request(std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                                  std::vector<std::uint8_t> initial_payload,
                                  std::string server_name, TlsObfsRequestHandler handler);

// Wraps Shadowsocks wire bytes in fake TLS application records.
void async_write_tls_obfs_records(std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                                  std::vector<std::uint8_t> payload, TlsObfsRequestHandler handler);

// Consumes the fake TLS server handshake and returns the first application
// record payload. The server response is read lazily by the first Shadowsocks
// read operation.
void async_read_tls_obfs_response(std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                                  TlsObfsResponseHandler handler);

// Reads one fake TLS application record and returns its payload.
void async_read_tls_obfs_record(std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                                TlsObfsResponseHandler handler);

} // namespace clash_native::transport::shadowsocks
