#include <clash_native/net/tcp_stream.hpp>
#include <clash_native/transport/exchange_session.hpp>
#include <clash_native/transport/grpc_client.hpp>
#include <clash_native/transport/tls_client.hpp>

#include <google/protobuf/wrappers.pb.h>

#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

namespace {

using namespace std::chrono_literals;
using clash_native::transport::ExchangeSession;
using clash_native::transport::GrpcCallOptions;
using clash_native::transport::GrpcClient;
using clash_native::transport::GrpcClientCall;
using clash_native::transport::GrpcMetadata;

struct ServerAddress {
    boost::asio::ip::address address;
    std::uint16_t port = 0;
};

ServerAddress parse_address(std::string_view value) {
    const auto separator = value.rfind(':');
    if (separator == std::string_view::npos || separator == 0 || separator + 1 == value.size()) {
        throw std::runtime_error("server must be formatted as IPv4:port");
    }
    unsigned int port = 0;
    for (const char character : value.substr(separator + 1)) {
        if (character < '0' || character > '9') {
            throw std::runtime_error("server port is invalid");
        }
        port = port * 10 + static_cast<unsigned int>(character - '0');
        if (port > 65535) {
            throw std::runtime_error("server port is out of range");
        }
    }
    if (port == 0) {
        throw std::runtime_error("server port is out of range");
    }
    boost::system::error_code error;
    const auto address = boost::asio::ip::make_address(value.substr(0, separator), error);
    if (error || !address.is_v4()) {
        throw std::runtime_error("server must use an IPv4 address");
    }
    return {address, static_cast<std::uint16_t>(port)};
}

std::string read_file(const char *path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("failed to open the gRPC fixture CA file");
    }
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

std::optional<std::string> environment_value(const char *name) {
#ifdef _WIN32
    char *value = nullptr;
    std::size_t length = 0;
    if (_dupenv_s(&value, &length, name) != 0 || value == nullptr) {
        return std::nullopt;
    }
    std::string result(value, length == 0 ? 0 : length - 1);
    std::free(value);
    return result;
#else
    const auto *value = std::getenv(name);
    if (value == nullptr) {
        return std::nullopt;
    }
    return std::string(value);
#endif
}

std::string metadata_value(const std::vector<GrpcMetadata> &metadata, std::string_view name) {
    for (const auto &item : metadata) {
        if (item.name == name) {
            return item.value;
        }
    }
    return {};
}

class GrpcProbe final : public std::enable_shared_from_this<GrpcProbe> {
  public:
    GrpcProbe(boost::asio::io_context &context, std::string mode)
        : context_(context), mode_(std::move(mode)), timer_(context) {}

    void start(std::shared_ptr<ExchangeSession> session) {
        session_ = std::move(session);
        timer_.expires_after(20s);
        const auto self = shared_from_this();
        timer_.async_wait([self](const boost::system::error_code &error) {
            if (!error) {
                self->finish("gRPC interoperability probe timed out");
            }
        });

        GrpcCallOptions options;
        options.scheme = "https";
        options.authority = "localhost";
        options.method = mode_ == "trailers-only"
                             ? "/clash_native.grpc.InteroperabilityService/UnaryError"
                         : mode_ == "bidi" ? "/clash_native.grpc.InteroperabilityService/Chat"
                                           : "/clash_native.grpc.InteroperabilityService/UnaryEcho";
        options.deadline = std::chrono::steady_clock::now() + 15s;
        options.metadata.push_back({"x-client-tag", "clash-native-grpc-test"});
        options.metadata.push_back({"x-opaque-bin", std::string("\0\x7f\xff", 3)});
        GrpcClient client(context_.get_executor(), session_);
        const auto self_call = shared_from_this();
        call_ =
            client.start_call(std::move(options), [self_call](clash_native::core::Status result) {
                self_call->on_open(std::move(result));
            });
        if (mode_ == "unary") {
            send_unary_request("hello from clash-native");
        } else if (mode_ == "trailers-only") {
            send_unary_request("trigger-error");
        } else {
            send_next_bidi_message();
        }
        read_next();
    }

    bool succeeded() const noexcept { return finished_ && error_.empty(); }
    const std::string &error() const noexcept { return error_; }
    void fail(std::string error) { finish(std::move(error)); }

  private:
    void on_open(clash_native::core::Status result) {
        if (!result) {
            finish("gRPC call failed to open: " + result.error().context);
            return;
        }
        const auto expected_header_name = mode_ == "bidi" ? "x-stream-header" : "x-server-header";
        const auto expected_header_value = mode_ == "bidi" ? "bidi-started" : "grpc-header";
        if (mode_ != "trailers-only" &&
            metadata_value(call_->initial_metadata(), expected_header_name) !=
                expected_header_value) {
            finish("gRPC response did not contain expected initial metadata");
            return;
        }
    }

    void send_unary_request(std::string value) {
        google::protobuf::StringValue request;
        request.set_value(std::move(value));
        const auto self = shared_from_this();
        call_->async_write(request, [self](clash_native::core::Status result) {
            if (!result) {
                self->finish("gRPC request write failed: " + result.error().context);
                return;
            }
            self->call_->close_send();
        });
    }

    void send_next_bidi_message() {
        if (send_index_ >= 3 || finished_) {
            if (send_index_ == 3 && !send_closed_) {
                send_closed_ = true;
                call_->close_send();
            }
            return;
        }
        google::protobuf::StringValue request;
        request.set_value("message-" + std::to_string(send_index_ + 1));
        const auto self = shared_from_this();
        call_->async_write(request, [self](clash_native::core::Status result) {
            if (!result) {
                self->finish("gRPC stream request write failed: " + result.error().context);
                return;
            }
            ++self->send_index_;
            self->send_next_bidi_message();
        });
    }

    void read_next() {
        if (finished_) {
            return;
        }
        const auto self = shared_from_this();
        call_->async_read_protobuf(response_,
                                   [self](clash_native::core::Result<bool> result) mutable {
                                       self->on_read(std::move(result));
                                   });
    }

    void on_read(clash_native::core::Result<bool> result) {
        if (!result) {
            finish("gRPC response read failed: " + result.error().context);
            return;
        }
        if (*result) {
            if (mode_ == "unary") {
                if (response_.value() != "hello from Go gRPC: hello from clash-native") {
                    finish("gRPC unary response protobuf did not match the expected value");
                    return;
                }
                ++received_count_;
            } else if (mode_ == "bidi") {
                if (received_count_ >= 3 ||
                    response_.value() != "echo:message-" + std::to_string(received_count_ + 1)) {
                    finish("gRPC bidirectional response messages were out of order");
                    return;
                }
                ++received_count_;
            } else {
                finish("trailers-only gRPC error unexpectedly carried a response message");
                return;
            }
            read_next();
            return;
        }
        const auto &status = call_->status();
        if (!status) {
            finish("gRPC call reached EOF without a final status");
            return;
        }
        if (mode_ == "trailers-only") {
            if (status->code != 7 || status->message != "fixture rejected request") {
                finish("trailers-only gRPC status or message was incorrect");
                return;
            }
        } else if (status->code != 0) {
            finish("gRPC call returned non-OK status " + std::to_string(status->code) + ": " +
                   status->message);
            return;
        }
        if (mode_ == "unary" && received_count_ != 1) {
            finish("gRPC unary call returned an unexpected number of messages");
            return;
        }
        if (mode_ == "bidi" && (received_count_ != 3 || !send_closed_)) {
            finish("gRPC bidirectional stream did not exchange all messages and half-close");
            return;
        }
        const auto expected_trailer_name =
            mode_ == "bidi" ? "x-stream-trailer" : "x-server-trailer";
        const auto expected_trailer_value = mode_ == "bidi" ? "bidi-complete" : "grpc-trailer";
        if (mode_ != "trailers-only" &&
            metadata_value(status->trailing_metadata, expected_trailer_name) !=
                expected_trailer_value) {
            finish("gRPC response did not contain expected trailing metadata");
            return;
        }
        if (mode_ == "unary" && metadata_value(status->trailing_metadata, "x-opaque-bin") !=
                                    std::string("\0\x01\xff", 3)) {
            finish("gRPC binary trailing metadata did not round-trip");
            return;
        }
        finish({});
    }

    void finish(std::string error) {
        if (finished_) {
            return;
        }
        finished_ = true;
        error_ = std::move(error);
        (void)timer_.cancel();
        if (session_) {
            session_->stop();
            session_.reset();
        }
        call_.reset();
    }

    boost::asio::io_context &context_;
    std::string mode_;
    boost::asio::steady_timer timer_;
    std::shared_ptr<ExchangeSession> session_;
    std::shared_ptr<GrpcClientCall> call_;
    google::protobuf::StringValue response_;
    std::size_t send_index_ = 0;
    std::size_t received_count_ = 0;
    bool send_closed_ = false;
    bool finished_ = false;
    std::string error_;
};

int run_probe(const ServerAddress &server, const std::string &mode) {
    const auto ca_path = environment_value("CLASH_NATIVE_TEST_OUTBOUND_CA_FILE");
    if (!ca_path || ca_path->empty()) {
        throw std::runtime_error("CLASH_NATIVE_TEST_OUTBOUND_CA_FILE is required");
    }
    const auto ca_pem = read_file(ca_path->c_str());
    boost::asio::io_context context;
    boost::asio::ip::tcp::socket socket(context);
    socket.connect({server.address.to_v4(), server.port});
    auto stream = std::make_unique<clash_native::net::TcpStream>(std::move(socket));
    auto probe = std::make_shared<GrpcProbe>(context, mode);
    clash_native::transport::TlsClientOptions options;
    options.server_name = "localhost";
    options.verify_peer = true;
    options.trusted_ca_pem = ca_pem;
    options.alpn_protocols = {"h2"};
    options.deadline = std::chrono::steady_clock::now() + 10s;
    (void)clash_native::transport::async_tls_client_handshake(
        std::move(stream), std::move(options),
        [probe](clash_native::core::Result<clash_native::transport::TlsClientConnection>
                    result) mutable {
            if (!result) {
                return probe->fail("gRPC TLS handshake failed: " + result.error().context);
            }
            if (result->negotiated_alpn != "h2") {
                return probe->fail("gRPC TLS server did not negotiate HTTP/2");
            }
            auto session =
                clash_native::transport::make_http2_exchange_session(std::move(result->stream));
            probe->start(std::move(session));
        });
    context.run();
    if (!probe->succeeded()) {
        spdlog::error("{}", probe->error());
        return 1;
    }
    return 0;
}

} // namespace

int main(int argc, char **argv) {
    auto logger = spdlog::stdout_color_mt("clash-native-grpc-client");
    logger->set_pattern("%v");
    logger->set_level(spdlog::level::info);
    logger->flush_on(spdlog::level::info);
    spdlog::set_default_logger(std::move(logger));

    if (argc != 3) {
        spdlog::error("usage: clash-native-grpc-client <IPv4:port> <unary|trailers-only|bidi>");
        return 2;
    }
    try {
        const auto server = parse_address(argv[1]);
        const std::string mode(argv[2]);
        if (mode != "unary" && mode != "trailers-only" && mode != "bidi") {
            spdlog::error("unsupported gRPC interoperability mode");
            return 2;
        }
        return run_probe(server, mode);
    } catch (const std::exception &error) {
        spdlog::error("{}", error.what());
        return 1;
    }
}
