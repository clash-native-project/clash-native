#include <clash_native/async/callback_sender.hpp>
#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/core/result.hpp>
#include <clash_native/io/exchange_body_stream.hpp>
#include <clash_native/io/exchange_session.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>
#include <clash_native/net/tcp_stream.hpp>
#include <clash_native/transport/http_sessions.hpp>

#include <gtest/gtest.h>

#include <stdexec/execution.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

namespace {

namespace asio = boost::asio;
namespace http = boost::beast::http;
using clash_native::io::ExchangeField;

// Request-body source for streaming uploads: serves payload_ in pulls,
// then ends. All work posts to the executor so pulls complete even when
// initiated off-thread.
class TestUploadBody final : public clash_native::io::ExchangeBodyStream,
                             public std::enable_shared_from_this<TestUploadBody> {
  public:
    using ReadHandler = std::function<void(const boost::system::error_code &, std::size_t)>;

    TestUploadBody(boost::asio::any_io_executor executor, std::vector<std::uint8_t> payload,
                   std::vector<ExchangeField> trailers)
        : executor_(std::move(executor)), payload_(std::move(payload)),
          trailers_(std::move(trailers)) {}

    clash_native::io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override {
        using Signatures =
            stdexec::completion_signatures<stdexec::set_value_t(std::optional<std::size_t>),
                                           stdexec::set_error_t(std::exception_ptr),
                                           stdexec::set_stopped_t()>;
        return clash_native::io::AnySender<std::optional<std::size_t>>{
            clash_native::async::callback_sender<Signatures>(
                [self = shared_from_this(), buffer](auto terminal) mutable {
                    self->read_some(buffer, std::move(terminal));
                },
                [](auto receiver, const boost::system::error_code &error, std::size_t size) {
                    if (!error) {
                        stdexec::set_value(std::move(receiver), std::optional<std::size_t>{size});
                        return;
                    }
                    if (error == boost::asio::error::eof) {
                        stdexec::set_value(std::move(receiver), std::optional<std::size_t>{});
                        return;
                    }
                    if (error == boost::asio::error::operation_aborted) {
                        stdexec::set_stopped(std::move(receiver));
                        return;
                    }
                    stdexec::set_error(std::move(receiver),
                                       std::make_exception_ptr(clash_native::core::Error{
                                           clash_native::core::ErrorCode::transport_io,
                                           "test upload body read failed", error}));
                })};
    }

    void read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) {
        const auto self = shared_from_this();
        boost::asio::post(executor_, [self, buffer, handler = std::move(handler)]() mutable {
            if (self->cancelled_) {
                handler(boost::asio::error::operation_aborted, 0);
                return;
            }
            if (self->offset_ >= self->payload_.size()) {
                handler(boost::asio::error::eof, 0);
                return;
            }
            const auto amount = std::min(buffer.size(), self->payload_.size() - self->offset_);
            std::memcpy(buffer.data(), self->payload_.data() + self->offset_, amount);
            self->offset_ += amount;
            handler({}, amount);
        });
    }

    std::vector<ExchangeField> trailers() const override { return trailers_; }
    void cancel() noexcept override { cancelled_ = true; }

  private:
    boost::asio::any_io_executor executor_;
    std::vector<std::uint8_t> payload_;
    std::vector<ExchangeField> trailers_;
    std::size_t offset_ = 0;
    bool cancelled_ = false;
};

// Reads a response body stream to EOF on the calling thread. The session
// lives on `context`, so completions post there while this blocks.
std::pair<boost::system::error_code, std::size_t>
pull_once(const std::shared_ptr<clash_native::io::ExchangeBodyStream> &body,
          boost::asio::mutable_buffer buffer) {
    try {
        auto wait = stdexec::sync_wait(body->async_read_some(buffer));
        if (!wait.has_value()) {
            return {boost::asio::error::operation_aborted, 0};
        }
        const auto size = std::get<0>(*wait);
        if (!size) {
            return {boost::asio::error::eof, 0};
        }
        return {{}, *size};
    } catch (...) {
        return {clash_native::net::unpack_error(std::current_exception()), 0};
    }
}

std::vector<std::uint8_t>
read_body_to_end(const std::shared_ptr<clash_native::io::ExchangeBodyStream> &body) {
    std::vector<std::uint8_t> out;
    std::array<std::uint8_t, 16 * 1024> chunk{};
    while (true) {
        const auto [error, size] = pull_once(body, boost::asio::buffer(chunk));
        if (size != 0) {
            out.insert(out.end(), chunk.begin(), chunk.begin() + size);
        }
        if (error) {
            EXPECT_EQ(error, boost::asio::error::eof);
            break;
        }
    }
    // One more pull surfaces EOF to the session and releases the exchange
    // for reuse.
    EXPECT_EQ(pull_once(body, boost::asio::buffer(chunk)).first, boost::asio::error::eof);
    return out;
}

template <class T> std::optional<T> wait_value(std::future<T> &future) {
    if (future.wait_for(std::chrono::seconds(30)) != std::future_status::ready) {
        ADD_FAILURE() << "timed out waiting for the exchange";
        return std::nullopt;
    }
    return future.get();
}

std::vector<std::uint8_t> make_payload(std::size_t size, unsigned int seed) {
    std::vector<std::uint8_t> payload(size);
    for (std::size_t i = 0; i < size; ++i) {
        payload[i] = static_cast<std::uint8_t>((i * 31 + seed) & 0xff);
    }
    return payload;
}

TEST(Http1ExchangeTest, StreamsChunkedUploadAndBackpressuredDownload) {
    asio::io_context context;
    // The session and its sockets live on a worker; this thread drives the
    // blocking peer side and coordinates through futures.
    auto work = std::make_optional<asio::executor_work_guard<asio::io_context::executor_type>>(
        context.get_executor());
    std::thread worker([&] { context.run(); });

    asio::ip::tcp::acceptor acceptor(context, {asio::ip::address_v4::loopback(), 0});
    asio::ip::tcp::socket client(context);
    client.connect({asio::ip::address_v4::loopback(), acceptor.local_endpoint().port()});
    asio::ip::tcp::socket peer(context);
    acceptor.accept(peer);

    const auto upload = make_payload(100 * 1024, 7);
    const std::size_t download_size = 1024 * 1024;
    auto download = make_payload(download_size, 13);

    std::thread server([peer = std::move(peer), upload, download]() mutable {
        try {
            // Exchange 1: chunked upload, chunked download with a trailer.
            {
                boost::beast::flat_buffer buffer;
                http::request_parser<http::string_body> parser;
                boost::system::error_code error;
                http::read(peer, buffer, parser, error);
                if (error) {
                    throw boost::system::system_error(error);
                }
                EXPECT_EQ(parser.get().target(), "/upload");
                const auto &received = parser.get().body();
                EXPECT_EQ(received.size(), upload.size());
                // Byte compare: string::value_type is (signed) char.
                EXPECT_TRUE(std::equal(
                    received.begin(), received.end(), upload.begin(),
                    [](char a, std::uint8_t b) { return static_cast<std::uint8_t>(a) == b; }));
            }
            {
                std::string head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                                   "Trailer: X-Res-Trailer\r\nConnection: keep-alive\r\n\r\n";
                boost::asio::write(peer, boost::asio::buffer(head));
                constexpr std::size_t kChunk = 16384;
                for (std::size_t offset = 0; offset < download.size(); offset += kChunk) {
                    const auto count = std::min(kChunk, download.size() - offset);
                    // Chunk sizes are hexadecimal on the wire.
                    char hex[32];
                    const auto hex_len = std::snprintf(hex, sizeof(hex), "%zx\r\n", count);
                    boost::asio::write(peer,
                                       boost::asio::buffer(hex, static_cast<std::size_t>(hex_len)));
                    boost::asio::write(peer, boost::asio::buffer(download.data() + offset, count));
                    boost::asio::write(peer, boost::asio::buffer("\r\n", 2));
                }
                const std::string tail = "0\r\nX-Res-Trailer: ok\r\n\r\n";
                boost::asio::write(peer, boost::asio::buffer(tail));
            }
            // Exchange 2: content-length upload, content-length download.
            {
                boost::beast::flat_buffer buffer;
                http::request_parser<http::string_body> parser;
                boost::system::error_code error;
                http::read(peer, buffer, parser, error);
                if (error) {
                    throw boost::system::system_error(error);
                }
                EXPECT_EQ(parser.get().target(), "/second");
                EXPECT_EQ(parser.get().body(), "second-upload");
                const std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n"
                                             "Connection: keep-alive\r\n\r\nsecond";
                boost::asio::write(peer, boost::asio::buffer(response));
            }
        } catch (const std::exception &error) {
            ADD_FAILURE() << "test server failed: " << error.what();
        }
    });

    auto session = clash_native::transport::make_http1_exchange_session(
        std::make_unique<clash_native::net::TcpStream>(std::move(client)));
    ASSERT_TRUE(session);

    // Exchange 1: chunked upload with a trailer, then a delayed 1 MiB
    // download that must park the receive queue on its space signal.
    clash_native::io::StreamingExchangeRequest streaming;
    streaming.request.method = "POST";
    streaming.request.scheme = "http";
    streaming.request.authority = "localhost";
    streaming.request.target = "/upload";
    streaming.request.headers.push_back({"Trailer", "X-Req-Trailer"});
    streaming.request.keep_alive = true;
    auto upload_body = std::make_shared<TestUploadBody>(
        context.get_executor(), upload, std::vector<ExchangeField>{{"X-Req-Trailer", "done"}});
    streaming.body = upload_body;

    auto headers_done = std::make_shared<
        std::promise<clash_native::core::Result<clash_native::io::StreamingExchangeResponse>>>();
    auto headers_future = headers_done->get_future();
    struct HeadersReceiver {
        using receiver_concept = stdexec::receiver_tag;
        std::shared_ptr<
            std::promise<clash_native::core::Result<clash_native::io::StreamingExchangeResponse>>>
            done;
        void set_value(clash_native::io::StreamingExchangeResponse response) && noexcept {
            done->set_value(std::move(response));
        }
        void set_error(std::exception_ptr error) && noexcept {
            try {
                std::rethrow_exception(std::move(error));
            } catch (const clash_native::core::Error &failure) {
                done->set_value(clash_native::core::fail(failure));
            } catch (...) {
                done->set_value(clash_native::core::fail(clash_native::core::Error{
                    clash_native::core::ErrorCode::transport_io, "exchange failed"}));
            }
        }
        void set_stopped() && noexcept {
            done->set_value(clash_native::core::fail(clash_native::core::Error{
                clash_native::core::ErrorCode::cancelled, "exchange stopped"}));
        }
    };
    clash_native::async::start_with_receiver(
        session->exchange_streaming(std::move(streaming),
                                    std::chrono::steady_clock::now() + std::chrono::seconds(60)),
        HeadersReceiver{headers_done});
    auto first = wait_value(headers_future);
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(*first) << (*first).error().context;
    EXPECT_EQ((*first)->response.status, 200U);
    ASSERT_TRUE((*first)->body);

    // Let the server fill the 256 KiB receive queue before consuming, so
    // the download task must park and later resume through consumed().
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    const auto downloaded = read_body_to_end((*first)->body);
    ASSERT_EQ(downloaded.size(), download.size());
    EXPECT_TRUE(std::equal(downloaded.begin(), downloaded.end(), download.begin()));
    EXPECT_EQ((*first)->body->trailers().size(), 1U);
    EXPECT_EQ((*first)->body->trailers()[0].name, "X-Res-Trailer");
    EXPECT_EQ((*first)->body->trailers()[0].value, "ok");

    // Exchange 2 reuses the connection: content-length upload exercises
    // the probe path, content-length download the plain path.
    const std::string second_upload = "second-upload";
    clash_native::io::StreamingExchangeRequest second;
    second.request.method = "POST";
    second.request.scheme = "http";
    second.request.authority = "localhost";
    second.request.target = "/second";
    second.request.keep_alive = true;
    second.content_length = second_upload.size();
    second.body = std::make_shared<TestUploadBody>(
        context.get_executor(),
        std::vector<std::uint8_t>(second_upload.begin(), second_upload.end()),
        std::vector<ExchangeField>{});
    auto second_done = std::make_shared<
        std::promise<clash_native::core::Result<clash_native::io::StreamingExchangeResponse>>>();
    auto second_future = second_done->get_future();
    clash_native::async::start_with_receiver(
        session->exchange_streaming(std::move(second),
                                    std::chrono::steady_clock::now() + std::chrono::seconds(60)),
        HeadersReceiver{second_done});
    auto second_response = wait_value(second_future);
    ASSERT_TRUE(second_response.has_value());
    ASSERT_TRUE(*second_response) << (*second_response).error().context;
    EXPECT_EQ((*second_response)->response.status, 200U);
    const auto second_downloaded = read_body_to_end((*second_response)->body);
    EXPECT_EQ(std::string(second_downloaded.begin(), second_downloaded.end()), "second");

    session->stop();
    work.reset();
    context.stop();
    worker.join();
    server.join();
}

} // namespace
