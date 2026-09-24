// Two streaming exchanges share one HTTP/2 session; aborting one must
// RST exactly that stream while the sibling runs to completion. The
// server here is a minimal nghttp2 responder over loopback TCP.
#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/io/exchange_session.hpp>
#include <clash_native/io/sender.hpp>
#include <clash_native/net/tcp_stream.hpp>
#include <clash_native/transport/http_sessions.hpp>

#include <gtest/gtest.h>

#include <nghttp2/nghttp2.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexec/execution.hpp>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

struct H2Server {
    boost::asio::ip::tcp::socket socket;
    nghttp2_session *session = nullptr;
    std::atomic<int> requests{0};
    std::atomic<std::int32_t> rst_stream{-1};
    std::promise<void> rst_seen;
    std::map<std::int32_t, std::string> paths;
    std::string body = "sibling-body";
    nghttp2_data_provider2 end_provider{};
    bool done = false;

    static nghttp2_ssize data_read(nghttp2_session *, std::int32_t, std::uint8_t *buf,
                                   std::size_t length, std::uint32_t *data_flags,
                                   nghttp2_data_source *, void *user_data) {
        auto *self = static_cast<H2Server *>(user_data);
        const auto amount = std::min(length, self->body.size());
        std::memcpy(buf, self->body.data(), amount);
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        return static_cast<nghttp2_ssize>(amount);
    }

    static int on_header(nghttp2_session *, const nghttp2_frame *frame, const std::uint8_t *name,
                         std::size_t name_length, const std::uint8_t *value,
                         std::size_t value_length, std::uint8_t, void *user_data) {
        auto *self = static_cast<H2Server *>(user_data);
        if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
            const std::string_view header_name(reinterpret_cast<const char *>(name), name_length);
            if (header_name == ":path") {
                self->paths[frame->hd.stream_id] =
                    std::string(reinterpret_cast<const char *>(value), value_length);
            }
        }
        return 0;
    }

    static int on_frame_recv(nghttp2_session *session, const nghttp2_frame *frame,
                             void *user_data) {
        auto *self = static_cast<H2Server *>(user_data);
        if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
            const std::int32_t stream_id = frame->hd.stream_id;
            self->requests.fetch_add(1);
            nghttp2_nv headers[] = {
                {(std::uint8_t *)":status", (std::uint8_t *)"200", 7, 3, NGHTTP2_NV_FLAG_NONE},
            };
            const auto path = self->paths.find(stream_id);
            const bool probe = path != self->paths.end() && path->second == "/probe";
            // Open HEADERS without END_STREAM (a NULL provider would end
            // the stream inline): held streams stay open until the test
            // drives the abort/completion; the probe EOFs inline.
            std::int32_t submitted = 0;
            if (probe) {
                self->body = "probe-body";
                submitted =
                    nghttp2_submit_response2(session, stream_id, headers, 1, &self->end_provider);
            } else {
                submitted = nghttp2_submit_headers(session, NGHTTP2_FLAG_NONE, stream_id, nullptr,
                                                   headers, 1, nullptr);
            }
            if (submitted != 0) {
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
        } else if (frame->hd.type == NGHTTP2_RST_STREAM) {
            self->rst_stream.store(frame->hd.stream_id);
            try {
                self->rst_seen.set_value();
            } catch (...) {
            }
        }
        return 0;
    }

    explicit H2Server(boost::asio::ip::tcp::socket peer) : socket(std::move(peer)) {
        nghttp2_session_callbacks *callbacks = nullptr;
        nghttp2_session_callbacks_new(&callbacks);
        nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header);
        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv);
        nghttp2_session_server_new(&session, callbacks, this);
        nghttp2_session_callbacks_del(callbacks);
        end_provider.read_callback = data_read;
        nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, nullptr, 0);
    }

    ~H2Server() {
        if (session != nullptr) {
            nghttp2_session_del(session);
        }
    }

    bool flush() {
        // Drain until empty: a single mem_send2 may emit HEADERS while
        // DATA is serialized on a later call.
        for (;;) {
            const std::uint8_t *data = nullptr;
            const auto length = nghttp2_session_mem_send2(session, &data);
            if (length < 0) {
                return false;
            }
            if (length == 0) {
                return true;
            }
            boost::system::error_code error;
            boost::asio::write(socket, boost::asio::buffer(data, static_cast<std::size_t>(length)),
                               error);
            if (error) {
                return false;
            }
        }
    }

    void pump_until_done(std::chrono::seconds budget) {
        if (!flush()) {
            return;
        }
        const auto deadline = std::chrono::steady_clock::now() + budget;
        std::array<std::uint8_t, 16384> buffer{};
        socket.non_blocking(false);
        while (!done && std::chrono::steady_clock::now() < deadline) {
            fd_set readable{};
            FD_ZERO(&readable);
            const auto fd = socket.native_handle();
            FD_SET(fd, &readable);
            timeval timeout{0, 5000};
            const auto ready = ::select(0, &readable, nullptr, nullptr, &timeout);
            if (ready <= 0) {
                continue;
            }
            boost::system::error_code error;
            const auto got = socket.receive(boost::asio::buffer(buffer), 0, error);
            if (error || got == 0) {
                return;
            }
            const auto received =
                nghttp2_session_mem_recv2(session, buffer.data(), static_cast<std::size_t>(got));
            if (received < 0 || !flush()) {
                return;
            }
        }
    }

    void complete_stream(std::int32_t stream) {
        nghttp2_data_provider2 provider{};
        provider.read_callback = data_read;
        nghttp2_submit_data2(session, NGHTTP2_FLAG_END_STREAM, stream, &provider);
        flush();
    }
};

struct HeadReceiver {
    using receiver_concept = stdexec::receiver_tag;
    std::promise<clash_native::io::StreamingExchangeResponse> head;
    // Unqualified: the erased session sender may invoke as an lvalue.
    void set_value(clash_native::io::StreamingExchangeResponse response) noexcept {
        head.set_value(std::move(response));
    }
    void set_error(std::exception_ptr error) noexcept {
        try {
            std::rethrow_exception(std::move(error));
        } catch (...) {
            head.set_exception(std::current_exception());
        }
    }
    void set_stopped() noexcept {
        try {
            throw std::runtime_error("exchange abandoned");
        } catch (...) {
            head.set_exception(std::current_exception());
        }
    }
};

clash_native::io::StreamingExchangeRequest make_streaming_get(const std::string &target) {
    clash_native::io::StreamingExchangeRequest streaming;
    streaming.request.method = "GET";
    streaming.request.scheme = "http";
    streaming.request.authority = "localhost";
    streaming.request.target = target;
    streaming.request.keep_alive = true;
    return streaming;
}

std::vector<std::uint8_t>
read_all(const std::shared_ptr<clash_native::io::ExchangeBodyStream> &body) {
    std::vector<std::uint8_t> out;
    for (;;) {
        std::array<std::uint8_t, 4096> chunk{};
        auto wait = stdexec::sync_wait(body->async_read_some(boost::asio::buffer(chunk)));
        if (!wait) {
            throw std::runtime_error("body read stopped");
        }
        const auto got = std::get<0>(std::move(*wait));
        if (!got) {
            return out;
        }
        out.insert(out.end(), chunk.begin(), chunk.begin() + *got);
    }
}

} // namespace

TEST(Http2StreamingTest, UnaryProbe) {
    boost::asio::io_context context;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{
        context.get_executor()};
    boost::asio::ip::tcp::acceptor acceptor(context, {boost::asio::ip::address_v4::loopback(), 0});
    boost::asio::ip::tcp::socket server_side(context);
    std::thread worker([&] { context.run(); });
    boost::asio::ip::tcp::socket client_side(context);
    client_side.connect(
        {boost::asio::ip::address_v4::loopback(), acceptor.local_endpoint().port()});
    acceptor.accept(server_side);

    H2Server server(std::move(server_side));
    std::thread server_thread([&] { server.pump_until_done(std::chrono::seconds(15)); });

    auto stream = std::make_unique<clash_native::net::TcpStream>(std::move(client_side));
    auto session = clash_native::transport::make_http2_exchange_session(std::move(stream));
    ASSERT_TRUE(session);

    clash_native::io::ExchangeRequest request;
    request.method = "GET";
    request.scheme = "http";
    request.authority = "localhost";
    request.target = "/probe";
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    struct UnaryReceiver {
        using receiver_concept = stdexec::receiver_tag;
        std::promise<clash_native::io::ExchangeResponse> done;
        void set_value(clash_native::io::ExchangeResponse response) noexcept {
            done.set_value(std::move(response));
        }
        void set_error(std::exception_ptr error) noexcept {
            try {
                std::rethrow_exception(std::move(error));
            } catch (...) {
                done.set_exception(std::current_exception());
            }
        }
        void set_stopped() noexcept {
            try {
                throw std::runtime_error("exchange abandoned");
            } catch (...) {
                done.set_exception(std::current_exception());
            }
        }
    };
    // NOTE: name the sender first; argument order is unspecified.
    auto sender = session->exchange(std::move(request), deadline);
    UnaryReceiver receiver;
    auto completed = receiver.done.get_future();
    auto op = stdexec::connect(std::move(sender), std::move(receiver));
    stdexec::start(op);
    ASSERT_EQ(completed.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    const auto response = completed.get();
    EXPECT_EQ(response.status, 200U);
    EXPECT_EQ(std::string(response.body.begin(), response.body.end()), "probe-body");
    server.done = true;
    server_thread.join();
    context.stop();
    worker.join();
}

TEST(Http2StreamingTest, AbortingOneExchangeLeavesSiblingFlowing) {
    boost::asio::io_context context;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{
        context.get_executor()};
    boost::asio::ip::tcp::acceptor acceptor(context, {boost::asio::ip::address_v4::loopback(), 0});
    boost::asio::ip::tcp::socket server_side(context);
    std::thread worker([&] { context.run(); });
    boost::asio::ip::tcp::socket client_side(context);
    client_side.connect(
        {boost::asio::ip::address_v4::loopback(), acceptor.local_endpoint().port()});
    acceptor.accept(server_side);

    H2Server server(std::move(server_side));
    std::thread server_thread([&] { server.pump_until_done(std::chrono::seconds(15)); });

    auto stream = std::make_unique<clash_native::net::TcpStream>(std::move(client_side));
    auto session = clash_native::transport::make_http2_exchange_session(std::move(stream));
    ASSERT_TRUE(session);

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    // NOTE: name each sender first; argument order is unspecified.
    auto first_exchange = session->exchange_streaming(make_streaming_get("/first"), deadline);
    HeadReceiver first_receiver;
    auto first_head = first_receiver.head.get_future();
    auto first_op = stdexec::connect(std::move(first_exchange), std::move(first_receiver));
    stdexec::start(first_op);
    auto second_exchange = session->exchange_streaming(make_streaming_get("/second"), deadline);
    HeadReceiver second_receiver;
    auto second_head = second_receiver.head.get_future();
    auto second_op = stdexec::connect(std::move(second_exchange), std::move(second_receiver));
    stdexec::start(second_op);

    ASSERT_EQ(first_head.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    ASSERT_EQ(second_head.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    auto first_response = first_head.get();
    auto second_response = second_head.get();
    EXPECT_EQ(first_response.response.status, 200U);
    EXPECT_EQ(second_response.response.status, 200U);

    // Abort exactly the first exchange through its response body; the
    // session must RST only that stream (client streams are 1 and 3).
    first_response.body->cancel();
    // Control: the session must still serve new exchanges after the abort.
    auto third_exchange = session->exchange_streaming(make_streaming_get("/third"), deadline);
    HeadReceiver third_receiver;
    auto third_head = third_receiver.head.get_future();
    auto third_op = stdexec::connect(std::move(third_exchange), std::move(third_receiver));
    stdexec::start(third_op);
    EXPECT_EQ(third_head.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    ASSERT_EQ(server.rst_seen.get_future().wait_for(std::chrono::seconds(5)),
              std::future_status::ready);
    EXPECT_EQ(server.rst_stream.load(), 1);

    // The sibling completes untouched.
    server.complete_stream(3);
    const auto body = read_all(second_response.body);
    EXPECT_EQ(std::string(body.begin(), body.end()), "sibling-body");

    server.done = true;
    server_thread.join();
    context.stop();
    worker.join();
}
