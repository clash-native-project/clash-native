#include <clash_native/io/datagram_handle.hpp>
#include <clash_native/io/exchange_session.hpp>
#include <clash_native/io/multiplexed_session.hpp>
#include <clash_native/io/stream_handle.hpp>
#include <clash_native/net/tcp_stream.hpp>

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <future>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "../core/async_test_helpers.hpp"

namespace {

using clash_native::async::test::EventReceiver;
using clash_native::async::test::OpHolder;
using clash_native::async::test::sync_get;
using clash_native::async::test::wait_get;
using clash_native::io::AnySender;
using clash_native::io::DatagramAddress;
using clash_native::io::DatagramHandle;
using clash_native::io::DatagramPacket;
using clash_native::io::ExchangeBodyStream;
using clash_native::io::ExchangeField;
using clash_native::io::ExchangeSession;
using clash_native::io::MultiplexedSession;
using clash_native::io::MultiplexedStreamRequest;
using clash_native::io::StreamHandle;
using clash_native::io::StreamUpgradeResponse;

// In-memory byte stream: preloaded inbound, vector sink outbound, sticky EOF
// and one-shot error injection. All completions are inline.
class FakeStreamHandle final : public StreamHandle {
  public:
    std::deque<std::uint8_t> inbound;
    std::vector<std::uint8_t> outbound;
    bool eof = false;
    bool fail_read = false;

    AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override {
        if (fail_read) {
            fail_read = false;
            return AnySender<std::optional<std::size_t>>{
                stdexec::just() | stdexec::then([]() -> std::optional<std::size_t> {
                    throw std::runtime_error("fake read failure");
                })};
        }
        std::size_t count = 0;
        auto *data = static_cast<std::uint8_t *>(buffer.data());
        while (count < buffer.size() && !inbound.empty()) {
            data[count++] = inbound.front();
            inbound.pop_front();
        }
        if (count > 0) {
            return AnySender<std::optional<std::size_t>>{
                stdexec::just(std::optional<std::size_t>(count))};
        }
        if (eof) {
            return AnySender<std::optional<std::size_t>>{
                stdexec::just(std::optional<std::size_t>())};
        }
        // No parking in the fake: tests always preload or set EOF first.
        return AnySender<std::optional<std::size_t>>{stdexec::just(std::optional<std::size_t>())};
    }

    AnySender<std::size_t> async_write(boost::asio::const_buffer buffer) override {
        const auto *data = static_cast<const std::uint8_t *>(buffer.data());
        outbound.insert(outbound.end(), data, data + buffer.size());
        return AnySender<std::size_t>{stdexec::just(buffer.size())};
    }

    boost::asio::any_io_executor executor() noexcept override { return {}; }

    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept override {
        error = boost::asio::error::not_connected;
        return {};
    }

    void shutdown_send(boost::system::error_code &error) noexcept override { error.clear(); }

    void close() noexcept override {
        inbound.clear();
        eof = true;
    }
};

TEST(IoHandlesTest, StreamReadWriteEof) {
    FakeStreamHandle stream;
    stream.inbound = {1, 2, 3, 4};
    std::uint8_t chunk[2] = {};
    EXPECT_EQ(sync_get(stream.async_read_some(boost::asio::buffer(chunk))),
              std::optional<std::size_t>(2));
    EXPECT_EQ(chunk[0], 1);
    EXPECT_EQ(chunk[1], 2);
    std::uint8_t rest[8] = {};
    EXPECT_EQ(sync_get(stream.async_read_some(boost::asio::buffer(rest))),
              std::optional<std::size_t>(2));
    stream.eof = true;
    EXPECT_EQ(sync_get(stream.async_read_some(boost::asio::buffer(rest))), std::nullopt);
    const std::uint8_t out[] = {9};
    EXPECT_EQ(sync_get(stream.async_write(boost::asio::buffer(out))), 1U);
    EXPECT_EQ(stream.outbound, (std::vector<std::uint8_t>{9}));
}

TEST(IoHandlesTest, StreamErrorSurfacesAsSetError) {
    FakeStreamHandle stream;
    stream.fail_read = true;
    std::uint8_t chunk[4] = {};
    EXPECT_THROW((void)sync_get(stream.async_read_some(boost::asio::buffer(chunk))),
                 std::runtime_error);
}

class FakeDatagramHandle final : public DatagramHandle {
  public:
    using Packet = std::pair<std::vector<std::uint8_t>, DatagramAddress>;
    std::deque<Packet> inbound;
    std::vector<Packet> outbound;

    AnySender<std::size_t> async_send_to(boost::asio::const_buffer buffer,
                                         DatagramAddress destination) override {
        const auto *data = static_cast<const std::uint8_t *>(buffer.data());
        outbound.emplace_back(std::vector<std::uint8_t>(data, data + buffer.size()),
                              std::move(destination));
        return AnySender<std::size_t>{stdexec::just(buffer.size())};
    }

    AnySender<DatagramPacket> async_receive_from(boost::asio::mutable_buffer buffer) override {
        DatagramPacket packet;
        if (!inbound.empty()) {
            auto &[payload, from] = inbound.front();
            const std::size_t count = std::min(buffer.size(), payload.size());
            std::memcpy(buffer.data(), payload.data(), count);
            packet.size = count;
            packet.address = std::move(from);
            inbound.pop_front();
        }
        return AnySender<DatagramPacket>{stdexec::just(std::move(packet))};
    }

    boost::asio::any_io_executor executor() noexcept override { return {}; }
    void cancel() noexcept override {}
    void close() noexcept override { inbound.clear(); }
};

TEST(IoHandlesTest, DatagramSendReceive) {
    FakeDatagramHandle datagram;
    datagram.inbound.emplace_back(std::vector<std::uint8_t>{7, 8},
                                  DatagramAddress::domain("example.com", 53));
    std::uint8_t slot[8] = {};
    auto received = sync_get(datagram.async_receive_from(boost::asio::buffer(slot)));
    EXPECT_EQ(received.size, 2U);
    EXPECT_EQ(received.address.domain(), "example.com");
    EXPECT_EQ(received.address.port(), 53);
    const std::uint8_t out[] = {1};
    EXPECT_EQ(sync_get(datagram.async_send_to(
                  boost::asio::buffer(out),
                  DatagramAddress::address(boost::asio::ip::make_address("127.0.0.1"), 53))),
              1U);
    ASSERT_EQ(datagram.outbound.size(), 1U);
    EXPECT_EQ(datagram.outbound[0].second.port(), 53);
}

class FakeBodyStream final : public ExchangeBodyStream {
  public:
    explicit FakeBodyStream(std::vector<std::uint8_t> data) : data_(std::move(data)) {}

    AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override {
        std::size_t count = std::min(buffer.size(), data_.size() - offset_);
        std::memcpy(buffer.data(), data_.data() + offset_, count);
        offset_ += count;
        if (count > 0) {
            return AnySender<std::optional<std::size_t>>{
                stdexec::just(std::optional<std::size_t>(count))};
        }
        return AnySender<std::optional<std::size_t>>{stdexec::just(std::optional<std::size_t>())};
    }

    std::vector<ExchangeField> trailers() const override { return {{"grpc-status", "0"}}; }

    void cancel() noexcept override {}

  private:
    std::vector<std::uint8_t> data_;
    std::size_t offset_ = 0;
};

class FakeExchangeSession final : public ExchangeSession {
  public:
    AnySender<clash_native::io::ExchangeResponse>
    exchange(clash_native::io::ExchangeRequest request,
             std::chrono::steady_clock::time_point) override {
        clash_native::io::ExchangeResponse response;
        response.status = 200;
        response.body = request.body;
        return AnySender<clash_native::io::ExchangeResponse>{stdexec::just(std::move(response))};
    }

    AnySender<clash_native::io::StreamingExchangeResponse>
    exchange_streaming(clash_native::io::StreamingExchangeRequest request,
                       std::chrono::steady_clock::time_point) override {
        clash_native::io::StreamingExchangeResponse out;
        out.response.status = 200;
        out.body = std::make_shared<FakeBodyStream>(std::vector<std::uint8_t>{1, 2, 3});
        (void)request;
        return AnySender<clash_native::io::StreamingExchangeResponse>{
            stdexec::just(std::move(out))};
    }

    AnySender<StreamUpgradeResponse> open_tunnel(clash_native::io::StreamUpgradeRequest request,
                                                 std::chrono::steady_clock::time_point) override {
        StreamUpgradeResponse out;
        out.response.status = 101;
        auto stream = std::make_unique<FakeStreamHandle>();
        stream->inbound = {42};
        stream->eof = true;
        out.stream = std::move(stream);
        (void)request;
        return AnySender<StreamUpgradeResponse>{stdexec::just(std::move(out))};
    }

    void cancel(ExchangeId) noexcept override {}
    void stop() noexcept override { stopped = true; }
    bool retired() const noexcept override { return stopped; }

    bool stopped = false;
};

TEST(IoHandlesTest, ExchangeRoundTrip) {
    FakeExchangeSession session;
    clash_native::io::ExchangeRequest request;
    request.target = "/dns-query";
    request.body = {9, 9};
    auto response =
        sync_get(session.exchange(std::move(request), std::chrono::steady_clock::now()));
    EXPECT_EQ(response.status, 200U);
    EXPECT_EQ(response.body, (std::vector<std::uint8_t>{9, 9}));

    clash_native::io::StreamingExchangeRequest streaming;
    auto streaming_response = sync_get(
        session.exchange_streaming(std::move(streaming), std::chrono::steady_clock::now()));
    std::uint8_t chunk[8] = {};
    EXPECT_EQ(sync_get(streaming_response.body->async_read_some(boost::asio::buffer(chunk))),
              std::optional<std::size_t>(3));
    EXPECT_EQ(streaming_response.body->trailers()[0].name, "grpc-status");

    clash_native::io::StreamUpgradeRequest tunnel;
    auto upgraded =
        sync_get(session.open_tunnel(std::move(tunnel), std::chrono::steady_clock::now()));
    EXPECT_EQ(upgraded.response.status, 101U);
    ASSERT_TRUE((bool)upgraded.stream);
    EXPECT_EQ(sync_get(upgraded.stream->async_read_some(boost::asio::buffer(chunk))),
              std::optional<std::size_t>(1));
    EXPECT_EQ(chunk[0], 42);
    EXPECT_TRUE(session.multiplexed_session() == nullptr);
    EXPECT_FALSE(session.open_datagram());
    session.stop();
    EXPECT_TRUE(session.retired());
}

class FakeMultiplexedSession final : public MultiplexedSession {
  public:
    AnySender<std::unique_ptr<StreamHandle>>
    open_stream(MultiplexedStreamRequest, std::chrono::steady_clock::time_point) override {
        ++opened;
        return AnySender<std::unique_ptr<StreamHandle>>{
            stdexec::just(std::unique_ptr<StreamHandle>(std::make_unique<FakeStreamHandle>()))};
    }

    void cancel(StreamId) noexcept override {}
    std::size_t active_streams() const noexcept override { return opened; }
    std::optional<std::size_t> max_concurrent_streams() const noexcept override {
        return std::nullopt;
    }
    void stop() noexcept override { halted = true; }
    bool retired() const noexcept override { return halted; }

    std::size_t opened = 0;
    bool halted = false;
};

// Loopback pair: server side wrapped as the TcpStream under test, peer side
// driven with blocking calls. The io_context runs on a worker so Asio
// completions (and use_sender cancellation) can fire.
struct Loopback {
    boost::asio::io_context context;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{
        context.get_executor()};
    boost::asio::ip::tcp::socket peer{context};
    std::optional<clash_native::net::TcpStream> stream;
    // Backing store for parked pulls: must outlive the operation.
    std::uint8_t parked_buffer_[64] = {};

    Loopback() {
        using boost::asio::ip::tcp;
        tcp::acceptor acceptor(context, tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
        tcp::socket server(context);
        std::promise<void> accepted;
        auto accepted_future = accepted.get_future();
        acceptor.async_accept(server, [&](const boost::system::error_code &error) {
            EXPECT_FALSE(error);
            accepted.set_value();
        });
        worker_ = std::thread([this] { context.run(); });
        peer.connect(tcp::endpoint(boost::asio::ip::address_v4::loopback(),
                                   acceptor.local_endpoint().port()));
        if (accepted_future.wait_for(std::chrono::seconds(5)) != std::future_status::ready) {
            throw std::runtime_error("loopback accept timed out");
        }
        stream.emplace(std::move(server));
    }

    ~Loopback() {
        stream.reset();
        context.stop();
        if (worker_.joinable()) {
            worker_.join();
        }
    }

  private:
    std::thread worker_;
};

TEST(IoHandlesTest, TcpStreamLoopbackReadWriteEof) {
    Loopback loop;
    const std::uint8_t out[] = {1, 2, 3};
    EXPECT_EQ(sync_get(loop.stream->async_write(boost::asio::buffer(out))), 3U);
    std::uint8_t via_peer[8] = {};
    EXPECT_EQ(loop.peer.receive(boost::asio::buffer(via_peer)), 3U);
    EXPECT_EQ(via_peer[0], 1);

    const std::uint8_t back[] = {7, 8};
    EXPECT_EQ(loop.peer.send(boost::asio::buffer(back)), 2U);
    std::uint8_t chunk[8] = {};
    EXPECT_EQ(sync_get(loop.stream->async_read_some(boost::asio::buffer(chunk))),
              std::optional<std::size_t>(2));
    EXPECT_EQ(chunk[0], 7);

    loop.peer.shutdown(boost::asio::ip::tcp::socket::shutdown_send);
    EXPECT_EQ(sync_get(loop.stream->async_read_some(boost::asio::buffer(chunk))), std::nullopt);
}

TEST(IoHandlesTest, TcpStreamStopCancelsParkedRead) {
    Loopback loop;
    stdexec::inplace_stop_source source;
    std::promise<EventReceiver<std::optional<std::size_t>>::Event> done;
    auto future = done.get_future();
    OpHolder parked(loop.stream->async_read_some(boost::asio::buffer(loop.parked_buffer_)),
                    EventReceiver<std::optional<std::size_t>>{{source.get_token()}, &done});
    parked.start();
    source.request_stop();
    auto event = wait_get(future);
    EXPECT_EQ(event.outcome, EventReceiver<std::optional<std::size_t>>::Outcome::kStopped);
    // The stream is still usable after the cancelled pull.
    const std::uint8_t back[] = {9};
    EXPECT_EQ(loop.peer.send(boost::asio::buffer(back)), 1U);
    EXPECT_EQ(sync_get(loop.stream->async_read_some(boost::asio::buffer(loop.parked_buffer_))),
              std::optional<std::size_t>(1));
}

TEST(IoHandlesTest, MultiplexedOpenYieldsUsableStream) {
    FakeMultiplexedSession session;
    auto stream =
        sync_get(session.open_stream(MultiplexedStreamRequest{}, std::chrono::steady_clock::now()));
    ASSERT_TRUE((bool)stream);
    EXPECT_EQ(session.active_streams(), 1U);
    const std::uint8_t out[] = {5};
    EXPECT_EQ(sync_get(stream->async_write(boost::asio::buffer(out))), 1U);
    session.stop();
    EXPECT_TRUE(session.retired());
}

} // namespace
