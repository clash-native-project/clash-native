#include <clash_native/core/error.hpp>
#include <clash_native/io/exchange_session.hpp>
#include <clash_native/io/sender.hpp>
#include <clash_native/transport/proxy/gun_client.hpp>
#include <clash_native/transport/proxy/gun_stream.hpp>

#include <gtest/gtest.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <future>
#include <memory>
#include <optional>
#include <stdexec/execution.hpp>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

template <stdexec::sender S> auto sync_get(S &&sender) {
    auto result = stdexec::sync_wait(std::forward<S>(sender));
    if (!result) {
        throw std::runtime_error("sync_get: sender completed with set_stopped");
    }
    return std::get<0>(std::move(*result));
}

// Scripted response body: canned chunks, then EOF.
class ScriptBody final : public clash_native::io::ExchangeBodyStream {
  public:
    explicit ScriptBody(std::deque<std::vector<std::uint8_t>> chunks)
        : chunks_(std::move(chunks)) {}

    clash_native::io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override {
        if (chunks_.empty()) {
            return clash_native::io::AnySender<std::optional<std::size_t>>{
                stdexec::just(std::optional<std::size_t>{})};
        }
        auto chunk = std::move(chunks_.front());
        chunks_.pop_front();
        const auto size = std::min(buffer.size(), chunk.size());
        std::memcpy(buffer.data(), chunk.data(), size);
        if (size < chunk.size()) {
            chunk.erase(chunk.begin(), chunk.begin() + size);
            chunks_.push_front(std::move(chunk));
        }
        return clash_native::io::AnySender<std::optional<std::size_t>>{
            stdexec::just(std::optional<std::size_t>{size})};
    }

    std::vector<clash_native::io::ExchangeField> trailers() const override { return {}; }
    void cancel() noexcept override {}

  private:
    std::deque<std::vector<std::uint8_t>> chunks_;
};

// Fake HTTP/2 session: serves a canned 200 head plus scripted response
// bytes, and captures the streaming request body for inspection.
class FakeSession final : public clash_native::io::ExchangeSession {
  public:
    explicit FakeSession(std::deque<std::vector<std::uint8_t>> response_chunks)
        : response_chunks_(std::move(response_chunks)) {}
    // Shared-frame mode: every exchange gets its own copy, so sibling
    // streams each see the full script.
    explicit FakeSession(std::vector<std::vector<std::uint8_t>> frames)
        : shared_frames_(std::move(frames)) {}

    clash_native::io::AnySender<clash_native::io::ExchangeResponse>
    exchange(clash_native::io::ExchangeRequest, std::chrono::steady_clock::time_point) override {
        return clash_native::io::AnySender<clash_native::io::ExchangeResponse>{
            stdexec::just_error(std::make_exception_ptr(clash_native::core::Error{
                clash_native::core::ErrorCode::unsupported, "fake session"}))};
    }

    clash_native::io::AnySender<clash_native::io::StreamingExchangeResponse>
    exchange_streaming(clash_native::io::StreamingExchangeRequest request,
                       std::chrono::steady_clock::time_point) override {
        last_request_ = std::move(request.request);
        last_body_ = std::move(request.body);
        clash_native::io::ExchangeResponse head;
        head.status = 200;
        head.keep_alive = true;
        std::deque<std::vector<std::uint8_t>> chunks;
        if (!shared_frames_.empty()) {
            chunks.assign(shared_frames_.begin(), shared_frames_.end());
        } else {
            chunks = std::move(response_chunks_);
        }
        return clash_native::io::AnySender<clash_native::io::StreamingExchangeResponse>{
            stdexec::just(clash_native::io::StreamingExchangeResponse{
                std::move(head), std::make_shared<ScriptBody>(std::move(chunks))})};
    }

    clash_native::io::AnySender<clash_native::io::StreamUpgradeResponse>
    open_tunnel(clash_native::io::StreamUpgradeRequest,
                std::chrono::steady_clock::time_point) override {
        return clash_native::io::AnySender<clash_native::io::StreamUpgradeResponse>{
            stdexec::just_error(std::make_exception_ptr(clash_native::core::Error{
                clash_native::core::ErrorCode::unsupported, "fake session"}))};
    }

    void cancel(ExchangeId) noexcept override {}
    void stop() noexcept override {}
    bool retired() const noexcept override { return false; }

    const clash_native::io::ExchangeRequest &last_request() const { return last_request_; }
    const std::shared_ptr<clash_native::io::ExchangeBodyStream> &last_body() const {
        return last_body_;
    }

  private:
    std::deque<std::vector<std::uint8_t>> response_chunks_;
    std::vector<std::vector<std::uint8_t>> shared_frames_;
    clash_native::io::ExchangeRequest last_request_;
    std::shared_ptr<clash_native::io::ExchangeBodyStream> last_body_;
};

// Executor with a worker thread: the gun bodies post all work.
struct GunEnv {
    boost::asio::io_context context;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{
        context.get_executor()};
    GunEnv() : worker_([this] { context.run(); }) {}
    ~GunEnv() {
        context.stop();
        if (worker_.joinable()) {
            worker_.join();
        }
    }

  private:
    std::thread worker_;
};

std::vector<std::uint8_t>
pull_all(const std::shared_ptr<clash_native::io::ExchangeBodyStream> &body, std::size_t want) {
    std::vector<std::uint8_t> out;
    while (out.size() < want) {
        std::array<std::uint8_t, 65536> chunk{};
        const auto got =
            sync_get(body->async_read_some(boost::asio::buffer(chunk.data(), want - out.size())));
        if (!got) {
            break;
        }
        out.insert(out.end(), chunk.begin(), chunk.begin() + *got);
    }
    return out;
}

} // namespace

TEST(GunFrameTest, EncodesKnownVectors) {
    using clash_native::transport::proxy::gun::encode_frame;
    using clash_native::transport::proxy::gun::uvarint_length;
    EXPECT_EQ(uvarint_length(0), 1U);
    EXPECT_EQ(uvarint_length(127), 1U);
    EXPECT_EQ(uvarint_length(128), 2U);
    EXPECT_EQ(uvarint_length(300), 2U);

    const std::vector<std::uint8_t> empty = encode_frame({});
    EXPECT_EQ(empty, std::vector<std::uint8_t>({0x00, 0x00, 0x00, 0x00, 0x02, 0x0a, 0x00}));

    const std::string payload = "hi";
    const std::vector<std::uint8_t> framed =
        encode_frame({reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()});
    EXPECT_EQ(framed,
              std::vector<std::uint8_t>({0x00, 0x00, 0x00, 0x00, 0x04, 0x0a, 0x02, 'h', 'i'}));
}

TEST(GunStreamTest, PostsTunHeadAndFramesWrites) {
    namespace gun = clash_native::transport::proxy::gun;
    GunEnv env;
    auto session = std::make_shared<FakeSession>(std::deque<std::vector<std::uint8_t>>{});
    gun::GunStreamOptions options;
    options.host = "example.com";
    options.executor = env.context.get_executor();
    std::optional<clash_native::core::Result<std::unique_ptr<clash_native::io::StreamHandle>>>
        opened;
    // The fake head completes inline, so the handler fires synchronously.
    gun::async_open_gun_stream(
        session, options,
        [&](clash_native::core::Result<std::unique_ptr<clash_native::io::StreamHandle>> result) {
            opened = std::move(result);
        });
    ASSERT_TRUE(opened);
    ASSERT_TRUE(*opened);
    auto stream = std::move(opened->value());

    EXPECT_EQ(session->last_request().method, "POST");
    EXPECT_EQ(session->last_request().target, "/GunService/Tun");
    EXPECT_EQ(session->last_request().authority, "example.com");

    const std::string payload = "tun payload";
    // Writes complete when consumed, so pull concurrently like a session.
    auto pulled = std::async(
        std::launch::async, [&] { return pull_all(session->last_body(), 6 + 1 + payload.size()); });
    EXPECT_EQ(sync_get(stream->async_write(boost::asio::buffer(payload))), payload.size());
    const auto wire = pulled.get();
    const auto expected =
        gun::encode_frame({reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()});
    EXPECT_EQ(wire, expected);
    stream->close();
}

TEST(GunStreamTest, DecodesResponseFramesWithRemainder) {
    namespace gun = clash_native::transport::proxy::gun;
    GunEnv env;
    const std::string first = "first-message";
    const std::string second = "second";
    auto frame = [&](const std::string &text) {
        return gun::encode_frame(
            {reinterpret_cast<const std::uint8_t *>(text.data()), text.size()});
    };
    std::deque<std::vector<std::uint8_t>> chunks;
    chunks.push_back(frame(first));
    chunks.push_back(frame(second));
    auto session = std::make_shared<FakeSession>(std::move(chunks));
    gun::GunStreamOptions options;
    options.host = "example.com";
    options.executor = env.context.get_executor();
    std::optional<clash_native::core::Result<std::unique_ptr<clash_native::io::StreamHandle>>>
        opened;
    gun::async_open_gun_stream(
        session, options,
        [&](clash_native::core::Result<std::unique_ptr<clash_native::io::StreamHandle>> result) {
            opened = std::move(result);
        });
    ASSERT_TRUE(opened && *opened);
    auto stream = std::move(opened->value());

    // Small reads split the first frame across pulls (remain handling).
    std::array<std::uint8_t, 4> piece{};
    std::string collected;
    for (std::size_t index = 0; index < 4; ++index) {
        const auto got = sync_get(stream->async_read_some(boost::asio::buffer(piece)));
        ASSERT_TRUE(got);
        collected.append(reinterpret_cast<const char *>(piece.data()), *got);
        if (collected.size() == first.size()) {
            break;
        }
    }
    EXPECT_EQ(collected, first);
    std::array<std::uint8_t, 64> rest{};
    const auto got = sync_get(stream->async_read_some(boost::asio::buffer(rest)));
    ASSERT_TRUE(got);
    EXPECT_EQ(std::string(reinterpret_cast<const char *>(rest.data()), *got), second);
    stream->close();
}

TEST(GunClientTest, SharesOneSessionByDefault) {
    namespace gun = clash_native::transport::proxy::gun;
    GunEnv env;
    std::atomic<int> sessions{0};
    gun::GunClientOptions options;
    options.stream.host = "example.com";
    options.stream.executor = env.context.get_executor();
    auto client = std::make_shared<gun::GunClient>(
        options,
        [&]() -> clash_native::io::AnySender<std::shared_ptr<clash_native::io::ExchangeSession>> {
            ++sessions;
            return clash_native::io::AnySender<std::shared_ptr<clash_native::io::ExchangeSession>>{
                stdexec::just(std::static_pointer_cast<clash_native::io::ExchangeSession>(
                    std::make_shared<FakeSession>(std::deque<std::vector<std::uint8_t>>{})))};
        });
    auto first = sync_get(client->dial());
    auto second = sync_get(client->dial());
    EXPECT_EQ(sessions.load(), 1);
    first->close();
    second->close();
    client->close();
}

TEST(GunClientTest, GrowsTransportsPastMaxStreams) {
    namespace gun = clash_native::transport::proxy::gun;
    GunEnv env;
    std::atomic<int> sessions{0};
    gun::GunClientOptions options;
    options.stream.host = "example.com";
    options.stream.executor = env.context.get_executor();
    options.max_connections = 0;
    options.max_streams = 1;
    auto client = std::make_shared<gun::GunClient>(
        options,
        [&]() -> clash_native::io::AnySender<std::shared_ptr<clash_native::io::ExchangeSession>> {
            ++sessions;
            return clash_native::io::AnySender<std::shared_ptr<clash_native::io::ExchangeSession>>{
                stdexec::just(std::static_pointer_cast<clash_native::io::ExchangeSession>(
                    std::make_shared<FakeSession>(std::deque<std::vector<std::uint8_t>>{})))};
        });
    auto first = sync_get(client->dial());
    auto second = sync_get(client->dial());
    EXPECT_EQ(sessions.load(), 2);
    first->close();
    second->close();
    client->close();
}

TEST(GunStreamTest, ClosingOneStreamLeavesSiblingFlowing) {
    namespace gun = clash_native::transport::proxy::gun;
    GunEnv env;
    const std::string payload = "sibling";
    auto frame =
        gun::encode_frame({reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()});
    auto session = std::make_shared<FakeSession>(std::vector<std::vector<std::uint8_t>>{frame});
    gun::GunStreamOptions options;
    options.host = "example.com";
    options.executor = env.context.get_executor();
    std::unique_ptr<clash_native::io::StreamHandle> first;
    std::unique_ptr<clash_native::io::StreamHandle> second;
    for (auto *slot : {&first, &second}) {
        std::optional<clash_native::core::Result<std::unique_ptr<clash_native::io::StreamHandle>>>
            opened;
        gun::async_open_gun_stream(
            session, options,
            [&](clash_native::core::Result<std::unique_ptr<clash_native::io::StreamHandle>>
                    result) { opened = std::move(result); });
        ASSERT_TRUE(opened && *opened);
        *slot = std::move(opened->value());
    }
    // Kill the first stream; the session and the sibling survive.
    first->close();
    first.reset();
    std::array<std::uint8_t, 64> receive{};
    const auto got = sync_get(second->async_read_some(boost::asio::buffer(receive)));
    ASSERT_TRUE(got);
    EXPECT_EQ(std::string(reinterpret_cast<const char *>(receive.data()), *got), payload);
    second->close();
}
