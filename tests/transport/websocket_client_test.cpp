#include <clash_native/io/sender.hpp>
#include <clash_native/transport/websocket_client.hpp>

#include <gtest/gtest.h>

#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>

#include <stdexec/execution.hpp>

#include <future>
#include <memory>
#include <optional>

namespace {

class TestStream final : public clash_native::io::StreamHandle {
  public:
    explicit TestStream(boost::asio::any_io_executor executor) : executor_(std::move(executor)) {}

    clash_native::io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer) override {
        return clash_native::io::AnySender<std::optional<std::size_t>>{
            stdexec::just(std::optional<std::size_t>())};
    }

    clash_native::io::AnySender<std::size_t>
    async_write(boost::asio::const_buffer buffer) override {
        return clash_native::io::AnySender<std::size_t>{stdexec::just(buffer.size())};
    }

    boost::asio::any_io_executor executor() noexcept override { return executor_; }

    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept override {
        error.clear();
        return {};
    }

    void shutdown_send(boost::system::error_code &error) noexcept override {
        error = boost::asio::error::operation_not_supported;
    }

    void close() noexcept override { closed_ = true; }

    bool closed() const noexcept { return closed_; }

  private:
    boost::asio::any_io_executor executor_;
    bool closed_ = false;
};

} // namespace

TEST(WebSocketClientTest, RejectsMissingStream) {
    std::promise<clash_native::core::Result<std::unique_ptr<clash_native::io::StreamHandle>>>
        completion;
    auto future = completion.get_future();
    const auto operation = clash_native::transport::async_websocket_client_handshake(
        nullptr, {}, [&completion](auto result) { completion.set_value(std::move(result)); });

    EXPECT_FALSE(operation);
    const auto result = future.get();
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::configuration);
}

TEST(WebSocketClientTest, RejectsInvalidOptionsBeforeOpeningHandshake) {
    boost::asio::io_context context;
    auto stream = std::make_unique<TestStream>(context.get_executor());
    auto *raw_stream = stream.get();
    clash_native::transport::WebSocketClientOptions options;
    options.host = "localhost";
    options.target = "relative-target";

    std::promise<clash_native::core::Result<std::unique_ptr<clash_native::io::StreamHandle>>>
        completion;
    auto future = completion.get_future();
    const auto operation = clash_native::transport::async_websocket_client_handshake(
        std::move(stream), std::move(options),
        [&completion](auto result) { completion.set_value(std::move(result)); });

    ASSERT_TRUE(operation);
    context.run();
    const auto result = future.get();
    ASSERT_FALSE(result);
    EXPECT_EQ(result.error().code, clash_native::core::ErrorCode::configuration);
    EXPECT_TRUE(raw_stream->closed());
}
