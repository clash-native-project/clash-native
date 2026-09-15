#include <clash_native/async/mpsc_channel.hpp>
#include <clash_native/async/oneshot.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <thread>

using namespace std::chrono_literals;

TEST(ChannelTest, OneshotDeliversOneValue) {
    auto [sender, receiver] = clash_native::async::OneshotChannel<int>::create();

    auto result = std::async(std::launch::async, [&receiver] { return receiver.receive(); });
    ASSERT_TRUE(sender.send(42));
    ASSERT_EQ(result.wait_for(1s), std::future_status::ready);
    const auto received = result.get();
    ASSERT_TRUE(received.has_value());
    EXPECT_EQ(*received, 42);
}

TEST(ChannelTest, OneshotStopTokenCancelsReceive) {
    auto [sender, receiver] = clash_native::async::OneshotChannel<int>::create();
    std::stop_source stop_source;

    auto result = std::async(std::launch::async, [&receiver, token = stop_source.get_token()] {
        return receiver.receive(token);
    });
    std::this_thread::sleep_for(10ms);
    stop_source.request_stop();

    ASSERT_EQ(result.wait_for(1s), std::future_status::ready);
    EXPECT_FALSE(result.get().has_value());
    ASSERT_TRUE(sender.send(42));
    EXPECT_EQ(receiver.receive(), std::optional<int>(42));
}

TEST(ChannelTest, BoundedMpscAppliesBackpressureAndCloses) {
    auto [sender, receiver] = clash_native::async::MpscChannel<int>::create(1);

    ASSERT_TRUE(sender.send(1));
    auto second_send = std::async(std::launch::async, [&sender] { return sender.send(2); });
    std::this_thread::sleep_for(10ms);
    EXPECT_EQ(second_send.wait_for(0ms), std::future_status::timeout);

    ASSERT_EQ(receiver.receive(), std::optional<int>(1));
    ASSERT_EQ(second_send.wait_for(1s), std::future_status::ready);
    EXPECT_TRUE(second_send.get());
    ASSERT_EQ(receiver.receive(), std::optional<int>(2));

    sender.close();
    EXPECT_FALSE(receiver.receive().has_value());
}

TEST(ChannelTest, ZeroCapacityMpscProvidesRendezvous) {
    auto [sender, receiver] = clash_native::async::MpscChannel<int>::create(0);

    auto result = std::async(std::launch::async, [&receiver] { return receiver.receive(); });
    std::this_thread::sleep_for(10ms);
    ASSERT_TRUE(sender.send(7));
    ASSERT_EQ(result.wait_for(1s), std::future_status::ready);
    ASSERT_TRUE(result.get().has_value());
}

TEST(ChannelTest, UnboundedMpscSupportsMultipleProducers) {
    auto [sender, receiver] = clash_native::async::MpscChannel<int>::create(
        clash_native::async::MpscChannel<int>::kUnbounded);
    auto second_sender = sender;

    ASSERT_TRUE(sender.send(1));
    ASSERT_TRUE(second_sender.send(2));
    sender.close();
    second_sender.close();

    EXPECT_EQ(receiver.receive(), std::optional<int>(1));
    EXPECT_EQ(receiver.receive(), std::optional<int>(2));
    EXPECT_FALSE(receiver.receive().has_value());
}
