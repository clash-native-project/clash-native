#pragma once

#include <clash_native/core/outbound.hpp>

#include <gtest/gtest.h>

#include <memory>

namespace clash_native::test_support {

class UnsupportedOutbound final : public core::Outbound {
  public:
    const core::OutboundDescriptor &descriptor() const noexcept override { return descriptor_; }

    core::OutboundCapabilities capabilities() const noexcept override { return capabilities_; }

    void connect_stream(core::StreamRequest, core::StreamOpenHandler handler) override {
        handler(core::StreamOpenResult::unsupported());
    }

    void open_datagram(core::DatagramRequest, core::DatagramOpenHandler handler) override {
        handler(core::DatagramOpenResult::unsupported());
    }

  private:
    core::OutboundDescriptor descriptor_{"test-unsupported", "test"};
    core::OutboundCapabilities capabilities_{};
};

inline void run_unsupported_outbound_conformance(core::Outbound &outbound) {
    EXPECT_FALSE(outbound.descriptor().id.empty());
    EXPECT_FALSE(outbound.descriptor().protocol.empty());

    const auto capabilities = outbound.capabilities();
    EXPECT_FALSE(capabilities.stream);
    EXPECT_EQ(capabilities.datagram, core::DatagramSemantics::unsupported);

    int stream_callbacks = 0;
    core::StreamOpenResult stream_result;
    outbound.connect_stream({core::Destination::domain("example.test", 443)},
                            [&stream_callbacks, &stream_result](core::StreamOpenResult result) {
                                ++stream_callbacks;
                                stream_result = std::move(result);
                            });
    EXPECT_EQ(stream_callbacks, 1);
    EXPECT_EQ(stream_result.status, core::OpenStatus::unsupported);
    EXPECT_FALSE(stream_result.succeeded());
    ASSERT_TRUE(stream_result.error.has_value());
    EXPECT_EQ(stream_result.error->code, core::ErrorCode::unsupported);

    int datagram_callbacks = 0;
    core::DatagramOpenResult datagram_result;
    outbound.open_datagram(
        {}, [&datagram_callbacks, &datagram_result](core::DatagramOpenResult result) {
            ++datagram_callbacks;
            datagram_result = std::move(result);
        });
    EXPECT_EQ(datagram_callbacks, 1);
    EXPECT_EQ(datagram_result.status, core::OpenStatus::unsupported);
    EXPECT_FALSE(datagram_result.succeeded());
    ASSERT_TRUE(datagram_result.error.has_value());
    EXPECT_EQ(datagram_result.error->code, core::ErrorCode::unsupported);
}

} // namespace clash_native::test_support
