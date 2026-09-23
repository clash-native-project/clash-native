#pragma once

#include <clash_native/core/outbound.hpp>
#include <clash_native/io/sender.hpp>

#include <gtest/gtest.h>

#include <stdexec/execution.hpp>

#include <memory>
#include <tuple>

namespace clash_native::test_support {

class UnsupportedOutbound final : public core::Outbound {
  public:
    const core::OutboundDescriptor &descriptor() const noexcept override { return descriptor_; }

    core::OutboundCapabilities capabilities() const noexcept override { return capabilities_; }

    io::AnySender<core::StreamOpenResult> connect_stream(core::StreamRequest) override {
        return io::AnySender<core::StreamOpenResult>{
            stdexec::just(core::StreamOpenResult::unsupported())};
    }

    io::AnySender<core::DatagramOpenResult> open_datagram(core::DatagramRequest) override {
        return io::AnySender<core::DatagramOpenResult>{
            stdexec::just(core::DatagramOpenResult::unsupported())};
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

    auto stream_wait = stdexec::sync_wait(
        outbound.connect_stream({core::Destination::domain("example.test", 443), std::nullopt}));
    ASSERT_TRUE(stream_wait.has_value());
    auto stream_result = std::move(std::get<0>(*stream_wait));
    EXPECT_EQ(stream_result.status, core::OpenStatus::unsupported);
    EXPECT_FALSE(stream_result.succeeded());
    ASSERT_TRUE(stream_result.error.has_value());
    EXPECT_EQ(stream_result.error->code, core::ErrorCode::unsupported);

    auto datagram_wait = stdexec::sync_wait(outbound.open_datagram({}));
    ASSERT_TRUE(datagram_wait.has_value());
    auto datagram_result = std::move(std::get<0>(*datagram_wait));
    EXPECT_EQ(datagram_result.status, core::OpenStatus::unsupported);
    EXPECT_FALSE(datagram_result.succeeded());
    ASSERT_TRUE(datagram_result.error.has_value());
    EXPECT_EQ(datagram_result.error->code, core::ErrorCode::unsupported);
}

} // namespace clash_native::test_support
