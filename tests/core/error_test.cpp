#include <clash_native/core/error.hpp>
#include <clash_native/core/result.hpp>

#include <gtest/gtest.h>

TEST(ErrorTest, ExposesStage0ErrorTaxonomy) {
    EXPECT_EQ(clash_native::core::to_string(clash_native::core::ErrorCode::cancelled), "cancelled");
    EXPECT_EQ(clash_native::core::to_string(clash_native::core::ErrorCode::resolution),
              "resolution");
    EXPECT_EQ(clash_native::core::to_string(clash_native::core::ErrorCode::timeout), "timeout");
    EXPECT_EQ(clash_native::core::to_string(clash_native::core::ErrorCode::unsupported),
              "unsupported");
    EXPECT_EQ(clash_native::core::to_string(clash_native::core::ErrorCode::transport_io),
              "transport_io");
}

TEST(ErrorTest, ProvidesExpectedResultVocabulary) {
    clash_native::core::Result<int> success = 42;
    ASSERT_TRUE(success.has_value());
    EXPECT_EQ(success.value(), 42);

    auto failure = clash_native::core::Result<int>(clash_native::core::fail(
        {clash_native::core::ErrorCode::transport_io, "connect target", {}}));
    ASSERT_FALSE(failure.has_value());
    EXPECT_EQ(failure.error().code, clash_native::core::ErrorCode::transport_io);
    EXPECT_EQ(failure.error().context, "connect target");
}

TEST(ErrorTest, SupportsStatusSuccess) {
    const clash_native::core::Status status{};
    EXPECT_TRUE(status.has_value());
}
