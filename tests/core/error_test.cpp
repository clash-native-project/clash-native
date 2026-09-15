#include <clash_native/core/error.hpp>

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
