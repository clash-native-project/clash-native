#include <clash_native/platform/platform_adapter.hpp>

#include <gtest/gtest.h>

TEST(PlatformAdapterTest, ReportsAPlatformName) {
    EXPECT_FALSE(clash_native::platform::name().empty());
}
