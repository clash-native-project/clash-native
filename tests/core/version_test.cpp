#include <clash_native/core/version.hpp>

#include <gtest/gtest.h>

TEST(VersionTest, IsNotEmpty) {
    EXPECT_FALSE(clash_native::core::version.empty());
}
