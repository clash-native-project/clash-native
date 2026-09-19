#include <clash_native/core/base64.hpp>

#include <gtest/gtest.h>

#include <string>

namespace {

TEST(Base64Test, EncodesStandardVectors) {
    EXPECT_EQ(clash_native::core::base64_encode(""), "");
    EXPECT_EQ(clash_native::core::base64_encode("f"), "Zg==");
    EXPECT_EQ(clash_native::core::base64_encode("fo"), "Zm8=");
    EXPECT_EQ(clash_native::core::base64_encode("foo"), "Zm9v");
    EXPECT_EQ(clash_native::core::base64_encode("foobar"), "Zm9vYmFy");
}

TEST(Base64Test, RoundTripsBinaryInput) {
    const std::string input("\0\x01\x7f\x80\xfe\xff", 6);

    const auto encoded = clash_native::core::base64_encode(input);
    EXPECT_EQ(encoded, "AAF/gP7/");

    const auto decoded = clash_native::core::base64_decode(encoded);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, input);
}

TEST(Base64Test, DecodesStandardVectors) {
    EXPECT_EQ(clash_native::core::base64_decode(""), std::optional<std::string>(""));
    EXPECT_EQ(clash_native::core::base64_decode("Zg=="), std::optional<std::string>("f"));
    EXPECT_EQ(clash_native::core::base64_decode("Zm8="), std::optional<std::string>("fo"));
    EXPECT_EQ(clash_native::core::base64_decode("Zm9v"), std::optional<std::string>("foo"));
}

TEST(Base64Test, RejectsMalformedInput) {
    for (const auto input : {"Zg=", "Zg===", "Zm$=", "=m9v", "Zm=9", "Zm9"}) {
        EXPECT_FALSE(clash_native::core::base64_decode(input).has_value()) << input;
    }
}

} // namespace
