#include "outbound_conformance.hpp"

#include <boost/asio/ip/address.hpp>

TEST(OutboundContractTest, PreservesDomainAndIpDestinations) {
    const auto domain = clash_native::core::Destination::domain("example.test", 443);
    EXPECT_TRUE(domain.is_domain());
    EXPECT_FALSE(domain.is_address());
    EXPECT_EQ(domain.domain(), "example.test");
    EXPECT_EQ(domain.port(), 443);

    const auto address =
        clash_native::core::Destination::address(boost::asio::ip::make_address("192.0.2.10"), 80);
    EXPECT_FALSE(address.is_domain());
    EXPECT_TRUE(address.is_address());
    EXPECT_EQ(address.address().to_string(), "192.0.2.10");
    EXPECT_EQ(address.port(), 80);
}

TEST(OutboundContractTest, PreservesDomainAndIpDatagramAddresses) {
    const auto domain = clash_native::core::DatagramAddress::domain("example.test", 5353);
    EXPECT_TRUE(domain.is_domain());
    EXPECT_FALSE(domain.is_address());
    EXPECT_EQ(domain.domain(), "example.test");
    EXPECT_EQ(domain.port(), 5353);
    EXPECT_EQ(domain.to_destination().domain(), "example.test");

    const auto address = clash_native::core::DatagramAddress::address(
        boost::asio::ip::make_address("192.0.2.10"), 53);
    EXPECT_FALSE(address.is_domain());
    EXPECT_TRUE(address.is_address());
    EXPECT_EQ(address.address().to_string(), "192.0.2.10");
    EXPECT_EQ(address.port(), 53);
    EXPECT_EQ(address.to_destination().address().to_string(), "192.0.2.10");
}

TEST(OutboundContractTest, UnsupportedOutboundHonorsCapabilityContract) {
    clash_native::test_support::UnsupportedOutbound outbound;
    clash_native::test_support::run_unsupported_outbound_conformance(outbound);
}
