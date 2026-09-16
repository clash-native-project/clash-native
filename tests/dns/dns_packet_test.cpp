#include <clash_native/dns/dns_codec.hpp>

#include <gtest/gtest.h>

#include <boost/asio/ip/address.hpp>

#include <cstdint>
#include <string_view>
#include <vector>

namespace {

void append_u16(std::vector<std::uint8_t> &message, std::uint16_t value) {
    message.push_back(static_cast<std::uint8_t>(value >> 8));
    message.push_back(static_cast<std::uint8_t>(value & 0xff));
}

void append_name(std::vector<std::uint8_t> &message, std::string_view name) {
    std::size_t begin = 0;
    while (begin < name.size()) {
        const auto end = name.find('.', begin);
        const auto label_end = end == std::string_view::npos ? name.size() : end;
        message.push_back(static_cast<std::uint8_t>(label_end - begin));
        message.insert(message.end(), name.begin() + static_cast<std::ptrdiff_t>(begin),
                       name.begin() + static_cast<std::ptrdiff_t>(label_end));
        if (end == std::string_view::npos) {
            break;
        }
        begin = end + 1;
    }
    message.push_back(0);
}

} // namespace

TEST(DnsPacketTest, PreservesWireMessageAndAllRecordSections) {
    const clash_native::dns::DnsQuestion question{"example.test",
                                                  clash_native::dns::DnsRecordType::a, 1};
    const auto query_wire =
        clash_native::dns::DnsMessageCodec::encode_query_packet(question, 0x1234);
    ASSERT_TRUE(query_wire);
    const auto query =
        clash_native::dns::DnsMessageCodec::decode_packet(query_wire.value(), 0x1234);
    ASSERT_TRUE(query);

    clash_native::dns::DnsAnswer answer;
    answer.question = question;
    answer.addresses.push_back(boost::asio::ip::make_address("192.0.2.1"));
    answer.ttl_seconds = 60;
    const clash_native::dns::DnsQuery legacy_query{0x1234, question, true};
    const auto response_wire =
        clash_native::dns::DnsMessageCodec::encode_response(legacy_query, answer);
    ASSERT_TRUE(response_wire);

    auto response_with_opt = response_wire.value();
    response_with_opt[10] = 0;
    response_with_opt[11] = 1;
    response_with_opt.push_back(0);
    append_u16(response_with_opt,
               static_cast<std::uint16_t>(clash_native::dns::DnsRecordType::opt));
    append_u16(response_with_opt, 1232);
    response_with_opt.insert(response_with_opt.end(), {0, 0, 0, 0});
    append_u16(response_with_opt, 4);
    response_with_opt.insert(response_with_opt.end(), {1, 2, 3, 4});

    const auto packet =
        clash_native::dns::DnsMessageCodec::decode_packet(response_with_opt, 0x1234);
    ASSERT_TRUE(packet);
    EXPECT_EQ(packet.value().wire, response_with_opt);
    ASSERT_EQ(packet.value().questions.size(), 1U);
    ASSERT_EQ(packet.value().answers.size(), 1U);
    ASSERT_EQ(packet.value().additionals.size(), 1U);
    EXPECT_EQ(packet.value().additionals.front().type,
              static_cast<std::uint16_t>(clash_native::dns::DnsRecordType::opt));
    EXPECT_EQ(packet.value().additionals.front().rdata, (std::vector<std::uint8_t>{1, 2, 3, 4}));

    const auto rewritten = clash_native::dns::DnsMessageCodec::rewrite_id(packet.value(), 0xbeef);
    ASSERT_TRUE(rewritten);
    EXPECT_EQ(rewritten.value()[0], 0xbe);
    EXPECT_EQ(rewritten.value()[1], 0xef);
    const auto rewritten_packet =
        clash_native::dns::DnsMessageCodec::decode_packet(rewritten.value(), 0xbeef);
    ASSERT_TRUE(rewritten_packet);
    EXPECT_EQ(rewritten_packet.value().additionals.front().rdata,
              (std::vector<std::uint8_t>{1, 2, 3, 4}));
}

TEST(DnsPacketTest, ProjectsAddressAnswerWithoutDiscardingPacketData) {
    const clash_native::dns::DnsQuestion question{"example.test",
                                                  clash_native::dns::DnsRecordType::aaaa, 1};
    clash_native::dns::DnsAnswer source;
    source.question = question;
    source.addresses.push_back(boost::asio::ip::make_address("2001:db8::1"));
    source.ttl_seconds = 120;
    const auto wire =
        clash_native::dns::DnsMessageCodec::encode_response({0x4321, question, true}, source);
    ASSERT_TRUE(wire);
    const auto packet = clash_native::dns::DnsMessageCodec::decode_packet(wire.value(), 0x4321);
    ASSERT_TRUE(packet);

    const auto answer = clash_native::dns::DnsMessageCodec::to_address_answer(packet.value());
    ASSERT_TRUE(answer);
    EXPECT_EQ(answer.value().addresses.front().to_string(), "2001:db8::1");
    EXPECT_EQ(answer.value().ttl_seconds, 120U);
}

TEST(DnsPacketTest, ProjectsAddressesThroughAnInMessageCnameChain) {
    const clash_native::dns::DnsQuestion question{"alias.test", clash_native::dns::DnsRecordType::a,
                                                  1};
    const auto query = clash_native::dns::DnsMessageCodec::encode_query_packet(question, 0x6789);
    ASSERT_TRUE(query);
    auto response = query.value();
    response[2] = 0x81;
    response[3] = 0x80;
    response[6] = 0;
    response[7] = 2;

    response.insert(response.end(), {0xc0, 0x0c});
    append_u16(response, static_cast<std::uint16_t>(clash_native::dns::DnsRecordType::cname));
    append_u16(response, 1);
    response.insert(response.end(), {0, 0, 0, 30});
    append_u16(response, 13);
    append_name(response, "target.test");

    append_name(response, "target.test");
    append_u16(response, static_cast<std::uint16_t>(clash_native::dns::DnsRecordType::a));
    append_u16(response, 1);
    response.insert(response.end(), {0, 0, 0, 120});
    append_u16(response, 4);
    response.insert(response.end(), {192, 0, 2, 44});

    const auto packet = clash_native::dns::DnsMessageCodec::decode_packet(response, 0x6789);
    ASSERT_TRUE(packet) << (packet ? "" : packet.error().context);
    ASSERT_TRUE(packet.value().answers.front().target_name);
    EXPECT_EQ(*packet.value().answers.front().target_name, "target.test");

    const auto answer = clash_native::dns::DnsMessageCodec::to_address_answer(packet.value());
    ASSERT_TRUE(answer);
    ASSERT_EQ(answer.value().addresses.size(), 1U);
    EXPECT_EQ(answer.value().addresses.front().to_string(), "192.0.2.44");
    EXPECT_EQ(answer.value().ttl_seconds, 30U);
    EXPECT_EQ(answer.value().question.name, "alias.test");
}
