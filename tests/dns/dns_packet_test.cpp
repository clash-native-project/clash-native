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

void append_u32(std::vector<std::uint8_t> &message, std::uint32_t value) {
    message.push_back(static_cast<std::uint8_t>(value >> 24));
    message.push_back(static_cast<std::uint8_t>(value >> 16));
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
    append_u16(response_with_opt, 8);
    response_with_opt.insert(response_with_opt.end(), {0, 1, 0, 4, 1, 2, 3, 4});

    const auto packet =
        clash_native::dns::DnsMessageCodec::decode_packet(response_with_opt, 0x1234);
    ASSERT_TRUE(packet);
    EXPECT_EQ(packet.value().wire, response_with_opt);
    ASSERT_EQ(packet.value().questions.size(), 1U);
    ASSERT_EQ(packet.value().answers.size(), 1U);
    ASSERT_EQ(packet.value().additionals.size(), 1U);
    ASSERT_TRUE(packet.value().answers.front().parsed_address);
    EXPECT_EQ(packet.value().answers.front().parsed_address->to_string(), "192.0.2.1");
    ASSERT_EQ(packet.value().answers.front().fields.size(), 1U);
    EXPECT_EQ(
        std::get<boost::asio::ip::address>(packet.value().answers.front().fields.front().value)
            .to_string(),
        "192.0.2.1");
    EXPECT_EQ(packet.value().additionals.front().type,
              static_cast<std::uint16_t>(clash_native::dns::DnsRecordType::opt));
    EXPECT_EQ(packet.value().additionals.front().rdata,
              (std::vector<std::uint8_t>{0, 1, 0, 4, 1, 2, 3, 4}));

    const auto rewritten = clash_native::dns::DnsMessageCodec::rewrite_id(packet.value(), 0xbeef);
    ASSERT_TRUE(rewritten);
    EXPECT_EQ(rewritten.value()[0], 0xbe);
    EXPECT_EQ(rewritten.value()[1], 0xef);
    const auto rewritten_packet =
        clash_native::dns::DnsMessageCodec::decode_packet(rewritten.value(), 0xbeef);
    ASSERT_TRUE(rewritten_packet);
    EXPECT_EQ(rewritten_packet.value().additionals.front().rdata,
              (std::vector<std::uint8_t>{0, 1, 0, 4, 1, 2, 3, 4}));
}

TEST(DnsPacketTest, RetainsExtendedResponseCodesFromEdns) {
    const clash_native::dns::DnsQuestion question{"extended.example",
                                                  clash_native::dns::DnsRecordType::a, 1};
    auto response =
        clash_native::dns::DnsMessageCodec::encode_query_packet(question, 0x1234).value();
    response[2] = 0x81;
    response[3] = 0x87;
    response[10] = 0;
    response[11] = 1;
    response.push_back(0);
    append_u16(response, static_cast<std::uint16_t>(clash_native::dns::DnsRecordType::opt));
    append_u16(response, 1232);
    append_u32(response, 0x01018000);
    append_u16(response, 0);

    const auto packet = clash_native::dns::DnsMessageCodec::decode_packet(response, 0x1234);
    ASSERT_TRUE(packet);
    EXPECT_EQ(packet.value().response_code(), 23U);
    EXPECT_EQ(packet.value().extended_response_code, 1U);
    ASSERT_EQ(packet.value().additionals.size(), 1U);
    EXPECT_EQ(packet.value().additionals.front().ttl_seconds, 0x01018000U);
    const auto answer = clash_native::dns::DnsMessageCodec::to_address_answer(packet.value());
    ASSERT_TRUE(answer);
    EXPECT_EQ(answer.value().response_code, 23U);
}

TEST(DnsPacketTest, PreservesEdnsOptionsAndFlagsInLocalResponses) {
    const clash_native::dns::DnsQuestion question{"edns.example",
                                                  clash_native::dns::DnsRecordType::a, 1};
    auto query_wire =
        clash_native::dns::DnsMessageCodec::encode_query_packet(question, 0x4567).value();
    query_wire[3] |= 0x10; // CD
    query_wire[10] = 0;
    query_wire[11] = 1;
    query_wire.push_back(0);
    append_u16(query_wire, static_cast<std::uint16_t>(clash_native::dns::DnsRecordType::opt));
    append_u16(query_wire, 1232);
    append_u32(query_wire, 0x00008000); // DO
    append_u16(query_wire, 8);
    query_wire.insert(query_wire.end(), {0, 1, 0, 4, 1, 2, 3, 4});
    const auto query = clash_native::dns::DnsMessageCodec::decode_packet(query_wire, 0x4567);
    ASSERT_TRUE(query);

    const auto error = clash_native::dns::DnsMessageCodec::encode_error_response(query.value(), 2);
    ASSERT_TRUE(error);
    const auto error_packet =
        clash_native::dns::DnsMessageCodec::decode_packet(error.value(), 0x4567);
    ASSERT_TRUE(error_packet);
    EXPECT_EQ(error_packet.value().response_code(), 2U);
    EXPECT_NE(error_packet.value().flags & 0x0010, 0);
    ASSERT_EQ(error_packet.value().additionals.size(), 1U);
    EXPECT_EQ(error_packet.value().additionals.front().class_code, 1232U);
    EXPECT_EQ(error_packet.value().additionals.front().ttl_seconds & 0x00008000U, 0x00008000U);
    EXPECT_EQ(error_packet.value().additionals.front().rdata,
              (std::vector<std::uint8_t>{0, 1, 0, 4, 1, 2, 3, 4}));

    clash_native::dns::DnsAnswer answer;
    answer.question = question;
    answer.addresses.push_back(boost::asio::ip::make_address("192.0.2.77"));
    answer.ttl_seconds = 30;
    const auto fake = clash_native::dns::DnsMessageCodec::encode_response(query.value(), answer);
    ASSERT_TRUE(fake);
    const auto fake_packet =
        clash_native::dns::DnsMessageCodec::decode_packet(fake.value(), 0x4567);
    ASSERT_TRUE(fake_packet);
    EXPECT_NE(fake_packet.value().flags & 0x0010, 0);
    ASSERT_EQ(fake_packet.value().additionals.size(), 1U);
    EXPECT_EQ(fake_packet.value().additionals.front().rdata,
              (std::vector<std::uint8_t>{0, 1, 0, 4, 1, 2, 3, 4}));
}

TEST(DnsPacketTest, TruncatesAtCompleteResourceSetBoundaries) {
    const clash_native::dns::DnsQuestion question{"large.example",
                                                  clash_native::dns::DnsRecordType::a, 1};
    clash_native::dns::DnsAnswer answer;
    answer.question = question;
    answer.ttl_seconds = 60;
    for (std::uint16_t index = 1; index <= 80; ++index) {
        const boost::asio::ip::address_v4::bytes_type bytes{192, 0, 2,
                                                            static_cast<unsigned char>(index)};
        answer.addresses.push_back(boost::asio::ip::address_v4(bytes));
    }
    auto query_wire =
        clash_native::dns::DnsMessageCodec::encode_query_packet(question, 0x8765).value();
    query_wire[10] = 0;
    query_wire[11] = 1;
    query_wire.push_back(0);
    append_u16(query_wire, static_cast<std::uint16_t>(clash_native::dns::DnsRecordType::opt));
    append_u16(query_wire, 1232);
    append_u32(query_wire, 0x00008000);
    append_u16(query_wire, 8);
    query_wire.insert(query_wire.end(), {0, 1, 0, 4, 1, 2, 3, 4});
    const auto query = clash_native::dns::DnsMessageCodec::decode_packet(query_wire, 0x8765);
    ASSERT_TRUE(query);
    const auto response =
        clash_native::dns::DnsMessageCodec::encode_response(query.value(), answer);
    ASSERT_TRUE(response);
    ASSERT_GT(response.value().size(), 512U);

    const auto truncated =
        clash_native::dns::DnsMessageCodec::truncate_udp_response(response.value(), 512);
    ASSERT_TRUE(truncated) << truncated.error().context;
    EXPECT_LE(truncated.value().size(), 512U);
    const auto packet =
        clash_native::dns::DnsMessageCodec::decode_packet(truncated.value(), 0x8765);
    ASSERT_TRUE(packet);
    EXPECT_TRUE(packet.value().truncated());
    EXPECT_TRUE(packet.value().answers.empty());
    ASSERT_EQ(packet.value().additionals.size(), 1U);
    EXPECT_EQ(packet.value().additionals.front().rdata,
              (std::vector<std::uint8_t>{0, 1, 0, 4, 1, 2, 3, 4}));
    EXPECT_EQ(packet.value().additionals.front().ttl_seconds & 0x00008000U, 0x00008000U);
}

TEST(DnsPacketTest, PreservesUnknownRecordTypeAndRawData) {
    const clash_native::dns::DnsQuestion question{
        "unknown.example", static_cast<clash_native::dns::DnsRecordType>(65000), 1};
    auto wire = clash_native::dns::DnsMessageCodec::encode_query_packet(question, 0x4321).value();
    wire[2] = 0x81;
    wire[3] = 0x80;
    wire[6] = 0;
    wire[7] = 1;
    wire.insert(wire.end(), {0xc0, 0x0c});
    append_u16(wire, 65000);
    append_u16(wire, 1);
    append_u32(wire, 15);
    append_u16(wire, 4);
    wire.insert(wire.end(), {0xde, 0xad, 0xbe, 0xef});

    const auto packet = clash_native::dns::DnsMessageCodec::decode_packet(wire, 0x4321);
    ASSERT_TRUE(packet) << (packet ? "" : packet.error().context);
    ASSERT_EQ(packet.value().answers.size(), 1U);
    EXPECT_EQ(packet.value().answers.front().type, 65000);
    EXPECT_EQ(packet.value().answers.front().rdata,
              (std::vector<std::uint8_t>{0xde, 0xad, 0xbe, 0xef}));
    ASSERT_EQ(packet.value().answers.front().fields.size(), 2U);
    EXPECT_EQ(packet.value().answers.front().fields[0].key_code, 6553601U);
    EXPECT_EQ(std::get<std::uint16_t>(packet.value().answers.front().fields[0].value), 65000U);
    EXPECT_EQ(packet.value().answers.front().fields[1].key_code, 6553602U);
    EXPECT_EQ(std::get<std::vector<std::uint8_t>>(packet.value().answers.front().fields[1].value),
              (std::vector<std::uint8_t>{0xde, 0xad, 0xbe, 0xef}));
    EXPECT_EQ(packet.value().wire, wire);
}

TEST(DnsPacketTest, ParsesHttpsQuestionsAndGenericServiceBindingFieldsWithCares) {
    const clash_native::dns::DnsQuestion question{
        "resolver.example", clash_native::dns::dns_record_type_from_code(65), 1};
    auto wire = clash_native::dns::DnsMessageCodec::encode_query_packet(question, 0x4567).value();
    wire[2] = 0x81;
    wire[3] = 0x80;
    wire[6] = 0;
    wire[7] = 1;

    std::vector<std::uint8_t> rdata;
    append_u16(rdata, 1);
    append_name(rdata, "svc.example");
    append_u16(rdata, 1);
    append_u16(rdata, 3);
    rdata.insert(rdata.end(), {2, 'h', '2'});
    append_u16(rdata, 3);
    append_u16(rdata, 2);
    rdata.insert(rdata.end(), {1, 187});

    wire.insert(wire.end(), {0xc0, 0x0c});
    append_u16(wire, 65);
    append_u16(wire, 1);
    append_u32(wire, 60);
    append_u16(wire, static_cast<std::uint16_t>(rdata.size()));
    wire.insert(wire.end(), rdata.begin(), rdata.end());

    const auto packet = clash_native::dns::DnsMessageCodec::decode_packet(wire, 0x4567);
    ASSERT_TRUE(packet) << (packet ? "" : packet.error().context);
    ASSERT_EQ(packet.value().questions.size(), 1U);
    EXPECT_EQ(clash_native::dns::dns_record_type_code(packet.value().questions.front().type), 65U);
    ASSERT_EQ(packet.value().answers.size(), 1U);

    const auto &fields = packet.value().answers.front().fields;
    ASSERT_EQ(fields.size(), 3U);
    EXPECT_EQ(fields[0].key_code, 6501U);
    EXPECT_EQ(std::get<std::uint16_t>(fields[0].value), 1U);
    EXPECT_EQ(fields[1].key_code, 6502U);
    EXPECT_EQ(std::get<std::string>(fields[1].value), "svc.example");
    EXPECT_EQ(fields[2].key_code, 6503U);
    const auto &parameters =
        std::get<std::vector<clash_native::dns::DnsResourceRecordOption>>(fields[2].value);
    ASSERT_EQ(parameters.size(), 2U);
    EXPECT_EQ(parameters[0].code, 1U);
    EXPECT_EQ(parameters[0].data, (std::vector<std::uint8_t>{2, 'h', '2'}));
    EXPECT_EQ(parameters[1].code, 3U);
    EXPECT_EQ(parameters[1].data, (std::vector<std::uint8_t>{1, 187}));
}

TEST(DnsPacketTest, ParsesHttpsTypedServiceBindingWithEchParam) {
    const clash_native::dns::DnsQuestion question{
        "resolver.example", clash_native::dns::dns_record_type_from_code(65), 1};
    auto wire = clash_native::dns::DnsMessageCodec::encode_query_packet(question, 0x4568).value();
    wire[2] = 0x81;
    wire[3] = 0x80;
    wire[6] = 0;
    wire[7] = 1;

    // priority 1, target svc.example, alpn h2, port 443, ech opaque bytes.
    const std::vector<std::uint8_t> ech_config{0x00, 0x0a, 0x0d, 0x14};
    std::vector<std::uint8_t> rdata;
    append_u16(rdata, 1);
    append_name(rdata, "svc.example");
    append_u16(rdata, 1);
    append_u16(rdata, 3);
    rdata.insert(rdata.end(), {2, 'h', '2'});
    append_u16(rdata, 3);
    append_u16(rdata, 2);
    rdata.insert(rdata.end(), {1, 187});
    append_u16(rdata, 5);
    append_u16(rdata, static_cast<std::uint16_t>(ech_config.size()));
    rdata.insert(rdata.end(), ech_config.begin(), ech_config.end());

    wire.insert(wire.end(), {0xc0, 0x0c});
    append_u16(wire, 65);
    append_u16(wire, 1);
    append_u32(wire, 60);
    append_u16(wire, static_cast<std::uint16_t>(rdata.size()));
    wire.insert(wire.end(), rdata.begin(), rdata.end());

    const auto packet = clash_native::dns::DnsMessageCodec::decode_packet(wire, 0x4568);
    ASSERT_TRUE(packet) << (packet ? "" : packet.error().context);
    ASSERT_EQ(packet.value().answers.size(), 1U);
    const auto &sxb = packet.value().answers.front().svcb;
    ASSERT_TRUE(sxb.has_value());
    EXPECT_EQ(sxb->priority, 1U);
    EXPECT_EQ(sxb->target, "svc.example");
    ASSERT_EQ(sxb->params.size(), 3U);
    EXPECT_EQ(sxb->params[0].code, 1U);
    EXPECT_EQ(sxb->params[1].code, 3U);
    EXPECT_EQ(sxb->params[2].code, 5U);
    EXPECT_EQ(sxb->params[2].data, ech_config);
}

TEST(DnsPacketTest, ParsesCaaFieldsWithCares) {
    const clash_native::dns::DnsQuestion question{"example", clash_native::dns::DnsRecordType::caa,
                                                  1};
    auto wire = clash_native::dns::DnsMessageCodec::encode_query_packet(question, 0x2468).value();
    wire[2] = 0x81;
    wire[3] = 0x80;
    wire[6] = 0;
    wire[7] = 1;
    wire.insert(wire.end(), {0xc0, 0x0c});
    append_u16(wire, clash_native::dns::dns_record_type_code(question.type));
    append_u16(wire, 1);
    append_u32(wire, 300);
    append_u16(wire, 21);
    wire.insert(wire.end(), {0, 5, 'i', 's', 's', 'u', 'e'});
    wire.insert(wire.end(), {'c', 'a', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'});

    const auto packet = clash_native::dns::DnsMessageCodec::decode_packet(wire, 0x2468);
    ASSERT_TRUE(packet) << (packet ? "" : packet.error().context);
    ASSERT_EQ(packet.value().answers.size(), 1U);
    const auto &fields = packet.value().answers.front().fields;
    ASSERT_EQ(fields.size(), 3U);
    EXPECT_EQ(fields[0].key_code, 25701U);
    EXPECT_EQ(std::get<std::uint8_t>(fields[0].value), 0U);
    EXPECT_EQ(fields[1].key_code, 25702U);
    EXPECT_EQ(std::get<std::string>(fields[1].value), "issue");
    EXPECT_EQ(fields[2].key_code, 25703U);
    EXPECT_EQ(std::get<std::vector<std::uint8_t>>(fields[2].value),
              (std::vector<std::uint8_t>{'c', 'a', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c',
                                         'o', 'm'}));
}

TEST(DnsPacketTest, ParsesSoaMinimumTtlForNegativeCaching) {
    const clash_native::dns::DnsQuestion question{"missing.example",
                                                  clash_native::dns::DnsRecordType::a, 1};
    auto wire = clash_native::dns::DnsMessageCodec::encode_query_packet(question, 0x8765).value();
    wire[2] = 0x81;
    wire[3] = 0x83;
    wire[8] = 0;
    wire[9] = 1;
    append_name(wire, "example");
    append_u16(wire, static_cast<std::uint16_t>(clash_native::dns::DnsRecordType::soa));
    append_u16(wire, 1);
    append_u32(wire, 90);
    const auto rdlength_position = wire.size();
    append_u16(wire, 0);
    const auto rdata_position = wire.size();
    append_name(wire, "ns.example");
    append_name(wire, "hostmaster.example");
    append_u32(wire, 1);
    append_u32(wire, 2);
    append_u32(wire, 3);
    append_u32(wire, 4);
    append_u32(wire, 5);
    const auto rdlength = static_cast<std::uint16_t>(wire.size() - rdata_position);
    wire[rdlength_position] = static_cast<std::uint8_t>(rdlength >> 8);
    wire[rdlength_position + 1] = static_cast<std::uint8_t>(rdlength & 0xff);

    const auto packet = clash_native::dns::DnsMessageCodec::decode_packet(wire, 0x8765);
    ASSERT_TRUE(packet) << (packet ? "" : packet.error().context);
    ASSERT_EQ(packet.value().authorities.size(), 1U);
    EXPECT_EQ(packet.value().authorities.front().type,
              static_cast<std::uint16_t>(clash_native::dns::DnsRecordType::soa));
    EXPECT_EQ(packet.value().authorities.front().ttl_seconds, 90U);
    ASSERT_TRUE(packet.value().authorities.front().soa);
    EXPECT_EQ(packet.value().authorities.front().soa->primary_name_server, "ns.example");
    EXPECT_EQ(packet.value().authorities.front().soa->responsible_mailbox, "hostmaster.example");
    EXPECT_EQ(packet.value().authorities.front().soa->serial, 1U);
    EXPECT_EQ(packet.value().authorities.front().soa->refresh, 2U);
    EXPECT_EQ(packet.value().authorities.front().soa->retry, 3U);
    EXPECT_EQ(packet.value().authorities.front().soa->expire, 4U);
    EXPECT_EQ(packet.value().authorities.front().soa->minimum_ttl, 5U);
    const auto &fields = packet.value().authorities.front().fields;
    ASSERT_EQ(fields.size(), 7U);
    EXPECT_EQ(fields[2].key_code, 603U);
    EXPECT_EQ(std::get<std::uint32_t>(fields[2].value), 1U);
}

TEST(DnsPacketTest, ParsesMxTxtAndSrvFieldsWithCares) {
    const auto make_response = [](clash_native::dns::DnsRecordType type,
                                  std::vector<std::uint8_t> rdata) {
        const clash_native::dns::DnsQuestion question{"service.example", type, 1};
        auto wire =
            clash_native::dns::DnsMessageCodec::encode_query_packet(question, 0x9876).value();
        wire[2] = 0x81;
        wire[3] = 0x80;
        wire[6] = 0;
        wire[7] = 1;
        wire.insert(wire.end(), {0xc0, 0x0c});
        append_u16(wire, static_cast<std::uint16_t>(type));
        append_u16(wire, 1);
        append_u32(wire, 60);
        append_u16(wire, static_cast<std::uint16_t>(rdata.size()));
        wire.insert(wire.end(), rdata.begin(), rdata.end());
        return wire;
    };

    std::vector<std::uint8_t> mx_rdata;
    append_u16(mx_rdata, 10);
    append_name(mx_rdata, "mail.example");
    const auto mx_packet = clash_native::dns::DnsMessageCodec::decode_packet(
        make_response(clash_native::dns::DnsRecordType::mx, std::move(mx_rdata)), 0x9876);
    ASSERT_TRUE(mx_packet);
    ASSERT_EQ(mx_packet.value().answers.size(), 1U);
    ASSERT_TRUE(mx_packet.value().answers.front().mx);
    EXPECT_EQ(mx_packet.value().answers.front().mx->preference, 10U);
    EXPECT_EQ(mx_packet.value().answers.front().mx->exchange, "mail.example");

    const auto txt_packet = clash_native::dns::DnsMessageCodec::decode_packet(
        make_response(clash_native::dns::DnsRecordType::txt, {3, 'f', 'o', 'o', 0}), 0x9876);
    ASSERT_TRUE(txt_packet);
    ASSERT_EQ(txt_packet.value().answers.size(), 1U);
    EXPECT_EQ(txt_packet.value().answers.front().txt_strings,
              (std::vector<std::vector<std::uint8_t>>{{'f', 'o', 'o'}, {}}));
    ASSERT_EQ(txt_packet.value().answers.front().fields.size(), 1U);
    EXPECT_EQ(txt_packet.value().answers.front().fields.front().type,
              clash_native::dns::DnsResourceRecordFieldType::binary_strings);
    EXPECT_EQ(std::get<std::vector<std::vector<std::uint8_t>>>(
                  txt_packet.value().answers.front().fields.front().value),
              (std::vector<std::vector<std::uint8_t>>{{'f', 'o', 'o'}, {}}));

    std::vector<std::uint8_t> srv_rdata;
    append_u16(srv_rdata, 1);
    append_u16(srv_rdata, 2);
    append_u16(srv_rdata, 443);
    append_name(srv_rdata, "target.example");
    const auto srv_packet = clash_native::dns::DnsMessageCodec::decode_packet(
        make_response(clash_native::dns::DnsRecordType::srv, std::move(srv_rdata)), 0x9876);
    ASSERT_TRUE(srv_packet);
    ASSERT_EQ(srv_packet.value().answers.size(), 1U);
    ASSERT_TRUE(srv_packet.value().answers.front().srv);
    EXPECT_EQ(srv_packet.value().answers.front().srv->priority, 1U);
    EXPECT_EQ(srv_packet.value().answers.front().srv->weight, 2U);
    EXPECT_EQ(srv_packet.value().answers.front().srv->port, 443U);
    EXPECT_EQ(srv_packet.value().answers.front().srv->target, "target.example");
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
    ASSERT_TRUE(packet.value().answers.front().parsed_address);
    EXPECT_EQ(packet.value().answers.front().parsed_address->to_string(), "2001:db8::1");

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
