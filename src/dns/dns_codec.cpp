#include <clash_native/dns/dns_codec.hpp>

#include <ares.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace clash_native::dns {

namespace {

core::Error codec_error(std::string context) {
    return {core::ErrorCode::protocol_framing, std::move(context)};
}

void append_u16(std::vector<std::uint8_t> &output, std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>(value >> 8));
    output.push_back(static_cast<std::uint8_t>(value & 0xff));
}

void append_u32(std::vector<std::uint8_t> &output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value >> 24));
    output.push_back(static_cast<std::uint8_t>(value >> 16));
    output.push_back(static_cast<std::uint8_t>(value >> 8));
    output.push_back(static_cast<std::uint8_t>(value & 0xff));
}

struct CaresLibrary final {
    CaresLibrary() : status(ares_library_init(ARES_LIB_INIT_ALL)) {}
    ~CaresLibrary() {
        if (status == ARES_SUCCESS) {
            ares_library_cleanup();
        }
    }

    int status;
};

int initialize_cares() {
    static CaresLibrary library;
    return library.status;
}

core::Error cares_error(std::string operation, int status) {
    return codec_error("c-ares failed to " + std::move(operation) + ": " + ares_strerror(status));
}

core::Result<std::vector<std::uint8_t>> write_dns_record(const ares_dns_record_t *record) {
    unsigned char *serialized = nullptr;
    std::size_t length = 0;
    const auto status = ares_dns_write(record, &serialized, &length);
    if (status != ARES_SUCCESS) {
        return core::fail(cares_error("write the DNS message", status));
    }
    std::unique_ptr<unsigned char, decltype(&ares_free_string)> bytes(serialized,
                                                                      &ares_free_string);
    return std::vector<std::uint8_t>(bytes.get(), bytes.get() + length);
}

void append_opt_record(std::vector<std::uint8_t> &response, const DnsPacket &query,
                       std::uint16_t response_code) {
    const auto opt = std::find_if(
        query.additionals.begin(), query.additionals.end(), [](const DnsResourceRecord &record) {
            return record.type == static_cast<std::uint16_t>(DnsRecordType::opt);
        });
    if (opt == query.additionals.end() && response_code <= 0x0f) {
        return;
    }

    const auto udp_payload_size = opt == query.additionals.end()
                                      ? std::uint16_t{1232}
                                      : std::max<std::uint16_t>(512, opt->class_code);
    const auto opt_ttl = (static_cast<std::uint32_t>(response_code >> 4) << 24) |
                         (opt == query.additionals.end() ? 0U : opt->ttl_seconds & 0x00ffffffU);
    response.push_back(0);
    append_u16(response, static_cast<std::uint16_t>(DnsRecordType::opt));
    append_u16(response, udp_payload_size);
    append_u32(response, opt_ttl);
    append_u16(response,
               static_cast<std::uint16_t>(opt == query.additionals.end() ? 0 : opt->rdata.size()));
    if (opt != query.additionals.end()) {
        response.insert(response.end(), opt->rdata.begin(), opt->rdata.end());
    }
    response[10] = 0;
    response[11] = 1;
}

std::uint16_t rr_type_code(const ares_dns_rr_t *rr) {
    const auto type = ares_dns_rr_get_type(rr);
    return type == ARES_REC_TYPE_RAW_RR ? ares_dns_rr_get_u16(rr, ARES_RR_RAW_RR_TYPE)
                                        : static_cast<std::uint16_t>(type);
}

std::uint16_t read_u16(std::span<const std::uint8_t> message, std::size_t offset) {
    return static_cast<std::uint16_t>((message[offset] << 8) | message[offset + 1]);
}

std::uint32_t read_u32(std::span<const std::uint8_t> message, std::size_t offset) {
    return (static_cast<std::uint32_t>(message[offset]) << 24) |
           (static_cast<std::uint32_t>(message[offset + 1]) << 16) |
           (static_cast<std::uint32_t>(message[offset + 2]) << 8) | message[offset + 3];
}

std::optional<std::size_t> skip_name(std::span<const std::uint8_t> message, std::size_t offset) {
    auto cursor = offset;
    std::optional<std::size_t> end;
    std::size_t jumps = 0;
    while (cursor < message.size()) {
        const auto length = message[cursor];
        if ((length & 0xc0) == 0xc0) {
            if (cursor + 1 >= message.size() || ++jumps > message.size()) {
                return std::nullopt;
            }
            if (!end) {
                end = cursor + 2;
            }
            cursor = static_cast<std::size_t>(((length & 0x3f) << 8) | message[cursor + 1]);
            continue;
        }
        if ((length & 0xc0) != 0 || cursor + 1 + length > message.size()) {
            return std::nullopt;
        }
        cursor += 1 + length;
        if (length == 0) {
            return end.value_or(cursor);
        }
    }
    return std::nullopt;
}

// c-ares exposes the OPT version, flags, and options but not its extended RCODE byte.
std::optional<std::uint32_t> read_opt_ttl(std::span<const std::uint8_t> message) {
    if (message.size() < 12) {
        return std::nullopt;
    }
    std::size_t offset = 12;
    const auto question_count = read_u16(message, 4);
    const std::array<std::uint16_t, 3> section_counts{read_u16(message, 6), read_u16(message, 8),
                                                      read_u16(message, 10)};
    for (std::size_t index = 0; index < question_count; ++index) {
        const auto next = skip_name(message, offset);
        if (!next || *next + 4 > message.size()) {
            return std::nullopt;
        }
        offset = *next + 4;
    }
    for (const auto count : section_counts) {
        for (std::size_t index = 0; index < count; ++index) {
            const auto next = skip_name(message, offset);
            if (!next || *next + 10 > message.size()) {
                return std::nullopt;
            }
            offset = *next;
            const auto type = read_u16(message, offset);
            const auto ttl = read_u32(message, offset + 4);
            const auto data_length = read_u16(message, offset + 8);
            offset += 10;
            if (offset + data_length > message.size()) {
                return std::nullopt;
            }
            if (type == static_cast<std::uint16_t>(DnsRecordType::opt)) {
                return ttl;
            }
            offset += data_length;
        }
    }
    return std::nullopt;
}

bool append_cares_fields(const ares_dns_rr_t *rr, ares_dns_rec_type_t parsed_type,
                         std::vector<DnsResourceRecordField> &fields) {
    std::size_t key_count = 0;
    const auto *keys = ares_dns_rr_get_keys(parsed_type, &key_count);
    if (key_count != 0 && keys == nullptr) {
        return false;
    }

    fields.reserve(key_count);
    for (std::size_t index = 0; index < key_count; ++index) {
        const auto key = keys[index];
        const auto *key_name = ares_dns_rr_key_tostr(key);
        if (key_name == nullptr) {
            continue;
        }

        DnsResourceRecordField field;
        field.key_code = static_cast<std::uint32_t>(key);
        field.key_name = key_name;
        switch (ares_dns_rr_key_datatype(key)) {
        case ARES_DATATYPE_INADDR: {
            const auto *address = ares_dns_rr_get_addr(rr, key);
            if (address == nullptr) {
                return false;
            }
            boost::asio::ip::address_v4::bytes_type bytes{};
            std::memcpy(bytes.data(), &address->s_addr, bytes.size());
            field.type = DnsResourceRecordFieldType::ipv4_address;
            field.value = boost::asio::ip::address_v4(bytes);
            break;
        }
        case ARES_DATATYPE_INADDR6: {
            const auto *address = ares_dns_rr_get_addr6(rr, key);
            if (address == nullptr) {
                return false;
            }
            boost::asio::ip::address_v6::bytes_type bytes{};
            std::memcpy(bytes.data(), address, bytes.size());
            field.type = DnsResourceRecordFieldType::ipv6_address;
            field.value = boost::asio::ip::address_v6(bytes);
            break;
        }
        case ARES_DATATYPE_U8:
            field.type = DnsResourceRecordFieldType::unsigned_8;
            field.value = static_cast<std::uint8_t>(ares_dns_rr_get_u8(rr, key));
            break;
        case ARES_DATATYPE_U16:
            field.type = DnsResourceRecordFieldType::unsigned_16;
            field.value = static_cast<std::uint16_t>(ares_dns_rr_get_u16(rr, key));
            break;
        case ARES_DATATYPE_U32:
            field.type = DnsResourceRecordFieldType::unsigned_32;
            field.value = static_cast<std::uint32_t>(ares_dns_rr_get_u32(rr, key));
            break;
        case ARES_DATATYPE_NAME:
        case ARES_DATATYPE_STR: {
            const auto *value = ares_dns_rr_get_str(rr, key);
            if (value == nullptr) {
                return false;
            }
            const auto datatype = ares_dns_rr_key_datatype(key);
            field.type = datatype == ARES_DATATYPE_NAME ? DnsResourceRecordFieldType::domain_name
                                                        : DnsResourceRecordFieldType::string;
            field.value = datatype == ARES_DATATYPE_NAME ? normalize_name(value) : value;
            break;
        }
        case ARES_DATATYPE_BIN:
        case ARES_DATATYPE_BINP: {
            std::size_t length = 0;
            const auto *value = ares_dns_rr_get_bin(rr, key, &length);
            if (value == nullptr && length != 0) {
                return false;
            }
            field.type = DnsResourceRecordFieldType::binary;
            if (value != nullptr) {
                field.value = std::vector<std::uint8_t>(value, value + length);
            } else {
                field.value = std::vector<std::uint8_t>{};
            }
            break;
        }
        case ARES_DATATYPE_ABINP: {
            const auto value_count = ares_dns_rr_get_abin_cnt(rr, key);
            std::vector<std::vector<std::uint8_t>> values;
            values.reserve(value_count);
            for (std::size_t value_index = 0; value_index < value_count; ++value_index) {
                std::size_t length = 0;
                const auto *value = ares_dns_rr_get_abin(rr, key, value_index, &length);
                if (value == nullptr && length != 0) {
                    return false;
                }
                if (value == nullptr) {
                    values.emplace_back();
                } else {
                    values.emplace_back(value, value + length);
                }
            }
            field.type = DnsResourceRecordFieldType::binary_strings;
            field.value = std::move(values);
            break;
        }
        case ARES_DATATYPE_OPT: {
            const auto option_count = ares_dns_rr_get_opt_cnt(rr, key);
            std::vector<DnsResourceRecordOption> options;
            options.reserve(option_count);
            for (std::size_t option_index = 0; option_index < option_count; ++option_index) {
                const unsigned char *value = nullptr;
                std::size_t length = 0;
                const auto code = ares_dns_rr_get_opt(rr, key, option_index, &value, &length);
                if (code == std::numeric_limits<unsigned short>::max() ||
                    (value == nullptr && length != 0)) {
                    return false;
                }
                DnsResourceRecordOption option;
                option.code = static_cast<std::uint16_t>(code);
                if (value != nullptr) {
                    option.data.assign(value, value + length);
                }
                options.push_back(std::move(option));
            }
            field.type = DnsResourceRecordFieldType::options;
            field.value = std::move(options);
            break;
        }
        default:
            continue;
        }
        fields.push_back(std::move(field));
    }
    return true;
}

bool append_section(const ares_dns_record_t *dns_record, ares_dns_section_t section,
                    std::vector<DnsResourceRecord> &records) {
    const auto count = ares_dns_record_rr_cnt(dns_record, section);
    records.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        const auto *rr = ares_dns_record_rr_get_const(dns_record, section, index);
        if (rr == nullptr) {
            return false;
        }

        DnsResourceRecord record;
        const auto *name = ares_dns_rr_get_name(rr);
        if (name == nullptr) {
            return false;
        }
        record.name = normalize_name(name);
        const auto parsed_type = ares_dns_rr_get_type(rr);
        if (parsed_type == ARES_REC_TYPE_RAW_RR) {
            record.type = ares_dns_rr_get_u16(rr, ARES_RR_RAW_RR_TYPE);
            std::size_t length = 0;
            const auto *data = ares_dns_rr_get_bin(rr, ARES_RR_RAW_RR_DATA, &length);
            if (data != nullptr && length != 0) {
                record.rdata.assign(data, data + length);
            }
        } else {
            record.type = static_cast<std::uint16_t>(parsed_type);
        }
        if (!append_cares_fields(rr, parsed_type, record.fields)) {
            return false;
        }
        record.class_code = static_cast<std::uint16_t>(ares_dns_rr_get_class(rr));
        record.ttl_seconds = ares_dns_rr_get_ttl(rr);
        if (record.type == static_cast<std::uint16_t>(DnsRecordType::opt)) {
            record.class_code = ares_dns_rr_get_u16(rr, ARES_RR_OPT_UDP_SIZE);
        }

        switch (record.type) {
        case static_cast<std::uint16_t>(DnsRecordType::a): {
            const auto *address = ares_dns_rr_get_addr(rr, ARES_RR_A_ADDR);
            if (address != nullptr) {
                const auto *bytes = reinterpret_cast<const std::uint8_t *>(&address->s_addr);
                record.rdata.assign(bytes, bytes + sizeof(address->s_addr));
                boost::asio::ip::address_v4::bytes_type address_bytes{};
                std::copy_n(bytes, address_bytes.size(), address_bytes.begin());
                record.parsed_address = boost::asio::ip::address_v4(address_bytes);
            }
            break;
        }
        case static_cast<std::uint16_t>(DnsRecordType::aaaa): {
            const auto *address = ares_dns_rr_get_addr6(rr, ARES_RR_AAAA_ADDR);
            if (address != nullptr) {
                boost::asio::ip::address_v6::bytes_type bytes{};
                std::memcpy(bytes.data(), address, bytes.size());
                record.rdata.assign(bytes.begin(), bytes.end());
                record.parsed_address = boost::asio::ip::address_v6(bytes);
            }
            break;
        }
        case static_cast<std::uint16_t>(DnsRecordType::ns):
            if (const auto *target = ares_dns_rr_get_str(rr, ARES_RR_NS_NSDNAME)) {
                record.target_name = normalize_name(target);
            }
            break;
        case static_cast<std::uint16_t>(DnsRecordType::cname):
            if (const auto *target = ares_dns_rr_get_str(rr, ARES_RR_CNAME_CNAME)) {
                record.target_name = normalize_name(target);
            }
            break;
        case static_cast<std::uint16_t>(DnsRecordType::ptr):
            if (const auto *target = ares_dns_rr_get_str(rr, ARES_RR_PTR_DNAME)) {
                record.target_name = normalize_name(target);
            }
            break;
        case static_cast<std::uint16_t>(DnsRecordType::soa): {
            const auto *primary_name_server = ares_dns_rr_get_str(rr, ARES_RR_SOA_MNAME);
            const auto *responsible_mailbox = ares_dns_rr_get_str(rr, ARES_RR_SOA_RNAME);
            if (primary_name_server == nullptr || responsible_mailbox == nullptr) {
                return false;
            }
            record.soa = DnsSoaData{normalize_name(primary_name_server),
                                    normalize_name(responsible_mailbox),
                                    ares_dns_rr_get_u32(rr, ARES_RR_SOA_SERIAL),
                                    ares_dns_rr_get_u32(rr, ARES_RR_SOA_REFRESH),
                                    ares_dns_rr_get_u32(rr, ARES_RR_SOA_RETRY),
                                    ares_dns_rr_get_u32(rr, ARES_RR_SOA_EXPIRE),
                                    ares_dns_rr_get_u32(rr, ARES_RR_SOA_MINIMUM)};
            break;
        }
        case static_cast<std::uint16_t>(DnsRecordType::mx): {
            const auto *exchange = ares_dns_rr_get_str(rr, ARES_RR_MX_EXCHANGE);
            if (exchange == nullptr) {
                return false;
            }
            record.mx =
                DnsMxData{ares_dns_rr_get_u16(rr, ARES_RR_MX_PREFERENCE), normalize_name(exchange)};
            break;
        }
        case static_cast<std::uint16_t>(DnsRecordType::txt): {
            const auto count = ares_dns_rr_get_abin_cnt(rr, ARES_RR_TXT_DATA);
            record.txt_strings.reserve(count);
            for (std::size_t text_index = 0; text_index < count; ++text_index) {
                std::size_t length = 0;
                const auto *data = ares_dns_rr_get_abin(rr, ARES_RR_TXT_DATA, text_index, &length);
                if (data == nullptr && length != 0) {
                    return false;
                }
                if (data == nullptr) {
                    record.txt_strings.emplace_back();
                } else {
                    record.txt_strings.emplace_back(data, data + length);
                }
            }
            break;
        }
        case static_cast<std::uint16_t>(DnsRecordType::srv): {
            const auto *target = ares_dns_rr_get_str(rr, ARES_RR_SRV_TARGET);
            if (target == nullptr) {
                return false;
            }
            record.srv = DnsSrvData{ares_dns_rr_get_u16(rr, ARES_RR_SRV_PRIORITY),
                                    ares_dns_rr_get_u16(rr, ARES_RR_SRV_WEIGHT),
                                    ares_dns_rr_get_u16(rr, ARES_RR_SRV_PORT), target};
            break;
        }
        case static_cast<std::uint16_t>(DnsRecordType::opt): {
            const auto option_count = ares_dns_rr_get_opt_cnt(rr, ARES_RR_OPT_OPTIONS);
            for (std::size_t option_index = 0; option_index < option_count; ++option_index) {
                const unsigned char *data = nullptr;
                std::size_t length = 0;
                const auto option =
                    ares_dns_rr_get_opt(rr, ARES_RR_OPT_OPTIONS, option_index, &data, &length);
                if (option == std::numeric_limits<unsigned short>::max() ||
                    length > std::numeric_limits<std::uint16_t>::max()) {
                    return false;
                }
                append_u16(record.rdata, option);
                append_u16(record.rdata, static_cast<std::uint16_t>(length));
                if (data != nullptr && length != 0) {
                    record.rdata.insert(record.rdata.end(), data, data + length);
                }
            }
            break;
        }
        default:
            break;
        }

        records.push_back(std::move(record));
    }
    return true;
}

} // namespace

core::Result<DnsPacket> DnsMessageCodec::decode_packet(std::span<const std::uint8_t> message,
                                                       std::optional<std::uint16_t> expected_id) {
    const auto init_status = initialize_cares();
    if (init_status != ARES_SUCCESS) {
        return core::fail(cares_error("initialize the DNS library", init_status));
    }

    ares_dns_record_t *parsed_record = nullptr;
    const auto parse_status = ares_dns_parse(message.data(), message.size(), 0, &parsed_record);
    if (parse_status != ARES_SUCCESS) {
        return core::fail(cares_error("parse the DNS message", parse_status));
    }
    const std::unique_ptr<ares_dns_record_t, decltype(&ares_dns_record_destroy)> dns_record(
        parsed_record, &ares_dns_record_destroy);

    DnsPacket packet;
    packet.id = ares_dns_record_get_id(dns_record.get());
    if (expected_id && packet.id != *expected_id) {
        return core::fail(codec_error("DNS response transaction ID does not match"));
    }

    const auto parsed_flags = ares_dns_record_get_flags(dns_record.get());
    const auto parsed_opcode =
        static_cast<std::uint16_t>(ares_dns_record_get_opcode(dns_record.get()));
    const auto parsed_response_code =
        static_cast<std::uint16_t>(ares_dns_record_get_rcode(dns_record.get()));
    packet.extended_response_code = static_cast<std::uint8_t>(parsed_response_code >> 4);
    if ((parsed_flags & ARES_FLAG_QR) != 0) {
        packet.flags |= 0x8000;
    }
    if ((parsed_flags & ARES_FLAG_AA) != 0) {
        packet.flags |= 0x0400;
    }
    if ((parsed_flags & ARES_FLAG_TC) != 0) {
        packet.flags |= 0x0200;
    }
    if ((parsed_flags & ARES_FLAG_RD) != 0) {
        packet.flags |= 0x0100;
    }
    if ((parsed_flags & ARES_FLAG_RA) != 0) {
        packet.flags |= 0x0080;
    }
    if ((parsed_flags & ARES_FLAG_AD) != 0) {
        packet.flags |= 0x0020;
    }
    if ((parsed_flags & ARES_FLAG_CD) != 0) {
        packet.flags |= 0x0010;
    }
    packet.flags |=
        static_cast<std::uint16_t>(((parsed_opcode & 0x0f) << 11) | (parsed_response_code & 0x0f));
    packet.wire.assign(message.begin(), message.end());

    const auto question_count = ares_dns_record_query_cnt(dns_record.get());
    packet.questions.reserve(question_count);
    for (std::size_t index = 0; index < question_count; ++index) {
        const char *name = nullptr;
        DnsQuestion question;
        ares_dns_rec_type_t type = ARES_REC_TYPE_A;
        ares_dns_class_t class_code = ARES_CLASS_IN;
        const auto question_status =
            ares_dns_record_query_get(dns_record.get(), index, &name, &type, &class_code);
        if (question_status != ARES_SUCCESS || name == nullptr) {
            return core::fail(cares_error("read a DNS question", question_status));
        }
        question.name = normalize_name(name);
        question.type = static_cast<DnsRecordType>(static_cast<std::uint16_t>(type));
        question.class_code = static_cast<std::uint16_t>(class_code);
        packet.questions.push_back(std::move(question));
    }

    if (!append_section(dns_record.get(), ARES_SECTION_ANSWER, packet.answers) ||
        !append_section(dns_record.get(), ARES_SECTION_AUTHORITY, packet.authorities) ||
        !append_section(dns_record.get(), ARES_SECTION_ADDITIONAL, packet.additionals)) {
        return core::fail(codec_error("c-ares returned an invalid DNS resource record"));
    }
    const auto opt = std::find_if(
        packet.additionals.begin(), packet.additionals.end(), [](const DnsResourceRecord &record) {
            return record.type == static_cast<std::uint16_t>(DnsRecordType::opt);
        });
    if (opt != packet.additionals.end()) {
        if (const auto ttl = read_opt_ttl(message)) {
            opt->ttl_seconds = *ttl;
            packet.extended_response_code = static_cast<std::uint8_t>(*ttl >> 24);
        }
    }
    return packet;
}

core::Result<std::vector<std::uint8_t>>
DnsMessageCodec::encode_query_packet(const DnsQuestion &question, std::uint16_t id) {
    const auto name = normalize_name(question.name);
    if (name.empty() || name.size() > 253 || name.front() == '.' || name.back() == '.') {
        return core::fail(codec_error("DNS query name is invalid"));
    }

    std::vector<std::uint8_t> output;
    output.reserve(12 + name.size() + 6);
    append_u16(output, id);
    append_u16(output, 0x0100);
    append_u16(output, 1);
    append_u16(output, 0);
    append_u16(output, 0);
    append_u16(output, 0);

    std::size_t begin = 0;
    while (begin < name.size()) {
        const auto end = name.find('.', begin);
        const auto label_end = end == std::string::npos ? name.size() : end;
        const auto label_size = label_end - begin;
        if (label_size == 0 || label_size > 63) {
            return core::fail(codec_error("DNS query label is invalid"));
        }
        output.push_back(static_cast<std::uint8_t>(label_size));
        output.insert(output.end(), name.begin() + static_cast<std::ptrdiff_t>(begin),
                      name.begin() + static_cast<std::ptrdiff_t>(label_end));
        if (end == std::string::npos) {
            break;
        }
        begin = end + 1;
    }
    output.push_back(0);
    append_u16(output, static_cast<std::uint16_t>(question.type));
    append_u16(output, question.class_code);
    return output;
}

core::Result<std::vector<std::uint8_t>> DnsMessageCodec::rewrite_id(const DnsPacket &packet,
                                                                    std::uint16_t id) {
    if (packet.wire.size() < 2) {
        return core::fail(codec_error("DNS packet wire message is missing a transaction ID"));
    }
    auto wire = packet.wire;
    wire[0] = static_cast<std::uint8_t>(id >> 8);
    wire[1] = static_cast<std::uint8_t>(id & 0xff);
    return wire;
}

core::Result<DnsAnswer> DnsMessageCodec::to_address_answer(const DnsPacket &packet) {
    if (!packet.response() || packet.questions.size() != 1) {
        return core::fail(codec_error("DNS packet is not a single-question response"));
    }

    DnsAnswer answer;
    answer.question = packet.questions.front();
    answer.response_code = packet.response_code();
    answer.truncated = packet.truncated();
    answer.authoritative = packet.authoritative();
    auto current_name = normalize_name(answer.question.name);
    std::vector<std::string> visited_names{current_name};
    std::uint32_t minimum_ttl = std::numeric_limits<std::uint32_t>::max();
    for (std::size_t depth = 0; depth < 8; ++depth) {
        const auto cname = std::find_if(
            packet.answers.begin(), packet.answers.end(), [&](const DnsResourceRecord &record) {
                return record.class_code == answer.question.class_code &&
                       record.type == static_cast<std::uint16_t>(DnsRecordType::cname) &&
                       normalize_name(record.name) == current_name && record.target_name;
            });
        if (cname == packet.answers.end()) {
            break;
        }
        const auto next_name = normalize_name(*cname->target_name);
        if (next_name.empty() || std::find(visited_names.begin(), visited_names.end(), next_name) !=
                                     visited_names.end()) {
            break;
        }
        visited_names.push_back(next_name);
        current_name = next_name;
        minimum_ttl = std::min(minimum_ttl, cname->ttl_seconds);
    }
    for (const auto &record : packet.answers) {
        if (record.class_code != answer.question.class_code ||
            record.type != static_cast<std::uint16_t>(answer.question.type) ||
            normalize_name(record.name) != current_name) {
            continue;
        }
        if (!record.parsed_address ||
            (answer.question.type == DnsRecordType::a && !record.parsed_address->is_v4()) ||
            (answer.question.type == DnsRecordType::aaaa && !record.parsed_address->is_v6())) {
            continue;
        }
        answer.addresses.push_back(*record.parsed_address);
        minimum_ttl = std::min(minimum_ttl, record.ttl_seconds);
    }
    if (!answer.addresses.empty()) {
        answer.ttl_seconds = minimum_ttl;
    }
    return answer;
}

std::string normalize_name(std::string_view name) {
    while (!name.empty() && name.back() == '.') {
        name.remove_suffix(1);
    }

    std::string result(name);
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}

core::Result<std::vector<std::uint8_t>> DnsMessageCodec::encode_query(const DnsQuestion &question,
                                                                      std::uint16_t id) {
    return encode_query_packet(question, id);
}

core::Result<DnsQuery> DnsMessageCodec::decode_query(std::span<const std::uint8_t> message) {
    const auto packet = decode_packet(message);
    if (!packet) {
        return core::fail(packet.error());
    }
    if (packet.value().response() || packet.value().questions.size() != 1 ||
        !packet.value().answers.empty() || !packet.value().authorities.empty()) {
        return core::fail(codec_error("DNS query must contain one question"));
    }

    DnsQuery query;
    query.id = packet.value().id;
    query.question = packet.value().questions.front();
    query.recursion_desired = packet.value().recursion_desired();
    return query;
}

core::Result<DnsAnswer> DnsMessageCodec::decode_response(std::span<const std::uint8_t> message,
                                                         std::uint16_t expected_id) {
    const auto packet = decode_packet(message, expected_id);
    if (!packet) {
        return core::fail(packet.error());
    }
    if (!packet.value().response() || packet.value().questions.size() != 1) {
        return core::fail(codec_error("DNS response must contain one question"));
    }
    return to_address_answer(packet.value());
}

core::Result<std::vector<std::uint8_t>> DnsMessageCodec::encode_response(const DnsQuery &query,
                                                                         const DnsAnswer &answer) {
    if (normalize_name(query.question.name) != normalize_name(answer.question.name) ||
        query.question.type != answer.question.type ||
        query.question.class_code != answer.question.class_code) {
        return core::fail(codec_error("DNS response question does not match the query"));
    }
    if (answer.addresses.size() > std::numeric_limits<std::uint16_t>::max()) {
        return core::fail(codec_error("DNS response contains too many answers"));
    }

    const auto encoded_query = encode_query(query.question, query.id);
    if (!encoded_query) {
        return core::fail(encoded_query.error());
    }

    const auto answer_count = answer.response_code == 0 ? answer.addresses.size() : 0;
    std::vector<std::uint8_t> response(encoded_query.value().begin(),
                                       encoded_query.value().begin() + 12);
    response[2] = static_cast<std::uint8_t>(0x80 | (query.recursion_desired ? 0x01 : 0x00) |
                                            (answer.authoritative ? 0x04 : 0x00));
    response[3] = static_cast<std::uint8_t>(0x80 | (answer.response_code & 0x0f));
    response[6] = static_cast<std::uint8_t>(answer_count >> 8);
    response[7] = static_cast<std::uint8_t>(answer_count & 0xff);
    response.insert(response.end(), encoded_query.value().begin() + 12,
                    encoded_query.value().end());

    for (std::size_t index = 0; index < answer_count; ++index) {
        const auto &address = answer.addresses[index];
        if ((answer.question.type == DnsRecordType::a && !address.is_v4()) ||
            (answer.question.type == DnsRecordType::aaaa && !address.is_v6())) {
            return core::fail(codec_error("DNS answer address type does not match the query"));
        }
        response.insert(response.end(), {0xc0, 0x0c});
        append_u16(response, static_cast<std::uint16_t>(answer.question.type));
        append_u16(response, answer.question.class_code);
        append_u32(response, answer.ttl_seconds);
        if (address.is_v4()) {
            const auto bytes = address.to_v4().to_bytes();
            append_u16(response, static_cast<std::uint16_t>(bytes.size()));
            response.insert(response.end(), bytes.begin(), bytes.end());
        } else {
            const auto bytes = address.to_v6().to_bytes();
            append_u16(response, static_cast<std::uint16_t>(bytes.size()));
            response.insert(response.end(), bytes.begin(), bytes.end());
        }
    }
    return response;
}

core::Result<std::vector<std::uint8_t>> DnsMessageCodec::encode_response(const DnsPacket &query,
                                                                         const DnsAnswer &answer) {
    if (query.response() || query.questions.size() != 1 || query.response_code() != 0 ||
        answer.response_code > 0x0fff) {
        return core::fail(codec_error("DNS response requires one valid query question"));
    }
    const DnsQuery legacy_query{query.id, query.questions.front(), query.recursion_desired()};
    auto response = encode_response(legacy_query, answer);
    if (!response) {
        return core::fail(response.error());
    }
    auto &wire = response.value();
    const auto flags = static_cast<std::uint16_t>((query.flags & 0x7910) | 0x8080 |
                                                  (answer.authoritative ? 0x0400 : 0x0000) |
                                                  (answer.response_code & 0x000f));
    wire[2] = static_cast<std::uint8_t>(flags >> 8);
    wire[3] = static_cast<std::uint8_t>(flags & 0xff);
    append_opt_record(wire, query, answer.response_code);
    return response;
}

core::Result<std::vector<std::uint8_t>>
DnsMessageCodec::encode_error_response(const DnsPacket &query, std::uint16_t code) {
    if (query.response() || query.questions.size() != 1) {
        return core::fail(codec_error("DNS error response requires one query question"));
    }
    if (code > 0x0fff) {
        return core::fail(codec_error("DNS response code exceeds the 12-bit wire limit"));
    }
    const auto encoded_query = encode_query_packet(query.questions.front(), query.id);
    if (!encoded_query) {
        return core::fail(encoded_query.error());
    }
    auto response = encoded_query.value();
    const auto flags = static_cast<std::uint16_t>((query.flags & 0x7910) | 0x8080 | (code & 0x0f));
    response[2] = static_cast<std::uint8_t>(flags >> 8);
    response[3] = static_cast<std::uint8_t>(flags & 0xff);
    append_opt_record(response, query, code);
    return response;
}

core::Result<std::vector<std::uint8_t>>
DnsMessageCodec::truncate_udp_response(std::span<const std::uint8_t> response,
                                       std::size_t maximum_size) {
    if (maximum_size < 12) {
        return core::fail(codec_error("UDP DNS payload capacity is smaller than a DNS header"));
    }
    if (response.size() <= maximum_size) {
        return std::vector<std::uint8_t>(response.begin(), response.end());
    }
    const auto init_status = initialize_cares();
    if (init_status != ARES_SUCCESS) {
        return core::fail(cares_error("initialize the DNS library", init_status));
    }
    ares_dns_record_t *parsed_record = nullptr;
    const auto parse_status = ares_dns_parse(response.data(), response.size(), 0, &parsed_record);
    if (parse_status != ARES_SUCCESS) {
        return core::fail(cares_error("parse the response for UDP truncation", parse_status));
    }
    std::unique_ptr<ares_dns_record_t, decltype(&ares_dns_record_destroy)> parsed(
        parsed_record, &ares_dns_record_destroy);
    std::unique_ptr<ares_dns_record_t, decltype(&ares_dns_record_destroy)> record(
        ares_dns_record_duplicate(parsed.get()), &ares_dns_record_destroy);
    if (!record) {
        return core::fail(codec_error("c-ares could not duplicate the DNS response"));
    }

    const auto encode_truncated = [&]() -> core::Result<std::vector<std::uint8_t>> {
        auto wire = write_dns_record(record.get());
        if (!wire) {
            return core::fail(wire.error());
        }
        if (wire.value().size() > maximum_size) {
            return core::fail(
                codec_error("DNS question and EDNS data exceed the UDP payload capacity"));
        }
        wire.value()[2] |= 0x02;
        return wire;
    };

    for (const auto section :
         {ARES_SECTION_ADDITIONAL, ARES_SECTION_AUTHORITY, ARES_SECTION_ANSWER}) {
        while (ares_dns_record_rr_cnt(record.get(), section) != 0) {
            const auto count = ares_dns_record_rr_cnt(record.get(), section);
            bool removed = false;
            for (std::size_t reverse_index = count; reverse_index > 0; --reverse_index) {
                const auto index = reverse_index - 1;
                const auto *rr = ares_dns_record_rr_get_const(record.get(), section, index);
                if (rr == nullptr) {
                    return core::fail(codec_error("c-ares returned an invalid resource record"));
                }
                const auto type = rr_type_code(rr);
                if (section == ARES_SECTION_ADDITIONAL &&
                    type == static_cast<std::uint16_t>(DnsRecordType::opt)) {
                    continue;
                }
                const auto *name = ares_dns_rr_get_name(rr);
                if (name == nullptr) {
                    return core::fail(
                        codec_error("c-ares returned a resource record without a name"));
                }
                const auto normalized_name = normalize_name(name);
                const auto class_code = static_cast<std::uint16_t>(ares_dns_rr_get_class(rr));
                for (std::size_t candidate = ares_dns_record_rr_cnt(record.get(), section);
                     candidate > 0; --candidate) {
                    const auto candidate_index = candidate - 1;
                    const auto *candidate_rr =
                        ares_dns_record_rr_get_const(record.get(), section, candidate_index);
                    const auto *candidate_name = ares_dns_rr_get_name(candidate_rr);
                    if (candidate_rr != nullptr && candidate_name != nullptr &&
                        rr_type_code(candidate_rr) == type &&
                        static_cast<std::uint16_t>(ares_dns_rr_get_class(candidate_rr)) ==
                            class_code &&
                        normalize_name(candidate_name) == normalized_name) {
                        const auto delete_status =
                            ares_dns_record_rr_del(record.get(), section, candidate_index);
                        if (delete_status != ARES_SUCCESS) {
                            return core::fail(cares_error(
                                "remove a resource record while truncating", delete_status));
                        }
                    }
                }
                removed = true;
                break;
            }
            if (!removed) {
                break;
            }
            auto truncated = encode_truncated();
            if (truncated) {
                return truncated;
            }
            if (truncated.error().context !=
                "DNS question and EDNS data exceed the UDP payload capacity") {
                return truncated;
            }
        }
    }

    // A pathological query can carry EDNS options larger than the client's receive limit.
    // Drop OPT only as a last resort, after all response RRsets have been removed.
    for (std::size_t index = ares_dns_record_rr_cnt(record.get(), ARES_SECTION_ADDITIONAL);
         index > 0; --index) {
        const auto rr_index = index - 1;
        const auto *rr =
            ares_dns_record_rr_get_const(record.get(), ARES_SECTION_ADDITIONAL, rr_index);
        if (rr != nullptr && rr_type_code(rr) == static_cast<std::uint16_t>(DnsRecordType::opt)) {
            const auto delete_status =
                ares_dns_record_rr_del(record.get(), ARES_SECTION_ADDITIONAL, rr_index);
            if (delete_status != ARES_SUCCESS) {
                return core::fail(
                    cares_error("remove oversized EDNS data while truncating", delete_status));
            }
        }
    }
    return encode_truncated();
}

} // namespace clash_native::dns
