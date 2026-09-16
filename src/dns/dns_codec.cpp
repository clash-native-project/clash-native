#include <clash_native/dns/dns_codec.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
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

bool read_u16(std::span<const std::uint8_t> message, std::size_t &position, std::uint16_t &value) {
    if (position + 2 > message.size()) {
        return false;
    }
    value = static_cast<std::uint16_t>(message[position] << 8 | message[position + 1]);
    position += 2;
    return true;
}

bool read_u32(std::span<const std::uint8_t> message, std::size_t &position, std::uint32_t &value) {
    if (position + 4 > message.size()) {
        return false;
    }
    value = (static_cast<std::uint32_t>(message[position]) << 24) |
            (static_cast<std::uint32_t>(message[position + 1]) << 16) |
            (static_cast<std::uint32_t>(message[position + 2]) << 8) |
            static_cast<std::uint32_t>(message[position + 3]);
    position += 4;
    return true;
}

core::Result<std::string> read_name(std::span<const std::uint8_t> message, std::size_t &position) {
    std::string name;
    std::size_t cursor = position;
    std::size_t jumps = 0;
    bool jumped = false;

    while (true) {
        if (cursor >= message.size()) {
            return core::fail(codec_error("DNS name exceeds message bounds"));
        }

        const auto length = message[cursor++];
        if (length == 0) {
            if (!jumped) {
                position = cursor;
            }
            return normalize_name(name);
        }

        if ((length & 0xc0) == 0xc0) {
            if (cursor >= message.size()) {
                return core::fail(codec_error("DNS name pointer is truncated"));
            }
            const auto pointer = static_cast<std::size_t>((length & 0x3f) << 8 | message[cursor++]);
            if (pointer >= message.size() || ++jumps > 32) {
                return core::fail(codec_error("DNS name pointer is invalid"));
            }
            if (!jumped) {
                position = cursor;
            }
            cursor = pointer;
            jumped = true;
            continue;
        }

        if ((length & 0xc0) != 0 || length > 63 || cursor + length > message.size()) {
            return core::fail(codec_error("DNS label is invalid"));
        }
        if (!name.empty()) {
            name.push_back('.');
        }
        name.append(reinterpret_cast<const char *>(message.data() + cursor), length);
        cursor += length;
        if (name.size() > 253) {
            return core::fail(codec_error("DNS name is too long"));
        }
    }
}

core::Result<DnsResourceRecord> read_record(std::span<const std::uint8_t> message,
                                            std::size_t &position) {
    auto name = read_name(message, position);
    if (!name) {
        return core::fail(name.error());
    }

    DnsResourceRecord record;
    record.name = std::move(name.value());
    std::uint16_t rdlength = 0;
    if (!read_u16(message, position, record.type) ||
        !read_u16(message, position, record.class_code) ||
        !read_u32(message, position, record.ttl_seconds) ||
        !read_u16(message, position, rdlength) || position + rdlength > message.size()) {
        return core::fail(codec_error("DNS resource record is truncated"));
    }
    record.rdata.assign(message.begin() + static_cast<std::ptrdiff_t>(position),
                        message.begin() + static_cast<std::ptrdiff_t>(position + rdlength));
    if (record.type == static_cast<std::uint16_t>(DnsRecordType::ns) ||
        record.type == static_cast<std::uint16_t>(DnsRecordType::cname) ||
        record.type == static_cast<std::uint16_t>(DnsRecordType::ptr)) {
        auto target_position = position;
        const auto target = read_name(message, target_position);
        if (target && target_position <= position + rdlength) {
            record.target_name = target.value();
        }
    }
    position += rdlength;
    return record;
}

} // namespace

core::Result<DnsPacket> DnsMessageCodec::decode_packet(std::span<const std::uint8_t> message,
                                                       std::optional<std::uint16_t> expected_id) {
    if (message.size() < 12) {
        return core::fail(codec_error("DNS message header is truncated"));
    }

    std::size_t position = 0;
    DnsPacket packet;
    std::uint16_t question_count = 0;
    std::uint16_t answer_count = 0;
    std::uint16_t authority_count = 0;
    std::uint16_t additional_count = 0;
    if (!read_u16(message, position, packet.id) || !read_u16(message, position, packet.flags) ||
        !read_u16(message, position, question_count) ||
        !read_u16(message, position, answer_count) ||
        !read_u16(message, position, authority_count) ||
        !read_u16(message, position, additional_count)) {
        return core::fail(codec_error("DNS message header is invalid"));
    }
    if (expected_id && packet.id != *expected_id) {
        return core::fail(codec_error("DNS response transaction ID does not match"));
    }

    packet.wire.assign(message.begin(), message.end());
    packet.questions.reserve(question_count);
    packet.answers.reserve(answer_count);
    packet.authorities.reserve(authority_count);
    packet.additionals.reserve(additional_count);

    for (std::uint16_t index = 0; index < question_count; ++index) {
        auto name = read_name(message, position);
        DnsQuestion question;
        std::uint16_t type = 0;
        if (!name || !read_u16(message, position, type) ||
            !read_u16(message, position, question.class_code)) {
            return core::fail(codec_error("DNS question is invalid"));
        }
        question.name = std::move(name.value());
        question.type = static_cast<DnsRecordType>(type);
        packet.questions.push_back(std::move(question));
    }

    const auto read_section = [&](std::uint16_t count,
                                  std::vector<DnsResourceRecord> &records) -> core::Status {
        for (std::uint16_t index = 0; index < count; ++index) {
            auto record = read_record(message, position);
            if (!record) {
                return core::fail(record.error());
            }
            records.push_back(std::move(record.value()));
        }
        return {};
    };
    if (!read_section(answer_count, packet.answers) ||
        !read_section(authority_count, packet.authorities) ||
        !read_section(additional_count, packet.additionals)) {
        return core::fail(codec_error("DNS resource record section is invalid"));
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
        if (answer.question.type == DnsRecordType::a && record.rdata.size() == 4) {
            boost::asio::ip::address_v4::bytes_type bytes{};
            std::copy(record.rdata.begin(), record.rdata.end(), bytes.begin());
            answer.addresses.emplace_back(boost::asio::ip::address_v4(bytes));
        } else if (answer.question.type == DnsRecordType::aaaa && record.rdata.size() == 16) {
            boost::asio::ip::address_v6::bytes_type bytes{};
            std::copy(record.rdata.begin(), record.rdata.end(), bytes.begin());
            answer.addresses.emplace_back(boost::asio::ip::address_v6(bytes));
        }
        if (!answer.addresses.empty()) {
            minimum_ttl = std::min(minimum_ttl, record.ttl_seconds);
        }
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

core::Result<std::vector<std::uint8_t>>
DnsMessageCodec::encode_error_response(const DnsPacket &query, std::uint8_t code) {
    if (query.response() || query.questions.size() != 1) {
        return core::fail(codec_error("DNS error response requires one query question"));
    }
    const auto encoded_query = encode_query_packet(query.questions.front(), query.id);
    if (!encoded_query) {
        return core::fail(encoded_query.error());
    }
    auto response = encoded_query.value();
    const auto flags = static_cast<std::uint16_t>((query.flags & 0x7900) | 0x8000 | (code & 0x0f));
    response[2] = static_cast<std::uint8_t>(flags >> 8);
    response[3] = static_cast<std::uint8_t>(flags & 0xff);
    return response;
}

} // namespace clash_native::dns
