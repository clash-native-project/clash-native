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

core::Result<void> skip_record(std::span<const std::uint8_t> message, std::size_t &position,
                               std::uint16_t &type, std::uint16_t &class_code, std::uint32_t &ttl,
                               std::span<const std::uint8_t> &rdata) {
    auto name = read_name(message, position);
    if (!name) {
        return core::fail(name.error());
    }

    std::uint16_t rdlength = 0;
    if (!read_u16(message, position, type) || !read_u16(message, position, class_code) ||
        !read_u32(message, position, ttl) || !read_u16(message, position, rdlength) ||
        position + rdlength > message.size()) {
        return core::fail(codec_error("DNS resource record is truncated"));
    }
    rdata = message.subspan(position, rdlength);
    position += rdlength;
    return {};
}

} // namespace

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
        output.insert(output.end(), name.begin() + begin, name.begin() + label_end);
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

core::Result<DnsAnswer> DnsMessageCodec::decode_response(std::span<const std::uint8_t> message,
                                                         std::uint16_t expected_id) {
    if (message.size() < 12) {
        return core::fail(codec_error("DNS response header is truncated"));
    }

    std::size_t position = 0;
    std::uint16_t id = 0;
    std::uint16_t flags = 0;
    std::uint16_t question_count = 0;
    std::uint16_t answer_count = 0;
    std::uint16_t authority_count = 0;
    std::uint16_t additional_count = 0;
    if (!read_u16(message, position, id) || !read_u16(message, position, flags) ||
        !read_u16(message, position, question_count) ||
        !read_u16(message, position, answer_count) ||
        !read_u16(message, position, authority_count) ||
        !read_u16(message, position, additional_count)) {
        return core::fail(codec_error("DNS response header is invalid"));
    }
    if (id != expected_id) {
        return core::fail(codec_error("DNS response transaction ID does not match"));
    }
    if ((flags & 0x8000) == 0) {
        return core::fail(codec_error("DNS response is not a response message"));
    }

    DnsAnswer answer;
    answer.response_code = static_cast<std::uint8_t>(flags & 0x000f);
    answer.truncated = (flags & 0x0200) != 0;
    answer.authoritative = (flags & 0x0400) != 0;

    for (std::uint16_t index = 0; index < question_count; ++index) {
        auto name = read_name(message, position);
        std::uint16_t type = 0;
        std::uint16_t class_code = 0;
        if (!name || !read_u16(message, position, type) ||
            !read_u16(message, position, class_code)) {
            return core::fail(codec_error("DNS question is invalid"));
        }
        if (index == 0) {
            answer.question.name = std::move(name.value());
            answer.question.type = static_cast<DnsRecordType>(type);
            answer.question.class_code = class_code;
        }
    }

    std::uint32_t minimum_ttl = std::numeric_limits<std::uint32_t>::max();
    const auto record_count =
        static_cast<std::size_t>(answer_count) + authority_count + additional_count;
    for (std::size_t index = 0; index < record_count; ++index) {
        std::uint16_t type = 0;
        std::uint16_t class_code = 0;
        std::uint32_t ttl = 0;
        std::span<const std::uint8_t> rdata;
        if (!skip_record(message, position, type, class_code, ttl, rdata)) {
            return core::fail(codec_error("DNS resource record is invalid"));
        }
        if (index >= answer_count || class_code != answer.question.class_code ||
            type != static_cast<std::uint16_t>(answer.question.type)) {
            continue;
        }

        if (answer.question.type == DnsRecordType::a && rdata.size() == 4) {
            boost::asio::ip::address_v4::bytes_type bytes{};
            std::copy(rdata.begin(), rdata.end(), bytes.begin());
            answer.addresses.push_back(boost::asio::ip::address_v4(bytes));
        } else if (answer.question.type == DnsRecordType::aaaa && rdata.size() == 16) {
            boost::asio::ip::address_v6::bytes_type bytes{};
            std::copy(rdata.begin(), rdata.end(), bytes.begin());
            answer.addresses.push_back(boost::asio::ip::address_v6(bytes));
        }
        if (!answer.addresses.empty()) {
            minimum_ttl = std::min(minimum_ttl, ttl);
        }
    }
    if (!answer.addresses.empty()) {
        answer.ttl_seconds = minimum_ttl;
    }
    return answer;
}

} // namespace clash_native::dns
