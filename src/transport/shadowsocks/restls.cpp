#include <clash_native/transport/shadowsocks/restls.hpp>

#include <blake3.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstring>
#include <functional>
#include <limits>
#include <string>
#include <utility>

namespace clash_native::transport::shadowsocks {

namespace {

constexpr std::size_t kRestlsApplicationMacLength = 8;
constexpr std::size_t kRestlsMaskLength = 4;
constexpr std::size_t kRestlsAuthHeaderLength = kRestlsApplicationMacLength + kRestlsMaskLength;
constexpr std::size_t kTlsRecordHeaderLength = 5;

core::Error restls_error(std::string message) {
    return {core::ErrorCode::protocol_framing, std::move(message), {}};
}

std::string_view trim(std::string_view value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) {
        value.remove_prefix(1);
    }
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) {
        value.remove_suffix(1);
    }
    return value;
}

core::Result<std::uint32_t> parse_integer(std::string_view value) {
    if (value.empty()) {
        return core::fail(restls_error("ResTLS script integer is empty"));
    }
    std::uint32_t result = 0;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()) {
        return core::fail(restls_error("ResTLS script contains an invalid integer"));
    }
    return result;
}

std::array<std::uint8_t, 32> blake3_keyed(std::span<const std::uint8_t, 32> key,
                                          std::span<const std::span<const std::uint8_t>> parts) {
    blake3_hasher hasher;
    blake3_hasher_init_keyed(&hasher, key.data());
    for (const auto part : parts) {
        blake3_hasher_update(&hasher, part.data(), part.size());
    }
    std::array<std::uint8_t, 32> output{};
    blake3_hasher_finalize(&hasher, output.data(), output.size());
    return output;
}

std::array<std::uint8_t, 32> blake3_derive(std::string_view context,
                                           std::span<const std::uint8_t> input) {
    blake3_hasher hasher;
    blake3_hasher_init_derive_key(&hasher, std::string(context).c_str());
    blake3_hasher_update(&hasher, input.data(), input.size());
    std::array<std::uint8_t, 32> output{};
    blake3_hasher_finalize(&hasher, output.data(), output.size());
    return output;
}

void append_u64_be(std::vector<std::uint8_t> &output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

std::array<std::uint8_t, 32> auth_hash(std::span<const std::uint8_t, 32> secret,
                                       std::span<const std::uint8_t> server_random, bool to_client,
                                       std::uint64_t counter,
                                       std::span<const std::uint8_t> extra = {}) {
    static constexpr std::array<std::uint8_t, 16> to_client_label{
        's', 'e', 'r', 'v', 'e', 'r', '-', 't', 'o', '-', 'c', 'l', 'i', 'e', 'n', 't'};
    static constexpr std::array<std::uint8_t, 16> to_server_label{
        'c', 'l', 'i', 'e', 'n', 't', '-', 't', 'o', '-', 's', 'e', 'r', 'v', 'e', 'r'};
    std::vector<std::uint8_t> counter_bytes;
    counter_bytes.reserve(8);
    append_u64_be(counter_bytes, counter);
    const auto &label = to_client ? to_client_label : to_server_label;
    const std::array<std::span<const std::uint8_t>, 4> parts{server_random, label, counter_bytes,
                                                             extra};
    return blake3_keyed(secret, parts);
}

} // namespace

std::array<std::uint8_t, 2> RestlsCommand::wire() const noexcept {
    if (kind == RestlsCommandKind::response) {
        return {0x01, response};
    }
    return {0x00, 0x00};
}

bool RestlsCommand::needs_peer_response() const noexcept {
    return kind == RestlsCommandKind::response;
}

core::Result<std::vector<RestlsScriptLine>> parse_restls_script(std::string_view script) {
    std::vector<RestlsScriptLine> result;
    while (!script.empty()) {
        const auto comma = script.find(',');
        const auto token = trim(script.substr(0, comma));
        if (!token.empty()) {
            std::size_t cursor = 0;
            while (cursor < token.size() &&
                   std::isdigit(static_cast<unsigned char>(token[cursor]))) {
                ++cursor;
            }
            auto target = parse_integer(token.substr(0, cursor));
            if (!target || target.value() > 32767) {
                return core::fail(restls_error("ResTLS script target length is invalid"));
            }
            RestlsScriptLine line;
            line.target_length = static_cast<std::uint16_t>(target.value());
            if (cursor < token.size() && (token[cursor] == '?' || token[cursor] == '~')) {
                line.randomize_target = token[cursor] == '?';
                ++cursor;
                std::size_t range_end = cursor;
                while (range_end < token.size() &&
                       std::isdigit(static_cast<unsigned char>(token[range_end]))) {
                    ++range_end;
                }
                auto range = parse_integer(token.substr(cursor, range_end - cursor));
                if (!range || range.value() > 32767 || range.value() + target.value() > 32768) {
                    return core::fail(restls_error("ResTLS script random range is invalid"));
                }
                line.random_range = static_cast<std::uint16_t>(range.value());
                cursor = range_end;
            }
            if (cursor < token.size()) {
                if (token[cursor] != '<') {
                    return core::fail(restls_error("ResTLS script command is invalid"));
                }
                ++cursor;
                auto response = parse_integer(token.substr(cursor));
                if (!response || response.value() >= 255) {
                    return core::fail(restls_error("ResTLS script response count is invalid"));
                }
                line.command.kind = RestlsCommandKind::response;
                line.command.response = static_cast<std::uint8_t>(response.value());
                cursor = token.size();
            }
            if (cursor != token.size()) {
                return core::fail(restls_error("ResTLS script has trailing characters"));
            }
            result.push_back(line);
        }
        if (comma == std::string_view::npos) {
            break;
        }
        script.remove_prefix(comma + 1);
    }
    if (result.empty()) {
        return core::fail(restls_error("ResTLS script must contain at least one record"));
    }
    return result;
}

core::Result<std::array<std::uint8_t, 32>> derive_restls_secret(std::string_view password) {
    const auto input = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t *>(password.data()), password.size());
    return blake3_derive("restls-traffic-key", input);
}

core::Result<std::array<std::uint8_t, 32>>
restls_hmac(std::span<const std::uint8_t, 32> secret,
            std::span<const std::span<const std::uint8_t>> parts) {
    return blake3_keyed(secret, parts);
}

core::Result<std::array<std::uint8_t, 32>>
derive_restls_tls12_session_id(std::span<const std::uint8_t, 32> secret,
                               const std::vector<std::vector<std::uint8_t>> &ecdhe_public_keys,
                               std::optional<std::span<const std::uint8_t>> session_ticket) {
    if (ecdhe_public_keys.size() != 3) {
        return core::fail(restls_error("ResTLS TLS 1.2 requires three ECDHE public keys"));
    }
    const bool with_ticket = session_ticket.has_value();
    std::array<std::uint8_t, 32> output{};
    const std::array<std::size_t, 5> layout = with_ticket
                                                  ? std::array<std::size_t, 5>{0, 8, 16, 24, 32}
                                                  : std::array<std::size_t, 5>{0, 11, 22, 32, 32};
    for (std::size_t index = 0; index < ecdhe_public_keys.size(); ++index) {
        const std::array<std::span<const std::uint8_t>, 1> parts{ecdhe_public_keys[index]};
        const auto digest = blake3_keyed(secret, parts);
        std::copy_n(digest.begin(), layout[index + 1] - layout[index],
                    output.begin() + static_cast<std::ptrdiff_t>(layout[index]));
    }
    if (with_ticket) {
        const std::array<std::span<const std::uint8_t>, 1> parts{*session_ticket};
        const auto digest = blake3_keyed(secret, parts);
        std::copy_n(digest.begin(), 8, output.begin() + 24);
    }
    return output;
}

core::Result<std::array<std::uint8_t, 16>> derive_restls_tls13_session_id(
    std::span<const std::uint8_t, 32> secret,
    const std::vector<std::pair<std::uint16_t, std::vector<std::uint8_t>>> &key_shares,
    const std::vector<std::vector<std::uint8_t>> &psk_labels) {
    std::vector<std::uint8_t> material;
    for (const auto &[group, share] : key_shares) {
        material.push_back(static_cast<std::uint8_t>(group >> 8));
        material.push_back(static_cast<std::uint8_t>(group));
        material.insert(material.end(), share.begin(), share.end());
    }
    for (const auto &label : psk_labels) {
        material.insert(material.end(), label.begin(), label.end());
    }
    const std::array<std::span<const std::uint8_t>, 1> parts{material};
    const auto digest = blake3_keyed(secret, parts);
    std::array<std::uint8_t, 16> output{};
    std::copy_n(digest.begin(), output.size(), output.begin());
    return output;
}

RestlsApplicationCodec::RestlsApplicationCodec(
    std::array<std::uint8_t, 32> secret, std::vector<std::uint8_t> server_random, bool to_client,
    bool tls12_gcm, std::vector<std::uint8_t> initial_auth_extra) noexcept
    : secret_(secret), server_random_(std::move(server_random)), to_client_(to_client),
      tls12_gcm_(tls12_gcm), initial_auth_extra_(std::move(initial_auth_extra)) {}

core::Result<std::vector<std::uint8_t>>
RestlsApplicationCodec::encode(std::span<const std::uint8_t> data, std::size_t data_length,
                               std::size_t padding_length, RestlsCommand command) {
    if (data_length > data.size() || data_length > std::numeric_limits<std::uint16_t>::max() ||
        padding_length > std::numeric_limits<std::uint16_t>::max()) {
        return core::fail(restls_error("ResTLS application record payload is too large"));
    }
    const auto payload_length =
        (tls12_gcm_ ? 8 : 0) + kRestlsAuthHeaderLength + data_length + padding_length;
    if (payload_length > std::numeric_limits<std::uint16_t>::max()) {
        return core::fail(restls_error("ResTLS application record exceeds TLS record size"));
    }
    std::vector<std::uint8_t> record(kTlsRecordHeaderLength + payload_length, 0);
    record[0] = 23;
    record[1] = 3;
    record[2] = 3;
    record[3] = static_cast<std::uint8_t>(payload_length >> 8);
    record[4] = static_cast<std::uint8_t>(payload_length);
    const auto payload_offset = kTlsRecordHeaderLength + (tls12_gcm_ ? 8 : 0);
    if (tls12_gcm_) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            record[kTlsRecordHeaderLength + static_cast<std::size_t>((56 - shift) / 8)] =
                static_cast<std::uint8_t>((counter_ + 1) >> shift);
        }
    }
    auto payload = std::span<std::uint8_t>(record).subspan(payload_offset);
    std::copy_n(data.begin(), data_length,
                payload.begin() + static_cast<std::ptrdiff_t>(kRestlsAuthHeaderLength));

    const auto sample_size = std::min<std::size_t>(32, payload.size() - kRestlsAuthHeaderLength);
    const auto sample = payload.subspan(kRestlsAuthHeaderLength, sample_size);
    const auto mask_digest = auth_hash(secret_, server_random_, to_client_, counter_, sample);
    const auto command_wire = command.wire();
    std::array<std::uint8_t, kRestlsMaskLength> masked_header{
        static_cast<std::uint8_t>(data_length >> 8), static_cast<std::uint8_t>(data_length),
        command_wire[0], command_wire[1]};
    std::transform(masked_header.begin(), masked_header.end(), mask_digest.begin(),
                   masked_header.begin(), std::bit_xor<std::uint8_t>());
    std::copy(masked_header.begin(), masked_header.end(),
              payload.begin() + static_cast<std::ptrdiff_t>(kRestlsApplicationMacLength));
    const auto header = std::span<const std::uint8_t>(record).first(payload_offset);
    std::vector<std::uint8_t> auth_input;
    auth_input.reserve(initial_auth_extra_.size() + header.size() + payload.size() -
                       kRestlsApplicationMacLength);
    if (!initial_auth_extra_.empty() && counter_ == 0) {
        auth_input.insert(auth_input.end(), initial_auth_extra_.begin(), initial_auth_extra_.end());
    }
    auth_input.insert(auth_input.end(), header.begin(), header.end());
    auth_input.insert(auth_input.end(), payload.begin() + kRestlsApplicationMacLength,
                      payload.end());
    const auto auth = auth_hash(secret_, server_random_, to_client_, counter_, auth_input);
    std::copy_n(auth.begin(), kRestlsApplicationMacLength, payload.begin());
    ++counter_;
    initial_auth_extra_.clear();
    return record;
}

core::Result<RestlsDecodedRecord>
RestlsApplicationCodec::decode(std::span<const std::uint8_t> record) {
    const auto minimum_size =
        kTlsRecordHeaderLength + (tls12_gcm_ ? 8 : 0) + kRestlsAuthHeaderLength;
    if (record.size() < minimum_size || record[0] != 23 || record[1] != 3 || record[2] != 3 ||
        static_cast<std::size_t>((record[3] << 8) | record[4]) !=
            record.size() - kTlsRecordHeaderLength) {
        return core::fail(restls_error("invalid ResTLS application record"));
    }
    const auto payload_offset = kTlsRecordHeaderLength + (tls12_gcm_ ? 8 : 0);
    if (tls12_gcm_) {
        std::uint64_t nonce = 0;
        for (std::size_t index = 0; index < 8; ++index) {
            nonce = (nonce << 8) | record[kTlsRecordHeaderLength + index];
        }
        if (nonce != counter_ + 1) {
            return core::fail(restls_error("ResTLS TLS 1.2 GCM record counter is invalid"));
        }
    }
    auto payload = std::vector<std::uint8_t>(
        record.begin() + static_cast<std::ptrdiff_t>(payload_offset), record.end());
    const auto header = record.first(payload_offset);
    std::vector<std::uint8_t> auth_input;
    auth_input.reserve(header.size() + payload.size() - kRestlsApplicationMacLength);
    auth_input.insert(auth_input.end(), header.begin(), header.end());
    auth_input.insert(auth_input.end(), payload.begin() + kRestlsApplicationMacLength,
                      payload.end());
    const auto auth = auth_hash(secret_, server_random_, to_client_, counter_, auth_input);
    if (!std::equal(auth.begin(), auth.begin() + kRestlsApplicationMacLength, payload.begin())) {
        return core::fail(restls_error("ResTLS application record authentication failed"));
    }
    const auto sample_size = std::min<std::size_t>(32, payload.size() - kRestlsAuthHeaderLength);
    const auto sample =
        std::span<const std::uint8_t>(payload).subspan(kRestlsAuthHeaderLength, sample_size);
    const auto mask_digest = auth_hash(secret_, server_random_, to_client_, counter_, sample);
    for (std::size_t index = 0; index < kRestlsMaskLength; ++index) {
        payload[kRestlsApplicationMacLength + index] ^= mask_digest[index];
    }
    const auto data_length = (static_cast<std::size_t>(payload[kRestlsApplicationMacLength]) << 8) |
                             payload[kRestlsApplicationMacLength + 1];
    if (data_length > payload.size() - kRestlsAuthHeaderLength) {
        return core::fail(restls_error("ResTLS application data length is invalid"));
    }
    const auto command_bytes =
        std::span<const std::uint8_t>(payload).subspan(kRestlsApplicationMacLength + 2, 2);
    RestlsCommand command;
    if (command_bytes[0] == 0 && command_bytes[1] == 0) {
        command.kind = RestlsCommandKind::noop;
    } else if (command_bytes[0] == 1) {
        command.kind = RestlsCommandKind::response;
        command.response = command_bytes[1];
    } else {
        return core::fail(restls_error("ResTLS application command is invalid"));
    }
    RestlsDecodedRecord result;
    result.data.assign(payload.begin() + static_cast<std::ptrdiff_t>(kRestlsAuthHeaderLength),
                       payload.begin() +
                           static_cast<std::ptrdiff_t>(kRestlsAuthHeaderLength + data_length));
    result.command = command;
    ++counter_;
    return result;
}

} // namespace clash_native::transport::shadowsocks
