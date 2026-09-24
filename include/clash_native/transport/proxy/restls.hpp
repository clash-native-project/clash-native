#pragma once

#include <clash_native/core/result.hpp>

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace clash_native::transport::proxy {

enum class RestlsCommandKind : std::uint8_t {
    noop = 0,
    response = 1,
};

struct RestlsCommand {
    RestlsCommandKind kind = RestlsCommandKind::noop;
    std::uint8_t response = 0;

    std::array<std::uint8_t, 2> wire() const noexcept;
    bool needs_peer_response() const noexcept;
};

struct RestlsScriptLine {
    std::uint16_t target_length = 0;
    std::uint16_t random_range = 0;
    bool randomize_target = false;
    RestlsCommand command;
};

core::Result<std::vector<RestlsScriptLine>> parse_restls_script(std::string_view script);

core::Result<std::array<std::uint8_t, 32>> derive_restls_secret(std::string_view password);

core::Result<std::array<std::uint8_t, 32>>
restls_hmac(std::span<const std::uint8_t, 32> secret,
            std::span<const std::span<const std::uint8_t>> parts);

core::Result<std::array<std::uint8_t, 32>> derive_restls_tls12_session_id(
    std::span<const std::uint8_t, 32> secret,
    const std::vector<std::vector<std::uint8_t>> &ecdhe_public_keys,
    std::optional<std::span<const std::uint8_t>> session_ticket = std::nullopt);

core::Result<std::array<std::uint8_t, 16>> derive_restls_tls13_session_id(
    std::span<const std::uint8_t, 32> secret,
    const std::vector<std::pair<std::uint16_t, std::vector<std::uint8_t>>> &key_shares,
    const std::vector<std::vector<std::uint8_t>> &psk_labels);

struct RestlsDecodedRecord {
    std::vector<std::uint8_t> data;
    RestlsCommand command;
};

// The post-handshake ResTLS application record format. This deliberately keeps
// padding generation outside the codec so callers can provide a cryptographic
// random source and tests can use deterministic padding. `initial_auth_extra`
// carries the TLS 1.3 client Finished record required by the first
// client-to-server ResTLS application record.
class RestlsApplicationCodec final {
  public:
    RestlsApplicationCodec(std::array<std::uint8_t, 32> secret,
                           std::vector<std::uint8_t> server_random, bool to_client,
                           bool tls12_gcm = false,
                           std::vector<std::uint8_t> initial_auth_extra = {}) noexcept;

    core::Result<std::vector<std::uint8_t>> encode(std::span<const std::uint8_t> data,
                                                   std::size_t data_length,
                                                   std::size_t padding_length,
                                                   RestlsCommand command);

    core::Result<RestlsDecodedRecord> decode(std::span<const std::uint8_t> record);

    std::uint64_t counter() const noexcept { return counter_; }

  private:
    std::array<std::uint8_t, 32> secret_{};
    std::vector<std::uint8_t> server_random_;
    bool to_client_ = false;
    bool tls12_gcm_ = false;
    std::vector<std::uint8_t> initial_auth_extra_;
    std::uint64_t counter_ = 0;
};

} // namespace clash_native::transport::proxy
