#pragma once

#include <clash_native/core/result.hpp>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace clash_native::transport::proxy {

struct JlsUser {
    std::string username;
    std::string password;
};

// Build the 32-byte JLS fake random from a 16-byte random seed and the
// serialized, zeroed TLS handshake message.
core::Result<std::vector<std::uint8_t>>
build_jls_fake_random(const JlsUser &user, std::span<const std::uint8_t, 16> seed,
                      std::span<const std::uint8_t> auth_data);

bool check_jls_fake_random(const JlsUser &user, std::span<const std::uint8_t> fake_random,
                           std::span<const std::uint8_t> auth_data);

// Return the exact ClientHello or ServerHello handshake bytes with the random
// field zeroed. ClientHello PSK binders are zeroed as required by JLS.
core::Result<std::vector<std::uint8_t>>
jls_client_hello_auth_data(std::span<const std::uint8_t> wire_message);
core::Result<std::vector<std::uint8_t>>
jls_server_hello_auth_data(std::span<const std::uint8_t> wire_message);

} // namespace clash_native::transport::proxy
