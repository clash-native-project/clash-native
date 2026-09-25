#pragma once

#include <clash_native/core/result.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/x509.h>

namespace clash_native::transport {

// Server certificate SHA-256 pin (Mihomo fingerprint = SSL pinning, shared
// by the TLS client and the ResTLS overlay). Browser profile names are
// rejected with a pointer to client-fingerprint, mirroring Mihomo. Colons
// and whitespace are ignored.
core::Result<std::array<std::uint8_t, 32>> parse_certificate_pin(const std::string &input);

// SHA-256 over an X509 DER encoding. Returns false when encoding fails.
bool certificate_sha256(const X509 *certificate, std::uint8_t out[32]);

// Compares raw DER bytes against a parsed pin.
bool der_matches_pin(const std::uint8_t *der, std::size_t length,
                     const std::array<std::uint8_t, 32> &pin) noexcept;

// Verifies a DER chain against a non-leaf pin: trusts ders[matched] as the
// root, validates the leaf through the intermediates, and checks the
// hostname, mirroring Mihomo's fingerprint verifier.
bool verify_der_pinned_chain(const std::vector<std::vector<std::uint8_t>> &ders,
                             std::size_t matched, const std::string &hostname);

bool hex_decode(std::string_view input, std::string &out);

} // namespace clash_native::transport
