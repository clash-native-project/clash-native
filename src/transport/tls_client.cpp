#include <clash_native/async/bridge.hpp>
#include <clash_native/net/tls_stream.hpp>
#include <clash_native/transport/cert_pin.hpp>
#include <clash_native/transport/tls_client.hpp>

#include "transport/builtin_ca_bundle.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/asio/steady_timer.hpp>

#include <openssl/aead.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/curve25519.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <zlib.h>

#include <brotli/decode.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <openssl/rand.h>
#include <vector>

namespace clash_native::transport {

namespace {

core::Error configuration_error(std::string context) {
    return {core::ErrorCode::configuration, std::move(context), {}};
}

core::Error handshake_error(const boost::system::error_code &error) {
    return {core::ErrorCode::carrier_handshake, "TLS client handshake failed: " + error.message(),
            std::error_code(error.value(), std::system_category())};
}

core::Error cancelled_error() {
    return {core::ErrorCode::cancelled, "TLS client handshake was cancelled", {}};
}

core::Error timeout_error() {
    return {core::ErrorCode::timeout, "TLS client handshake timed out", {}};
}

core::Error transport_error(std::string context, const boost::system::error_code &error) {
    return {core::ErrorCode::transport_io, std::move(context),
            std::error_code(error.value(), std::system_category())};
}

// Chrome ClientHello signature algorithms, in Chrome's fixed order.
// Plus Ed25519 appended: not in Chrome's stock list (nor in utls's Chrome
// spec), but REALITY servers present Ed25519 certificates and BoringSSL
// enforces on both ends that the peer's scheme was offered (the server
// aborts without a common scheme; the client rejects an unadvertised peer
// scheme). uTLS clients skip both checks, which is why the utls spec omits
// it. Offering Ed25519 is required for REALITY to complete.
constexpr uint16_t kChromeSignatureAlgorithms[] = {
    SSL_SIGN_ECDSA_SECP256R1_SHA256, SSL_SIGN_RSA_PSS_RSAE_SHA256, SSL_SIGN_RSA_PKCS1_SHA256,
    SSL_SIGN_ECDSA_SECP384R1_SHA384, SSL_SIGN_RSA_PSS_RSAE_SHA384, SSL_SIGN_RSA_PKCS1_SHA384,
    SSL_SIGN_RSA_PSS_RSAE_SHA512,    SSL_SIGN_RSA_PKCS1_SHA512,    SSL_SIGN_ED25519,
};

// Firefox ClientHello signature algorithms, in Firefox's fixed order.
constexpr uint16_t kFirefoxSignatureAlgorithms[] = {
    SSL_SIGN_ECDSA_SECP256R1_SHA256, SSL_SIGN_ECDSA_SECP384R1_SHA384,
    SSL_SIGN_ECDSA_SECP521R1_SHA512, SSL_SIGN_RSA_PSS_RSAE_SHA256,
    SSL_SIGN_RSA_PSS_RSAE_SHA384,    SSL_SIGN_RSA_PSS_RSAE_SHA512,
    SSL_SIGN_RSA_PKCS1_SHA256,       SSL_SIGN_RSA_PKCS1_SHA384,
    SSL_SIGN_RSA_PKCS1_SHA512,       SSL_SIGN_ECDSA_SHA1,
    SSL_SIGN_RSA_PKCS1_SHA1,
};

// Firefox ClientHello legacy cipher suites as a BoringSSL cipher rule string.
constexpr char kFirefoxCipherRule[] = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
                                      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
                                      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
                                      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
                                      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
                                      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
                                      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:"
                                      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:"
                                      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
                                      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
                                      "TLS_RSA_WITH_AES_128_GCM_SHA256:"
                                      "TLS_RSA_WITH_AES_256_GCM_SHA384:"
                                      "TLS_RSA_WITH_AES_128_CBC_SHA:"
                                      "TLS_RSA_WITH_AES_256_CBC_SHA";

// Sets signature algorithm prefs for a profile, appending Ed25519 when
// REALITY camouflage needs it. REALITY certificates are Ed25519 and BoringSSL
// refuses to verify a scheme that was not offered, so every non-Chrome
// profile (Chrome always offers it) gains 0x0807 under REALITY. uTLS does not
// enforce this, which is a documented wire delta, not a failure.
core::Status set_profile_sigalgs(SSL *session, const uint16_t *base, std::size_t count,
                                 bool ed25519_for_reality, const char *profile) {
    if (!ed25519_for_reality) {
        if (SSL_set_verify_algorithm_prefs(session, base, count) != 1) {
            return core::fail(configuration_error(std::string("failed to configure ") + profile +
                                                  " TLS signature algorithms"));
        }
        return {};
    }
    std::vector<uint16_t> prefs(base, base + count);
    if (std::find(prefs.begin(), prefs.end(), SSL_SIGN_ED25519) == prefs.end()) {
        prefs.push_back(SSL_SIGN_ED25519);
    }
    if (SSL_set_verify_algorithm_prefs(session, prefs.data(), prefs.size()) != 1) {
        return core::fail(configuration_error(std::string("failed to configure ") + profile +
                                              " TLS signature algorithms"));
    }
    return {};
}

// Fisher-Yates shuffle with RAND_bytes for per-connection lotteries
// (randomized profile, random weights). Modulo bias is irrelevant here.
void shuffle_u16(std::vector<uint16_t> &values) {
    for (std::size_t i = values.size(); i > 1; --i) {
        uint8_t byte = 0;
        if (RAND_bytes(&byte, sizeof(byte)) != 1) {
            return;
        }
        const std::size_t j = static_cast<std::size_t>(byte) % i;
        std::swap(values[i - 1], values[j]);
    }
}

bool flip_coin(double probability) {
    uint8_t byte = 0;
    if (RAND_bytes(&byte, sizeof(byte)) != 1) {
        return false;
    }
    return static_cast<double>(byte) < probability * 256.0;
}

// Mihomo `random` picks one profile per process, weighted chrome 6 / safari 3
// / ios 2 / firefox 1.
std::string resolve_random_fingerprint() {
    static std::once_flag flag;
    static std::string picked;
    std::call_once(flag, [] {
        uint8_t byte = 0;
        if (RAND_bytes(&byte, sizeof(byte)) != 1) {
            picked = "chrome";
            return;
        }
        const int roll = byte % 12;
        picked = roll < 6 ? "chrome" : roll < 9 ? "safari" : roll < 11 ? "ios" : "firefox";
    });
    return picked;
}

// Applies the Firefox ClientHello profile: fixed extension order without
// GREASE (except ECH), Firefox-only extensions from the overlay patch,
// X25519+P-256 key shares, and FFDHE groups appended by the patch.
core::Status apply_firefox_profile(SSL_CTX *context, SSL *session, bool ed25519_for_reality) {
    if (SSL_set_client_hello_profile(session, CLASH_NATIVE_CLIENT_HELLO_FIREFOX) != 1) {
        return core::fail(configuration_error("failed to select Firefox TLS profile"));
    }
    SSL_CTX_set_grease_enabled(context, 0);
    SSL_CTX_set_permute_extensions(context, 0);
    SSL_set_enable_ech_grease(session, 1);
    SSL_set_tlsext_status_type(session, TLSEXT_STATUSTYPE_ocsp);
    if (const auto status = set_profile_sigalgs(session, kFirefoxSignatureAlgorithms,
                                                std::size(kFirefoxSignatureAlgorithms),
                                                ed25519_for_reality, "Firefox");
        !status) {
        return status;
    }
    if (SSL_set_strict_cipher_list(session, kFirefoxCipherRule) != 1) {
        return core::fail(configuration_error("failed to configure Firefox TLS cipher list"));
    }
    if (SSL_set_min_proto_version(session, TLS1_2_VERSION) != 1) {
        return core::fail(configuration_error("failed to configure Firefox TLS minimum version"));
    }
    static constexpr int kFirefoxGroups[] = {NID_X25519, NID_X9_62_prime256v1, NID_secp384r1,
                                             NID_secp521r1};
    if (SSL_set1_groups(session, kFirefoxGroups, std::size(kFirefoxGroups)) != 1) {
        return core::fail(configuration_error("failed to configure Firefox TLS groups"));
    }
    static constexpr uint16_t kFirefoxKeyShares[] = {SSL_GROUP_X25519, SSL_GROUP_SECP256R1};
    if (SSL_set1_client_key_shares(session, kFirefoxKeyShares, std::size(kFirefoxKeyShares)) != 1) {
        return core::fail(configuration_error("failed to configure Firefox TLS key shares"));
    }
    return {};
}

// Safari ClientHello signature algorithms, in Safari's fixed order. Safari
// repeats PSS-SHA384 on the wire, but BoringSSL rejects duplicate prefs, so
// the duplicate is dropped (signature algorithms are outside JA3 and the
// duplicate carries no negotiation meaning).
constexpr uint16_t kSafariSignatureAlgorithms[] = {
    SSL_SIGN_ECDSA_SECP256R1_SHA256, SSL_SIGN_RSA_PSS_RSAE_SHA256, SSL_SIGN_RSA_PKCS1_SHA256,
    SSL_SIGN_ECDSA_SECP384R1_SHA384, SSL_SIGN_ECDSA_SHA1,          SSL_SIGN_RSA_PSS_RSAE_SHA384,
    SSL_SIGN_RSA_PKCS1_SHA384,       SSL_SIGN_RSA_PSS_RSAE_SHA512, SSL_SIGN_RSA_PKCS1_SHA512,
    SSL_SIGN_RSA_PKCS1_SHA1,
};

// Safari ClientHello legacy cipher suites as a BoringSSL cipher rule string
// (no 3DES tokens: BoringSSL implements no 3DES key exchange, so the
// trailing 3DES suites are emitted as raw IDs by the overlay patch).
constexpr char kSafariCipherRule[] = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
                                     "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
                                     "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
                                     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
                                     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
                                     "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
                                     "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:"
                                     "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:"
                                     "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
                                     "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
                                     "TLS_RSA_WITH_AES_256_GCM_SHA384:"
                                     "TLS_RSA_WITH_AES_128_GCM_SHA256:"
                                     "TLS_RSA_WITH_AES_256_CBC_SHA:"
                                     "TLS_RSA_WITH_AES_128_CBC_SHA";

// Decompresses a zlib-compressed certificate for the Safari profile's
// compress_certificate extension.
int safari_zlib_decompress(SSL * /*ssl*/, CRYPTO_BUFFER **out, size_t uncompressed_len,
                           const uint8_t *in, size_t in_len) {
    constexpr size_t kMaxCertificateSize = 4u * 1024u * 1024u;
    if (uncompressed_len == 0 || uncompressed_len > kMaxCertificateSize) {
        return 0;
    }
    uint8_t *buffer = static_cast<uint8_t *>(OPENSSL_malloc(uncompressed_len));
    if (buffer == nullptr) {
        return 0;
    }
    uLongf decoded_len = static_cast<uLongf>(uncompressed_len);
    if (uncompress(buffer, &decoded_len, in, static_cast<uLong>(in_len)) != Z_OK ||
        decoded_len != uncompressed_len) {
        OPENSSL_free(buffer);
        return 0;
    }
    CRYPTO_BUFFER *result = CRYPTO_BUFFER_new(buffer, decoded_len, nullptr);
    OPENSSL_free(buffer);
    if (result == nullptr) {
        return 0;
    }
    *out = result;
    return 1;
}

// Applies the Safari ClientHello profile through the overlay BoringSSL
// profile API plus the public configuration knobs Safari enables.
core::Status apply_safari_profile(SSL_CTX *context, SSL *session, bool ed25519_for_reality) {
    if (SSL_set_client_hello_profile(session, CLASH_NATIVE_CLIENT_HELLO_SAFARI) != 1) {
        return core::fail(configuration_error("failed to select Safari TLS profile"));
    }
    SSL_CTX_set_grease_enabled(context, 1);
    SSL_CTX_set_permute_extensions(context, 0);
    SSL_enable_signed_cert_timestamps(session);
    SSL_set_tlsext_status_type(session, TLSEXT_STATUSTYPE_ocsp);
    // Safari sends no session ticket extension.
    SSL_set_options(session, SSL_OP_NO_TICKET);
    if (const auto status = set_profile_sigalgs(session, kSafariSignatureAlgorithms,
                                                std::size(kSafariSignatureAlgorithms),
                                                ed25519_for_reality, "Safari");
        !status) {
        return status;
    }
    if (SSL_set_strict_cipher_list(session, kSafariCipherRule) != 1) {
        return core::fail(configuration_error("failed to configure Safari TLS cipher list"));
    }
    if (SSL_set_min_proto_version(session, TLS1_VERSION) != 1) {
        return core::fail(configuration_error("failed to configure Safari TLS minimum version"));
    }
    static constexpr int kSafariGroups[] = {NID_X25519, NID_X9_62_prime256v1, NID_secp384r1,
                                            NID_secp521r1};
    if (SSL_set1_groups(session, kSafariGroups, std::size(kSafariGroups)) != 1) {
        return core::fail(configuration_error("failed to configure Safari TLS groups"));
    }
    static constexpr uint16_t kSafariKeyShares[] = {SSL_GROUP_X25519};
    if (SSL_set1_client_key_shares(session, kSafariKeyShares, std::size(kSafariKeyShares)) != 1) {
        return core::fail(configuration_error("failed to configure Safari TLS key shares"));
    }
    // TLS_CertCompressionZlib (1).
    if (SSL_CTX_add_cert_compression_alg(context, 1, nullptr, safari_zlib_decompress) != 1) {
        return core::fail(
            configuration_error("failed to configure Safari TLS certificate compression"));
    }
    return {};
}

// Chrome ClientHello legacy cipher suites as a BoringSSL cipher rule string.
constexpr char kChromeCipherRule[] = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
                                     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
                                     "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
                                     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
                                     "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
                                     "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
                                     "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
                                     "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
                                     "TLS_RSA_WITH_AES_128_GCM_SHA256:"
                                     "TLS_RSA_WITH_AES_256_GCM_SHA384:"
                                     "TLS_RSA_WITH_AES_128_CBC_SHA:"
                                     "TLS_RSA_WITH_AES_256_CBC_SHA";

// Decompresses a brotli-compressed certificate for the Chrome profile's
// compress_certificate extension. Servers effectively never send compressed
// certificates, but Chrome offers brotli so the profile must too.
int chrome_brotli_decompress(SSL * /*ssl*/, CRYPTO_BUFFER **out, size_t uncompressed_len,
                             const uint8_t *in, size_t in_len) {
    constexpr size_t kMaxCertificateSize = 4u * 1024u * 1024u;
    if (uncompressed_len == 0 || uncompressed_len > kMaxCertificateSize) {
        return 0;
    }
    uint8_t *buffer = static_cast<uint8_t *>(OPENSSL_malloc(uncompressed_len));
    if (buffer == nullptr) {
        return 0;
    }
    size_t decoded_len = uncompressed_len;
    if (BrotliDecoderDecompress(in_len, in, &decoded_len, buffer) !=
            BROTLI_DECODER_RESULT_SUCCESS ||
        decoded_len != uncompressed_len) {
        OPENSSL_free(buffer);
        return 0;
    }
    CRYPTO_BUFFER *result = CRYPTO_BUFFER_new(buffer, decoded_len, nullptr);
    OPENSSL_free(buffer);
    if (result == nullptr) {
        return 0;
    }
    *out = result;
    return 1;
}

// Decodes unpadded base64url (Mihomo reality public-key format).
bool base64url_decode(std::string_view input, std::string &out) {
    out.clear();
    uint32_t bits = 0;
    int width = 0;
    for (const char c : input) {
        int value = -1;
        if (c >= 'A' && c <= 'Z') {
            value = c - 'A';
        } else if (c >= 'a' && c <= 'z') {
            value = c - 'a' + 26;
        } else if (c >= '0' && c <= '9') {
            value = c - '0' + 52;
        } else if (c == '-' || c == '+') {
            value = 62;
        } else if (c == '_' || c == '/') {
            value = 63;
        } else {
            return false;
        }
        bits = (bits << 6) | static_cast<uint32_t>(value);
        width += 6;
        if (width >= 8) {
            width -= 8;
            out.push_back(static_cast<char>((bits >> width) & 0xff));
        }
    }
    // A single trailing character (width 6) is an invalid length, and
    // trailing bits must be zero (canonical unpadded encoding).
    return width != 6 && (bits & ((1u << width) - 1)) == 0;
}

// REALITY client state shared between the ClientHello mutator (ticket
// construction) and the verify callback (identity check). Owned by the
// handshake operation; the mutator runs synchronously inside the handshake.
struct RealityState {
    uint8_t server_public[32] = {0};
    uint8_t short_id[8] = {0};
    uint8_t auth_key[32] = {0};
    bool mutated = false;
};

// Builds the REALITY session-ID ticket and seals it in place, mirroring
// Mihomo's reality.go: plaintext [010802][5-byte time][8-byte short ID],
// AES-128-GCM with nonce client_random[20:32] over the zeroed hello.
int reality_client_hello_mutator(SSL * /*ssl*/, uint8_t *hello, size_t hello_len,
                                 size_t session_id_offset, const uint8_t client_random[32],
                                 const uint8_t *x25519_private, void *arg) {
    auto *state = static_cast<RealityState *>(arg);
    if (x25519_private == nullptr || session_id_offset != 39 || hello_len < 39 + 32) {
        return 0;
    }
    uint8_t plaintext[16] = {1, 8, 2};
    const auto now = static_cast<uint64_t>(std::chrono::system_clock::now().time_since_epoch() /
                                           std::chrono::seconds(1));
    for (int i = 0; i < 8; ++i) {
        plaintext[i] = static_cast<uint8_t>(now >> (56 - 8 * i));
    }
    plaintext[0] = 1;
    plaintext[1] = 8;
    plaintext[2] = 2;
    std::memcpy(plaintext + 8, state->short_id, sizeof(state->short_id));
    uint8_t secret[32] = {0};
    if (X25519(secret, x25519_private, state->server_public) != 1 ||
        HKDF(state->auth_key, sizeof(state->auth_key), EVP_sha256(), secret, sizeof(secret),
             client_random, 20, reinterpret_cast<const uint8_t *>("REALITY"), 7) != 1) {
        OPENSSL_cleanse(secret, sizeof(secret));
        return 0;
    }
    OPENSSL_cleanse(secret, sizeof(secret));
    uint8_t sealed[32] = {0};
    size_t sealed_len = 0;
    EVP_AEAD_CTX aead;
    EVP_AEAD_CTX_zero(&aead);
    // Mihomo seals with the full 32-byte auth key (AES-256-GCM).
    if (!EVP_AEAD_CTX_init(&aead, EVP_aead_aes_256_gcm(), state->auth_key, sizeof(state->auth_key),
                           EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr)) {
        return 0;
    }
    const bool sealed_ok =
        EVP_AEAD_CTX_seal(&aead, sealed, &sealed_len, sizeof(sealed), client_random + 20, 12,
                          plaintext, sizeof(plaintext), hello, hello_len) == 1 &&
        sealed_len == sizeof(sealed);
    EVP_AEAD_CTX_cleanup(&aead);
    if (!sealed_ok) {
        return 0;
    }
    std::memcpy(hello + session_id_offset, sealed, sizeof(sealed));
    state->mutated = true;
    return 1;
}

// Applies the Chrome ClientHello profile through the overlay BoringSSL
// profile API plus the public configuration knobs Chrome enables.
core::Status apply_chrome_profile(SSL_CTX *context, SSL *session, bool post_quantum = true) {
    if (SSL_set_client_hello_profile(session, CLASH_NATIVE_CLIENT_HELLO_CHROME) != 1) {
        return core::fail(configuration_error("failed to select Chrome TLS profile"));
    }
    // NOTE: the handshake SSL object already exists here, so every knob must
    // be set at SSL level; CTX-level values were snapshotted at SSL_new.
    SSL_CTX_set_grease_enabled(context, 1);
    SSL_set_permute_extensions(session, 1);
    SSL_set_enable_ech_grease(session, 1);
    SSL_enable_signed_cert_timestamps(session);
    SSL_set_tlsext_status_type(session, TLSEXT_STATUSTYPE_ocsp);
    if (SSL_set_verify_algorithm_prefs(session, kChromeSignatureAlgorithms,
                                       std::size(kChromeSignatureAlgorithms)) != 1) {
        return core::fail(
            configuration_error("failed to configure Chrome TLS signature algorithms"));
    }
    if (SSL_set_strict_cipher_list(session, kChromeCipherRule) != 1) {
        return core::fail(configuration_error("failed to configure Chrome TLS cipher list"));
    }
    if (SSL_set_min_proto_version(session, TLS1_2_VERSION) != 1) {
        return core::fail(configuration_error("failed to configure Chrome TLS minimum version"));
    }
    if (!post_quantum) {
        // Chrome 120 predates the PQ keyshare: X25519 only, no PQ group.
        static constexpr uint16_t kNoPqShares[] = {SSL_GROUP_X25519};
        if (SSL_set1_client_key_shares(session, kNoPqShares, std::size(kNoPqShares)) != 1) {
            return core::fail(configuration_error("failed to configure Chrome 120 TLS key shares"));
        }
        static constexpr int kNoPqGroups[] = {NID_X25519, NID_X9_62_prime256v1, NID_secp384r1};
        if (SSL_set1_groups(session, kNoPqGroups, std::size(kNoPqGroups)) != 1) {
            return core::fail(configuration_error("failed to configure Chrome 120 TLS groups"));
        }
    }
    // Chrome offers ALPS with the new codepoint whenever ALPN is offered.
    SSL_set_alps_use_new_codepoint(session, 1);
    static constexpr uint8_t kHttp2Alpn[] = {'h', '2'};
    if (SSL_add_application_settings(session, kHttp2Alpn, sizeof(kHttp2Alpn), nullptr, 0) != 1) {
        return core::fail(configuration_error("failed to configure Chrome TLS ALPS"));
    }
    // TLS_CertCompressionBrotli (2). The decompressor only runs if a server
    // actually sends a compressed certificate.
    if (SSL_CTX_add_cert_compression_alg(context, 2, nullptr, chrome_brotli_decompress) != 1) {
        return core::fail(
            configuration_error("failed to configure Chrome TLS certificate compression"));
    }
    return {};
}

// iOS 14 signature algorithms in iOS order. iOS repeats PSS-SHA384 on the
// wire, but BoringSSL rejects duplicate prefs, so the duplicate is dropped.
constexpr uint16_t kIosSignatureAlgorithms[] = {
    SSL_SIGN_ECDSA_SECP256R1_SHA256, SSL_SIGN_RSA_PSS_RSAE_SHA256, SSL_SIGN_RSA_PKCS1_SHA256,
    SSL_SIGN_ECDSA_SECP384R1_SHA384, SSL_SIGN_ECDSA_SHA1,          SSL_SIGN_RSA_PSS_RSAE_SHA384,
    SSL_SIGN_RSA_PKCS1_SHA384,       SSL_SIGN_RSA_PSS_RSAE_SHA512, SSL_SIGN_RSA_PKCS1_SHA512,
    SSL_SIGN_RSA_PKCS1_SHA1,
};

core::Status apply_ios_profile(SSL_CTX *context, SSL *session, bool ed25519_for_reality) {
    if (SSL_set_client_hello_profile(session, CLASH_NATIVE_CLIENT_HELLO_IOS) != 1) {
        return core::fail(configuration_error("failed to select iOS TLS profile"));
    }
    SSL_CTX_set_grease_enabled(context, 1);
    SSL_set_permute_extensions(session, 0);
    SSL_enable_signed_cert_timestamps(session);
    SSL_set_tlsext_status_type(session, TLSEXT_STATUSTYPE_ocsp);
    // iOS sends no session ticket extension.
    SSL_set_options(session, SSL_OP_NO_TICKET);
    if (const auto status =
            set_profile_sigalgs(session, kIosSignatureAlgorithms,
                                std::size(kIosSignatureAlgorithms), ed25519_for_reality, "iOS");
        !status) {
        return status;
    }
    // Legacy suites go out as raw IDs (see kIosRawCiphers); no cipher rule.
    if (SSL_set_min_proto_version(session, TLS1_VERSION) != 1) {
        return core::fail(configuration_error("failed to configure iOS TLS minimum version"));
    }
    static constexpr int kIosGroups[] = {NID_X25519, NID_X9_62_prime256v1, NID_secp384r1,
                                         NID_secp521r1};
    if (SSL_set1_groups(session, kIosGroups, std::size(kIosGroups)) != 1) {
        return core::fail(configuration_error("failed to configure iOS TLS groups"));
    }
    static constexpr uint16_t kIosKeyShares[] = {SSL_GROUP_X25519};
    if (SSL_set1_client_key_shares(session, kIosKeyShares, std::size(kIosKeyShares)) != 1) {
        return core::fail(configuration_error("failed to configure iOS TLS key shares"));
    }
    return {};
}

// Android 11 OkHttp signature algorithms in OkHttp order.
constexpr uint16_t kAndroidSignatureAlgorithms[] = {
    SSL_SIGN_ECDSA_SECP256R1_SHA256, SSL_SIGN_RSA_PSS_RSAE_SHA256, SSL_SIGN_RSA_PKCS1_SHA256,
    SSL_SIGN_ECDSA_SECP384R1_SHA384, SSL_SIGN_RSA_PSS_RSAE_SHA384, SSL_SIGN_RSA_PKCS1_SHA384,
    SSL_SIGN_RSA_PSS_RSAE_SHA512,    SSL_SIGN_RSA_PKCS1_SHA512,    SSL_SIGN_RSA_PKCS1_SHA1,
};

// Android 11 OkHttp legacy cipher suites as a BoringSSL cipher rule string.
constexpr char kAndroidCipherRule[] = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
                                      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
                                      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
                                      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
                                      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
                                      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
                                      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
                                      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
                                      "TLS_RSA_WITH_AES_128_GCM_SHA256:"
                                      "TLS_RSA_WITH_AES_256_GCM_SHA384:"
                                      "TLS_RSA_WITH_AES_128_CBC_SHA:"
                                      "TLS_RSA_WITH_AES_256_CBC_SHA";

core::Status apply_android_profile(SSL_CTX *context, SSL *session, bool ed25519_for_reality) {
    if (SSL_set_client_hello_profile(session, CLASH_NATIVE_CLIENT_HELLO_ANDROID) != 1) {
        return core::fail(configuration_error("failed to select Android TLS profile"));
    }
    SSL_CTX_set_grease_enabled(context, 0);
    SSL_set_permute_extensions(session, 0);
    // OkHttp sends no session ticket extension and no ALPN (suppressed by the
    // caller); the stock F5 padding workaround is suppressed by the patch.
    SSL_set_options(session, SSL_OP_NO_TICKET);
    SSL_set_tlsext_status_type(session, TLSEXT_STATUSTYPE_ocsp);
    if (const auto status = set_profile_sigalgs(session, kAndroidSignatureAlgorithms,
                                                std::size(kAndroidSignatureAlgorithms),
                                                ed25519_for_reality, "Android");
        !status) {
        return status;
    }
    if (SSL_set_strict_cipher_list(session, kAndroidCipherRule) != 1) {
        return core::fail(configuration_error("failed to configure Android TLS cipher list"));
    }
    if (SSL_set_min_proto_version(session, TLS1_VERSION) != 1 ||
        SSL_set_max_proto_version(session, TLS1_2_VERSION) != 1) {
        return core::fail(configuration_error("failed to configure Android TLS version range"));
    }
    static constexpr int kAndroidGroups[] = {NID_X25519, NID_X9_62_prime256v1, NID_secp384r1};
    if (SSL_set1_groups(session, kAndroidGroups, std::size(kAndroidGroups)) != 1) {
        return core::fail(configuration_error("failed to configure Android TLS groups"));
    }
    return {};
}

// Edge 85 / QQ Browser signature algorithms in Edge order.
constexpr uint16_t kEdgeSignatureAlgorithms[] = {
    SSL_SIGN_ECDSA_SECP256R1_SHA256, SSL_SIGN_RSA_PSS_RSAE_SHA256, SSL_SIGN_RSA_PKCS1_SHA256,
    SSL_SIGN_ECDSA_SECP384R1_SHA384, SSL_SIGN_RSA_PSS_RSAE_SHA384, SSL_SIGN_RSA_PKCS1_SHA384,
    SSL_SIGN_RSA_PSS_RSAE_SHA512,    SSL_SIGN_RSA_PKCS1_SHA512,
};

// Edge 85 legacy cipher suites as a BoringSSL cipher rule string (shared with
// QQ Browser, whose legacy order is identical).
constexpr char kEdgeCipherRule[] = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
                                   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
                                   "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
                                   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
                                   "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
                                   "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
                                   "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
                                   "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
                                   "TLS_RSA_WITH_AES_128_GCM_SHA256:"
                                   "TLS_RSA_WITH_AES_256_GCM_SHA384:"
                                   "TLS_RSA_WITH_AES_128_CBC_SHA:"
                                   "TLS_RSA_WITH_AES_256_CBC_SHA";

core::Status apply_edge_profile(SSL_CTX *context, SSL *session, bool ed25519_for_reality,
                                bool alps) {
    const int profile = alps ? CLASH_NATIVE_CLIENT_HELLO_QQ : CLASH_NATIVE_CLIENT_HELLO_EDGE;
    if (SSL_set_client_hello_profile(session, profile) != 1) {
        return core::fail(configuration_error("failed to select Edge/QQ TLS profile"));
    }
    SSL_CTX_set_grease_enabled(context, 1);
    SSL_set_permute_extensions(session, 0);
    SSL_enable_signed_cert_timestamps(session);
    SSL_set_tlsext_status_type(session, TLSEXT_STATUSTYPE_ocsp);
    if (const auto status = set_profile_sigalgs(session, kEdgeSignatureAlgorithms,
                                                std::size(kEdgeSignatureAlgorithms),
                                                ed25519_for_reality, alps ? "QQ" : "Edge");
        !status) {
        return status;
    }
    if (SSL_set_strict_cipher_list(session, kEdgeCipherRule) != 1) {
        return core::fail(configuration_error("failed to configure Edge TLS cipher list"));
    }
    if (SSL_set_min_proto_version(session, TLS1_VERSION) != 1) {
        return core::fail(configuration_error("failed to configure Edge TLS minimum version"));
    }
    // No PQ group or share: Edge 85 predates post-quantum key exchange.
    static constexpr int kEdgeGroups[] = {NID_X25519, NID_X9_62_prime256v1, NID_secp384r1};
    if (SSL_set1_groups(session, kEdgeGroups, std::size(kEdgeGroups)) != 1) {
        return core::fail(configuration_error("failed to configure Edge TLS groups"));
    }
    static constexpr uint16_t kEdgeKeyShares[] = {SSL_GROUP_X25519};
    if (SSL_set1_client_key_shares(session, kEdgeKeyShares, std::size(kEdgeKeyShares)) != 1) {
        return core::fail(configuration_error("failed to configure Edge TLS key shares"));
    }
    if (alps) {
        // QQ offers ALPS with the new codepoint whenever ALPN is offered.
        SSL_set_alps_use_new_codepoint(session, 1);
        static constexpr uint8_t kHttp2Alpn[] = {'h', '2'};
        if (SSL_add_application_settings(session, kHttp2Alpn, sizeof(kHttp2Alpn), nullptr, 0) !=
            1) {
            return core::fail(configuration_error("failed to configure QQ TLS ALPS"));
        }
    }
    // TLS_CertCompressionBrotli (2), shared with Chrome.
    if (SSL_CTX_add_cert_compression_alg(context, 2, nullptr, chrome_brotli_decompress) != 1) {
        return core::fail(
            configuration_error("failed to configure Edge TLS certificate compression"));
    }
    return {};
}

// Dummy NPN select callback: 360 Browser sends an empty NPN extension, which
// stock BoringSSL only emits while a select callback is configured. No server
// negotiates NPN anymore, so this is never meaningfully called.
int refuse_next_proto_select(SSL * /*ssl*/, unsigned char ** /*out*/, unsigned char * /*outlen*/,
                             const unsigned char * /*in*/, unsigned int /*inlen*/, void * /*arg*/) {
    return SSL_TLSEXT_ERR_NOACK;
}

core::Status apply_360_profile(SSL_CTX *context, SSL *session) {
    if (SSL_set_client_hello_profile(session, CLASH_NATIVE_CLIENT_HELLO_360) != 1) {
        return core::fail(configuration_error("failed to select 360 TLS profile"));
    }
    SSL_CTX_set_grease_enabled(context, 0);
    SSL_set_permute_extensions(session, 0);
    SSL_set_tlsext_status_type(session, TLSEXT_STATUSTYPE_ocsp);
    // Legacy suites and signature algorithms go out as raw IDs (see the
    // k360 tables); the prefs below only satisfy the emission gate, the patch
    // hook replaces the body.
    static constexpr uint16_t k360GateSigalgs[] = {
        SSL_SIGN_RSA_PKCS1_SHA256,       SSL_SIGN_RSA_PKCS1_SHA384,       SSL_SIGN_RSA_PKCS1_SHA1,
        SSL_SIGN_ECDSA_SECP256R1_SHA256, SSL_SIGN_ECDSA_SECP384R1_SHA384, SSL_SIGN_ECDSA_SHA1,
    };
    if (SSL_set_verify_algorithm_prefs(session, k360GateSigalgs, std::size(k360GateSigalgs)) != 1) {
        return core::fail(configuration_error("failed to configure 360 TLS signature algorithms"));
    }
    // No cipher rule: raw emission ignores the configured list.
    if (SSL_set_min_proto_version(session, TLS1_VERSION) != 1 ||
        SSL_set_max_proto_version(session, TLS1_2_VERSION) != 1) {
        return core::fail(configuration_error("failed to configure 360 TLS version range"));
    }
    static constexpr int k360Groups[] = {NID_X9_62_prime256v1, NID_secp384r1, NID_secp521r1};
    if (SSL_set1_groups(session, k360Groups, std::size(k360Groups)) != 1) {
        return core::fail(configuration_error("failed to configure 360 TLS groups"));
    }
    SSL_CTX_set_next_proto_select_cb(context, refuse_next_proto_select, nullptr);
    return {};
}

core::Status apply_randomized_profile(SSL_CTX *context, SSL *session, bool alps_allowed) {
    if (SSL_set_client_hello_profile(session, CLASH_NATIVE_CLIENT_HELLO_RANDOMIZED) != 1) {
        return core::fail(configuration_error("failed to select randomized TLS profile"));
    }

    SSL_CTX_set_grease_enabled(context, 1);
    SSL_set_permute_extensions(session, 1);
    SSL_set_enable_ech_grease(session, 0);
    // Full Chrome suite selectedness: the default rule omits static RSA,
    // but the shuffled legacy multiset includes it.
    if (SSL_set_strict_cipher_list(session, kChromeCipherRule) != 1) {
        return core::fail(configuration_error("failed to configure randomized TLS cipher list"));
    }
    // Mihomo forces TLS 1.3 max with a 1.0/1.2 minimum lottery.
    if (SSL_set_min_proto_version(session, flip_coin(0.5) ? TLS1_VERSION : TLS1_2_VERSION) != 1) {
        return core::fail(
            configuration_error("failed to configure randomized TLS minimum version"));
    }
    // Curves stay ordered (uTLS only shuffles extensions); P-521 joins at 46%.
    std::vector<int> groups = {NID_X25519, NID_X9_62_prime256v1, NID_secp384r1};
    if (flip_coin(0.46)) {
        groups.push_back(NID_secp521r1);
    }
    // X25519 first share always; P-256 and PQ prepends are 50% lotteries.
    // The PQ share needs its group first in the list: BoringSSL validates
    // shares as an ordered subsequence of groups. uTLS omits PQ from curves,
    // a documented delta.
    std::vector<uint16_t> shares = {SSL_GROUP_X25519};
    if (flip_coin(0.5)) {
        shares.push_back(SSL_GROUP_SECP256R1);
    }
    if (flip_coin(0.5)) {
        shares.insert(shares.begin(), SSL_GROUP_X25519_MLKEM768);
        groups.insert(groups.begin(), NID_X25519MLKEM768);
    }
    if (SSL_set1_groups(session, groups.data(), groups.size()) != 1) {
        return core::fail(configuration_error("failed to configure randomized TLS groups"));
    }
    if (SSL_set1_client_key_shares(session, shares.data(), shares.size()) != 1) {
        return core::fail(configuration_error("failed to configure randomized TLS key shares"));
    }
    // Signature lotteries around the TLS 1.3-mandatory PSS-SHA256, shuffled.
    std::vector<uint16_t> sigalgs = {SSL_SIGN_ECDSA_SECP256R1_SHA256, SSL_SIGN_RSA_PKCS1_SHA256,
                                     SSL_SIGN_ECDSA_SECP384R1_SHA384, SSL_SIGN_RSA_PKCS1_SHA384,
                                     SSL_SIGN_RSA_PKCS1_SHA1,         SSL_SIGN_RSA_PKCS1_SHA512,
                                     SSL_SIGN_RSA_PSS_RSAE_SHA256};
    if (flip_coin(0.63)) {
        sigalgs.push_back(SSL_SIGN_ECDSA_SHA1);
    }
    if (flip_coin(0.59)) {
        sigalgs.push_back(SSL_SIGN_ECDSA_SECP521R1_SHA512);
    }
    if (flip_coin(0.9)) {
        sigalgs.push_back(SSL_SIGN_RSA_PSS_RSAE_SHA384);
        sigalgs.push_back(SSL_SIGN_RSA_PSS_RSAE_SHA512);
    }
    shuffle_u16(sigalgs);
    if (SSL_set_verify_algorithm_prefs(session, sigalgs.data(), sigalgs.size()) != 1) {
        return core::fail(
            configuration_error("failed to configure randomized TLS signature algorithms"));
    }
    // Extension lotteries: OCSP 74%, SCT 46%, ALPS 33% (ALPS needs ALPN).
    if (flip_coin(0.74)) {
        SSL_set_tlsext_status_type(session, TLSEXT_STATUSTYPE_ocsp);
    }
    if (flip_coin(0.46)) {
        SSL_enable_signed_cert_timestamps(session);
    }
    if (alps_allowed && flip_coin(0.33)) {
        SSL_set_alps_use_new_codepoint(session, 1);
        static constexpr uint8_t kHttp2Alpn[] = {'h', '2'};
        if (SSL_add_application_settings(session, kHttp2Alpn, sizeof(kHttp2Alpn), nullptr, 0) !=
            1) {
            return core::fail(configuration_error("failed to configure randomized TLS ALPS"));
        }
    }
    return {};
}

} // namespace

namespace detail {

using TlsClientHandler = std::function<void(core::Result<TlsClientConnection>)>;

class TlsClientHandshakeOperationImpl final
    : public std::enable_shared_from_this<TlsClientHandshakeOperationImpl> {
  public:
    TlsClientHandshakeOperationImpl(std::unique_ptr<io::StreamHandle> stream,
                                    TlsClientOptions options, TlsClientHandler handler)
        : executor_(stream->executor()), options_(std::move(options)), handler_(std::move(handler)),
          context_(
              std::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::tls_client)),
          stream_(std::make_unique<net::TlsStream>(context_, std::move(stream))),
          timer_(executor_) {}

    void start() {
        const auto self = shared_from_this();
        boost::asio::post(executor_, [self] { self->configure_and_handshake(); });
    }

    void cancel() noexcept {
        try {
            const auto self = shared_from_this();
            boost::asio::dispatch(executor_,
                                  [self] { self->finish(core::fail(cancelled_error())); });
        } catch (...) {
            if (stream_) {
                stream_->close();
            }
        }
    }

  private:
    core::Status configure() {
        context_->set_options(boost::asio::ssl::context::default_workarounds |
                              boost::asio::ssl::context::no_sslv2 |
                              boost::asio::ssl::context::no_sslv3);

        if (!options_.client_certificate_pem.empty() != !options_.client_private_key_pem.empty()) {
            return core::fail(
                configuration_error("TLS client certificate and private key must be set together"));
        }
        if (!options_.client_certificate_pem.empty()) {
            auto *native_context = context_->native_handle();
            using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
            BioPtr cert_bio(
                BIO_new_mem_buf(options_.client_certificate_pem.data(),
                                static_cast<int>(options_.client_certificate_pem.size())),
                BIO_free);
            if (!cert_bio) {
                return core::fail(configuration_error("TLS client certificate is not valid PEM"));
            }
            std::unique_ptr<X509, decltype(&X509_free)> certificate(
                PEM_read_bio_X509_AUX(cert_bio.get(), nullptr, nullptr, nullptr), X509_free);
            if (!certificate) {
                return core::fail(configuration_error("TLS client certificate is not valid PEM"));
            }
            if (SSL_CTX_use_certificate(native_context, certificate.get()) != 1) {
                return core::fail(
                    configuration_error("failed to configure TLS client certificate"));
            }
            BioPtr key_bio(
                BIO_new_mem_buf(options_.client_private_key_pem.data(),
                                static_cast<int>(options_.client_private_key_pem.size())),
                BIO_free);
            if (!key_bio) {
                return core::fail(configuration_error("TLS client private key is not valid PEM"));
            }
            std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> private_key(
                PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
            if (!private_key) {
                return core::fail(configuration_error("TLS client private key is not valid PEM"));
            }
            if (SSL_CTX_use_PrivateKey(native_context, private_key.get()) != 1) {
                return core::fail(
                    configuration_error("failed to configure TLS client private key"));
            }
            if (SSL_CTX_check_private_key(native_context) != 1) {
                return core::fail(
                    configuration_error("TLS client private key does not match the certificate"));
            }
        }
        if (options_.verify_peer) {
            if (options_.server_name.empty()) {
                return core::fail(
                    configuration_error("TLS peer verification requires a server name"));
            }
            const auto roots = detail::builtin_ca_bundle_pem();
            boost::system::error_code error;
            context_->add_certificate_authority(boost::asio::buffer(roots.data(), roots.size()),
                                                error);
            if (error) {
                return core::fail(
                    transport_error("failed to load embedded TLS trust roots", error));
            }
            if (!options_.trusted_ca_pem.empty()) {
                context_->add_certificate_authority(
                    boost::asio::buffer(options_.trusted_ca_pem.data(),
                                        options_.trusted_ca_pem.size()),
                    error);
                if (error) {
                    return core::fail(
                        transport_error("failed to load custom TLS trust roots", error));
                }
            }
            const auto &verify_name =
                options_.verify_hostname.empty() ? options_.server_name : options_.verify_hostname;
            stream_->stream_->set_verify_mode(boost::asio::ssl::verify_peer);
            stream_->stream_->set_verify_callback(
                boost::asio::ssl::host_name_verification(verify_name));
        } else {
            stream_->stream_->set_verify_mode(boost::asio::ssl::verify_none);
        }

        if (options_.maximum_tls_version) {
            if (SSL_set_max_proto_version(stream_->stream_->native_handle(),
                                          *options_.maximum_tls_version) != 1) {
                return core::fail(configuration_error("failed to configure TLS maximum version"));
            }
        }

        if (!options_.server_name.empty()) {
            boost::system::error_code address_error;
            (void)boost::asio::ip::make_address(options_.server_name, address_error);
            if (address_error && SSL_set_tlsext_host_name(stream_->stream_->native_handle(),
                                                          options_.server_name.c_str()) != 1) {
                return core::fail(configuration_error("failed to configure TLS server name"));
            }
        }

        std::string hello_profile = options_.fingerprint;
        if (hello_profile == "random") {
            hello_profile = resolve_random_fingerprint();
        } else if (hello_profile == "firefox120") {
            hello_profile = "firefox";
        } else if (hello_profile == "safari16") {
            hello_profile = "safari";
        }
        if (!hello_profile.empty() && hello_profile != "chrome" && hello_profile != "chrome120" &&
            hello_profile != "firefox" && hello_profile != "safari" && hello_profile != "ios" &&
            hello_profile != "android" && hello_profile != "edge" && hello_profile != "360" &&
            hello_profile != "qq" && hello_profile != "randomized") {
            return core::fail(
                configuration_error("unsupported TLS fingerprint: " + options_.fingerprint));
        }
        // REALITY certificates are Ed25519: BoringSSL refuses schemes that
        // were not offered, so non-Chrome profiles append Ed25519 below.
        const bool ed25519_for_reality = options_.reality.has_value();
        if (ed25519_for_reality && hello_profile == "360") {
            return core::fail(configuration_error(
                "the 360 fingerprint cannot do REALITY: its signature list is fixed raw IDs "
                "without Ed25519"));
        }
        if (!hello_profile.empty()) {
            auto *native_context = context_->native_handle();
            auto *native_session = stream_->stream_->native_handle();
            core::Status profile = {};
            if (hello_profile == "chrome") {
                profile = apply_chrome_profile(native_context, native_session);
            } else if (hello_profile == "chrome120") {
                profile = apply_chrome_profile(native_context, native_session, false);
            } else if (hello_profile == "firefox") {
                profile =
                    apply_firefox_profile(native_context, native_session, ed25519_for_reality);
            } else if (hello_profile == "safari") {
                profile = apply_safari_profile(native_context, native_session, ed25519_for_reality);
            } else if (hello_profile == "ios") {
                profile = apply_ios_profile(native_context, native_session, ed25519_for_reality);
            } else if (hello_profile == "android") {
                profile =
                    apply_android_profile(native_context, native_session, ed25519_for_reality);
            } else if (hello_profile == "edge") {
                profile =
                    apply_edge_profile(native_context, native_session, ed25519_for_reality, false);
            } else if (hello_profile == "qq") {
                profile =
                    apply_edge_profile(native_context, native_session, ed25519_for_reality, true);
            } else if (hello_profile == "360") {
                profile = apply_360_profile(native_context, native_session);
            } else if (hello_profile == "randomized") {
                // ALPN runs a 70% lottery; the caller below honors the draw.
                randomized_alpn_allowed_ = flip_coin(0.7);
                profile = apply_randomized_profile(native_context, native_session,
                                                   randomized_alpn_allowed_);
            }
            if (!profile) {
                return profile;
            }
        }
        if (!options_.certificate_pin.empty()) {
            auto pin = parse_certificate_pin(options_.certificate_pin);
            if (!pin) {
                return core::fail(pin.error());
            }
            cert_pin_ = pin.value();
            has_cert_pin_ = true;
            pin_verify_name_ =
                options_.verify_hostname.empty() ? options_.server_name : options_.verify_hostname;
        }
        if (options_.reality) {
            // Mihomo requires a fingerprint for REALITY camouflage.
            if (options_.fingerprint.empty()) {
                return core::fail(configuration_error("REALITY requires a TLS fingerprint"));
            }
            if (options_.server_name.empty()) {
                return core::fail(configuration_error("REALITY requires a server name"));
            }
            if (options_.maximum_tls_version && *options_.maximum_tls_version < TLS1_3_VERSION) {
                return core::fail(configuration_error("REALITY requires TLS 1.3 or higher"));
            }
            std::string public_key;
            if (!base64url_decode(options_.reality->public_key_base64url, public_key) ||
                public_key.size() != sizeof(reality_state_.server_public)) {
                return core::fail(configuration_error("REALITY public key is not valid base64url"));
            }
            std::string short_id;
            if (!hex_decode(options_.reality->short_id_hex, short_id) ||
                short_id.size() > sizeof(reality_state_.short_id)) {
                return core::fail(configuration_error("REALITY short ID is not valid hex"));
            }
            std::memcpy(reality_state_.server_public, public_key.data(),
                        sizeof(reality_state_.server_public));
            std::memcpy(reality_state_.short_id, short_id.data(), short_id.size());
            SSL_set_client_hello_mutator(stream_->stream_->native_handle(),
                                         reality_client_hello_mutator, &reality_state_);
            reality_verify_name_ =
                options_.verify_hostname.empty() ? options_.server_name : options_.verify_hostname;
            stream_->stream_->set_verify_mode(options_.verify_peer ? boost::asio::ssl::verify_peer
                                                                   : boost::asio::ssl::verify_none);
            const auto self = shared_from_this();
            stream_->stream_->set_verify_callback(
                [self](bool preverified, boost::asio::ssl::verify_context &context) {
                    boost::asio::ssl::host_name_verification fallback(self->reality_verify_name_);
                    return self->verify_reality_peer(preverified, context, fallback);
                });
        } else if (has_cert_pin_) {
            stream_->stream_->set_verify_mode(options_.verify_peer ? boost::asio::ssl::verify_peer
                                                                   : boost::asio::ssl::verify_none);
            const auto self = shared_from_this();
            stream_->stream_->set_verify_callback(
                [self](bool, boost::asio::ssl::verify_context &context) {
                    return self->verify_pinned_peer(context);
                });
        }

        std::vector<std::string> alpn_protocols = options_.alpn_protocols;
        if (hello_profile == "android") {
            // OkHttp sends no ALPN extension.
            alpn_protocols.clear();
        } else if (hello_profile == "360") {
            alpn_protocols = {"spdy/2", "spdy/3", "spdy/3.1", "http/1.1"};
        } else if (hello_profile == "randomized" && !randomized_alpn_allowed_) {
            alpn_protocols.clear();
        }
        if (!alpn_protocols.empty()) {
            std::vector<unsigned char> wire;
            std::size_t wire_size = 0;
            for (const auto &protocol : alpn_protocols) {
                if (protocol.empty() || protocol.size() > 255 ||
                    wire_size + protocol.size() + 1 > 65535) {
                    return core::fail(configuration_error("TLS ALPN protocol list is invalid"));
                }
                wire_size += protocol.size() + 1;
            }
            wire.reserve(wire_size);
            for (const auto &protocol : alpn_protocols) {
                wire.push_back(static_cast<unsigned char>(protocol.size()));
                wire.insert(wire.end(), protocol.begin(), protocol.end());
            }
            if (SSL_set_alpn_protos(stream_->stream_->native_handle(), wire.data(),
                                    static_cast<unsigned int>(wire.size())) != 0) {
                return core::fail(configuration_error("failed to configure TLS ALPN"));
            }
        }
        if (options_.ech_config_list && !options_.ech_config_list->empty()) {
            if (SSL_set1_ech_config_list(stream_->stream_->native_handle(),
                                         options_.ech_config_list->data(),
                                         options_.ech_config_list->size()) != 1) {
                return core::fail(configuration_error("failed to configure TLS ECH"));
            }
        }
        return {};
    }

    void configure_and_handshake() {
        if (completed_) {
            return;
        }
        if (options_.deadline) {
            if (*options_.deadline <= std::chrono::steady_clock::now()) {
                finish(core::fail(timeout_error()));
                return;
            }
            timer_.expires_at(*options_.deadline);
            const auto self = shared_from_this();
            timer_.async_wait([self](const boost::system::error_code &error) {
                if (!error) {
                    self->finish(core::fail(timeout_error()));
                }
            });
        }
        const auto configured = configure();
        if (!configured) {
            finish(core::fail(configured.error()));
            return;
        }
        const auto self = shared_from_this();
        stream_->stream_->async_handshake(
            boost::asio::ssl::stream_base::client, [self](const boost::system::error_code &error) {
                if (self->completed_) {
                    return;
                }
                if (error) {
                    self->finish(core::fail(handshake_error(error)));
                    return;
                }
                const unsigned char *protocol = nullptr;
                unsigned int protocol_length = 0;
                SSL_get0_alpn_selected(self->stream_->stream_->native_handle(), &protocol,
                                       &protocol_length);
                std::string negotiated_alpn;
                if (protocol_length != 0) {
                    negotiated_alpn.assign(reinterpret_cast<const char *>(protocol),
                                           protocol_length);
                }
                std::unique_ptr<io::StreamHandle> stream;
                if (self->options_.handoff_raw_transport) {
                    stream = self->stream_->take_transport();
                } else {
                    stream = std::move(self->stream_);
                }
                if (!stream) {
                    self->finish(core::fail(
                        transport_error("TLS client handshake lost its underlying stream",
                                        boost::asio::error::operation_aborted)));
                    return;
                }
                TlsClientConnection connection{std::move(stream), std::move(negotiated_alpn)};
                self->finish(std::move(connection));
            });
    }

    void finish(core::Result<TlsClientConnection> result) {
        if (completed_) {
            return;
        }
        completed_ = true;
        (void)timer_.cancel();
        if (!result && stream_) {
            stream_->close();
            stream_.reset();
        }
        auto handler = std::move(handler_);
        if (handler) {
            handler(std::move(result));
        }
    }

    // REALITY identity check for the leaf certificate: an Ed25519 key whose
    // certificate signature equals HMAC-SHA512(auth_key, raw public key),
    // mirroring Mihomo's realityVerifier.
    bool reality_identity_verified(const X509 *leaf) const {
        if (leaf == nullptr) {
            return false;
        }
        const EVP_PKEY *key = X509_get0_pubkey(leaf);
        if (key == nullptr || EVP_PKEY_id(key) != EVP_PKEY_ED25519) {
            return false;
        }
        uint8_t raw[32] = {0};
        size_t raw_length = sizeof(raw);
        if (EVP_PKEY_get_raw_public_key(key, raw, &raw_length) != 1 || raw_length != sizeof(raw)) {
            return false;
        }
        uint8_t mac[EVP_MAX_MD_SIZE] = {0};
        unsigned int mac_length = 0;
        if (HMAC(EVP_sha512(), reality_state_.auth_key, sizeof(reality_state_.auth_key), raw,
                 sizeof(raw), mac, &mac_length) == nullptr ||
            mac_length != 64) {
            return false;
        }
        const ASN1_BIT_STRING *signature = nullptr;
        X509_get0_signature(&signature, nullptr, leaf);
        if (signature == nullptr || ASN1_STRING_length(signature) != 64) {
            return false;
        }
        return CRYPTO_memcmp(ASN1_STRING_get0_data(signature), mac, 64) == 0;
    }

    bool verify_reality_peer(bool preverified, boost::asio::ssl::verify_context &context,
                             const boost::asio::ssl::host_name_verification &fallback) const {
        // Fail closed: without a sealed ticket there is no REALITY session.
        if (!reality_state_.mutated) {
            return false;
        }
        // OpenSSL invokes the callback top-down per certificate; collect the
        // whole chain and decide only at the leaf, mirroring Mihomo's
        // VerifyConnection (SPKI check first, chain fallback second).
        X509_STORE_CTX *store = context.native_handle();
        if (X509_STORE_CTX_get_error_depth(store) != 0) {
            return true;
        }
        if (reality_identity_verified(X509_STORE_CTX_get_current_cert(store))) {
            return true;
        }
        return fallback(preverified, context);
    }

    boost::asio::any_io_executor executor_;
    TlsClientOptions options_;
    TlsClientHandler handler_;
    std::shared_ptr<boost::asio::ssl::context> context_;
    std::unique_ptr<net::TlsStream> stream_;
    boost::asio::steady_timer timer_;
    bool completed_ = false;
    RealityState reality_state_{};
    std::string reality_verify_name_;
    bool randomized_alpn_allowed_ = true;
    std::array<std::uint8_t, 32> cert_pin_{};
    bool has_cert_pin_ = false;
    std::string pin_verify_name_;

    // Pinned-chain verification for a non-leaf match: trust the matched
    // certificate as the root and verify the leaf plus hostname, mirroring
    // Mihomo's fingerprint verifier.
    bool verify_pinned_chain(STACK_OF(X509) * chain, int matched) const {
        X509 *leaf = sk_X509_value(chain, 0);
        X509 *trusted = sk_X509_value(chain, matched);
        if (leaf == nullptr || trusted == nullptr) {
            return false;
        }
        bssl::UniquePtr<X509_STORE> store(X509_STORE_new());
        // Borrowed elements: free the container only (pop-free would eat a
        // reference it never owned).
        std::unique_ptr<STACK_OF(X509), decltype(&sk_X509_free)> intermediates(sk_X509_new_null(),
                                                                               &sk_X509_free);
        bssl::UniquePtr<X509_STORE_CTX> verify(X509_STORE_CTX_new());
        if (!store || !intermediates || !verify) {
            return false;
        }
        if (X509_STORE_add_cert(store.get(), trusted) != 1) {
            return false;
        }
        for (int index = 1; index < matched; ++index) {
            X509 *intermediate = sk_X509_value(chain, index);
            if (intermediate == nullptr || sk_X509_push(intermediates.get(), intermediate) == 0) {
                return false;
            }
        }
        if (X509_STORE_CTX_init(verify.get(), store.get(), leaf, intermediates.get()) != 1 ||
            X509_verify_cert(verify.get()) != 1) {
            return false;
        }
        return X509_check_host(leaf, pin_verify_name_.data(), pin_verify_name_.size(), 0,
                               nullptr) == 1;
    }

    bool verify_pinned_peer(boost::asio::ssl::verify_context &context) const {
        X509_STORE_CTX *store = context.native_handle();
        // Collect the whole chain; the pin decides at the leaf.
        if (X509_STORE_CTX_get_error_depth(store) != 0) {
            return true;
        }
        STACK_OF(X509) *chain = X509_STORE_CTX_get0_chain(store);
        if (chain == nullptr) {
            return false;
        }
        const auto count = static_cast<int>(sk_X509_num(chain));
        for (int index = 0; index < count; ++index) {
            const X509 *certificate = sk_X509_value(chain, index);
            if (certificate == nullptr) {
                return false;
            }
            uint8_t digest[32] = {0};
            if (!certificate_sha256(certificate, digest)) {
                return false;
            }
            if (CRYPTO_memcmp(digest, cert_pin_.data(), cert_pin_.size()) != 0) {
                continue;
            }
            if (index == 0) {
                return true;
            }
            return verify_pinned_chain(chain, index);
        }
        return false;
    }
};

} // namespace detail

io::AnySender<TlsClientConnection>
async_tls_client_handshake(std::unique_ptr<io::StreamHandle> stream, TlsClientOptions options) {
    if (!stream) {
        return io::AnySender<TlsClientConnection>{stdexec::just_error(std::make_exception_ptr(
            configuration_error("TLS client handshake requires a stream")))};
    }
    // Shared: the bridge starter is a std::function and must be copyable;
    // a second start after the move fails fast instead of hanging.
    auto state = std::make_shared<std::pair<std::unique_ptr<io::StreamHandle>, TlsClientOptions>>(
        std::move(stream), std::move(options));
    auto bridged = async::bridge_sender<core::Result<TlsClientConnection>>(
        [state](async::BridgeSender<core::Result<TlsClientConnection>>::Handler terminal) mutable {
            if (!state->first) {
                terminal(core::fail(
                    configuration_error("TLS client handshake stream was already consumed")));
                return async::BridgeSender<core::Result<TlsClientConnection>>::AbortFn{};
            }
            auto operation = std::make_shared<detail::TlsClientHandshakeOperationImpl>(
                std::move(state->first), std::move(state->second), std::move(terminal));
            operation->start();
            using AbortFn = async::BridgeSender<core::Result<TlsClientConnection>>::AbortFn;
            return AbortFn{[operation] { operation->cancel(); }};
        });
    auto sender = std::move(bridged) | stdexec::then([](core::Result<TlsClientConnection> result) {
                      if (!result) {
                          throw result.error();
                      }
                      return std::move(result.value());
                  });
    return io::AnySender<TlsClientConnection>{std::move(sender)};
}

} // namespace clash_native::transport
