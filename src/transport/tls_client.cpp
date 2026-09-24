#include <clash_native/async/bridge.hpp>
#include <clash_native/net/tls_stream.hpp>
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
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <brotli/decode.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
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

bool hex_decode(std::string_view input, std::string &out) {
    if (input.size() % 2 != 0) {
        return false;
    }
    out.clear();
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    };
    for (std::size_t i = 0; i < input.size(); i += 2) {
        const int high = nibble(input[i]);
        const int low = nibble(input[i + 1]);
        if (high < 0 || low < 0) {
            return false;
        }
        out.push_back(static_cast<char>((high << 4) | low));
    }
    return true;
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
core::Status apply_chrome_profile(SSL_CTX *context, SSL *session) {
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

        if (!options_.fingerprint.empty() && options_.fingerprint != "chrome") {
            return core::fail(
                configuration_error("unsupported TLS fingerprint: " + options_.fingerprint));
        }
        if (options_.fingerprint == "chrome") {
            const auto profile =
                apply_chrome_profile(context_->native_handle(), stream_->stream_->native_handle());
            if (!profile) {
                return profile;
            }
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
        }

        if (!options_.alpn_protocols.empty()) {
            std::vector<unsigned char> wire;
            std::size_t wire_size = 0;
            for (const auto &protocol : options_.alpn_protocols) {
                if (protocol.empty() || protocol.size() > 255 ||
                    wire_size + protocol.size() + 1 > 65535) {
                    return core::fail(configuration_error("TLS ALPN protocol list is invalid"));
                }
                wire_size += protocol.size() + 1;
            }
            wire.reserve(wire_size);
            for (const auto &protocol : options_.alpn_protocols) {
                wire.push_back(static_cast<unsigned char>(protocol.size()));
                wire.insert(wire.end(), protocol.begin(), protocol.end());
            }
            if (SSL_set_alpn_protos(stream_->stream_->native_handle(), wire.data(),
                                    static_cast<unsigned int>(wire.size())) != 0) {
                return core::fail(configuration_error("failed to configure TLS ALPN"));
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
