#include <clash_native/transport/cert_pin.hpp>

#include <cctype>
#include <cstring>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/mem.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

namespace clash_native::transport {

namespace {

core::Error pin_error(std::string context) {
    return {core::ErrorCode::configuration, std::move(context), {}};
}

} // namespace

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
        out.push_back(static_cast<char>(static_cast<unsigned>(high << 4 | low)));
    }
    return true;
}

core::Result<std::array<std::uint8_t, 32>> parse_certificate_pin(const std::string &input) {
    static constexpr const char *kBrowserNames[] = {
        "chrome", "firefox", "safari",     "ios",       "android",    "edge",     "360",
        "qq",     "random",  "randomized", "chrome120", "firefox120", "safari16",
    };
    for (const char *name : kBrowserNames) {
        if (input == name) {
            return core::fail(pin_error(
                "`fingerprint` is used for TLS certificate pinning. If you need to specify "
                "the browser fingerprint, use `client-fingerprint`"));
        }
    }
    std::string cleaned;
    cleaned.reserve(input.size());
    for (const char c : input) {
        if (c == ':' || std::isspace(static_cast<unsigned char>(c)) != 0) {
            continue;
        }
        cleaned.push_back(c);
    }
    std::string raw;
    if (!hex_decode(cleaned, raw) || raw.size() != 32) {
        return core::fail(pin_error("TLS certificate pin is not a valid SHA-256 hex fingerprint"));
    }
    std::array<std::uint8_t, 32> pin{};
    std::memcpy(pin.data(), raw.data(), pin.size());
    return pin;
}

bool certificate_sha256(const X509 *certificate, std::uint8_t out[32]) {
    uint8_t *der = nullptr;
    const int length = i2d_X509(certificate, &der);
    if (length <= 0 || der == nullptr) {
        return false;
    }
    SHA256(der, static_cast<std::size_t>(length), out);
    OPENSSL_free(der);
    return true;
}

bool verify_der_pinned_chain(const std::vector<std::vector<std::uint8_t>> &ders,
                             std::size_t matched, const std::string &hostname) {
    if (matched == 0 || matched >= ders.size() || ders.empty() || hostname.empty()) {
        return false;
    }
    using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
    std::vector<X509Ptr> certs;
    certs.reserve(ders.size());
    for (const auto &der : ders) {
        if (der.empty()) {
            return false;
        }
        const auto *cursor = der.data();
        X509 *cert = d2i_X509(nullptr, &cursor, static_cast<long>(der.size()));
        if (cert == nullptr) {
            return false;
        }
        certs.emplace_back(cert, X509_free);
    }
    bssl::UniquePtr<X509_STORE> store(X509_STORE_new());
    // The intermediates stack borrows its elements (no up-ref): free the
    // container only, otherwise the pop-free deleter would eat a reference
    // it never owned and corrupt the heap.
    std::unique_ptr<STACK_OF(X509), decltype(&sk_X509_free)> intermediates(sk_X509_new_null(),
                                                                           &sk_X509_free);
    bssl::UniquePtr<X509_STORE_CTX> verify(X509_STORE_CTX_new());
    if (!store || !intermediates || !verify) {
        return false;
    }
    if (X509_STORE_add_cert(store.get(), certs[matched].get()) != 1) {
        return false;
    }
    for (std::size_t index = 1; index < matched; ++index) {
        if (sk_X509_push(intermediates.get(), certs[index].get()) == 0) {
            return false;
        }
    }
    if (X509_STORE_CTX_init(verify.get(), store.get(), certs.front().get(), intermediates.get()) !=
            1 ||
        X509_verify_cert(verify.get()) != 1) {
        return false;
    }
    return X509_check_host(certs.front().get(), hostname.data(), hostname.size(), 0, nullptr) == 1;
}

bool der_matches_pin(const std::uint8_t *der, std::size_t length,
                     const std::array<std::uint8_t, 32> &pin) noexcept {
    if (der == nullptr || length == 0) {
        return false;
    }
    std::uint8_t digest[32] = {0};
    SHA256(der, length, digest);
    return CRYPTO_memcmp(digest, pin.data(), pin.size()) == 0;
}

} // namespace clash_native::transport
