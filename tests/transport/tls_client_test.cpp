// Mutual-TLS client options: malformed and mismatched credentials fail
// fast with configuration errors; a well-formed pair loads (the peer
// here is plain TCP, so the handshake itself fails downstream).
#include <clash_native/core/error.hpp>
#include <clash_native/io/stream_handle.hpp>
#include <clash_native/net/tcp_stream.hpp>
#include <clash_native/transport/tls_client.hpp>

#include <gtest/gtest.h>

#include <openssl/aead.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/curve25519.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/hpke.h>
#include <openssl/ssl.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <optional>
#include <stdexec/execution.hpp>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {

// Localhost credentials shared with the proxy TLS tests.
constexpr std::string_view kCertificate = R"PEM(-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUO6OQllxsGBdm0PuTwj9ToJ4AjB4wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDkyMTA2MzY0M1oXDTM2MDkx
ODA2MzY0M1owFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAq10m35sk60KZX9hD8aWJ6TfrrYjdwlz63Th/ju54KtUO
yKS1Rgd4whSkKxADtUzIxa4UNT0k6271DI0suJsZJjgY4aFcrbNBFX7sV1nIPWmo
gp+L/6tuFgtDdz3qYxHZvrcqRGv8DmUTMWtGVXpAAfiowWIZkLZfarvA/73ORUG9
MI+yYm7XXySrMccIf1Z7v9XPyeDeundLSynrF8ZhxHIMqqjTM+gQLYCy6ai5jg26
t5TH2yhq9jxEBuVmaP+dPQIk1jn0Kcv27qmgswLUNzj7Lp+49tDhdqHND+P4iuwS
yAcFsz+73tVqph+pUaJeQKzstvTrXUp7+XPO7ZvPKQIDAQABo1MwUTAdBgNVHQ4E
FgQUsV/gyaUNU+o2oGpI1bcxt4UUWB4wHwYDVR0jBBgwFoAUsV/gyaUNU+o2oGpI
1bcxt4UUWB4wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAaz7l
WRYHY5T1jnYiXr1iG8/SKbDnhgfO9hY6gtYEAkA2oqL43ddnKD2ifqFtesiOiUC/
3B6bwV5GltVIjXS97JaELrqe8z/Y0Y02KJsSWPY225W3i/1p4dIQwcFZW9d+F0b8
830RC9rQoN9pNLdBuGL9rPX+v3WMQXj3d7SavzW+UPEycnVVGCZqIzhokWV5p7+e
MU+mUTCJlVQ7s7yn47HD3wsVuEGgbVGgxb7rw6O/UfBZ4WJMsg46Ng2pp3m63ao1
IT3SBG6YN2R/CEOZs5zpYBie9LxckgbPpJpnBwsqt173rZhjKyt4Znu5bny7MVbj
Gn6mTaUf8ez5zXGuKQ==
-----END CERTIFICATE-----
)PEM";

constexpr std::string_view kPrivateKey = R"PEM(-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCrXSbfmyTrQplf
2EPxpYnpN+utiN3CXPrdOH+O7ngq1Q7IpLVGB3jCFKQrEAO1TMjFrhQ1PSTrbvUM
jSy4mxkmOBjhoVyts0EVfuxXWcg9aaiCn4v/q24WC0N3PepjEdm+typEa/wOZRMx
a0ZVekAB+KjBYhmQtl9qu8D/vc5FQb0wj7JibtdfJKsxxwh/Vnu/1c/J4N66d0tL
KesXxmHEcgyqqNMz6BAtgLLpqLmODbq3lMfbKGr2PEQG5WZo/509AiTWOfQpy/bu
qaCzAtQ3OPsun7j20OF2oc0P4/iK7BLIBwWzP7ve1WqmH6lRol5ArOy29OtdSnv5
c87tm88pAgMBAAECggEACqYMuttwtV/bmQ2e1z7SrZfogM2e/it5+VI/9vlRpVO9
CfHWQ+ZF9kWDGBv0JwmA9mvFXLOSfkDUYHXLYCNfMjVNMoQs9qxLcJMFC76MB2jv
7EIO2JHmEt+bTycdUA+1aLkIGt1c+eYFBc6lPb2NibHShsXaUdhLYJ4PNbUtQrdj
eAmqRZWBTXnTyieUAS0QR5WYp3Mlr/jeEDs8+NEJRkjux1CrQbgR2lipxPO3+bFj
me1A6SWlyv9JeR6FgELVqtZqZzxmdz6H519pLhOILSVph7fQgGssBC49wqsOf1WD
TT4jLeDKo3MsLh38o/0DS+1DL0Z0h6fi6PpKYg0vywKBgQDhyaEUeiXMow6qPhed
MEoMhAvkECUwcatP6D2RU6di/AgF4xc8P2KcDc/Dfc7YTfpF1DIKTLZ3X+6NAaIp
2e2SmNBvKuAULjlnWyOyBvvY7wK8locDqx67ii6SBg/A+LDCfRqTkM627IJ/6Mm6
sfr0RTVMtycqGBDGn9XAiVXgtwKBgQDCSzvKTYFHJR4wuiUFfW95aF1gfHzn435Q
vrZXL3SC7Vz6mbcU30D+bCj950dbNJzJ4yzA3OQ8Zu7cLVYudded+dYrXcsbEAiq
rN4fW72rkEar5o5usEMT1DuKL4aCynW77OtZxmpS2OCQtHY57qj/wGfvK3ur0/Su
6ldo26wvHwKBgEIuoeKosy+6k+/e53kR0IK+qeWdvejnSLnRb0qL5MKk8Y0YNZVZ
VwQ7IC1DUUAiCzwwqMJQHiP7oKcAVZJC6NpRpLcRMEF6EyVyl5H1bhj2Ziz1SnoO
zKFYLbJryG5d9yHrHcEnbxA7Xz0y9P6ecNrs9mSYQwiZqUEvVK5tExkdAoGAH/xM
sohB4Rl+N91dHONCh8Ujoi+8TFyKPfa3g/DfCHLVHLhTiI8cXwYlVW9OsvgdW6sX
ggSbWkpDxmF8T5e80FgB5w/A0Qq5sodU5eqvdeABkmkZR6Wi1U/aIWyjg0KbUT22
nQfqFwt3JLtgvzbIAZqGQbxx1p7FKEqR60RGu1cCgYEAnYLzTUX/sOH7v9N9E+IM
Dc1dlDCETgxKW7JNLoz1+EoZKIQa25cu7qOaKvDcHok2vmUK2jVWbirUwDcmVag8
q+/uX0dsbJ0YrkgcitVCuHhDEcMF6H9YHPIzQyuAXUDtLRtCMSpJTN4qDPw81gXx
nyqrF/39wcJWPcvrAIUUArk=
-----END PRIVATE KEY-----
)PEM";

struct Loopback {
    boost::asio::io_context context;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{
        context.get_executor()};
    boost::asio::ip::tcp::socket peer{context};
    std::unique_ptr<clash_native::net::TcpStream> stream;

    Loopback() {
        using boost::asio::ip::tcp;
        tcp::acceptor acceptor(context, tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
        tcp::socket server(context);
        std::promise<void> accepted;
        auto accepted_future = accepted.get_future();
        acceptor.async_accept(server, [&](const boost::system::error_code &error) {
            EXPECT_FALSE(error);
            accepted.set_value();
        });
        std::thread runner([this] { context.run(); });
        runner.detach();
        peer.connect(tcp::endpoint(boost::asio::ip::address_v4::loopback(),
                                   acceptor.local_endpoint().port()));
        if (accepted_future.wait_for(std::chrono::seconds(5)) != std::future_status::ready) {
            throw std::runtime_error("loopback accept timed out");
        }
        stream = std::make_unique<clash_native::net::TcpStream>(std::move(server));
    }
};

struct HandshakeReceiver {
    using receiver_concept = stdexec::receiver_tag;
    std::promise<clash_native::core::Error> done;
    void set_value(clash_native::transport::TlsClientConnection) noexcept {
        done.set_value({clash_native::core::ErrorCode::cancelled, "handshake succeeded"});
    }
    void set_error(std::exception_ptr error) noexcept {
        try {
            std::rethrow_exception(std::move(error));
        } catch (const clash_native::core::Error &failure) {
            done.set_value(failure);
            return;
        } catch (...) {
        }
        done.set_value({clash_native::core::ErrorCode::transport_io, "handshake threw"});
    }
    void set_stopped() noexcept {
        done.set_value({clash_native::core::ErrorCode::cancelled, "handshake stopped"});
    }
};

clash_native::core::Error handshake_error(clash_native::transport::TlsClientOptions options) {
    Loopback loop;
    // NOTE: name the sender first; argument order is unspecified.
    auto sender = clash_native::transport::async_tls_client_handshake(std::move(loop.stream),
                                                                      std::move(options));
    HandshakeReceiver receiver;
    auto completed = receiver.done.get_future();
    auto op = stdexec::connect(std::move(sender), std::move(receiver));
    stdexec::start(op);
    std::thread worker([&] { loop.context.run(); });
    const auto status = completed.wait_for(std::chrono::seconds(5));
    loop.context.stop();
    worker.join();
    if (status != std::future_status::ready) {
        return {clash_native::core::ErrorCode::timeout, "handshake hung"};
    }
    return completed.get();
}

} // namespace

TEST(TlsClientTest, RejectsHalfConfiguredClientCredentials) {
    clash_native::transport::TlsClientOptions options;
    options.server_name = "localhost";
    options.verify_peer = false;
    options.client_certificate_pem = std::string(kCertificate);
    const auto failure = handshake_error(std::move(options));
    EXPECT_EQ(failure.code, clash_native::core::ErrorCode::configuration);
}

TEST(TlsClientTest, RejectsMalformedClientCredentials) {
    clash_native::transport::TlsClientOptions options;
    options.server_name = "localhost";
    options.verify_peer = false;
    options.client_certificate_pem = "not-a-certificate";
    options.client_private_key_pem = "not-a-key";
    const auto failure = handshake_error(std::move(options));
    EXPECT_EQ(failure.code, clash_native::core::ErrorCode::configuration);
}

TEST(TlsClientTest, RejectsMismatchedClientKey) {
    clash_native::transport::TlsClientOptions options;
    options.server_name = "localhost";
    options.verify_peer = false;
    // Valid certificate paired with a valid-but-unrelated key.
    options.client_certificate_pem = std::string(kCertificate);
    options.client_private_key_pem = std::string(kCertificate);
    const auto failure = handshake_error(std::move(options));
    EXPECT_EQ(failure.code, clash_native::core::ErrorCode::configuration);
}

TEST(TlsClientTest, OverlayBoringsslMarkerIsPresent) {
    // Proves the overlay-port patch pipeline end to end: this symbol only
    // exists in BoringSSL built from third_party/vcpkg/ports/boringssl.
    EXPECT_EQ(CLASH_NATIVE_overlay_marker(), 1);
}
namespace {

// Minimal ClientHello parser for the Chrome-profile test. All offsets are
// bounds-checked; any truncation fails the test at the offending offset.
struct Cursor {
    const uint8_t *data = nullptr;
    std::size_t size = 0;

    bool take8(uint8_t &out) {
        if (size < 1) {
            return false;
        }
        out = data[0];
        data += 1;
        size -= 1;
        return true;
    }

    bool take16(uint16_t &out) {
        if (size < 2) {
            return false;
        }
        out = static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) | data[1]);
        data += 2;
        size -= 2;
        return true;
    }

    bool take24(uint32_t &out) {
        if (size < 3) {
            return false;
        }
        out = (static_cast<uint32_t>(data[0]) << 16) | (static_cast<uint32_t>(data[1]) << 8) |
              data[2];
        data += 3;
        size -= 3;
        return true;
    }

    bool take_bytes(std::size_t count, const uint8_t *&out) {
        if (size < count) {
            return false;
        }
        out = data;
        data += count;
        size -= count;
        return true;
    }

    bool skip(std::size_t count) {
        const uint8_t *ignored = nullptr;
        return take_bytes(count, ignored);
    }
};

bool is_grease(uint16_t value) {
    return (value & 0x0f0f) == 0x0a0a && ((value >> 8) & 0x0f) == (value & 0x0f);
}

struct KeyShareEntry {
    uint16_t group = 0;
    std::vector<uint8_t> key;
};

struct ClientHello {
    std::vector<uint16_t> ciphers;
    std::vector<uint16_t> extension_types;
    std::vector<uint8_t> random;
    std::vector<uint8_t> session_id;
    std::vector<KeyShareEntry> key_shares;
    std::vector<uint16_t> groups;
    std::vector<uint16_t> key_share_groups;
    std::vector<uint16_t> signature_algorithms;
    std::vector<uint16_t> versions;
    std::vector<std::string> alpn;
    std::string server_name;
    bool has_alps = false;
    bool has_ech = false;
    bool has_compress_brotli = false;
    bool has_compress_zlib = false;
    std::vector<uint16_t> delegated_credential_sigalgs;
    uint16_t record_size_limit = 0;
    bool has_padding = false;
};

bool parse_client_hello(const std::vector<uint8_t> &record, ClientHello &hello) {
    Cursor record_cursor{record.data(), record.size()};
    uint8_t record_type = 0;
    uint16_t record_version = 0;
    uint16_t record_length = 0;
    if (!record_cursor.take8(record_type) || !record_cursor.take16(record_version) ||
        !record_cursor.take16(record_length) || record_type != 22 ||
        record_cursor.size < record_length) {
        return false;
    }
    Cursor cursor{record_cursor.data, record_length};
    uint8_t handshake_type = 0;
    uint32_t handshake_length = 0;
    if (!cursor.take8(handshake_type) || !cursor.take24(handshake_length) || handshake_type != 1 ||
        cursor.size < handshake_length) {
        return false;
    }
    Cursor body{cursor.data, handshake_length};
    uint16_t legacy_version = 0;
    const uint8_t *random = nullptr;
    if (!body.take16(legacy_version) || legacy_version != 0x0303 || !body.take_bytes(32, random)) {
        return false;
    }
    hello.random.assign(random, random + 32);
    uint8_t session_id_length = 0;
    const uint8_t *session_id = nullptr;
    if (!body.take8(session_id_length) || !body.take_bytes(session_id_length, session_id)) {
        return false;
    }
    hello.session_id.assign(session_id, session_id + session_id_length);
    uint16_t cipher_length = 0;
    if (!body.take16(cipher_length) || (cipher_length % 2) != 0) {
        return false;
    }
    for (uint16_t left = cipher_length; left > 0; left -= 2) {
        uint16_t cipher = 0;
        if (!body.take16(cipher)) {
            return false;
        }
        hello.ciphers.push_back(cipher);
    }
    uint8_t compression_length = 0;
    if (!body.take8(compression_length) || !body.skip(compression_length)) {
        return false;
    }
    uint16_t extensions_length = 0;
    if (!body.take16(extensions_length) || body.size < extensions_length) {
        return false;
    }
    Cursor extensions{body.data, extensions_length};
    while (extensions.size > 0) {
        uint16_t type = 0;
        uint16_t length = 0;
        const uint8_t *value = nullptr;
        if (!extensions.take16(type) || !extensions.take16(length) ||
            !extensions.take_bytes(length, value)) {
            return false;
        }
        hello.extension_types.push_back(type);
        Cursor ext{value, length};
        if (type == 0) {
            uint16_t list_length = 0;
            uint8_t name_type = 0;
            uint16_t name_length = 0;
            const uint8_t *name = nullptr;
            if (!ext.take16(list_length) || !ext.take8(name_type) || !ext.take16(name_length) ||
                !ext.take_bytes(name_length, name)) {
                return false;
            }
            hello.server_name.assign(reinterpret_cast<const char *>(name), name_length);
        } else if (type == 10) {
            uint16_t list_length = 0;
            if (!ext.take16(list_length) || (list_length % 2) != 0) {
                return false;
            }
            for (uint16_t left = list_length; left > 0; left -= 2) {
                uint16_t group = 0;
                if (!ext.take16(group)) {
                    return false;
                }
                hello.groups.push_back(group);
            }
        } else if (type == 13) {
            uint16_t list_length = 0;
            if (!ext.take16(list_length) || (list_length % 2) != 0) {
                return false;
            }
            for (uint16_t left = list_length; left > 0; left -= 2) {
                uint16_t scheme = 0;
                if (!ext.take16(scheme)) {
                    return false;
                }
                hello.signature_algorithms.push_back(scheme);
            }
        } else if (type == 16) {
            uint16_t list_length = 0;
            if (!ext.take16(list_length) || ext.size < list_length) {
                return false;
            }
            Cursor protocols{ext.data, list_length};
            while (protocols.size > 0) {
                uint8_t name_length = 0;
                const uint8_t *name = nullptr;
                if (!protocols.take8(name_length) || !protocols.take_bytes(name_length, name)) {
                    return false;
                }
                hello.alpn.emplace_back(reinterpret_cast<const char *>(name), name_length);
            }
        } else if (type == 27) {
            uint8_t list_length = 0;
            if (!ext.take8(list_length) || (list_length % 2) != 0) {
                return false;
            }
            for (uint8_t left = list_length; left > 0; left -= 2) {
                uint16_t alg = 0;
                if (!ext.take16(alg)) {
                    return false;
                }
                hello.has_compress_brotli = hello.has_compress_brotli || alg == 2;
                hello.has_compress_zlib = hello.has_compress_zlib || alg == 1;
            }
        } else if (type == 43) {
            uint8_t list_length = 0;
            if (!ext.take8(list_length) || (list_length % 2) != 0) {
                return false;
            }
            for (uint8_t left = list_length; left > 0; left -= 2) {
                uint16_t version = 0;
                if (!ext.take16(version)) {
                    return false;
                }
                hello.versions.push_back(version);
            }
        } else if (type == 51) {
            uint16_t list_length = 0;
            if (!ext.take16(list_length) || ext.size < list_length) {
                return false;
            }
            Cursor shares{ext.data, list_length};
            while (shares.size > 0) {
                uint16_t group = 0;
                uint16_t share_length = 0;
                const uint8_t *share = nullptr;
                if (!shares.take16(group) || !shares.take16(share_length) ||
                    !shares.take_bytes(share_length, share)) {
                    return false;
                }
                hello.key_share_groups.push_back(group);
                KeyShareEntry entry;
                entry.group = group;
                entry.key.assign(share, share + share_length);
                hello.key_shares.push_back(std::move(entry));
            }
        } else if (type == 17613) {
            hello.has_alps = true;
        } else if (type == 65037) {
            hello.has_ech = true;
        } else if (type == 34) {
            uint16_t list_length = 0;
            if (!ext.take16(list_length) || (list_length % 2) != 0) {
                return false;
            }
            for (uint16_t left = list_length; left > 0; left -= 2) {
                uint16_t scheme = 0;
                if (!ext.take16(scheme)) {
                    return false;
                }
                hello.delegated_credential_sigalgs.push_back(scheme);
            }
        } else if (type == 28) {
            uint16_t limit = 0;
            if (!ext.take16(limit) || ext.size != 0) {
                return false;
            }
            hello.record_size_limit = limit;
        } else if (type == 21) {
            hello.has_padding = true;
        }
    }
    return true;
}

std::vector<uint8_t> read_tls_record(boost::asio::io_context &context,
                                     boost::asio::ip::tcp::socket &server) {
    auto header = std::make_shared<std::vector<uint8_t>>(5);
    auto record = std::make_shared<std::vector<uint8_t>>();
    std::promise<std::vector<uint8_t>> captured;
    auto captured_future = captured.get_future();
    boost::asio::async_read(
        server, boost::asio::buffer(*header),
        [&, header, record, promise = std::move(captured)](const boost::system::error_code &error,
                                                           std::size_t) mutable {
            if (error) {
                promise.set_value({});
                return;
            }
            const auto length =
                static_cast<std::size_t>((static_cast<uint16_t>((*header)[3]) << 8) | (*header)[4]);
            record->reserve(5 + length);
            record->insert(record->end(), header->begin(), header->end());
            record->resize(5 + length);
            boost::asio::async_read(
                server, boost::asio::buffer(record->data() + 5, length),
                [record, promise = std::move(promise)](const boost::system::error_code &body_error,
                                                       std::size_t) mutable {
                    promise.set_value(body_error ? std::vector<uint8_t>{} : *record);
                });
        });
    if (captured_future.wait_for(std::chrono::seconds(5)) != std::future_status::ready) {
        context.stop();
        throw std::runtime_error("TLS record read timed out");
    }
    return captured_future.get();
}

} // namespace

TEST(TlsClientTest, RejectsUnknownFingerprint) {
    clash_native::transport::TlsClientOptions options;
    options.verify_peer = false;
    options.server_name = "example.com";
    options.fingerprint = "firefox-esr-1952";
    const auto failure = handshake_error(std::move(options));
    EXPECT_EQ(failure.code, clash_native::core::ErrorCode::configuration);
}

TEST(TlsClientTest, ChromeFingerprintMatchesChromeClientHello) {
    using boost::asio::ip::tcp;
    boost::asio::io_context context;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{
        context.get_executor()};
    std::thread runner([&] { context.run(); });

    tcp::acceptor acceptor(context, tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
    tcp::socket server(context);
    std::promise<void> accepted;
    auto accepted_future = accepted.get_future();
    acceptor.async_accept(server, [&](const boost::system::error_code &error) {
        EXPECT_FALSE(error);
        accepted.set_value();
    });

    tcp::socket peer(context);
    peer.connect(
        tcp::endpoint(boost::asio::ip::address_v4::loopback(), acceptor.local_endpoint().port()));
    ASSERT_EQ(accepted_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    auto stream = std::make_unique<clash_native::net::TcpStream>(std::move(peer));

    clash_native::transport::TlsClientOptions options;
    options.verify_peer = false;
    options.server_name = "example.com";
    options.alpn_protocols = {"h2", "http/1.1"};
    options.fingerprint = "chrome";
    options.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    auto sender =
        clash_native::transport::async_tls_client_handshake(std::move(stream), std::move(options));
    HandshakeReceiver receiver;
    auto completed = receiver.done.get_future();
    auto op = stdexec::connect(std::move(sender), std::move(receiver));
    stdexec::start(op);

    // The peer never answers, so the client must emit the ClientHello and
    // then fail. Capture the first flight straight off the socket.
    const auto record = read_tls_record(context, server);
    server.close();
    ASSERT_TRUE(completed.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    const auto failure = completed.get();
    EXPECT_NE(failure.code, clash_native::core::ErrorCode::configuration);

    ClientHello hello;
    ASSERT_TRUE(parse_client_hello(record, hello));
    EXPECT_EQ(hello.session_id.size(), 32u);
    EXPECT_EQ(hello.server_name, "example.com");
    EXPECT_EQ(hello.alpn, (std::vector<std::string>{"h2", "http/1.1"}));

    const std::vector<uint16_t> expected_ciphers = {0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f,
                                                    0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                                                    0xc014, 0x009c, 0x009d, 0x002f, 0x0035};
    ASSERT_EQ(hello.ciphers.size(), expected_ciphers.size() + 1);
    EXPECT_TRUE(is_grease(hello.ciphers[0]));
    EXPECT_EQ(std::vector<uint16_t>(hello.ciphers.begin() + 1, hello.ciphers.end()),
              expected_ciphers);

    // Extension order is shuffled (like Chrome); compare as a multiset with
    // GREASE values normalized.
    std::vector<uint16_t> normalized;
    std::size_t grease_count = 0;
    for (const auto type : hello.extension_types) {
        if (is_grease(type)) {
            grease_count += 1;
            continue;
        }
        normalized.push_back(type);
    }
    std::sort(normalized.begin(), normalized.end());
    // 17613 is the new ALPS codepoint (RFC 9460); Chrome offers ALPS with it.
    const std::vector<uint16_t> expected_extensions = {0,  5,  10, 11, 13, 16,    18,    23,
                                                       27, 35, 43, 45, 51, 17613, 65037, 65281};
    EXPECT_EQ(grease_count, 2u);
    EXPECT_EQ(normalized, expected_extensions);

    ASSERT_EQ(hello.groups.size(), 5u);
    EXPECT_TRUE(is_grease(hello.groups[0]));
    EXPECT_EQ(std::vector<uint16_t>(hello.groups.begin() + 1, hello.groups.end()),
              (std::vector<uint16_t>{0x11ec, 0x001d, 0x0017, 0x0018}));

    ASSERT_EQ(hello.key_share_groups.size(), 3u);
    EXPECT_TRUE(is_grease(hello.key_share_groups[0]));
    EXPECT_EQ(hello.key_share_groups[1], 0x11ec);
    EXPECT_EQ(hello.key_share_groups[2], 0x001d);

    // Chrome's eight plus Ed25519 (0x0807): required for REALITY because
    // REALITY certificates are Ed25519 and BoringSSL enforces that the peer
    // scheme was offered. Documented on kChromeSignatureAlgorithms.
    EXPECT_EQ(hello.signature_algorithms,
              (std::vector<uint16_t>{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
                                     0x0807}));

    ASSERT_EQ(hello.versions.size(), 3u);
    EXPECT_TRUE(is_grease(hello.versions[0]));
    EXPECT_EQ(hello.versions[1], 0x0304);
    EXPECT_EQ(hello.versions[2], 0x0303);

    EXPECT_TRUE(hello.has_alps);
    EXPECT_TRUE(hello.has_ech);
    EXPECT_TRUE(hello.has_compress_brotli);

    context.stop();
    runner.join();
}

namespace {

std::string test_base64url_encode(const uint8_t *data, std::size_t length) {
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    uint32_t bits = 0;
    int width = 0;
    for (std::size_t i = 0; i < length; ++i) {
        bits = (bits << 8) | data[i];
        width += 8;
        while (width >= 6) {
            width -= 6;
            out.push_back(kAlphabet[(bits >> width) & 63]);
        }
    }
    if (width > 0) {
        out.push_back(kAlphabet[(bits << (6 - width)) & 63]);
    }
    return out;
}

} // namespace

TEST(TlsClientTest, RejectsRealityWithoutFingerprint) {
    clash_native::transport::TlsClientOptions options;
    options.verify_peer = false;
    options.server_name = "example.com";
    options.reality = clash_native::transport::TlsRealityOptions{
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "deadbeef"};
    const auto failure = handshake_error(std::move(options));
    EXPECT_EQ(failure.code, clash_native::core::ErrorCode::configuration);
}

TEST(TlsClientTest, RejectsRealityWithBadKeys) {
    clash_native::transport::TlsClientOptions options;
    options.verify_peer = false;
    options.server_name = "example.com";
    options.fingerprint = "chrome";
    options.reality = clash_native::transport::TlsRealityOptions{"not-a-key", "deadbeef"};
    EXPECT_EQ(handshake_error(options).code, clash_native::core::ErrorCode::configuration);
    options.reality = clash_native::transport::TlsRealityOptions{
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "xyz"};
    EXPECT_EQ(handshake_error(options).code, clash_native::core::ErrorCode::configuration);
    options.reality = clash_native::transport::TlsRealityOptions{
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "deadbeef"};
    options.maximum_tls_version = 0x0303;
    EXPECT_EQ(handshake_error(std::move(options)).code,
              clash_native::core::ErrorCode::configuration);
}

TEST(TlsClientTest, RealityTicketVerifiesAgainstLoopbackServer) {
    using boost::asio::ip::tcp;
    uint8_t server_public[32] = {0};
    uint8_t server_private[32] = {0};
    X25519_keypair(server_public, server_private);

    boost::asio::io_context context;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{
        context.get_executor()};
    std::thread runner([&] { context.run(); });

    tcp::acceptor acceptor(context, tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
    tcp::socket server(context);
    std::promise<void> accepted;
    auto accepted_future = accepted.get_future();
    acceptor.async_accept(server, [&](const boost::system::error_code &error) {
        EXPECT_FALSE(error);
        accepted.set_value();
    });

    tcp::socket peer(context);
    peer.connect(
        tcp::endpoint(boost::asio::ip::address_v4::loopback(), acceptor.local_endpoint().port()));
    ASSERT_EQ(accepted_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    auto stream = std::make_unique<clash_native::net::TcpStream>(std::move(peer));

    clash_native::transport::TlsClientOptions options;
    options.verify_peer = false;
    options.server_name = "example.com";
    options.alpn_protocols = {"h2", "http/1.1"};
    options.fingerprint = "chrome";
    options.reality = clash_native::transport::TlsRealityOptions{
        test_base64url_encode(server_public, sizeof(server_public)), "deadbeef"};
    options.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    auto sender =
        clash_native::transport::async_tls_client_handshake(std::move(stream), std::move(options));
    HandshakeReceiver receiver;
    auto completed = receiver.done.get_future();
    auto op = stdexec::connect(std::move(sender), std::move(receiver));
    stdexec::start(op);

    const auto record = read_tls_record(context, server);
    server.close();
    ASSERT_TRUE(completed.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    EXPECT_NE(completed.get().code, clash_native::core::ErrorCode::configuration);

    ClientHello hello;
    ASSERT_TRUE(parse_client_hello(record, hello));
    // The ticket replaced the random compatibility-mode session ID.
    ASSERT_EQ(hello.session_id.size(), 32u);
    ASSERT_EQ(hello.random.size(), 32u);

    const KeyShareEntry *x25519 = nullptr;
    for (const auto &share : hello.key_shares) {
        if (share.group == 0x001d && share.key.size() == 32) {
            x25519 = &share;
        }
    }
    ASSERT_NE(x25519, nullptr);

    // Server side: ECDH(server_private, client share) then HKDF, mirroring
    // the REALITY authentication check.
    uint8_t secret[32] = {0};
    ASSERT_EQ(X25519(secret, server_private, x25519->key.data()), 1);
    uint8_t auth_key[32] = {0};
    ASSERT_EQ(HKDF(auth_key, sizeof(auth_key), EVP_sha256(), secret, sizeof(secret),
                   hello.random.data(), 20, reinterpret_cast<const uint8_t *>("REALITY"), 7),
              1);

    // AAD is the handshake message with the sealed session ID zeroed.
    ASSERT_GE(record.size(), 5u + 39u + 32u);
    std::vector<uint8_t> aad(record.begin() + 5, record.end());
    std::fill(aad.begin() + 39, aad.begin() + 39 + 32, 0);
    uint8_t plaintext[16] = {0};
    EVP_AEAD_CTX aead;
    EVP_AEAD_CTX_zero(&aead);
    ASSERT_TRUE(EVP_AEAD_CTX_init(&aead, EVP_aead_aes_256_gcm(), auth_key, sizeof(auth_key),
                                  EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr));
    const bool opened = EVP_AEAD_CTX_open_gather(
                            &aead, plaintext, hello.random.data() + 20, 12, hello.session_id.data(),
                            16, hello.session_id.data() + 16, 16, aad.data(), aad.size()) == 1;
    EVP_AEAD_CTX_cleanup(&aead);
    ASSERT_TRUE(opened);
    EXPECT_EQ(plaintext[0], 1);
    EXPECT_EQ(plaintext[1], 8);
    EXPECT_EQ(plaintext[2], 2);
    EXPECT_EQ(std::vector<uint8_t>(plaintext + 8, plaintext + 12),
              (std::vector<uint8_t>{0xde, 0xad, 0xbe, 0xef}));
    uint64_t ticket_time = 0;
    for (int i = 3; i < 8; ++i) {
        ticket_time = (ticket_time << 8) | plaintext[i];
    }
    const auto now = static_cast<uint64_t>(std::chrono::system_clock::now().time_since_epoch() /
                                           std::chrono::seconds(1));
    EXPECT_LE(ticket_time <= now ? now - ticket_time : ticket_time - now, 120u);

    context.stop();
    runner.join();
}
namespace {

// Prefix BIO state: serves an initial memory buffer, then delegates to a
// socket BIO. Lets a test server inspect the ClientHello before BoringSSL
// parses it (a plain BIO chain reports EOF once the memory part drains).
struct PrefixBioState {
    const uint8_t *data = nullptr;
    std::size_t length = 0;
    std::size_t position = 0;
    BIO *next = nullptr;
};

int prefix_bio_create(BIO *bio) {
    BIO_set_init(bio, 1);
    BIO_set_data(bio, nullptr);
    return 1;
}

int prefix_bio_destroy(BIO *bio) {
    delete static_cast<PrefixBioState *>(BIO_get_data(bio));
    BIO_set_data(bio, nullptr);
    return 1;
}

int prefix_bio_read(BIO *bio, char *out, int length) {
    auto *state = static_cast<PrefixBioState *>(BIO_get_data(bio));
    if (state == nullptr || state->next == nullptr) {
        return 0;
    }
    if (state->position < state->length) {
        const std::size_t available = state->length - state->position;
        const std::size_t count = std::min<std::size_t>(available, static_cast<size_t>(length));
        std::memcpy(out, state->data + state->position, count);
        state->position += count;
        return static_cast<int>(count);
    }
    return BIO_read(state->next, out, length);
}

int prefix_bio_write(BIO *bio, const char *in, int length) {
    auto *state = static_cast<PrefixBioState *>(BIO_get_data(bio));
    if (state == nullptr || state->next == nullptr) {
        return 0;
    }
    return BIO_write(state->next, in, length);
}

long prefix_bio_ctrl(BIO *bio, int cmd, long num, void *ptr) {
    auto *state = static_cast<PrefixBioState *>(BIO_get_data(bio));
    if (state == nullptr || state->next == nullptr) {
        return 0;
    }
    return BIO_ctrl(state->next, cmd, num, ptr);
}

BIO *make_prefix_bio(const std::vector<uint8_t> &prefix, BIO *next) {
    static BIO_METHOD *method = nullptr;
    if (method == nullptr) {
        method = BIO_meth_new(BIO_TYPE_SOURCE_SINK | 0x10, "prefix");
        BIO_meth_set_write(method, prefix_bio_write);
        BIO_meth_set_read(method, prefix_bio_read);
        BIO_meth_set_ctrl(method, prefix_bio_ctrl);
        BIO_meth_set_create(method, prefix_bio_create);
        BIO_meth_set_destroy(method, prefix_bio_destroy);
    }
    BIO *bio = BIO_new(method);
    auto *state = new PrefixBioState{prefix.data(), prefix.size(), 0, next};
    BIO_set_data(bio, state);
    return bio;
}

X509 *forge_reality_certificate(EVP_PKEY *ed_key, const uint8_t auth_key[32]) {
    // A self-signed Ed25519 certificate whose signature bytes are replaced
    // with HMAC-SHA512(auth_key, raw public key), exactly what a REALITY
    // server presents. Test-only forgery: the signature is meaningless as a
    // real signature; only the byte comparison matters.
    uint8_t raw[32] = {0};
    size_t raw_length = sizeof(raw);
    if (EVP_PKEY_get_raw_public_key(ed_key, raw, &raw_length) != 1 || raw_length != sizeof(raw)) {
        return nullptr;
    }
    uint8_t mac[64] = {0};
    unsigned int mac_length = 0;
    if (HMAC(EVP_sha512(), auth_key, 32, raw, sizeof(raw), mac, &mac_length) == nullptr ||
        mac_length != sizeof(mac)) {
        return nullptr;
    }
    bssl::UniquePtr<X509> cert(X509_new());
    bssl::UniquePtr<X509_NAME> name(X509_NAME_new());
    if (!cert || !name ||
        !X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_ASC,
                                    reinterpret_cast<const uint8_t *>("localhos"
                                                                      "t"),
                                    -1, -1, 0) ||
        !X509_set_version(cert.get(), 2) ||
        !ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1) ||
        !X509_set_issuer_name(cert.get(), name.get()) ||
        !X509_set_subject_name(cert.get(), name.get()) || !X509_set_pubkey(cert.get(), ed_key) ||
        !X509_gmtime_adj(X509_getm_notBefore(cert.get()), -3600) ||
        !X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600) ||
        !X509_sign(cert.get(), ed_key, nullptr)) {
        return nullptr;
    }
    const ASN1_BIT_STRING *signature = nullptr;
    X509_get0_signature(&signature, nullptr, cert.get());
    if (signature == nullptr) {
        return nullptr;
    }
    if (!ASN1_STRING_set(const_cast<ASN1_BIT_STRING *>(signature), mac, sizeof(mac))) {
        return nullptr;
    }
    return cert.release();
}

struct SuccessReceiver {
    using receiver_concept = stdexec::receiver_tag;
    // Keeps the established connection alive: dropping it would close the
    // socket under a concurrently blocked server accept.
    std::promise<std::optional<clash_native::transport::TlsClientConnection>> done;
    void set_value(clash_native::transport::TlsClientConnection connection) noexcept {
        done.set_value(std::move(connection));
    }
    void set_error(std::exception_ptr) noexcept { done.set_value(std::nullopt); }
    void set_stopped() noexcept { done.set_value(std::nullopt); }
};

} // namespace

TEST(TlsClientTest, RealitySpkiVerifyCompletesHandshake) {
    using boost::asio::ip::tcp;
    // Ticket keys (X25519) are independent from the certificate keys
    // (Ed25519), exactly like a REALITY deployment.
    uint8_t server_public[32] = {0};
    uint8_t server_private[32] = {0};
    X25519_keypair(server_public, server_private);
    uint8_t ed_public[32] = {0};
    uint8_t ed_private[64] = {0};
    ED25519_keypair(ed_public, ed_private);
    // The raw private form is the 32-byte seed (first half of the 64-byte
    // ED25519_keypair output).
    bssl::UniquePtr<EVP_PKEY> ed_key(
        EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, ed_private, 32));
    ASSERT_TRUE(ed_key);

    boost::asio::io_context context;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{
        context.get_executor()};
    std::thread runner([&] { context.run(); });

    tcp::acceptor acceptor(context, tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
    tcp::socket server(context);
    std::promise<void> accepted;
    auto accepted_future = accepted.get_future();
    acceptor.async_accept(server, [&](const boost::system::error_code &error) {
        EXPECT_FALSE(error);
        accepted.set_value();
    });

    tcp::socket peer(context);
    peer.connect(
        tcp::endpoint(boost::asio::ip::address_v4::loopback(), acceptor.local_endpoint().port()));
    ASSERT_EQ(accepted_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    auto stream = std::make_unique<clash_native::net::TcpStream>(std::move(peer));

    clash_native::transport::TlsClientOptions options;
    options.verify_peer = true;
    options.server_name = "localhost";
    options.fingerprint = "chrome";
    options.reality = clash_native::transport::TlsRealityOptions{
        test_base64url_encode(server_public, sizeof(server_public)), "deadbeef"};
    options.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    auto sender =
        clash_native::transport::async_tls_client_handshake(std::move(stream), std::move(options));
    SuccessReceiver receiver;
    auto completed = receiver.done.get_future();
    auto op = stdexec::connect(std::move(sender), std::move(receiver));
    stdexec::start(op);

    // Minimal REALITY server: read the hello, derive the auth key like
    // Mihomo does, forge the certificate, then serve BoringSSL over a BIO
    // chain that replays the consumed hello bytes first.
    const auto record = read_tls_record(context, server);
    ASSERT_GE(record.size(), 5u + 39u + 32u);
    ClientHello hello;
    ASSERT_TRUE(parse_client_hello(record, hello));
    const KeyShareEntry *x25519 = nullptr;
    for (const auto &share : hello.key_shares) {
        if (share.group == 0x001d && share.key.size() == 32) {
            x25519 = &share;
        }
    }
    ASSERT_NE(x25519, nullptr);
    uint8_t secret[32] = {0};
    ASSERT_EQ(X25519(secret, server_private, x25519->key.data()), 1);
    uint8_t auth_key[32] = {0};
    ASSERT_EQ(HKDF(auth_key, sizeof(auth_key), EVP_sha256(), secret, sizeof(secret),
                   hello.random.data(), 20, reinterpret_cast<const uint8_t *>("REALITY"), 7),
              1);
    X509 *certificate = forge_reality_certificate(ed_key.get(), auth_key);
    ASSERT_NE(certificate, nullptr);
    // The forged signature bytes must not corrupt the DER structure.
    int forged_length = i2d_X509(certificate, nullptr);
    ASSERT_GT(forged_length, 0);
    std::vector<uint8_t> forged_der(static_cast<size_t>(forged_length));
    uint8_t *der_cursor = forged_der.data();
    ASSERT_EQ(i2d_X509(certificate, &der_cursor), forged_length);
    const uint8_t *parse_cursor = forged_der.data();
    bssl::UniquePtr<X509> reparsed(d2i_X509(nullptr, &parse_cursor, forged_length));
    ASSERT_TRUE(reparsed);

    bssl::UniquePtr<SSL_CTX> server_context(SSL_CTX_new(TLS_server_method()));
    ASSERT_TRUE(server_context);
    ASSERT_EQ(SSL_CTX_use_certificate(server_context.get(), certificate), 1);
    ASSERT_EQ(SSL_CTX_use_PrivateKey(server_context.get(), ed_key.get()), 1);
    X509_free(certificate);
    bssl::UniquePtr<SSL> server_ssl(SSL_new(server_context.get()));
    ASSERT_TRUE(server_ssl);
    BIO *socket_bio = BIO_new_socket(server.native_handle(), BIO_NOCLOSE);
    ASSERT_NE(socket_bio, nullptr);
    // The prefix BIO replays the consumed record (header included: the
    // server record layer parses framing itself), then delegates to the
    // socket. A plain BIO chain would report EOF once memory drains.
    BIO *prefix = make_prefix_bio(record, socket_bio);
    ASSERT_NE(prefix, nullptr);
    SSL_set_bio(server_ssl.get(), prefix, socket_bio);
    EXPECT_EQ(SSL_accept(server_ssl.get()), 1);
    server.close();

    ASSERT_TRUE(completed.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    auto established = completed.get();
    EXPECT_TRUE(established.has_value());

    context.stop();
    runner.join();
}

TEST(TlsClientTest, ChromeProfileCompletesAgainstBoringsslServer) {
    using boost::asio::ip::tcp;
    // Bisects DECODE_ERROR seen with the REALITY test server: stock Chrome
    // profile (no ticket mutation) against a stock BoringSSL server.
    boost::asio::io_context context;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{
        context.get_executor()};
    std::thread runner([&] { context.run(); });

    tcp::acceptor acceptor(context, tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
    tcp::socket server(context);
    std::promise<void> accepted;
    auto accepted_future = accepted.get_future();
    acceptor.async_accept(server, [&](const boost::system::error_code &error) {
        EXPECT_FALSE(error);
        accepted.set_value();
    });

    tcp::socket peer(context);
    peer.connect(
        tcp::endpoint(boost::asio::ip::address_v4::loopback(), acceptor.local_endpoint().port()));
    ASSERT_EQ(accepted_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    auto stream = std::make_unique<clash_native::net::TcpStream>(std::move(peer));

    clash_native::transport::TlsClientOptions options;
    options.verify_peer = false;
    options.server_name = "localhost";
    options.fingerprint = "chrome";
    options.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    auto sender =
        clash_native::transport::async_tls_client_handshake(std::move(stream), std::move(options));
    SuccessReceiver receiver;
    auto completed = receiver.done.get_future();
    auto op = stdexec::connect(std::move(sender), std::move(receiver));
    stdexec::start(op);

    bssl::UniquePtr<SSL_CTX> server_context(SSL_CTX_new(TLS_server_method()));
    ASSERT_TRUE(server_context);
    bssl::UniquePtr<BIO> cert_bio(
        BIO_new_mem_buf(kCertificate.data(), static_cast<int>(kCertificate.size())));
    bssl::UniquePtr<X509> certificate(PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr));
    ASSERT_TRUE(certificate);
    ASSERT_EQ(SSL_CTX_use_certificate(server_context.get(), certificate.get()), 1);
    bssl::UniquePtr<BIO> key_bio(
        BIO_new_mem_buf(kPrivateKey.data(), static_cast<int>(kPrivateKey.size())));
    bssl::UniquePtr<EVP_PKEY> private_key(
        PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr));
    ASSERT_TRUE(private_key);
    ASSERT_EQ(SSL_CTX_use_PrivateKey(server_context.get(), private_key.get()), 1);
    bssl::UniquePtr<SSL> server_ssl(SSL_new(server_context.get()));
    ASSERT_TRUE(server_ssl);
    BIO *socket_bio = BIO_new_socket(server.native_handle(), BIO_NOCLOSE);
    ASSERT_NE(socket_bio, nullptr);
    SSL_set_bio(server_ssl.get(), socket_bio, socket_bio);
    EXPECT_EQ(SSL_accept(server_ssl.get()), 1);
    server.close();

    ASSERT_TRUE(completed.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    auto established = completed.get();
    EXPECT_TRUE(established.has_value());

    context.stop();
    runner.join();
}

TEST(TlsClientTest, ChromeProfileParsesEd25519Certificate) {
    using boost::asio::ip::tcp;
    // Bisects the REALITY DECODE_ERROR: stock Chrome profile (no ticket
    // mutation, no custom verify) against a stock BoringSSL server
    // presenting a self-signed Ed25519 certificate.
    uint8_t ed_public[32] = {0};
    uint8_t ed_private[64] = {0};
    ED25519_keypair(ed_public, ed_private);
    bssl::UniquePtr<EVP_PKEY> ed_key(
        EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, ed_private, 32));
    ASSERT_TRUE(ed_key);
    bssl::UniquePtr<X509> certificate(X509_new());
    bssl::UniquePtr<X509_NAME> name(X509_NAME_new());
    ASSERT_TRUE(certificate && name);
    ASSERT_TRUE(X509_NAME_add_entry_by_txt(
        name.get(), "CN", MBSTRING_ASC, reinterpret_cast<const uint8_t *>("localhost"), -1, -1, 0));
    ASSERT_TRUE(X509_set_version(certificate.get(), 2));
    ASSERT_TRUE(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1));
    ASSERT_TRUE(X509_set_issuer_name(certificate.get(), name.get()));
    ASSERT_TRUE(X509_set_subject_name(certificate.get(), name.get()));
    ASSERT_TRUE(X509_set_pubkey(certificate.get(), ed_key.get()));
    ASSERT_TRUE(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -3600));
    ASSERT_TRUE(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600));
    // X509_sign returns the signature length (64 for Ed25519) on success.
    ASSERT_GT(X509_sign(certificate.get(), ed_key.get(), nullptr), 0);

    boost::asio::io_context context;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{
        context.get_executor()};
    std::thread runner([&] { context.run(); });

    tcp::acceptor acceptor(context, tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
    tcp::socket server(context);
    std::promise<void> accepted;
    auto accepted_future = accepted.get_future();
    acceptor.async_accept(server, [&](const boost::system::error_code &error) {
        EXPECT_FALSE(error);
        accepted.set_value();
    });

    tcp::socket peer(context);
    peer.connect(
        tcp::endpoint(boost::asio::ip::address_v4::loopback(), acceptor.local_endpoint().port()));
    ASSERT_EQ(accepted_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    auto stream = std::make_unique<clash_native::net::TcpStream>(std::move(peer));

    clash_native::transport::TlsClientOptions options;
    options.verify_peer = false;
    options.server_name = "localhost";
    options.fingerprint = "chrome";
    options.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    auto sender =
        clash_native::transport::async_tls_client_handshake(std::move(stream), std::move(options));
    SuccessReceiver receiver;
    auto completed = receiver.done.get_future();
    auto op = stdexec::connect(std::move(sender), std::move(receiver));
    stdexec::start(op);

    bssl::UniquePtr<SSL_CTX> server_context(SSL_CTX_new(TLS_server_method()));
    ASSERT_TRUE(server_context);
    ASSERT_EQ(SSL_CTX_use_certificate(server_context.get(), certificate.get()), 1);
    ASSERT_EQ(SSL_CTX_use_PrivateKey(server_context.get(), ed_key.get()), 1);
    bssl::UniquePtr<SSL> server_ssl(SSL_new(server_context.get()));
    ASSERT_TRUE(server_ssl);
    BIO *socket_bio = BIO_new_socket(server.native_handle(), BIO_NOCLOSE);
    ASSERT_NE(socket_bio, nullptr);
    SSL_set_bio(server_ssl.get(), socket_bio, socket_bio);
    EXPECT_EQ(SSL_accept(server_ssl.get()), 1);
    server.close();

    ASSERT_TRUE(completed.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    auto established = completed.get();
    EXPECT_TRUE(established.has_value());

    context.stop();
    runner.join();
}
TEST(TlsClientTest, RealityTicketInteroperatesWithBoringsslServer) {
    using boost::asio::ip::tcp;
    // Bisects the REALITY DECODE_ERROR: sealed ticket, but no custom verify
    // callback (verify_peer=false) and a normally-signed Ed25519 server
    // certificate. A pass isolates the trigger to the verify path.
    uint8_t server_public[32] = {0};
    uint8_t server_private[32] = {0};
    X25519_keypair(server_public, server_private);
    uint8_t ed_public[32] = {0};
    uint8_t ed_private[64] = {0};
    ED25519_keypair(ed_public, ed_private);
    bssl::UniquePtr<EVP_PKEY> ed_key(
        EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, ed_private, 32));
    ASSERT_TRUE(ed_key);
    bssl::UniquePtr<X509> certificate(X509_new());
    bssl::UniquePtr<X509_NAME> name(X509_NAME_new());
    ASSERT_TRUE(certificate && name);
    ASSERT_TRUE(X509_NAME_add_entry_by_txt(
        name.get(), "CN", MBSTRING_ASC, reinterpret_cast<const uint8_t *>("localhost"), -1, -1, 0));
    ASSERT_TRUE(X509_set_version(certificate.get(), 2));
    ASSERT_TRUE(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1));
    ASSERT_TRUE(X509_set_issuer_name(certificate.get(), name.get()));
    ASSERT_TRUE(X509_set_subject_name(certificate.get(), name.get()));
    ASSERT_TRUE(X509_set_pubkey(certificate.get(), ed_key.get()));
    ASSERT_TRUE(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -3600));
    ASSERT_TRUE(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600));
    ASSERT_GT(X509_sign(certificate.get(), ed_key.get(), nullptr), 0);

    boost::asio::io_context context;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{
        context.get_executor()};
    std::thread runner([&] { context.run(); });

    tcp::acceptor acceptor(context, tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
    tcp::socket server(context);
    std::promise<void> accepted;
    auto accepted_future = accepted.get_future();
    acceptor.async_accept(server, [&](const boost::system::error_code &error) {
        EXPECT_FALSE(error);
        accepted.set_value();
    });

    tcp::socket peer(context);
    peer.connect(
        tcp::endpoint(boost::asio::ip::address_v4::loopback(), acceptor.local_endpoint().port()));
    ASSERT_EQ(accepted_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    auto stream = std::make_unique<clash_native::net::TcpStream>(std::move(peer));

    clash_native::transport::TlsClientOptions options;
    options.verify_peer = false;
    options.server_name = "localhost";
    options.fingerprint = "chrome";
    options.reality = clash_native::transport::TlsRealityOptions{
        test_base64url_encode(server_public, sizeof(server_public)), "deadbeef"};
    options.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    auto sender =
        clash_native::transport::async_tls_client_handshake(std::move(stream), std::move(options));
    SuccessReceiver receiver;
    auto completed = receiver.done.get_future();
    auto op = stdexec::connect(std::move(sender), std::move(receiver));
    stdexec::start(op);

    bssl::UniquePtr<SSL_CTX> server_context(SSL_CTX_new(TLS_server_method()));
    ASSERT_TRUE(server_context);
    ASSERT_EQ(SSL_CTX_use_certificate(server_context.get(), certificate.get()), 1);
    ASSERT_EQ(SSL_CTX_use_PrivateKey(server_context.get(), ed_key.get()), 1);
    bssl::UniquePtr<SSL> server_ssl(SSL_new(server_context.get()));
    ASSERT_TRUE(server_ssl);
    BIO *socket_bio = BIO_new_socket(server.native_handle(), BIO_NOCLOSE);
    ASSERT_NE(socket_bio, nullptr);
    SSL_set_bio(server_ssl.get(), socket_bio, socket_bio);
    EXPECT_EQ(SSL_accept(server_ssl.get()), 1);
    server.close();

    ASSERT_TRUE(completed.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    auto established = completed.get();
    EXPECT_TRUE(established.has_value());

    context.stop();
    runner.join();
}

TEST(TlsClientTest, RejectsUnknownFirefoxVariant) {
    // Only the bare profile names are accepted; versioned utls IDs are not.
    clash_native::transport::TlsClientOptions options;
    options.verify_peer = false;
    options.server_name = "example.com";
    options.fingerprint = "firefox-120";
    const auto failure = handshake_error(std::move(options));
    EXPECT_EQ(failure.code, clash_native::core::ErrorCode::configuration);
}

TEST(TlsClientTest, FirefoxFingerprintMatchesFirefoxClientHello) {
    using boost::asio::ip::tcp;
    boost::asio::io_context context;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{
        context.get_executor()};
    std::thread runner([&] { context.run(); });

    tcp::acceptor acceptor(context, tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
    tcp::socket server(context);
    std::promise<void> accepted;
    auto accepted_future = accepted.get_future();
    acceptor.async_accept(server, [&](const boost::system::error_code &error) {
        EXPECT_FALSE(error);
        accepted.set_value();
    });

    tcp::socket peer(context);
    peer.connect(
        tcp::endpoint(boost::asio::ip::address_v4::loopback(), acceptor.local_endpoint().port()));
    ASSERT_EQ(accepted_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    auto stream = std::make_unique<clash_native::net::TcpStream>(std::move(peer));

    clash_native::transport::TlsClientOptions options;
    options.verify_peer = false;
    options.server_name = "example.com";
    options.alpn_protocols = {"h2", "http/1.1"};
    options.fingerprint = "firefox";
    options.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    auto sender =
        clash_native::transport::async_tls_client_handshake(std::move(stream), std::move(options));
    HandshakeReceiver receiver;
    auto completed = receiver.done.get_future();
    auto op = stdexec::connect(std::move(sender), std::move(receiver));
    stdexec::start(op);

    const auto record = read_tls_record(context, server);
    server.close();
    ASSERT_TRUE(completed.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    EXPECT_NE(completed.get().code, clash_native::core::ErrorCode::configuration);

    ClientHello hello;
    ASSERT_TRUE(parse_client_hello(record, hello));
    EXPECT_EQ(hello.session_id.size(), 32u);
    EXPECT_EQ(hello.server_name, "example.com");
    EXPECT_EQ(hello.alpn, (std::vector<std::string>{"h2", "http/1.1"}));

    // Firefox emits no GREASE cipher and its own fixed order.
    const std::vector<uint16_t> expected_ciphers = {0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9,
                                                    0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013,
                                                    0xc014, 0x009c, 0x009d, 0x002f, 0x0035};
    EXPECT_EQ(hello.ciphers, expected_ciphers);
    for (const auto cipher : hello.ciphers) {
        EXPECT_FALSE(is_grease(cipher));
    }

    // Firefox extension order is fixed (unlike Chrome's shuffle); padding,
    // when the record would otherwise land under 512 bytes, comes last.
    std::vector<uint16_t> extensions = hello.extension_types;
    if (!extensions.empty() && extensions.back() == 21) {
        EXPECT_TRUE(hello.has_padding);
        // BoringPaddingStyle pads the handshake body to 512 bytes, so the
        // record totals 5 + 512.
        EXPECT_EQ(record.size(), 517u);
        extensions.pop_back();
    } else {
        EXPECT_FALSE(hello.has_padding);
    }
    const std::vector<uint16_t> expected_extensions = {0,  23, 65281, 10, 11, 35, 16,   5,
                                                       34, 51, 43,    13, 45, 28, 65037};
    EXPECT_EQ(extensions, expected_extensions);
    for (const auto type : hello.extension_types) {
        EXPECT_FALSE(is_grease(type));
    }

    EXPECT_EQ(hello.groups, (std::vector<uint16_t>{0x001d, 0x0017, 0x0018, 0x0019, 256, 257}));
    EXPECT_EQ(hello.key_share_groups, (std::vector<uint16_t>{0x001d, 0x0017}));

    EXPECT_EQ(hello.signature_algorithms,
              (std::vector<uint16_t>{0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501,
                                     0x0601, 0x0203, 0x0201}));
    EXPECT_EQ(hello.versions, (std::vector<uint16_t>{0x0304, 0x0303}));

    EXPECT_EQ(hello.delegated_credential_sigalgs,
              (std::vector<uint16_t>{0x0403, 0x0503, 0x0603, 0x0203}));
    EXPECT_EQ(hello.record_size_limit, 0x4001);
    EXPECT_FALSE(hello.has_alps);
    EXPECT_FALSE(hello.has_compress_brotli);
    EXPECT_TRUE(hello.has_ech);

    context.stop();
    runner.join();
}

TEST(TlsClientTest, RejectsUnknownSafariVariant) {
    clash_native::transport::TlsClientOptions options;
    options.verify_peer = false;
    options.server_name = "example.com";
    options.fingerprint = "safari-16";
    const auto failure = handshake_error(std::move(options));
    EXPECT_EQ(failure.code, clash_native::core::ErrorCode::configuration);
}

TEST(TlsClientTest, SafariFingerprintMatchesSafariClientHello) {
    using boost::asio::ip::tcp;
    boost::asio::io_context context;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{
        context.get_executor()};
    std::thread runner([&] { context.run(); });

    tcp::acceptor acceptor(context, tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
    tcp::socket server(context);
    std::promise<void> accepted;
    auto accepted_future = accepted.get_future();
    acceptor.async_accept(server, [&](const boost::system::error_code &error) {
        EXPECT_FALSE(error);
        accepted.set_value();
    });

    tcp::socket peer(context);
    peer.connect(
        tcp::endpoint(boost::asio::ip::address_v4::loopback(), acceptor.local_endpoint().port()));
    ASSERT_EQ(accepted_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    auto stream = std::make_unique<clash_native::net::TcpStream>(std::move(peer));

    clash_native::transport::TlsClientOptions options;
    options.verify_peer = false;
    options.server_name = "example.com";
    options.alpn_protocols = {"h2", "http/1.1"};
    options.fingerprint = "safari";
    options.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    auto sender =
        clash_native::transport::async_tls_client_handshake(std::move(stream), std::move(options));
    HandshakeReceiver receiver;
    auto completed = receiver.done.get_future();
    auto op = stdexec::connect(std::move(sender), std::move(receiver));
    stdexec::start(op);

    const auto record = read_tls_record(context, server);
    server.close();
    ASSERT_TRUE(completed.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    EXPECT_NE(completed.get().code, clash_native::core::ErrorCode::configuration);

    ClientHello hello;
    ASSERT_TRUE(parse_client_hello(record, hello));
    EXPECT_EQ(hello.session_id.size(), 32u);
    EXPECT_EQ(hello.server_name, "example.com");
    EXPECT_EQ(hello.alpn, (std::vector<std::string>{"h2", "http/1.1"}));

    // Safari emits GREASE first and 3DES suites (raw IDs) last.
    const std::vector<uint16_t> expected_ciphers = {
        0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xc00a,
        0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x0035, 0x002f, 0xc008, 0xc012, 0x000a};
    ASSERT_EQ(hello.ciphers.size(), expected_ciphers.size() + 1);
    EXPECT_TRUE(is_grease(hello.ciphers[0]));
    EXPECT_EQ(std::vector<uint16_t>(hello.ciphers.begin() + 1, hello.ciphers.end()),
              expected_ciphers);

    // Safari extension order is fixed; padding, when the record would
    // otherwise land under 512 bytes, comes last.
    std::vector<uint16_t> extensions = hello.extension_types;
    if (!extensions.empty() && extensions.back() == 21) {
        EXPECT_TRUE(hello.has_padding);
        // BoringPaddingStyle pads the handshake body to 512 bytes, so the
        // record totals 5 + 512.
        EXPECT_EQ(record.size(), 517u);
        extensions.pop_back();
    } else {
        EXPECT_FALSE(hello.has_padding);
    }
    std::vector<uint16_t> normalized;
    std::size_t grease_count = 0;
    for (const auto type : extensions) {
        if (is_grease(type)) {
            grease_count += 1;
            continue;
        }
        normalized.push_back(type);
    }
    const std::vector<uint16_t> expected_extensions = {0,  23, 65281, 10, 11, 16, 5,
                                                       13, 18, 51,    45, 43, 27};
    EXPECT_EQ(grease_count, 2u);
    EXPECT_EQ(normalized, expected_extensions);

    ASSERT_EQ(hello.groups.size(), 5u);
    EXPECT_TRUE(is_grease(hello.groups[0]));
    EXPECT_EQ(std::vector<uint16_t>(hello.groups.begin() + 1, hello.groups.end()),
              (std::vector<uint16_t>{0x001d, 0x0017, 0x0018, 0x0019}));

    ASSERT_EQ(hello.key_share_groups.size(), 2u);
    EXPECT_TRUE(is_grease(hello.key_share_groups[0]));
    EXPECT_EQ(hello.key_share_groups[1], 0x001d);

    // Safari repeats PSS-SHA384 on the wire; BoringSSL rejects duplicate
    // prefs so the duplicate is dropped (documented on
    // kSafariSignatureAlgorithms).
    EXPECT_EQ(hello.signature_algorithms,
              (std::vector<uint16_t>{0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0501, 0x0806,
                                     0x0601, 0x0201}));

    ASSERT_EQ(hello.versions.size(), 5u);
    EXPECT_TRUE(is_grease(hello.versions[0]));
    EXPECT_EQ(std::vector<uint16_t>(hello.versions.begin() + 1, hello.versions.end()),
              (std::vector<uint16_t>{0x0304, 0x0303, 0x0302, 0x0301}));

    EXPECT_TRUE(hello.has_compress_zlib);
    EXPECT_FALSE(hello.has_compress_brotli);
    EXPECT_FALSE(hello.has_alps);
    EXPECT_FALSE(hello.has_ech);

    context.stop();
    runner.join();
}
namespace {

void append_u16(std::vector<uint8_t> &out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value & 0xff));
}

// Builds a minimal ECHConfigList (RFC 9849) for public_name backed by key.
// config_id 7, X25519 KEM, HKDF-SHA256/AES-128-GCM, no extensions.
bool build_ech_config_list(std::vector<uint8_t> &out, const EVP_HPKE_KEY *key,
                           std::string_view public_name) {
    uint8_t raw_public[EVP_HPKE_MAX_PUBLIC_KEY_LENGTH] = {0};
    size_t raw_length = 0;
    if (EVP_HPKE_KEY_public_key(key, raw_public, &raw_length, sizeof(raw_public)) != 1) {
        return false;
    }
    std::vector<uint8_t> config;
    append_u16(config, 0xfe0d);
    std::vector<uint8_t> contents;
    contents.push_back(7);
    append_u16(contents, 0x0020);
    append_u16(contents, static_cast<uint16_t>(raw_length));
    contents.insert(contents.end(), raw_public, raw_public + raw_length);
    append_u16(contents, 4);
    append_u16(contents, 0x0001);
    append_u16(contents, 0x0001);
    contents.push_back(64);
    contents.push_back(static_cast<uint8_t>(public_name.size()));
    contents.insert(contents.end(), public_name.begin(), public_name.end());
    append_u16(contents, 0);
    append_u16(config, static_cast<uint16_t>(contents.size()));
    config.insert(config.end(), contents.begin(), contents.end());
    append_u16(out, static_cast<uint16_t>(config.size()));
    out.insert(out.end(), config.begin(), config.end());
    return true;
}

struct OuterHelloCapture {
    std::vector<uint8_t> bytes;
};

void ech_outer_hello_callback(int write_p, int version, int content_type, const void *data,
                              size_t length, SSL *, void *arg) {
    (void)version;
    if (write_p || content_type != 22 || data == nullptr || length == 0 ||
        static_cast<const uint8_t *>(data)[0] != 1) {
        return;
    }
    auto *capture = static_cast<OuterHelloCapture *>(arg);
    if (capture->bytes.empty()) {
        const auto *bytes = static_cast<const uint8_t *>(data);
        capture->bytes.assign(bytes, bytes + length);
    }
}

} // namespace

TEST(TlsClientTest, EchHandshakeCompletesAndHidesInnerServerName) {
    using boost::asio::ip::tcp;
    // ECH server keys for public.test; the inner name stays secret.test.
    bssl::UniquePtr<EVP_HPKE_KEY> hpke_key(EVP_HPKE_KEY_new());
    ASSERT_TRUE(hpke_key);
    ASSERT_EQ(EVP_HPKE_KEY_generate(hpke_key.get(), EVP_hpke_x25519_hkdf_sha256()), 1);
    std::vector<uint8_t> ech_config_list;
    ASSERT_TRUE(build_ech_config_list(ech_config_list, hpke_key.get(), "public.test"));

    bssl::UniquePtr<SSL_ECH_KEYS> ech_keys(SSL_ECH_KEYS_new());
    ASSERT_TRUE(ech_keys);
    // SSL_ECH_KEYS_add takes the single ECHConfig (without list framing).
    // The server requires a retry config alongside the live one.
    ASSERT_GT(ech_config_list.size(), 2u);
    ASSERT_EQ(SSL_ECH_KEYS_add(ech_keys.get(), 0, ech_config_list.data() + 2,
                               ech_config_list.size() - 2, hpke_key.get()),
              1);
    ASSERT_EQ(SSL_ECH_KEYS_add(ech_keys.get(), 1, ech_config_list.data() + 2,
                               ech_config_list.size() - 2, hpke_key.get()),
              1);

    boost::asio::io_context context;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{
        context.get_executor()};
    std::thread runner([&] { context.run(); });

    tcp::acceptor acceptor(context, tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
    tcp::socket server(context);
    std::promise<void> accepted;
    auto accepted_future = accepted.get_future();
    acceptor.async_accept(server, [&](const boost::system::error_code &error) {
        EXPECT_FALSE(error);
        accepted.set_value();
    });

    tcp::socket peer(context);
    peer.connect(
        tcp::endpoint(boost::asio::ip::address_v4::loopback(), acceptor.local_endpoint().port()));
    ASSERT_EQ(accepted_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    auto stream = std::make_unique<clash_native::net::TcpStream>(std::move(peer));

    clash_native::transport::TlsClientOptions options;
    options.verify_peer = false;
    options.server_name = "secret.test";
    options.ech_config_list = ech_config_list;
    options.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    auto sender =
        clash_native::transport::async_tls_client_handshake(std::move(stream), std::move(options));
    SuccessReceiver receiver;
    auto completed = receiver.done.get_future();
    auto op = stdexec::connect(std::move(sender), std::move(receiver));
    stdexec::start(op);

    bssl::UniquePtr<SSL_CTX> server_context(SSL_CTX_new(TLS_server_method()));
    ASSERT_TRUE(server_context);
    ASSERT_EQ(SSL_CTX_set1_ech_keys(server_context.get(), ech_keys.get()), 1);
    bssl::UniquePtr<BIO> cert_bio(
        BIO_new_mem_buf(kCertificate.data(), static_cast<int>(kCertificate.size())));
    bssl::UniquePtr<X509> certificate(PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr));
    ASSERT_TRUE(certificate);
    ASSERT_EQ(SSL_CTX_use_certificate(server_context.get(), certificate.get()), 1);
    bssl::UniquePtr<BIO> key_bio(
        BIO_new_mem_buf(kPrivateKey.data(), static_cast<int>(kPrivateKey.size())));
    bssl::UniquePtr<EVP_PKEY> private_key(
        PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr));
    ASSERT_TRUE(private_key);
    ASSERT_EQ(SSL_CTX_use_PrivateKey(server_context.get(), private_key.get()), 1);
    OuterHelloCapture capture;
    SSL_CTX_set_msg_callback(server_context.get(), ech_outer_hello_callback);
    SSL_CTX_set_msg_callback_arg(server_context.get(), &capture);
    bssl::UniquePtr<SSL> server_ssl(SSL_new(server_context.get()));
    ASSERT_TRUE(server_ssl);
    BIO *socket_bio = BIO_new_socket(server.native_handle(), BIO_NOCLOSE);
    ASSERT_NE(socket_bio, nullptr);
    SSL_set_bio(server_ssl.get(), socket_bio, socket_bio);
    EXPECT_EQ(SSL_accept(server_ssl.get()), 1);
    server.close();

    ASSERT_TRUE(completed.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    auto established = completed.get();
    EXPECT_TRUE(established.has_value());

    // The outer ClientHello must carry the public name; the inner name never
    // appears on the wire. The capture holds the handshake message, so frame
    // it as a record for the parser.
    std::vector<std::uint8_t> outer_record{22, 3, 3, 0, 0};
    outer_record[3] = static_cast<std::uint8_t>(capture.bytes.size() >> 8);
    outer_record[4] = static_cast<std::uint8_t>(capture.bytes.size() & 0xff);
    outer_record.insert(outer_record.end(), capture.bytes.begin(), capture.bytes.end());
    ClientHello outer;
    ASSERT_TRUE(parse_client_hello(outer_record, outer));
    EXPECT_EQ(outer.server_name, "public.test");

    context.stop();
    runner.join();
}
