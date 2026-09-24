// Mutual-TLS client options: malformed and mismatched credentials fail
// fast with configuration errors; a well-formed pair loads (the peer
// here is plain TCP, so the handshake itself fails downstream).
#include <clash_native/core/error.hpp>
#include <clash_native/io/stream_handle.hpp>
#include <clash_native/net/tcp_stream.hpp>
#include <clash_native/transport/tls_client.hpp>

#include <gtest/gtest.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <future>
#include <memory>
#include <optional>
#include <stdexec/execution.hpp>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

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
