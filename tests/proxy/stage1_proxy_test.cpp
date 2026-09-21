#include <clash_native/core/base64.hpp>
#include <clash_native/observability/connection_registry.hpp>
#include <clash_native/proxy/proxy_server.hpp>

#include <gtest/gtest.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http.hpp>

#include <array>
#include <atomic>
#include <cstdint>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

constexpr std::string_view kLocalProxyCertificate = R"PEM(-----BEGIN CERTIFICATE-----
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

constexpr std::string_view kLocalProxyPrivateKey = R"PEM(-----BEGIN PRIVATE KEY-----
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

constexpr std::string_view kLocalProxyChainRootCertificate = R"PEM(-----BEGIN CERTIFICATE-----
MIIDNjCCAh6gAwIBAgIUGX9Zn5krNxV/jxzjkwJmNv61yXQwDQYJKoZIhvcNAQEL
BQAwITEfMB0GA1UEAwwWQ2xhc2ggTmF0aXZlIFRlc3QgUm9vdDAeFw0yNjA5MjEw
NjU1MThaFw0zNjA5MTgwNjU1MThaMCExHzAdBgNVBAMMFkNsYXNoIE5hdGl2ZSBU
ZXN0IFJvb3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtfuQgAwct
v55U/QB78OjW2MN2Z7IWvimE1nP7RaqZqKyv+3b/LnHOUe/bvmBr/8J0zbFqqUGJ
BejiqwtJj8K3IlujvCpxeVj1NnM/E4CRuVRgi2MutqZ7WQnczU6nPANFfMKDhqGe
Rkb50X/WY87vJIAh1faqmtYB6s5z0IpqXCw5sUW6a1yvQ+dLyXKkunAAc0k+8QRs
BiiaAmfmsATUCAMYhX5HrY9P2iM0ZGOx1/CCcsM+EHXUIr90icJLpjF3X6CfUQi5
YCvK6XeLIkOfIEYowHwtzHZtBhr0x0155L2gacu3HUwHF3Cbk844vHNW/Q6Wo2NS
lGHsTBQzkonbAgMBAAGjZjBkMB0GA1UdDgQWBBQz/M8s+sGmfmEQHGwirb7ptAJz
1TAfBgNVHSMEGDAWgBQz/M8s+sGmfmEQHGwirb7ptAJz1TASBgNVHRMBAf8ECDAG
AQH/AgEBMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAqhUrGWjJ
0Q9GwEuHYuaPPGn+outBFfz8/AwHAGemaoJCObsuLxOdblTsdCr5nXc/h4/6i5Yk
/DnoaUhwaNuEZMIkJGUJszqvEgfXHEn/fv0HUXOplOq+XvNVKe6n4BYQ9KvyHUtd
nPIGkuTJ6CtS4nPqt3FndDyIDZG6yhdTyE5H3foBUJy32spzDhGikPUekqInzCDH
eD9WnYhti3dsUQn8iqy1sYhw/H53nmWcxWaAqbChRdPd4zkzY8pGlppdj84Z9MUi
E8ksd1dC0UOG178KVw1kiV5UnDKAhwYUg0TIL+uuEZA6+XhBX7nUYTY5V0jV0K1i
Pc52WSx5/dy/Jg==
-----END CERTIFICATE-----
)PEM";

constexpr std::string_view kLocalProxyChainLeafCertificate = R"PEM(-----BEGIN CERTIFICATE-----
MIIDVjCCAj6gAwIBAgIUFecMJaFQgq7d3E9MzeA8smXtMekwDQYJKoZIhvcNAQEL
BQAwITEfMB0GA1UEAwwWQ2xhc2ggTmF0aXZlIFRlc3QgUm9vdDAeFw0yNjA5MjEw
NjU1MTlaFw0zNjA5MTgwNjU1MTlaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMM1av+K3WRoEl21gYu+6fQWf5HU
DMJkcmBEJd5uMiY+iSwZcJVRxVhkpilqcTLSHedQNgsAMvWTexrFUPWXxwfUv6Yu
UJX6DDZqOiNpP5922eXTLKKTawtZtZ5Rmn7CFOfI4i6FmT7ULfmH+hJW9b6wulT0
gFJmrp6vnwtvi0SBKGf3+P0Mn33qZMD9Lk6PqP+qsEPRhxXoHZ+UbNGGfk4wtHTi
Kf4QKy791JLRCFRGiyDw5Ps0Vvx3j0H0VKuG1Keu5zfM73EW8M8s+j9Ixwl8V8jn
rEZg5cTReF44I+cHaZyaYnwDYMg9HUFp2B0t+qgG+bZAOATSzhEA4lMdCm8CAwEA
AaOBkjCBjzAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwDAYDVR0TAQH/BAIw
ADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYE
FOl9CDsHrhRvdY04GxVRIIqoLO0JMB8GA1UdIwQYMBaAFDP8zyz6waZ+YRAcbCKt
vum0AnPVMA0GCSqGSIb3DQEBCwUAA4IBAQBhKhAvHJ3igw16aAaCLDPeCsDK2sRY
zNk2vTT3sVG50wCo9BWqM5tB8xZJwOzD2fYGUDEumFZ4JJqBBejrv+/l+RgkdltL
Dj0Yf7DulbslSlJMxBqQDFuAkyiOiS92ExoNQfT/EQUGtm+sm8qek/eKMdqymGck
K8RB7o4drdWL88KAFLfW5fQu/MR92bZXkMMBpdZG1RynSVgDdBicuj7o8vgHpljE
+OZZ75Gzph1103nl1PWKrDPuapC1SWF3dpug8/qXH3JIcsUGTpIYZsAs1tvYkVaQ
EpFtxMB7MUjXRpBbcZIaFJxEugOigar4SRH4Nd0chdJL3Haf4vYwcLTo
-----END CERTIFICATE-----
)PEM";

constexpr std::string_view kLocalProxyChainLeafPrivateKey = R"PEM(-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDDNWr/it1kaBJd
tYGLvun0Fn+R1AzCZHJgRCXebjImPoksGXCVUcVYZKYpanEy0h3nUDYLADL1k3sa
xVD1l8cH1L+mLlCV+gw2ajojaT+fdtnl0yyik2sLWbWeUZp+whTnyOIuhZk+1C35
h/oSVvW+sLpU9IBSZq6er58Lb4tEgShn9/j9DJ996mTA/S5Oj6j/qrBD0YcV6B2f
lGzRhn5OMLR04in+ECsu/dSS0QhURosg8OT7NFb8d49B9FSrhtSnruc3zO9xFvDP
LPo/SMcJfFfI56xGYOXE0XheOCPnB2mcmmJ8A2DIPR1BadgdLfqoBvm2QDgE0s4R
AOJTHQpvAgMBAAECggEAAbmAF3/fktqEhwVqfpSSNpDYUa6A6lq+0/DmML/ie4oD
5jrXTsppJu3Etgr1sxA+KWQBBjnbOWYzKTpjC7hqjrwncU1pctnBr91iZBuy7zK6
nBgwhcMtp+0D+MEZz1LhomaY8PZHM1HmkhTMdcsE4slm7Ac49wFnO4mrqwsyPMmv
YDhDY8hl/dVteximzgFkFnvdbUWkSRBU38HjUttLPijtp65Gpz/yPBHxxQ4YpKfp
DpL4x2uVp5HEWARPbDd4yWsJJIlcUh519AoVzDuEnmYdSNPCJ34f/8CGxion0FWB
jxvc10c4vQGEHgPAYIidzMbLIh/kqAj92hTELdnxqQKBgQDrFOn71FjqRE/E7VI9
IL0NiVJ+IbDChRKUJGKb2fMxgN1kLw8ePldV8GYp+8/CaLMRA2/ODJxe3sM7Gxx4
90eZPYBPjam3MhWDpnN5Isj6uEysvFfYv2yJKgvPqjfSGV1CWj1ifT55HCIWx/oH
+VJM9BgCvuAjmfRxIZLV77EmywKBgQDUlDWDG4gJIRnScQL42NhQWoKuUIXFlIpm
g0Ijwq/+yNQPAjUNuia2SZEa5OGShTJVNApwg29CU+bFb4Hjbf48WQRXTRC2fI9S
aNFztOX/pG1EDk+5VG1Kh/hFzMrUdfqroTy+8CacaFhts2pVinAXM3M0ddDsNtn9
17kY7/fSbQKBgAtETFaSfdR0g7I3gZqGaCku7LI44SThhdttxwAbOQmlWHcFvl6/
tCXdSLg4ZmO16uck2AXzGsd9O7Qof3vYtijFBtJJQtoR33AY2S30GdfSX3Jj8H3l
5sjIKBrC2LwMFSkp9Ak1YXoifAvFd9lL/MLNbB0tksaCCXImnsf8HexzAoGBAJPP
TfoQraEza+IAhIGFPbt5g74y7SD57NXk1JtK5tbwy0p4TW1zDzHWq1eY6CPaC6pk
2hFrwnPLJP4JT7ZUp99MQhF123YX3AwAKAsdMIN10CfvD44c3zVgn8fg4vOh6R9n
qHZXQ3GjuEDm7Lv324K2WpeSiCeG6EJxuhlV2eptAoGBAKGHX7UssIoXsrt5tq1+
mkVLr/4IAmiwybsmGU5PKxEnshpeMTFqPtu5kU/xwtIeXEdmDpirXTIhFFx2iQ+j
7FqL4n+Z98+m/ChXrCQ96TBpPv+X1rJdiOIkYMEC5VYxBH+4XHOeyFDs4E9sMVqW
OmmhkmVQ7H5XKzj4d5nLYN2Z
-----END PRIVATE KEY-----
)PEM";

class EchoSession : public std::enable_shared_from_this<EchoSession> {
  public:
    explicit EchoSession(boost::asio::ip::tcp::socket socket) : socket_(std::move(socket)) {}

    void start() { read(); }

  private:
    void read() {
        auto self = shared_from_this();
        socket_.async_read_some(
            boost::asio::buffer(buffer_),
            [self](const boost::system::error_code &error, std::size_t size) {
                if (error) {
                    return;
                }

                boost::asio::async_write(
                    self->socket_, boost::asio::buffer(self->buffer_, size),
                    [self](const boost::system::error_code &write_error, std::size_t) {
                        if (!write_error) {
                            self->read();
                        }
                    });
            });
    }

    boost::asio::ip::tcp::socket socket_;
    std::array<char, 1024> buffer_{};
};

struct EchoTarget {
    boost::asio::ip::tcp::acceptor acceptor;
    boost::asio::ip::tcp::endpoint endpoint;

    explicit EchoTarget(clash_native::runtime::AsioRuntime &runtime)
        : acceptor(runtime.context(), {boost::asio::ip::address_v4::loopback(), 0}),
          endpoint(acceptor.local_endpoint()) {
        auto socket = std::make_shared<boost::asio::ip::tcp::socket>(runtime.context());
        acceptor.async_accept(*socket, [socket](const boost::system::error_code &error) {
            if (!error) {
                std::make_shared<EchoSession>(std::move(*socket))->start();
            }
        });
    }
};

namespace http = boost::beast::http;

class HttpTargetSession : public std::enable_shared_from_this<HttpTargetSession> {
  public:
    HttpTargetSession(boost::asio::ip::tcp::socket socket, std::atomic_int &request_count)
        : socket_(std::move(socket)), request_count_(request_count) {}

    void start() {
        auto self = shared_from_this();
        http::async_read(
            socket_, buffer_, parser_, [self](const boost::system::error_code &error, std::size_t) {
                if (error) {
                    return;
                }

                const auto request_number = ++self->request_count_;
                self->response_.version(11);
                self->response_.result(http::status::ok);
                self->response_.keep_alive(true);
                self->response_.set(http::field::content_type, "text/plain");
                self->response_.body() = "http-target-response-" + std::to_string(request_number);
                self->response_.prepare_payload();

                http::async_write(self->socket_, self->response_,
                                  [self](const boost::system::error_code &, std::size_t) {
                                      boost::system::error_code ignored;
                                      self->socket_.shutdown(
                                          boost::asio::ip::tcp::socket::shutdown_both, ignored);
                                      self->socket_.close(ignored);
                                  });
            });
    }

  private:
    boost::asio::ip::tcp::socket socket_;
    boost::beast::flat_buffer buffer_;
    http::request_parser<http::string_body> parser_;
    http::response<http::string_body> response_;
    std::atomic_int &request_count_;
};

class HttpTarget {
  public:
    explicit HttpTarget(clash_native::runtime::AsioRuntime &runtime)
        : acceptor(runtime.context(), {boost::asio::ip::address_v4::loopback(), 0}),
          endpoint(acceptor.local_endpoint()) {
        accept();
    }

    void stop() {
        boost::system::error_code ignored;
        acceptor.close(ignored);
    }

    boost::asio::ip::tcp::acceptor acceptor;
    boost::asio::ip::tcp::endpoint endpoint;
    std::atomic_int request_count{0};

  private:
    void accept() {
        auto socket = std::make_shared<boost::asio::ip::tcp::socket>(acceptor.get_executor());
        acceptor.async_accept(*socket, [this, socket](const boost::system::error_code &error) {
            if (!error) {
                std::make_shared<HttpTargetSession>(std::move(*socket), request_count)->start();
                accept();
            }
        });
    }
};

class HttpUpgradeTargetSession final
    : public std::enable_shared_from_this<HttpUpgradeTargetSession> {
  public:
    HttpUpgradeTargetSession(boost::asio::ip::tcp::socket socket, std::atomic_bool &valid_request)
        : socket_(std::move(socket)), valid_request_(valid_request) {}

    void start() { read_request(); }

  private:
    void read_request() {
        auto self = shared_from_this();
        boost::asio::async_read_until(
            socket_, request_buffer_, "\r\n\r\n",
            [self](const boost::system::error_code &error, std::size_t header_size) {
                if (error) {
                    return;
                }

                const std::string request(boost::asio::buffers_begin(self->request_buffer_.data()),
                                          boost::asio::buffers_end(self->request_buffer_.data()));
                self->valid_request_ =
                    request.find("GET /upgrade HTTP/1.1\r\n") != std::string::npos &&
                    request.find("Upgrade: test-protocol\r\n") != std::string::npos &&
                    request.find("X-Upgrade-Test: forwarded\r\n") != std::string::npos;

                self->request_buffer_.consume(header_size);
                self->initial_data_.assign(boost::asio::buffers_begin(self->request_buffer_.data()),
                                           boost::asio::buffers_end(self->request_buffer_.data()));
                self->request_buffer_.consume(self->request_buffer_.size());
                self->write_response();
            });
    }

    void write_response() {
        response_ = "HTTP/1.1 101 Switching Protocols\r\n"
                    "Connection: Upgrade\r\n"
                    "Upgrade: test-protocol\r\n"
                    "X-Upgrade-Ack: yes\r\n\r\n";
        auto self = shared_from_this();
        boost::asio::async_write(socket_, boost::asio::buffer(response_),
                                 [self](const boost::system::error_code &error, std::size_t) {
                                     if (error) {
                                         return;
                                     }
                                     self->write_initial_data();
                                 });
    }

    void write_initial_data() {
        if (initial_data_.empty()) {
            read_data();
            return;
        }
        auto self = shared_from_this();
        boost::asio::async_write(socket_, boost::asio::buffer(initial_data_),
                                 [self](const boost::system::error_code &error, std::size_t) {
                                     if (!error) {
                                         self->initial_data_.clear();
                                         self->read_data();
                                     }
                                 });
    }

    void read_data() {
        auto self = shared_from_this();
        socket_.async_read_some(
            boost::asio::buffer(data_),
            [self](const boost::system::error_code &error, std::size_t size) {
                if (error) {
                    return;
                }
                boost::asio::async_write(
                    self->socket_, boost::asio::buffer(self->data_, size),
                    [self](const boost::system::error_code &write_error, std::size_t) {
                        if (!write_error) {
                            self->read_data();
                        }
                    });
            });
    }

    boost::asio::ip::tcp::socket socket_;
    boost::asio::streambuf request_buffer_;
    std::vector<std::uint8_t> initial_data_;
    std::string response_;
    std::array<std::uint8_t, 4096> data_{};
    std::atomic_bool &valid_request_;
};

class HttpUpgradeTarget {
  public:
    explicit HttpUpgradeTarget(clash_native::runtime::AsioRuntime &runtime)
        : acceptor(runtime.context(), {boost::asio::ip::address_v4::loopback(), 0}),
          endpoint(acceptor.local_endpoint()) {
        accept();
    }

    void stop() {
        boost::system::error_code ignored;
        acceptor.close(ignored);
    }

    boost::asio::ip::tcp::acceptor acceptor;
    boost::asio::ip::tcp::endpoint endpoint;
    std::atomic_bool valid_request{false};

  private:
    void accept() {
        auto socket = std::make_shared<boost::asio::ip::tcp::socket>(acceptor.get_executor());
        acceptor.async_accept(*socket, [this, socket](const boost::system::error_code &error) {
            if (!error) {
                std::make_shared<HttpUpgradeTargetSession>(std::move(*socket), valid_request)
                    ->start();
            }
        });
    }
};

} // namespace

TEST(Stage1ProxyTest, AcceptsHttpConnectAndRelaysBufferedData) {
    clash_native::runtime::AsioRuntime runtime;
    EchoTarget target(runtime);
    clash_native::proxy::ProxyServer proxy(runtime, {boost::asio::ip::address_v4::loopback(), 0});
    ASSERT_TRUE(proxy.start());
    runtime.start();

    boost::asio::ip::tcp::socket client(runtime.context());
    client.connect(proxy.endpoint());

    const auto authority = "127.0.0.1:" + std::to_string(target.endpoint.port());
    const std::string request =
        "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\nclash-native-http";
    boost::asio::write(client, boost::asio::buffer(request));

    boost::asio::streambuf response;
    boost::asio::read_until(client, response, "\r\n\r\n");
    const std::string response_bytes(boost::asio::buffers_begin(response.data()),
                                     boost::asio::buffers_end(response.data()));
    const auto header_end = response_bytes.find("\r\n\r\n");
    ASSERT_NE(header_end, std::string::npos);
    ASSERT_EQ(response_bytes.substr(0, response_bytes.find("\r\n")),
              "HTTP/1.1 200 Connection Established");

    const std::string payload = "clash-native-http";
    std::string echoed = response_bytes.substr(header_end + 4);
    ASSERT_LE(echoed.size(), payload.size());
    if (echoed.size() < payload.size()) {
        const auto offset = echoed.size();
        echoed.resize(payload.size());
        boost::asio::read(client,
                          boost::asio::buffer(echoed.data() + offset, payload.size() - offset));
    }
    EXPECT_EQ(echoed, payload);

    boost::system::error_code ignored;
    client.close(ignored);
    proxy.stop();
    target.acceptor.close(ignored);
    runtime.stop();
}

TEST(HttpProxyTest, AcceptsHttpsProxyConnectionsWithConfiguredServerCredentials) {
    clash_native::runtime::AsioRuntime runtime;
    EchoTarget target(runtime);
    clash_native::proxy::ProxyServer proxy(runtime, {boost::asio::ip::address_v4::loopback(), 0});
    proxy.set_inbound_mode(clash_native::proxy::ProxyInboundMode::http);
    proxy.set_tls_server_credentials(
        std::vector<std::uint8_t>(kLocalProxyCertificate.begin(), kLocalProxyCertificate.end()),
        std::vector<std::uint8_t>(kLocalProxyPrivateKey.begin(), kLocalProxyPrivateKey.end()));
    ASSERT_TRUE(proxy.tls_enabled());
    ASSERT_TRUE(proxy.start());
    runtime.start();

    auto tls_context =
        std::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::tls_client);
    tls_context->set_verify_mode(boost::asio::ssl::verify_none);
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> client(runtime.context(), *tls_context);
    client.lowest_layer().connect(proxy.endpoint());
    client.handshake(boost::asio::ssl::stream_base::client);

    const auto authority = "127.0.0.1:" + std::to_string(target.endpoint.port());
    const std::string request =
        "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\nhttps-proxy-test";
    boost::asio::write(client, boost::asio::buffer(request));

    boost::asio::streambuf response;
    boost::asio::read_until(client, response, "\r\n\r\n");
    const std::string response_bytes(boost::asio::buffers_begin(response.data()),
                                     boost::asio::buffers_end(response.data()));
    const auto header_end = response_bytes.find("\r\n\r\n");
    ASSERT_NE(header_end, std::string::npos);
    ASSERT_EQ(response_bytes.substr(0, response_bytes.find("\r\n")),
              "HTTP/1.1 200 Connection Established");

    const std::string payload = "https-proxy-test";
    std::string echoed = response_bytes.substr(header_end + 4);
    ASSERT_LE(echoed.size(), payload.size());
    if (echoed.size() < payload.size()) {
        const auto offset = echoed.size();
        echoed.resize(payload.size());
        boost::asio::read(client,
                          boost::asio::buffer(echoed.data() + offset, payload.size() - offset));
    }
    EXPECT_EQ(echoed, payload);

    boost::system::error_code ignored;
    client.lowest_layer().close(ignored);
    proxy.stop();
    target.acceptor.close(ignored);
    runtime.stop();
}

TEST(HttpProxyTest, SendsConfiguredCertificateChainToVerifiedHttpsClient) {
    clash_native::runtime::AsioRuntime runtime;
    EchoTarget target(runtime);
    clash_native::proxy::ProxyServer proxy(runtime, {boost::asio::ip::address_v4::loopback(), 0});
    proxy.set_inbound_mode(clash_native::proxy::ProxyInboundMode::http);

    std::vector<std::uint8_t> certificate_chain;
    certificate_chain.insert(certificate_chain.end(), kLocalProxyChainLeafCertificate.begin(),
                             kLocalProxyChainLeafCertificate.end());
    certificate_chain.insert(certificate_chain.end(), kLocalProxyChainRootCertificate.begin(),
                             kLocalProxyChainRootCertificate.end());
    const std::vector<std::uint8_t> private_key(kLocalProxyChainLeafPrivateKey.begin(),
                                                kLocalProxyChainLeafPrivateKey.end());
    proxy.set_tls_server_credentials(std::move(certificate_chain), private_key);
    ASSERT_TRUE(proxy.tls_enabled());
    ASSERT_TRUE(proxy.start());
    runtime.start();

    auto tls_context =
        std::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::tls_client);
    boost::system::error_code ca_error;
    const std::vector<std::uint8_t> root_certificate(kLocalProxyChainRootCertificate.begin(),
                                                     kLocalProxyChainRootCertificate.end());
    tls_context->add_certificate_authority(boost::asio::buffer(root_certificate), ca_error);
    ASSERT_FALSE(ca_error) << ca_error.message();
    tls_context->set_verify_mode(boost::asio::ssl::verify_peer);
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> client(runtime.context(), *tls_context);
    client.lowest_layer().connect(proxy.endpoint());
    client.handshake(boost::asio::ssl::stream_base::client);

    const auto authority = "127.0.0.1:" + std::to_string(target.endpoint.port());
    const std::string request = "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority +
                                "\r\n\r\ncertificate-chain-test";
    boost::asio::write(client, boost::asio::buffer(request));

    boost::asio::streambuf response;
    boost::asio::read_until(client, response, "\r\n\r\n");
    const std::string response_bytes(boost::asio::buffers_begin(response.data()),
                                     boost::asio::buffers_end(response.data()));
    const auto header_end = response_bytes.find("\r\n\r\n");
    ASSERT_NE(header_end, std::string::npos);
    ASSERT_EQ(response_bytes.substr(0, response_bytes.find("\r\n")),
              "HTTP/1.1 200 Connection Established");

    const std::string payload = "certificate-chain-test";
    std::string echoed = response_bytes.substr(header_end + 4);
    ASSERT_LE(echoed.size(), payload.size());
    if (echoed.size() < payload.size()) {
        const auto offset = echoed.size();
        echoed.resize(payload.size());
        boost::asio::read(client,
                          boost::asio::buffer(echoed.data() + offset, payload.size() - offset));
    }
    EXPECT_EQ(echoed, payload);

    boost::system::error_code ignored;
    client.lowest_layer().close(ignored);
    proxy.stop();
    target.acceptor.close(ignored);
    runtime.stop();
}

TEST(Stage1ProxyTest, RejectOutboundReturnsSocks5Rejection) {
    clash_native::runtime::AsioRuntime runtime;
    clash_native::proxy::ProxyServer proxy(runtime, {boost::asio::ip::address_v4::loopback(), 0});
    proxy.set_default_action(clash_native::router::RouteAction::reject());
    ASSERT_TRUE(proxy.start());
    runtime.start();

    boost::asio::ip::tcp::socket client(runtime.context());
    client.connect(proxy.endpoint());

    const std::array<std::uint8_t, 3> method_request{5, 1, 0};
    boost::asio::write(client, boost::asio::buffer(method_request));
    std::array<std::uint8_t, 2> method_response{};
    boost::asio::read(client, boost::asio::buffer(method_response));
    ASSERT_EQ(method_response, (std::array<std::uint8_t, 2>{5, 0}));

    const std::array<std::uint8_t, 10> request{5, 1, 0, 1, 127, 0, 0, 1, 0, 1};
    boost::asio::write(client, boost::asio::buffer(request));
    std::array<std::uint8_t, 10> response{};
    boost::asio::read(client, boost::asio::buffer(response));
    EXPECT_EQ(response[0], 5);
    EXPECT_EQ(response[1], 2);

    boost::system::error_code ignored;
    client.close(ignored);
    proxy.stop();
    runtime.stop();
}

TEST(Stage1ProxyTest, TracksAProxyConnectionUntilTheClientCloses) {
    clash_native::runtime::AsioRuntime runtime;
    EchoTarget target(runtime);
    auto registry = std::make_shared<clash_native::observability::ConnectionRegistry>();
    clash_native::proxy::ProxyServer proxy(runtime, {boost::asio::ip::address_v4::loopback(), 0});
    proxy.set_connection_registry(registry);
    ASSERT_TRUE(proxy.start());
    runtime.start();

    boost::asio::ip::tcp::socket client(runtime.context());
    client.connect(proxy.endpoint());
    const std::array<std::uint8_t, 3> method_request{5, 1, 0};
    boost::asio::write(client, boost::asio::buffer(method_request));
    std::array<std::uint8_t, 2> method_response{};
    boost::asio::read(client, boost::asio::buffer(method_response));
    ASSERT_EQ(method_response, (std::array<std::uint8_t, 2>{5, 0}));

    const auto port = target.endpoint.port();
    const std::array<std::uint8_t, 10> request{5,
                                               1,
                                               0,
                                               1,
                                               127,
                                               0,
                                               0,
                                               1,
                                               static_cast<std::uint8_t>(port >> 8),
                                               static_cast<std::uint8_t>(port & 0xff)};
    boost::asio::write(client, boost::asio::buffer(request));
    std::array<std::uint8_t, 10> response{};
    boost::asio::read(client, boost::asio::buffer(response));
    ASSERT_EQ(response[0], 5);
    ASSERT_EQ(response[1], 0);

    const auto records = registry->snapshot();
    ASSERT_EQ(records.size(), 1U);
    EXPECT_EQ(records.front().outbound_id, "direct");
    EXPECT_EQ(records.front().metadata.destination.port(), port);

    boost::system::error_code ignored;
    client.close(ignored);
    for (int attempt = 0; attempt < 200 && !registry->snapshot().empty(); ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_TRUE(registry->snapshot().empty());

    proxy.stop();
    target.acceptor.close(ignored);
    runtime.stop();
}

TEST(HttpProxyTest, HttpOnlyModeRequiresBasicAuthentication) {
    clash_native::runtime::AsioRuntime runtime;
    EchoTarget target(runtime);
    clash_native::proxy::ProxyServer proxy(runtime, {boost::asio::ip::address_v4::loopback(), 0});
    proxy.set_inbound_mode(clash_native::proxy::ProxyInboundMode::http);
    proxy.set_http_authentication("proxy-user", "proxy-password");
    ASSERT_TRUE(proxy.start());
    runtime.start();

    const auto authority = "127.0.0.1:" + std::to_string(target.endpoint.port());
    {
        boost::asio::ip::tcp::socket client(runtime.context());
        client.connect(proxy.endpoint());
        const auto request =
            "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n";
        boost::asio::write(client, boost::asio::buffer(request));

        boost::asio::streambuf response;
        boost::asio::read_until(client, response, "\r\n\r\n");
        const std::string response_bytes(boost::asio::buffers_begin(response.data()),
                                         boost::asio::buffers_end(response.data()));
        EXPECT_EQ(response_bytes.substr(0, response_bytes.find("\r\n")),
                  "HTTP/1.1 407 Proxy Authentication Required");
    }

    {
        boost::asio::ip::tcp::socket client(runtime.context());
        client.connect(proxy.endpoint());
        const auto credentials = clash_native::core::base64_encode("proxy-user:wrong");
        const auto request = "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority +
                             "\r\nProxy-Authorization: Basic " + credentials + "\r\n\r\n";
        boost::asio::write(client, boost::asio::buffer(request));

        boost::asio::streambuf response;
        boost::asio::read_until(client, response, "\r\n\r\n");
        const std::string response_bytes(boost::asio::buffers_begin(response.data()),
                                         boost::asio::buffers_end(response.data()));
        EXPECT_EQ(response_bytes.substr(0, response_bytes.find("\r\n")), "HTTP/1.1 403 Forbidden");
    }

    boost::asio::ip::tcp::socket client(runtime.context());
    client.connect(proxy.endpoint());
    const auto credentials = clash_native::core::base64_encode("proxy-user:proxy-password");
    const auto request = "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority +
                         "\r\nProxy-Authorization: Basic " + credentials + "\r\n\r\n";
    boost::asio::write(client, boost::asio::buffer(request));

    boost::asio::streambuf response;
    boost::asio::read_until(client, response, "\r\n\r\n");
    const std::string response_bytes(boost::asio::buffers_begin(response.data()),
                                     boost::asio::buffers_end(response.data()));
    ASSERT_EQ(response_bytes.substr(0, response_bytes.find("\r\n")),
              "HTTP/1.1 200 Connection Established");

    const std::string payload = "authenticated-http";
    boost::asio::write(client, boost::asio::buffer(payload));
    std::string echoed(payload.size(), '\0');
    boost::asio::read(client, boost::asio::buffer(echoed));
    EXPECT_EQ(echoed, payload);

    boost::system::error_code ignored;
    client.close(ignored);
    proxy.stop();
    target.acceptor.close(ignored);
    runtime.stop();
}

TEST(HttpProxyTest, KeepsHttp11ClientConnectionForMultipleRequests) {
    clash_native::runtime::AsioRuntime runtime;
    HttpTarget target(runtime);
    clash_native::proxy::ProxyServer proxy(runtime, {boost::asio::ip::address_v4::loopback(), 0});
    proxy.set_inbound_mode(clash_native::proxy::ProxyInboundMode::http);
    ASSERT_TRUE(proxy.start());
    runtime.start();

    boost::asio::ip::tcp::socket client(runtime.context());
    client.connect(proxy.endpoint());
    boost::beast::flat_buffer response_buffer;

    for (const auto path : {"/first", "/second"}) {
        const auto request = "GET http://127.0.0.1:" + std::to_string(target.endpoint.port()) +
                             path +
                             " HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                             "Proxy-Connection: keep-alive\r\n\r\n";
        boost::asio::write(client, boost::asio::buffer(request));

        http::response<http::string_body> response;
        boost::beast::error_code error;
        http::read(client, response_buffer, response, error);
        ASSERT_FALSE(error) << error.message();
        EXPECT_EQ(response.result(), http::status::ok);
        EXPECT_TRUE(response.keep_alive());
        EXPECT_EQ(response.body(), path == std::string_view("/first") ? "http-target-response-1"
                                                                      : "http-target-response-2");
    }

    EXPECT_EQ(target.request_count.load(), 2);
    boost::system::error_code ignored;
    client.close(ignored);
    proxy.stop();
    target.stop();
    runtime.stop();
}

TEST(HttpProxyTest, ForwardsHttp11UpgradeAndRelaysTheUpgradedStream) {
    clash_native::runtime::AsioRuntime runtime;
    HttpUpgradeTarget target(runtime);
    clash_native::proxy::ProxyServer proxy(runtime, {boost::asio::ip::address_v4::loopback(), 0});
    proxy.set_inbound_mode(clash_native::proxy::ProxyInboundMode::http);
    ASSERT_TRUE(proxy.start());
    runtime.start();

    boost::asio::ip::tcp::socket client(runtime.context());
    client.connect(proxy.endpoint());
    const auto authority = "127.0.0.1:" + std::to_string(target.endpoint.port());
    const std::string initial_data = "upgrade-initial-data";
    const std::string request = "GET http://" + authority +
                                "/upgrade HTTP/1.1\r\nHost: " + authority +
                                "\r\nConnection: Upgrade\r\nUpgrade: test-protocol\r\n"
                                "X-Upgrade-Test: forwarded\r\n\r\n" +
                                initial_data;
    boost::asio::write(client, boost::asio::buffer(request));

    boost::asio::streambuf response;
    boost::asio::read_until(client, response, "\r\n\r\n");
    std::string response_bytes(boost::asio::buffers_begin(response.data()),
                               boost::asio::buffers_end(response.data()));
    const auto header_end = response_bytes.find("\r\n\r\n");
    ASSERT_NE(header_end, std::string::npos);
    EXPECT_EQ(response_bytes.substr(0, response_bytes.find("\r\n")),
              "HTTP/1.1 101 Switching Protocols");
    EXPECT_NE(response_bytes.find("Upgrade: test-protocol\r\n"), std::string::npos);
    EXPECT_NE(response_bytes.find("X-Upgrade-Ack: yes\r\n"), std::string::npos);

    std::string echoed = response_bytes.substr(header_end + 4);
    while (echoed.size() < initial_data.size()) {
        std::array<char, 1024> buffer{};
        const auto size = client.read_some(boost::asio::buffer(buffer));
        echoed.append(buffer.data(), size);
    }
    EXPECT_EQ(echoed.substr(0, initial_data.size()), initial_data);

    const std::string later_data = "upgrade-later-data";
    boost::asio::write(client, boost::asio::buffer(later_data));
    std::string later_echo(later_data.size(), '\0');
    boost::asio::read(client, boost::asio::buffer(later_echo));
    EXPECT_EQ(later_echo, later_data);
    EXPECT_TRUE(target.valid_request.load());

    boost::system::error_code ignored;
    client.close(ignored);
    proxy.stop();
    target.stop();
    runtime.stop();
}
