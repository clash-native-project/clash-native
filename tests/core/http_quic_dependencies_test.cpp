#include <boost/asio/buffer.hpp>
#include <boost/beast/http.hpp>
#include <nghttp2/nghttp2.h>
#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#include <openssl/ssl.h>

#include <gtest/gtest.h>

#include <memory>
#include <string>

namespace {

TEST(HttpQuicDependenciesTest, BeastParsesHttp11Response) {
    namespace http = boost::beast::http;

    const std::string wire = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc";
    http::response_parser<http::string_body> parser;
    parser.eager(true);
    boost::system::error_code error;

    const auto consumed = parser.put(boost::asio::buffer(wire), error);

    ASSERT_FALSE(error) << error.message();
    ASSERT_EQ(consumed, wire.size());
    ASSERT_TRUE(parser.is_done());

    const auto response = parser.release();
    EXPECT_EQ(response.version(), 11);
    EXPECT_EQ(response.result(), http::status::ok);
    EXPECT_EQ(response.body(), "abc");
}

TEST(HttpQuicDependenciesTest, Nghttp2CreatesClientSession) {
    nghttp2_session_callbacks *callbacks = nullptr;
    ASSERT_EQ(nghttp2_session_callbacks_new(&callbacks), 0);
    const auto callbacks_guard =
        std::unique_ptr<nghttp2_session_callbacks, decltype(&nghttp2_session_callbacks_del)>(
            callbacks, &nghttp2_session_callbacks_del);

    nghttp2_session *session = nullptr;
    ASSERT_EQ(nghttp2_session_client_new(&session, callbacks_guard.get(), nullptr), 0);
    const auto session_guard = std::unique_ptr<nghttp2_session, decltype(&nghttp2_session_del)>(
        session, &nghttp2_session_del);

    EXPECT_NE(session_guard.get(), nullptr);
}

TEST(HttpQuicDependenciesTest, Nghttp3CreatesClientConnection) {
    nghttp3_callbacks callbacks{};
    nghttp3_settings settings{};
    nghttp3_settings_default(&settings);

    nghttp3_conn *connection = nullptr;
    ASSERT_EQ(nghttp3_conn_client_new(&connection, &callbacks, &settings, nullptr, nullptr), 0);
    const auto connection_guard =
        std::unique_ptr<nghttp3_conn, decltype(&nghttp3_conn_del)>(connection, &nghttp3_conn_del);

    EXPECT_NE(connection_guard.get(), nullptr);
}

TEST(HttpQuicDependenciesTest, Ngtcp2UsesBoringSslClientContext) {
    SSL_CTX *context = SSL_CTX_new(TLS_method());
    ASSERT_NE(context, nullptr);
    const auto context_guard =
        std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(context, &SSL_CTX_free);

    EXPECT_EQ(ngtcp2_crypto_boringssl_configure_client_context(context_guard.get()), 0);
    EXPECT_NE(ngtcp2_version(0), nullptr);
}

} // namespace
