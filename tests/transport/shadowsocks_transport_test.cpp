#include <clash_native/core/base64.hpp>
#include <clash_native/core/outbound.hpp>
#include <clash_native/outbound/shadowsocks_outbound.hpp>
#include <clash_native/runtime/asio_runtime.hpp>
#include <clash_native/transport/proxy/crypto.hpp>
#include <clash_native/transport/proxy/jls.hpp>
#include <clash_native/transport/proxy/restls.hpp>
#include <clash_native/transport/shadowsocks/legacy_packet.hpp>
#include <clash_native/transport/shadowsocks/ss2022_packet.hpp>
#include <clash_native/transport/shadowsocks/udp_over_tcp.hpp>

#include <gtest/gtest.h>

#include <stdexec/execution.hpp>

#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <future>
#include <memory>
#include <numeric>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

namespace {

using clash_native::transport::proxy::LegacyStreamCipher;

class BufferedStream final : public clash_native::io::StreamHandle {
  public:
    BufferedStream(boost::asio::any_io_executor executor, std::vector<std::uint8_t> input)
        : executor_(std::move(executor)), input_(std::move(input)) {}

    clash_native::io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override {
        if (input_.empty()) {
            return clash_native::io::AnySender<std::optional<std::size_t>>{
                stdexec::just(std::optional<std::size_t>{})};
        }
        const auto size = std::min(buffer.size(), input_.size());
        std::memcpy(buffer.data(), input_.data(), size);
        input_.erase(input_.begin(), input_.begin() + static_cast<std::ptrdiff_t>(size));
        return clash_native::io::AnySender<std::optional<std::size_t>>{
            stdexec::just(std::optional<std::size_t>{size})};
    }

    clash_native::io::AnySender<std::size_t>
    async_write(boost::asio::const_buffer buffer) override {
        written_.insert(written_.end(), static_cast<const std::uint8_t *>(buffer.data()),
                        static_cast<const std::uint8_t *>(buffer.data()) + buffer.size());
        return clash_native::io::AnySender<std::size_t>{stdexec::just(buffer.size())};
    }

    boost::asio::any_io_executor executor() noexcept override { return executor_; }

    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept override {
        error.clear();
        return {};
    }

    void shutdown_send(boost::system::error_code &error) noexcept override { error.clear(); }
    void close() noexcept override { closed_ = true; }

  private:
    boost::asio::any_io_executor executor_;
    std::vector<std::uint8_t> input_;
    std::vector<std::uint8_t> written_;
    bool closed_ = false;
};

TEST(ShadowsocksTransportTest, RecognizesClassicCipherFamilies) {
    constexpr std::array methods{"aes-128-ctr",
                                 "aes-192-ctr",
                                 "aes-256-ctr",
                                 "aes-128-cfb",
                                 "aes-192-cfb",
                                 "aes-256-cfb",
                                 "rc4-md5",
                                 "chacha20-ietf",
                                 "aes-128-gcm",
                                 "aes-192-gcm",
                                 "aes-256-gcm",
                                 "chacha20-ietf-poly1305",
                                 "xchacha20-ietf-poly1305",
                                 "chacha20",
                                 "xchacha20",
                                 "chacha8-ietf-poly1305",
                                 "xchacha8-ietf-poly1305",
                                 "aes-128-ccm",
                                 "aes-192-ccm",
                                 "aes-256-ccm"};
    for (const auto method : methods) {
        EXPECT_TRUE(clash_native::transport::proxy::cipher_method(method)) << method;
    }
}

TEST(ShadowsocksTransportTest, RecognizesAndRoundTripsShadowsocks2022) {
    constexpr std::array methods{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
                                 "2022-blake3-chacha20-poly1305"};
    const std::vector<std::uint8_t> plaintext{'s', 's', '2', '0', '2', '2'};
    for (const auto method : methods) {
        const auto spec = clash_native::transport::proxy::cipher_method(method);
        ASSERT_TRUE(spec) << method;
        std::vector<std::uint8_t> psk(spec.value().key_size, 0x31);
        const auto password = clash_native::core::base64_encode(
            std::string(reinterpret_cast<const char *>(psk.data()), psk.size()));
        std::vector<std::uint8_t> salt(spec.value().salt_size, 0x52);
        const auto key = clash_native::transport::proxy::derive_shadowsocks_2022_session_key(
            method, password, salt);
        ASSERT_TRUE(key) << method;
        std::vector<std::uint8_t> nonce(spec.value().nonce_size, 0x17);
        const auto ciphertext =
            clash_native::transport::proxy::aead_encrypt(method, key.value(), nonce, plaintext);
        ASSERT_TRUE(ciphertext) << method;
        const auto recovered = clash_native::transport::proxy::aead_decrypt(
            method, key.value(), nonce, ciphertext.value());
        ASSERT_TRUE(recovered) << method;
        EXPECT_EQ(recovered.value(), plaintext) << method;
    }
}

TEST(ShadowsocksTransportTest, EncryptsAndDecryptsAeadPayloads) {
    constexpr std::array methods{"aes-128-gcm",
                                 "aes-192-gcm",
                                 "aes-256-gcm",
                                 "chacha20-ietf-poly1305",
                                 "xchacha20-ietf-poly1305",
                                 "chacha8-ietf-poly1305",
                                 "xchacha8-ietf-poly1305",
                                 "aes-128-ccm",
                                 "aes-192-ccm",
                                 "aes-256-ccm"};
    const std::vector<std::uint8_t> plaintext{'s', 'h', 'a', 'd', 'o', 'w',
                                              's', 'o', 'c', 'k', 's'};
    for (const auto method : methods) {
        const auto spec = clash_native::transport::proxy::cipher_method(method);
        ASSERT_TRUE(spec) << method;
        std::vector<std::uint8_t> salt(spec.value().salt_size, 0x23);
        std::vector<std::uint8_t> nonce(spec.value().nonce_size, 0x42);
        const auto key =
            clash_native::transport::proxy::derive_aead_subkey(method, "test-password", salt);
        ASSERT_TRUE(key) << method;
        const auto ciphertext =
            clash_native::transport::proxy::aead_encrypt(method, key.value(), nonce, plaintext);
        ASSERT_TRUE(ciphertext) << method;
        const auto recovered = clash_native::transport::proxy::aead_decrypt(
            method, key.value(), nonce, ciphertext.value());
        ASSERT_TRUE(recovered) << method;
        EXPECT_EQ(recovered.value(), plaintext) << method;
    }
}

TEST(ShadowsocksTransportTest, EncryptsShadowsocks2022DatagramRequests) {
    const std::vector<std::uint8_t> destination{1, 127, 0, 0, 1, 0x01, 0xbb};
    const std::vector<std::uint8_t> payload{'u', 'd', 'p'};
    constexpr std::array methods{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
                                 "2022-blake3-chacha20-poly1305"};
    for (const auto method : methods) {
        const auto spec = clash_native::transport::proxy::cipher_method(method);
        ASSERT_TRUE(spec) << method;
        std::vector<std::uint8_t> psk(spec.value().key_size, 0x41);
        const auto password = clash_native::core::base64_encode(
            std::string(reinterpret_cast<const char *>(psk.data()), psk.size()));
        clash_native::transport::shadowsocks::Shadowsocks2022DatagramCodec codec(method, password);
        const auto wire = codec.encrypt(destination, payload);
        ASSERT_TRUE(wire) << method;
        EXPECT_GT(wire.value().size(), destination.size() + payload.size()) << method;
        EXPECT_LE(wire.value().size(), 1500U) << method;
        EXPECT_GT(codec.max_datagram_size(1500, 1 + 255 + 2), payload.size()) << method;
    }
}

TEST(ShadowsocksTransportTest, ReservesDestinationSpaceForShadowsocks2022Datagrams) {
    constexpr std::size_t wire_limit = 1500;
    constexpr std::size_t maximum_proxy_address = 1 + 1 + 255 + 2;
    const std::vector<std::uint8_t> psk(32, 0x31);
    const auto password = clash_native::core::base64_encode(
        std::string(reinterpret_cast<const char *>(psk.data()), psk.size()));
    clash_native::transport::shadowsocks::Shadowsocks2022DatagramCodec codec(
        "2022-blake3-chacha20-poly1305", password);

    const auto advertised = codec.max_datagram_size(wire_limit, maximum_proxy_address);
    const auto wire_without_destination = codec.max_datagram_size(wire_limit, 0);
    ASSERT_GT(wire_without_destination, advertised);
    EXPECT_EQ(wire_without_destination - advertised, maximum_proxy_address);
}

TEST(ShadowsocksTransportTest, RoundTripsXchacha20Poly1305PacketPrimitive) {
    const std::vector<std::uint8_t> key(32, 0x2a);
    std::vector<std::uint8_t> nonce(24);
    for (std::size_t index = 0; index < nonce.size(); ++index) {
        nonce[index] = static_cast<std::uint8_t>(index * 13U + 5U);
    }
    const std::vector<std::uint8_t> plaintext{'x', 'c', 'h', 'a', 'c', 'h', 'a'};
    const auto ciphertext =
        clash_native::transport::proxy::xchacha20_poly1305_encrypt(key, nonce, plaintext);
    ASSERT_TRUE(ciphertext);
    const auto recovered =
        clash_native::transport::proxy::xchacha20_poly1305_decrypt(key, nonce, ciphertext.value());
    ASSERT_TRUE(recovered);
    EXPECT_EQ(recovered.value(), plaintext);
}

TEST(ShadowsocksTransportTest, MatchesMihomoXchacha8Construction) {
    const std::vector<std::uint8_t> key(32, 0x2a);
    std::vector<std::uint8_t> nonce(24);
    for (std::size_t index = 0; index < nonce.size(); ++index) {
        nonce[index] = static_cast<std::uint8_t>(index * 13U + 5U);
    }
    for (const auto size : {0U, 1U, 8U, 31U, 64U, 4096U, 16384U}) {
        std::vector<std::uint8_t> plaintext(size);
        for (std::size_t index = 0; index < plaintext.size(); ++index) {
            plaintext[index] = static_cast<std::uint8_t>(index * 17U + 3U);
        }
        const auto xchacha8 = clash_native::transport::proxy::aead_encrypt("xchacha8-ietf-poly1305",
                                                                           key, nonce, plaintext);
        ASSERT_TRUE(xchacha8) << "size=" << size;
        const auto xchacha20 =
            clash_native::transport::proxy::xchacha20_poly1305_encrypt(key, nonce, plaintext);
        ASSERT_TRUE(xchacha20) << "size=" << size;
        EXPECT_NE(xchacha8.value(), xchacha20.value()) << "size=" << size;
        const auto recovered = clash_native::transport::proxy::aead_decrypt(
            "xchacha8-ietf-poly1305", key, nonce, xchacha8.value());
        ASSERT_TRUE(recovered) << "size=" << size;
        EXPECT_EQ(recovered.value(), plaintext) << "size=" << size;
        clash_native::transport::proxy::increment_nonce(nonce);
    }

    const std::vector<std::uint8_t> vector_plaintext = [] {
        std::vector<std::uint8_t> result(31);
        for (std::size_t index = 0; index < result.size(); ++index) {
            result[index] = static_cast<std::uint8_t>(index * 17U + 3U);
        }
        return result;
    }();
    const auto vector_ciphertext = clash_native::transport::proxy::aead_encrypt(
        "xchacha8-ietf-poly1305", key,
        std::vector<std::uint8_t>{5,   18,  31,  44,  57,  70,  83,  96,  109, 122, 135, 148,
                                  161, 174, 187, 200, 213, 226, 239, 252, 9,   22,  35,  48},
        vector_plaintext);
    ASSERT_TRUE(vector_ciphertext);
    const std::vector<std::uint8_t> expected{
        0xc7, 0x99, 0x06, 0x5f, 0x78, 0x17, 0x60, 0x1d, 0xc5, 0x41, 0x4d, 0x1e,
        0x27, 0x63, 0xad, 0x4b, 0x6c, 0xd5, 0x2a, 0xde, 0x92, 0x7d, 0x10, 0xc6,
        0xb4, 0x40, 0xd5, 0xc7, 0x1e, 0x77, 0x2a, 0x76, 0x33, 0xff, 0xf3, 0x9c,
        0xbb, 0xa0, 0x8c, 0xd0, 0xb2, 0xcd, 0xad, 0x62, 0x75, 0xa7, 0xf1};
    EXPECT_EQ(vector_ciphertext.value(), expected);
}

TEST(ShadowsocksTransportTest, EncryptsAndDecryptsLegacyStreams) {
    constexpr std::array methods{"aes-128-ctr",   "aes-192-ctr", "aes-256-ctr", "aes-128-cfb",
                                 "aes-192-cfb",   "aes-256-cfb", "rc4-md5",     "chacha20",
                                 "chacha20-ietf", "xchacha20"};
    const std::vector<std::uint8_t> source(257, 0x7a);
    for (const auto method : methods) {
        const auto spec = clash_native::transport::proxy::cipher_method(method);
        ASSERT_TRUE(spec) << method;
        std::vector<std::uint8_t> iv(spec.value().iv_size, 0x19);
        const auto key =
            clash_native::transport::proxy::derive_legacy_key(method, "test-password", iv);
        ASSERT_TRUE(key) << method;
        auto encrypted = source;
        auto encryptor = LegacyStreamCipher::create(method, key.value(), iv, true);
        ASSERT_TRUE(encryptor) << method;
        ASSERT_TRUE(encryptor.value().update(encrypted)) << method;
        auto decryptor = LegacyStreamCipher::create(method, key.value(), iv, false);
        ASSERT_TRUE(decryptor) << method;
        ASSERT_TRUE(decryptor.value().update(encrypted)) << method;
        EXPECT_EQ(encrypted, source) << method;
    }
}

TEST(ShadowsocksTransportTest, EncryptsAndDecryptsLegacyDatagrams) {
    constexpr std::array methods{"aes-128-ctr",   "aes-192-ctr", "aes-256-ctr", "aes-128-cfb",
                                 "aes-192-cfb",   "aes-256-cfb", "rc4-md5",     "chacha20",
                                 "chacha20-ietf", "xchacha20"};
    const std::vector<std::uint8_t> source{'d', 'a', 't', 'a', 'g', 'r', 'a', 'm'};
    for (const auto method : methods) {
        const auto wire = clash_native::transport::shadowsocks::encrypt_legacy_datagram(
            method, "test-password", source);
        ASSERT_TRUE(wire) << method;
        const auto recovered = clash_native::transport::shadowsocks::decrypt_legacy_datagram(
            method, "test-password", wire.value());
        ASSERT_TRUE(recovered) << method;
        EXPECT_EQ(recovered.value(), source) << method;
    }
}

TEST(ShadowsocksTransportTest, PreservesDomainAddressInUdpOverTcpResponse) {
    boost::asio::io_context context;
    const std::string domain = "example.test";
    std::vector<std::uint8_t> frame{0x02, static_cast<std::uint8_t>(domain.size())};
    frame.insert(frame.end(), domain.begin(), domain.end());
    frame.insert(frame.end(), {0x01, 0xbb, 0x00, 0x02, 'o', 'k'});
    auto stream = std::make_unique<BufferedStream>(context.get_executor(), frame);
    auto datagram = clash_native::transport::shadowsocks::make_udp_over_tcp_datagram_handle(
        std::move(stream), {});
    ASSERT_TRUE(datagram);

    std::array<std::uint8_t, 8> payload{};
    // The state posts completions to the context; pump it while blocked.
    auto work = boost::asio::require(context.get_executor(),
                                     boost::asio::execution::outstanding_work.tracked);
    std::thread runner([&] { context.run(); });
    auto wait =
        stdexec::sync_wait(datagram.value()->async_receive_from(boost::asio::buffer(payload)));
    ASSERT_TRUE(wait.has_value());
    const auto packet = std::move(std::get<0>(*wait));
    EXPECT_EQ(packet.size, 2U);
    EXPECT_EQ(std::string(reinterpret_cast<const char *>(payload.data()), packet.size), "ok");
    ASSERT_TRUE(packet.address.is_domain());
    EXPECT_EQ(packet.address.domain(), domain);
    EXPECT_EQ(packet.address.port(), 443);
    context.stop();
    runner.join();
}

TEST(ShadowsocksTransportTest, ParsesResTlsRecordScript) {
    const auto script = clash_native::transport::proxy::parse_restls_script(
        "250?100<1,350~100<1,600~100,300~200,300~100");
    ASSERT_TRUE(script);
    ASSERT_EQ(script.value().size(), 5U);
    EXPECT_TRUE(script.value()[0].randomize_target);
    EXPECT_EQ(script.value()[0].target_length, 250U);
    EXPECT_EQ(script.value()[0].random_range, 100U);
    EXPECT_TRUE(script.value()[0].command.needs_peer_response());
    EXPECT_EQ(script.value()[0].command.response, 1U);
    EXPECT_FALSE(script.value()[2].command.needs_peer_response());
    EXPECT_FALSE(clash_native::transport::proxy::parse_restls_script("250<256"));
}

TEST(ShadowsocksTransportTest, RoundTripsResTlsApplicationRecord) {
    std::array<std::uint8_t, 32> secret{};
    std::iota(secret.begin(), secret.end(), 1);
    std::vector<std::uint8_t> server_random(32);
    std::iota(server_random.begin(), server_random.end(), 0xa0);
    const std::vector<std::uint8_t> data{'r', 'e', 's', 't', 'l', 's'};
    const clash_native::transport::proxy::RestlsCommand command{
        clash_native::transport::proxy::RestlsCommandKind::response, 1};

    clash_native::transport::proxy::RestlsApplicationCodec encoder(secret, server_random, false);
    const auto wire = encoder.encode(data, data.size(), 17, command);
    ASSERT_TRUE(wire);
    ASSERT_EQ(encoder.counter(), 1U);
    EXPECT_EQ(wire.value()[0], 23U);
    EXPECT_EQ(wire.value()[1], 3U);
    EXPECT_EQ(wire.value()[2], 3U);

    clash_native::transport::proxy::RestlsApplicationCodec decoder(secret, server_random, false);
    const auto decoded = decoder.decode(wire.value());
    ASSERT_TRUE(decoded);
    EXPECT_EQ(decoded.value().data, data);
    EXPECT_EQ(decoded.value().command.kind,
              clash_native::transport::proxy::RestlsCommandKind::response);
    EXPECT_EQ(decoded.value().command.response, 1U);
    EXPECT_EQ(decoder.counter(), 1U);

    auto tampered = wire.value();
    tampered.back() ^= 0x01;
    clash_native::transport::proxy::RestlsApplicationCodec rejector(secret, server_random, false);
    EXPECT_FALSE(rejector.decode(tampered));

    clash_native::transport::proxy::RestlsApplicationCodec gcm_encoder(secret, server_random, false,
                                                                       true);
    const auto gcm_wire = gcm_encoder.encode(data, data.size(), 17, command);
    ASSERT_TRUE(gcm_wire);
    ASSERT_EQ(gcm_wire.value().size(), wire.value().size() + 8U);
    clash_native::transport::proxy::RestlsApplicationCodec gcm_decoder(secret, server_random, false,
                                                                       true);
    const auto gcm_decoded = gcm_decoder.decode(gcm_wire.value());
    ASSERT_TRUE(gcm_decoded);
    EXPECT_EQ(gcm_decoded.value().data, data);
    EXPECT_EQ(gcm_decoded.value().command.response, 1U);
}

TEST(ShadowsocksTransportTest, DerivesResTlsSessionAuthenticationIds) {
    const auto secret = clash_native::transport::proxy::derive_restls_secret("password");
    ASSERT_TRUE(secret);
    std::vector<std::vector<std::uint8_t>> ecdhe{std::vector<std::uint8_t>(32, 0x11),
                                                 std::vector<std::uint8_t>(65, 0x22),
                                                 std::vector<std::uint8_t>(97, 0x33)};
    const auto tls12 =
        clash_native::transport::proxy::derive_restls_tls12_session_id(secret.value(), ecdhe);
    ASSERT_TRUE(tls12);
    EXPECT_EQ(tls12.value().size(), 32U);
    const std::vector<std::uint8_t> ticket(48, 0x44);
    const auto tls12_ticket = clash_native::transport::proxy::derive_restls_tls12_session_id(
        secret.value(), ecdhe, ticket);
    ASSERT_TRUE(tls12_ticket);
    EXPECT_NE(tls12.value(), tls12_ticket.value());

    const auto tls13 = clash_native::transport::proxy::derive_restls_tls13_session_id(
        secret.value(), {{0x001d, std::vector<std::uint8_t>(32, 0x55)}},
        {std::vector<std::uint8_t>{'p', 's', 'k'}});
    ASSERT_TRUE(tls13);
    EXPECT_EQ(tls13.value().size(), 16U);
}

TEST(ShadowsocksTransportTest, MatchesJlsFakeRandomVector) {
    const clash_native::transport::proxy::JlsUser user{"jls-user", "jls-password"};
    const std::array<std::uint8_t, 16> seed{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    const std::array<std::uint8_t, 23> auth_data{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                                 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
    const std::vector<std::uint8_t> expected{0xa5, 0x19, 0xf2, 0xd0, 0xa2, 0xb3, 0x6b, 0x3a,
                                             0x96, 0xfc, 0x5f, 0x43, 0x9c, 0x8e, 0xd9, 0x36,
                                             0x82, 0xa3, 0xc7, 0x16, 0xd1, 0xf1, 0xe9, 0xbe,
                                             0x6d, 0xa9, 0x4d, 0x98, 0x44, 0x43, 0x1d, 0xa6};

    const auto fake = clash_native::transport::proxy::build_jls_fake_random(
        user, std::span<const std::uint8_t, 16>(seed), auth_data);
    ASSERT_TRUE(fake);
    EXPECT_EQ(fake.value(), expected);
    EXPECT_TRUE(
        clash_native::transport::proxy::check_jls_fake_random(user, fake.value(), auth_data));

    auto tampered = fake.value();
    tampered.front() ^= 0x01;
    EXPECT_FALSE(clash_native::transport::proxy::check_jls_fake_random(user, tampered, auth_data));
    EXPECT_FALSE(clash_native::transport::proxy::check_jls_fake_random(
        {"wrong-user", user.password}, fake.value(), auth_data));
}

TEST(ShadowsocksTransportTest, ZeroesJlsHelloAuthenticationFields) {
    auto append_u16 = [](std::vector<std::uint8_t> &wire, std::uint16_t value) {
        wire.push_back(static_cast<std::uint8_t>(value >> 8));
        wire.push_back(static_cast<std::uint8_t>(value));
    };
    std::vector<std::uint8_t> body{0x03, 0x03};
    body.insert(body.end(), 32, 0xaa);
    body.push_back(0);
    append_u16(body, 2);
    body.insert(body.end(), {0x13, 0x01});
    body.insert(body.end(), {1, 0});

    std::vector<std::uint8_t> extensions;
    append_u16(extensions, 0x0000);
    append_u16(extensions, 0);
    std::vector<std::uint8_t> psk{0, 9, 0, 3, 'a', 'b', 'c', 0, 0, 0, 1, 0, 3, 2, 0x11, 0x22};
    append_u16(extensions, 0x0029);
    append_u16(extensions, static_cast<std::uint16_t>(psk.size()));
    extensions.insert(extensions.end(), psk.begin(), psk.end());
    append_u16(body, static_cast<std::uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<std::uint8_t> client_hello{1, 0, 0, 0};
    client_hello.insert(client_hello.end(), body.begin(), body.end());
    const auto body_length = client_hello.size() - 4;
    client_hello[1] = static_cast<std::uint8_t>(body_length >> 16);
    client_hello[2] = static_cast<std::uint8_t>(body_length >> 8);
    client_hello[3] = static_cast<std::uint8_t>(body_length);

    const auto client_auth =
        clash_native::transport::proxy::jls_client_hello_auth_data(client_hello);
    ASSERT_TRUE(client_auth);
    EXPECT_TRUE(std::all_of(client_auth.value().begin() + 6, client_auth.value().begin() + 6 + 32,
                            [](std::uint8_t value) { return value == 0; }));
    EXPECT_EQ(client_auth.value()[client_auth.value().size() - 2], 0);
    EXPECT_EQ(client_auth.value().back(), 0);
    EXPECT_EQ(client_auth.value()[client_auth.value().size() - 3], 2);

    std::vector<std::uint8_t> server_hello{2, 0, 0, 0, 0x03, 0x03};
    server_hello.insert(server_hello.end(), 32, 0xbb);
    server_hello.insert(server_hello.end(), {0x13, 0x01, 0, 0, 0});
    const auto server_length = server_hello.size() - 4;
    server_hello[1] = static_cast<std::uint8_t>(server_length >> 16);
    server_hello[2] = static_cast<std::uint8_t>(server_length >> 8);
    server_hello[3] = static_cast<std::uint8_t>(server_length);
    const auto server_auth =
        clash_native::transport::proxy::jls_server_hello_auth_data(server_hello);
    ASSERT_TRUE(server_auth);
    EXPECT_TRUE(std::all_of(server_auth.value().begin() + 6, server_auth.value().begin() + 6 + 32,
                            [](std::uint8_t value) { return value == 0; }));
}

} // namespace

TEST(ShadowsocksOutboundTest, DisabledUdpFailsDatagramOpen) {
    auto &runtime = clash_native::runtime::AsioRuntime::instance();
    clash_native::outbound::ShadowsocksOutboundConfig config;
    config.id = "test-ss-no-udp";
    config.server_host = "127.0.0.1";
    config.server_port = 8388;
    config.method = "aes-128-gcm";
    config.password = "password";
    config.udp_enabled = false;
    clash_native::outbound::ShadowsocksOutbound outbound(runtime, std::move(config), nullptr);

    EXPECT_EQ(outbound.capabilities().datagram, clash_native::core::DatagramSemantics::unsupported);
    auto wait = stdexec::sync_wait(outbound.open_datagram({}));
    ASSERT_TRUE(wait.has_value());
    const auto result = std::move(std::get<0>(*wait));
    EXPECT_EQ(result.status, clash_native::core::OpenStatus::failed);
    ASSERT_TRUE(result.error);
    EXPECT_EQ(result.error->code, clash_native::core::ErrorCode::configuration);
}
