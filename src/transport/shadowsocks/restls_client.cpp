#include <clash_native/transport/shadowsocks/restls_client.hpp>

#include <clash_native/transport/shadowsocks/restls.hpp>

#include <botan/auto_rng.h>
#include <botan/asn1_obj.h>
#include <botan/credentials_manager.h>
#include <botan/exceptn.h>
#include <botan/dl_group.h>
#include <botan/ecdh.h>
#include <botan/ec_group.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_client.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_policy.h>
#include <botan/tls_server_info.h>
#include <botan/tls_messages.h>
#include <botan/tls_session.h>
#include <botan/tls_session_manager.h>
#include <botan/tls_session_manager_noop.h>
#include <botan/x509cert.h>
#include <botan/x25519.h>

#include <openssl/curve25519.h>

#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <cstring>
#include <system_error>
#include <utility>
#include <vector>

namespace clash_native::transport::shadowsocks {

namespace {

constexpr std::size_t kTlsRecordHeaderLength = 5;
constexpr std::size_t kMaxTlsRecordPayload = 16384;
constexpr std::size_t kTlsRandomLength = 32;
constexpr std::size_t kTls13SessionIdLength = 32;
constexpr auto kHandshakeTimeout = std::chrono::seconds(10);

core::Error restls_error(core::ErrorCode code, std::string message) {
    return {code, std::move(message), {}};
}

core::Error restls_io_error(std::string context, const boost::system::error_code& error) {
    return {core::ErrorCode::transport_io, std::move(context),
            std::error_code(error.value(), std::system_category())};
}

core::Error restls_exception(std::string context, const std::exception& exception) {
    context.append(": ");
    context.append(exception.what());
    return restls_error(core::ErrorCode::carrier_handshake, std::move(context));
}

std::vector<std::uint8_t> to_bytes(std::span<const std::uint8_t> data) {
    return {data.begin(), data.end()};
}

struct RestlsTls13ClientHelloMaterials {
    std::vector<std::pair<std::uint16_t, std::vector<std::uint8_t>>> key_shares;
    std::vector<std::vector<std::uint8_t>> psk_labels;
};

std::optional<RestlsTls13ClientHelloMaterials>
parse_restls_tls13_client_hello(std::span<const std::uint8_t> body) {
    auto read_u8 = [&](std::size_t &offset, std::uint8_t &value) {
        if (offset >= body.size()) {
            return false;
        }
        value = body[offset++];
        return true;
    };
    auto read_u16 = [&](std::size_t &offset, std::uint16_t &value) {
        if (offset + 2 > body.size()) {
            return false;
        }
        value = (static_cast<std::uint16_t>(body[offset]) << 8) | body[offset + 1];
        offset += 2;
        return true;
    };

    if (body.size() < 2 + kTlsRandomLength + 1) {
        return std::nullopt;
    }
    std::size_t offset = 2 + kTlsRandomLength;
    std::uint8_t session_id_length = 0;
    if (!read_u8(offset, session_id_length) || offset + session_id_length > body.size()) {
        return std::nullopt;
    }
    offset += session_id_length;

    std::uint16_t cipher_suites_length = 0;
    if (!read_u16(offset, cipher_suites_length) ||
        offset + cipher_suites_length > body.size()) {
        return std::nullopt;
    }
    offset += cipher_suites_length;
    std::uint8_t compression_methods_length = 0;
    if (!read_u8(offset, compression_methods_length) ||
        offset + compression_methods_length > body.size()) {
        return std::nullopt;
    }
    offset += compression_methods_length;

    std::uint16_t extensions_length = 0;
    if (!read_u16(offset, extensions_length) || offset + extensions_length > body.size()) {
        return std::nullopt;
    }
    const auto extensions_end = offset + extensions_length;
    RestlsTls13ClientHelloMaterials result;
    while (offset < extensions_end) {
        std::uint16_t extension_type = 0;
        std::uint16_t extension_length = 0;
        if (!read_u16(offset, extension_type) || !read_u16(offset, extension_length) ||
            offset + extension_length > extensions_end) {
            return std::nullopt;
        }
        const auto extension_end = offset + extension_length;
        if (extension_type == 0x0033) { // key_share
            std::uint16_t shares_length = 0;
            if (!read_u16(offset, shares_length) || offset + shares_length > extension_end) {
                return std::nullopt;
            }
            const auto shares_end = offset + shares_length;
            while (offset < shares_end) {
                std::uint16_t group = 0;
                std::uint16_t share_length = 0;
                if (!read_u16(offset, group) || !read_u16(offset, share_length) ||
                    offset + share_length > shares_end) {
                    return std::nullopt;
                }
                result.key_shares.emplace_back(
                    group, std::vector<std::uint8_t>(body.begin() + offset,
                                                     body.begin() + offset + share_length));
                offset += share_length;
            }
            if (offset != shares_end) {
                return std::nullopt;
            }
        } else if (extension_type == 0x0029) { // pre_shared_key
            std::uint16_t identities_length = 0;
            if (!read_u16(offset, identities_length) || offset + identities_length > extension_end) {
                return std::nullopt;
            }
            const auto identities_end = offset + identities_length;
            while (offset < identities_end) {
                std::uint16_t identity_length = 0;
                if (!read_u16(offset, identity_length) || offset + identity_length + 4 > identities_end) {
                    return std::nullopt;
                }
                result.psk_labels.emplace_back(body.begin() + offset,
                                               body.begin() + offset + identity_length);
                offset += identity_length + 4; // identity plus obfuscated_ticket_age
            }
            if (offset != identities_end) {
                return std::nullopt;
            }
            std::uint16_t binders_length = 0;
            if (!read_u16(offset, binders_length) || offset + binders_length != extension_end) {
                return std::nullopt;
            }
            offset += binders_length;
        }
        offset = extension_end;
    }
    if (offset != extensions_end || result.key_shares.empty()) {
        return std::nullopt;
    }
    return result;
}

class RestlsPolicy final : public Botan::TLS::Text_Policy {
  public:
    explicit RestlsPolicy(bool tls13) : Botan::TLS::Text_Policy(""), tls13_(tls13) {}

    bool allow_tls12() const override { return !tls13_; }
    bool allow_tls13() const override { return tls13_; }

    std::vector<Botan::TLS::Group_Params> key_exchange_groups() const override {
        return {Botan::TLS::Group_Params::X25519, Botan::TLS::Group_Params::SECP256R1,
                Botan::TLS::Group_Params::SECP384R1};
    }

    std::vector<Botan::TLS::Group_Params> key_exchange_groups_to_offer() const override {
        return key_exchange_groups();
    }

    std::vector<std::string> allowed_key_exchange_methods() const override { return {"ECDH"}; }

    bool negotiate_encrypt_then_mac() const override { return false; }
    bool require_extended_master_secret() const override { return true; }

  private:
    bool tls13_ = false;
};

class RestlsCredentials final : public Botan::Credentials_Manager {
  public:
    std::vector<Botan::Certificate_Store*> trusted_certificate_authorities(
        const std::string&, const std::string&) override {
        return {};
    }

    std::vector<Botan::X509_Certificate> find_cert_chain(
        const std::vector<std::string>&, const std::vector<Botan::AlgorithmIdentifier>&,
        const std::vector<Botan::X509_DN>&, const std::string&, const std::string&) override {
        return {};
    }

    std::shared_ptr<Botan::Private_Key> private_key_for(
        const Botan::X509_Certificate&, const std::string&, const std::string&) override {
        return {};
    }
};

class RestlsX25519Key final : public Botan::PK_Key_Agreement_Key {
  public:
    explicit RestlsX25519Key(Botan::RandomNumberGenerator& rng) {
        const auto generated = rng.random_vec(32);
        std::copy(generated.begin(), generated.end(), private_key_.begin());
        X25519_public_from_private(public_key_.data(), private_key_.data());
    }

    explicit RestlsX25519Key(std::array<std::uint8_t, 32> private_key)
        : private_key_(private_key) {
        X25519_public_from_private(public_key_.data(), private_key_.data());
    }

    std::string algo_name() const override { return "X25519"; }
    std::size_t estimated_strength() const override { return 128; }
    bool supports_operation(Botan::PublicKeyOperation op) const override {
        return op == Botan::PublicKeyOperation::KeyAgreement;
    }
    std::unique_ptr<Botan::Private_Key> generate_another(
        Botan::RandomNumberGenerator& rng) const override {
        return std::make_unique<RestlsX25519Key>(rng);
    }
    bool check_key(Botan::RandomNumberGenerator&, bool) const override { return true; }
    std::size_t key_length() const override { return 255; }
    Botan::AlgorithmIdentifier algorithm_identifier() const override {
        return {"X25519", Botan::AlgorithmIdentifier::USE_EMPTY_PARAM};
    }
    std::vector<std::uint8_t> raw_public_key_bits() const override {
        return {public_key_.begin(), public_key_.end()};
    }
    std::vector<std::uint8_t> public_key_bits() const override {
        return raw_public_key_bits();
    }
    Botan::secure_vector<std::uint8_t> private_key_bits() const override {
        return {private_key_.begin(), private_key_.end()};
    }
    Botan::secure_vector<std::uint8_t> raw_private_key_bits() const override {
        return private_key_bits();
    }
    std::unique_ptr<Botan::Public_Key> public_key() const override {
        throw Botan::Not_Implemented("ResTLS X25519 public key export is not needed");
    }
    std::vector<std::uint8_t> public_value() const override { return raw_public_key_bits(); }

  private:
    std::array<std::uint8_t, 32> private_key_{};
    std::array<std::uint8_t, 32> public_key_{};
};

class RestlsSessionManager final : public Botan::TLS::Session_Manager {
  public:
    RestlsSessionManager(std::shared_ptr<Botan::RandomNumberGenerator> rng,
                         Botan::TLS::Session session, Botan::TLS::Session_Handle handle)
        : Botan::TLS::Session_Manager(std::move(rng)),
          session_(std::move(session)),
          handle_(std::move(handle)) {}

    void store(const Botan::TLS::Session&, const Botan::TLS::Session_Handle&) override {}

    std::vector<Botan::TLS::Session_with_Handle>
    find(const Botan::TLS::Server_Information&, Botan::TLS::Callbacks&,
         const Botan::TLS::Policy&) override {
        return {{session_, handle_}};
    }

    std::size_t remove(const Botan::TLS::Session_Handle&) override { return 0; }
    std::size_t remove_all() override { return 0; }

  protected:
    std::optional<Botan::TLS::Session>
    retrieve_one(const Botan::TLS::Session_Handle&) override { return session_; }

    std::vector<Botan::TLS::Session_with_Handle>
    find_some(const Botan::TLS::Server_Information&, std::size_t) override {
        return {{session_, handle_}};
    }

  private:
    Botan::TLS::Session session_;
    Botan::TLS::Session_Handle handle_;
};

class RestlsCallbacks final : public Botan::TLS::Callbacks {
  public:
    using EmitHandler = std::function<void(std::span<const std::uint8_t>)>;
    using RecordHandler = std::function<void(std::span<const std::uint8_t>)>;

    RestlsCallbacks(std::shared_ptr<Botan::RandomNumberGenerator> rng,
                    std::array<std::uint8_t, 32> secret, EmitHandler emit,
                    RecordHandler record, bool skip_cert_verify, bool tls13)
        : rng_(std::move(rng)),
          secret_(secret),
          emit_(std::move(emit)),
          record_(std::move(record)),
          skip_cert_verify_(skip_cert_verify),
          tls13_(tls13) {
        x25519_key_ = std::make_unique<RestlsX25519Key>(*rng_);
        p256_key_ = std::make_unique<Botan::ECDH_PrivateKey>(
            *rng_, Botan::EC_Group::from_name("secp256r1"));
        p384_key_ = std::make_unique<Botan::ECDH_PrivateKey>(
            *rng_, Botan::EC_Group::from_name("secp384r1"));

        const auto x25519_private = x25519_key_->raw_private_key_bits();
        std::copy(x25519_private.begin(), x25519_private.end(), x25519_private_.begin());
        public_keys_.push_back(x25519_key_->raw_public_key_bits());
        public_keys_.push_back(
            p256_key_->public_value(Botan::EC_Point_Format::Uncompressed));
        public_keys_.push_back(
            p384_key_->public_value(Botan::EC_Point_Format::Uncompressed));
    }

    std::vector<std::vector<std::uint8_t>> public_keys() const { return public_keys_; }

    void tls_emit_data(std::span<const std::uint8_t> data) override {
        if (emit_) {
            emit_(data);
        }
    }

    void tls_record_received(std::uint64_t, std::span<const std::uint8_t> data) override {
        if (record_) {
            record_(data);
        }
    }

    void tls_alert(Botan::TLS::Alert alert) override {
        last_alert_ = alert.type_string();
    }

    void tls_modify_client_hello_random(std::vector<std::uint8_t> &random,
                                        const Botan::TLS::Client_Hello &hello) override {
        if (!tls13_) {
            return;
        }
        if (random.size() != kTlsRandomLength) {
            throw Botan::TLS::TLS_Exception(
                Botan::TLS::Alert::IllegalParameter,
                "ResTLS TLS 1.3 ClientHello random has an invalid length");
        }
        auto &session_id = const_cast<Botan::TLS::Session_ID &>(hello.session_id()).get();
        if (session_id.size() != kTls13SessionIdLength) {
            throw Botan::TLS::TLS_Exception(
                Botan::TLS::Alert::IllegalParameter,
                "ResTLS TLS 1.3 requires a 32-byte session ID");
        }
        const auto materials = parse_restls_tls13_client_hello(hello.serialize());
        if (!materials) {
            throw Botan::TLS::TLS_Exception(
                Botan::TLS::Alert::DecodeError,
                "ResTLS TLS 1.3 ClientHello is missing key-share materials");
        }
        const auto session_id_prefix = derive_restls_tls13_session_id(
            secret_, materials->key_shares, materials->psk_labels);
        if (!session_id_prefix) {
            throw Botan::TLS::TLS_Exception(
                Botan::TLS::Alert::InternalError,
                "ResTLS TLS 1.3 ClientHello authentication derivation failed");
        }
        std::copy(session_id_prefix.value().begin(), session_id_prefix.value().end(),
                  session_id.begin());
    }

    void tls_verify_cert_chain(
        const std::vector<Botan::X509_Certificate>&,
        const std::vector<std::optional<Botan::OCSP::Response>>&,
        const std::vector<Botan::Certificate_Store*>&, Botan::Usage_Type,
        std::string_view, const Botan::TLS::Policy&) override {
        if (!skip_cert_verify_) {
            throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::BadCertificate,
                                             "ResTLS native trust store is not configured");
        }
    }

    std::unique_ptr<Botan::PK_Key_Agreement_Key> tls12_generate_ephemeral_ecdh_key(
        Botan::TLS::Group_Params group, Botan::RandomNumberGenerator& rng,
        Botan::EC_Point_Format format) override {
        switch (group.wire_code()) {
        case 29:
            if (x25519_key_) {
                return std::move(x25519_key_);
            }
            break;
        case 23:
            if (p256_key_) {
                p256_key_->set_point_encoding(format);
                return std::move(p256_key_);
            }
            break;
        case 24:
            if (p384_key_) {
                p384_key_->set_point_encoding(format);
                return std::move(p384_key_);
            }
            break;
        }
        throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::IllegalParameter,
                                         "ResTLS requested an unsupported ECDHE group");
    }

    std::unique_ptr<Botan::PK_Key_Agreement_Key> tls_generate_ephemeral_key(
        const std::variant<Botan::TLS::Group_Params, Botan::DL_Group>& group,
        Botan::RandomNumberGenerator& rng) override {
        if (std::holds_alternative<Botan::TLS::Group_Params>(group)) {
            const auto selected = std::get<Botan::TLS::Group_Params>(group);
            if (selected == Botan::TLS::Group_Params::X25519) {
                if (!x25519_key_) {
                    throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::IllegalParameter,
                                                     "ResTLS X25519 key already consumed");
                }
                x25519_active_ = true;
                return std::move(x25519_key_);
            }
            return tls12_generate_ephemeral_ecdh_key(
                selected, rng, Botan::EC_Point_Format::Uncompressed);
        }
        return Botan::TLS::Callbacks::tls_generate_ephemeral_key(group, rng);
    }

    Botan::secure_vector<std::uint8_t> tls_ephemeral_key_agreement(
        const std::variant<Botan::TLS::Group_Params, Botan::DL_Group>& group,
        const Botan::PK_Key_Agreement_Key& private_key,
        const std::vector<std::uint8_t>& public_value, Botan::RandomNumberGenerator& rng,
        const Botan::TLS::Policy& policy) override {
        if (std::holds_alternative<Botan::TLS::Group_Params>(group) &&
            std::get<Botan::TLS::Group_Params>(group) == Botan::TLS::Group_Params::X25519) {
            if (!x25519_active_ || public_value.size() != X25519_PUBLIC_VALUE_LEN) {
                throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::IllegalParameter,
                                                 "ResTLS X25519 key agreement input is invalid");
            }
            std::array<std::uint8_t, X25519_SHARED_KEY_LEN> shared{};
            if (X25519(shared.data(), x25519_private_.data(), public_value.data()) == 0) {
                throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::IllegalParameter,
                                                 "ResTLS X25519 key agreement failed");
            }
            Botan::secure_vector<std::uint8_t> result(shared.begin(), shared.end());
            return result;
        }
        auto result = Botan::TLS::Callbacks::tls_ephemeral_key_agreement(
            group, private_key, public_value, rng, policy);
        return result;
    }

    const std::string& last_alert() const noexcept { return last_alert_; }

  private:
    std::shared_ptr<Botan::RandomNumberGenerator> rng_;
    std::array<std::uint8_t, 32> secret_{};
    EmitHandler emit_;
    RecordHandler record_;
    bool skip_cert_verify_ = false;
    bool tls13_ = false;
    std::unique_ptr<RestlsX25519Key> x25519_key_;
    std::unique_ptr<Botan::ECDH_PrivateKey> p256_key_;
    std::unique_ptr<Botan::ECDH_PrivateKey> p384_key_;
    std::vector<std::vector<std::uint8_t>> public_keys_;
    std::array<std::uint8_t, 32> x25519_private_{};
    bool x25519_active_ = false;
    std::string last_alert_;
};

class RestlsStream final : public core::StreamHandle,
                           public std::enable_shared_from_this<RestlsStream> {
  public:
    RestlsStream(std::unique_ptr<core::StreamHandle> lower,
                 std::array<std::uint8_t, 32> secret, std::vector<std::uint8_t> server_random,
                 std::shared_ptr<Botan::RandomNumberGenerator> rng,
                 std::vector<RestlsScriptLine> script, std::vector<std::uint8_t> initial_wire,
                 bool tls12_gcm, std::vector<std::uint8_t> initial_auth_extra)
        : lower_(std::move(lower)),
          encoder_(secret, server_random, false, tls12_gcm, std::move(initial_auth_extra)),
          decoder_(secret, std::move(server_random), true, tls12_gcm),
          rng_(std::move(rng)),
          script_(std::move(script)),
          read_wire_(std::move(initial_wire)),
          read_temp_(16 * 1024) {}

    ~RestlsStream() override = default;

    void async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) override {
        if (read_handler_) {
            post_read(std::move(handler), boost::asio::error::already_started, 0);
            return;
        }
        if (buffer.size() == 0) {
            post_read(std::move(handler), {}, 0);
            return;
        }
        read_buffer_ = buffer;
        read_handler_ = std::move(handler);
        if (deliver_pending()) {
            return;
        }
        pump_read();
    }

    void async_write(boost::asio::const_buffer buffer, WriteHandler handler) override {
        if (write_handler_) {
            post_write(std::move(handler), boost::asio::error::already_started, 0);
            return;
        }
        if (buffer.size() == 0) {
            post_write(std::move(handler), {}, 0);
            return;
        }
        const auto* data = static_cast<const std::uint8_t*>(buffer.data());
        pending_write_.assign(data, data + buffer.size());
        pending_write_offset_ = 0;
        pending_write_size_ = buffer.size();
        write_handler_ = std::move(handler);
        pump_write();
    }

    boost::asio::any_io_executor executor() noexcept override { return lower_->executor(); }

    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code& error) const noexcept override {
        return lower_->local_endpoint(error);
    }

    void shutdown_send(boost::system::error_code& error) noexcept override {
        lower_->shutdown_send(error);
    }

    void close() noexcept override {
        lower_->close();
        finish_read(boost::asio::error::operation_aborted, 0);
        finish_write(boost::asio::error::operation_aborted, 0);
    }

  private:
    std::size_t script_target(const RestlsScriptLine &line) {
        std::size_t target = line.target_length;
        if (line.random_range != 0) {
            std::uint32_t random_value = 0;
            for (int index = 0; index != 4; ++index) {
                random_value = (random_value << 8) | rng_->next_byte();
            }
            target += random_value % line.random_range;
        }
        return target;
    }

    void post_read(ReadHandler handler, boost::system::error_code error, std::size_t size) {
        boost::asio::post(executor(), [handler = std::move(handler), error, size]() mutable {
            handler(error, size);
        });
    }

    void post_write(WriteHandler handler, boost::system::error_code error, std::size_t size) {
        boost::asio::post(executor(), [handler = std::move(handler), error, size]() mutable {
            handler(error, size);
        });
    }

    bool deliver_pending() {
        if (pending_plain_offset_ >= pending_plain_.size()) {
            pending_plain_.clear();
            pending_plain_offset_ = 0;
            return false;
        }
        const auto size = std::min(read_buffer_.size(), pending_plain_.size() - pending_plain_offset_);
        std::memcpy(read_buffer_.data(), pending_plain_.data() + pending_plain_offset_, size);
        pending_plain_offset_ += size;
        auto handler = std::move(read_handler_);
        boost::asio::post(executor(), [handler = std::move(handler), size]() mutable {
            handler({}, size);
        });
        return true;
    }

    void pump_read() {
        if (!read_handler_ || lower_read_pending_) {
            return;
        }
        if (process_wire()) {
            return;
        }
        lower_read_pending_ = true;
        auto self = shared_from_this();
        lower_->async_read_some(
            boost::asio::buffer(read_temp_),
            [self](const boost::system::error_code& error, std::size_t size) {
                self->lower_read_pending_ = false;
                if (error) {
                    self->finish_read(error, 0);
                    return;
                }
                if (size == 0) {
                    self->finish_read(boost::asio::error::eof, 0);
                    return;
                }
                self->read_wire_.insert(self->read_wire_.end(), self->read_temp_.begin(),
                                        self->read_temp_.begin() + static_cast<std::ptrdiff_t>(size));
                self->pump_read();
            });
    }

    bool process_wire() {
        while (read_wire_.size() >= kTlsRecordHeaderLength) {
            const auto payload_size = (static_cast<std::size_t>(read_wire_[3]) << 8) |
                                       read_wire_[4];
            if (payload_size > kMaxTlsRecordPayload ||
                read_wire_.size() < kTlsRecordHeaderLength + payload_size) {
                return false;
            }
            std::vector<std::uint8_t> record(
                read_wire_.begin(),
                read_wire_.begin() + static_cast<std::ptrdiff_t>(kTlsRecordHeaderLength + payload_size));
            read_wire_.erase(read_wire_.begin(),
                             read_wire_.begin() + static_cast<std::ptrdiff_t>(record.size()));
            const auto decoded = decoder_.decode(record);
            if (!decoded) {
                finish_read(boost::asio::error::fault, 0);
                return true;
            }
            const auto &command = decoded.value().command;
            if (!decoded.value().data.empty()) {
                pending_plain_.insert(pending_plain_.end(), decoded.value().data.begin(),
                                      decoded.value().data.end());
            }
            if (write_waiting_response_) {
                // Any authenticated peer record releases a client write that
                // was interrupted by a script response marker. The Go
                // implementation clears this gate before handling the
                // marker-specific random response action.
                write_waiting_response_ = false;
            }
            if (decoded.value().command.kind == RestlsCommandKind::response) {
                pending_control_responses_ += decoded.value().command.response;
                pump_control_write();
            }
            pump_write();
            if (deliver_pending()) {
                return true;
            }
        }
        return false;
    }

    void pump_write() {
        if (write_in_progress_) {
            return;
        }
        if (pending_control_responses_ != 0) {
            pump_control_write();
            return;
        }
        if (!write_handler_ || write_waiting_response_) {
            if (write_waiting_response_) {
                ensure_control_read();
            }
            return;
        }
        if (pending_write_offset_ == pending_write_.size()) {
            finish_write({}, pending_write_size_);
            return;
        }
        RestlsScriptLine line;
        const bool scripted = script_index_ < script_.size();
        if (scripted) {
            line = script_[script_index_];
        }
        std::size_t target = scripted ? script_target(line)
                                      : pending_write_.size() - pending_write_offset_;
        if (target == 0) {
            target = std::min<std::size_t>(16384, pending_write_.size() - pending_write_offset_);
        }
        target = std::min<std::size_t>(target, std::numeric_limits<std::uint16_t>::max());
        const auto remaining = pending_write_.size() - pending_write_offset_;
        const auto chunk = std::min(remaining, target);
        const auto padding = target - chunk;
        const auto wire = encoder_.encode(
            std::span<const std::uint8_t>(pending_write_).subspan(pending_write_offset_, chunk),
            chunk, padding, line.command);
        if (!wire) {
            finish_write(boost::asio::error::fault, 0);
            return;
        }
        write_wire_ = std::move(wire.value());
        write_in_progress_ = true;
        auto self = shared_from_this();
        lower_->async_write(boost::asio::buffer(write_wire_),
                            [self, chunk, needs_response = line.command.needs_peer_response()](
                                const boost::system::error_code& error, std::size_t) {
                                self->write_in_progress_ = false;
                                if (error) {
                                    self->finish_write(error, 0);
                                    return;
                                }
                                self->pending_write_offset_ += chunk;
                                ++self->script_index_;
                                if (needs_response && self->pending_write_offset_ <
                                                            self->pending_write_.size()) {
                                    self->write_waiting_response_ = true;
                                }
                                self->pump_write();
                            });
    }

    void pump_control_write() {
        if (pending_control_responses_ == 0 || write_in_progress_) {
            return;
        }
        RestlsScriptLine line;
        if (script_index_ < script_.size()) {
            line = script_[script_index_];
        }
        const auto target = std::min<std::size_t>(
            (script_index_ < script_.size() ? script_target(line) : 32),
            std::numeric_limits<std::uint16_t>::max());
        const auto wire = encoder_.encode({}, 0, target, line.command);
        if (!wire) {
            finish_read(boost::asio::error::fault, 0);
            finish_write(boost::asio::error::fault, 0);
            return;
        }
        write_wire_ = std::move(wire.value());
        write_in_progress_ = true;
        auto self = shared_from_this();
        lower_->async_write(
            boost::asio::buffer(write_wire_),
            [self](const boost::system::error_code &error, std::size_t) {
                self->write_in_progress_ = false;
                if (error) {
                    self->finish_read(error, 0);
                    self->finish_write(error, 0);
                    return;
                }
                --self->pending_control_responses_;
                ++self->script_index_;
                self->pump_control_write();
                self->pump_write();
            });
    }

    void ensure_control_read() {
        if (lower_read_pending_) {
            return;
        }
        lower_read_pending_ = true;
        auto self = shared_from_this();
        lower_->async_read_some(
            boost::asio::buffer(read_temp_),
            [self](const boost::system::error_code& error, std::size_t size) {
                self->lower_read_pending_ = false;
                if (error) {
                    self->finish_write(error, 0);
                    self->finish_read(error, 0);
                    return;
                }
                self->read_wire_.insert(self->read_wire_.end(), self->read_temp_.begin(),
                                        self->read_temp_.begin() + static_cast<std::ptrdiff_t>(size));
                (void)self->process_wire();
                if (self->write_waiting_response_) {
                    self->ensure_control_read();
                }
            });
    }

    void finish_read(boost::system::error_code error, std::size_t size) {
        auto handler = std::move(read_handler_);
        if (handler) {
            handler(error, size);
        }
    }

    void finish_write(boost::system::error_code error, std::size_t size) {
        auto handler = std::move(write_handler_);
        if (handler) {
            handler(error, size);
        }
        pending_write_.clear();
        pending_write_offset_ = 0;
        pending_write_size_ = 0;
    }

    std::unique_ptr<core::StreamHandle> lower_;
    RestlsApplicationCodec encoder_;
    RestlsApplicationCodec decoder_;
    std::shared_ptr<Botan::RandomNumberGenerator> rng_;
    std::vector<RestlsScriptLine> script_;
    std::size_t script_index_ = 0;
    std::vector<std::uint8_t> read_wire_;
    std::vector<std::uint8_t> read_temp_;
    std::vector<std::uint8_t> pending_plain_;
    std::size_t pending_plain_offset_ = 0;
    boost::asio::mutable_buffer read_buffer_;
    ReadHandler read_handler_;
    bool lower_read_pending_ = false;
    std::vector<std::uint8_t> pending_write_;
    std::size_t pending_write_offset_ = 0;
    std::size_t pending_write_size_ = 0;
    std::vector<std::uint8_t> write_wire_;
    WriteHandler write_handler_;
    bool write_in_progress_ = false;
    bool write_waiting_response_ = false;
    std::size_t pending_control_responses_ = 0;
};

class RestlsStreamHandle final : public core::StreamHandle {
  public:
    explicit RestlsStreamHandle(std::shared_ptr<RestlsStream> stream)
        : stream_(std::move(stream)) {}

    ~RestlsStreamHandle() override { close(); }

    void async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) override {
        stream_->async_read_some(buffer, std::move(handler));
    }

    void async_write(boost::asio::const_buffer buffer, WriteHandler handler) override {
        stream_->async_write(buffer, std::move(handler));
    }

    boost::asio::any_io_executor executor() noexcept override { return stream_->executor(); }

    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept override {
        return stream_->local_endpoint(error);
    }

    void shutdown_send(boost::system::error_code &error) noexcept override {
        stream_->shutdown_send(error);
    }

    void close() noexcept override {
        if (stream_) {
            stream_->close();
            stream_.reset();
        }
    }

  private:
    std::shared_ptr<RestlsStream> stream_;
};

class RestlsOpenOperation final : public std::enable_shared_from_this<RestlsOpenOperation> {
  public:
    RestlsOpenOperation(std::unique_ptr<core::StreamHandle> stream, RestlsClientOptions options,
                        RestlsOpenHandler handler)
        : stream_(std::move(stream)),
          options_(std::move(options)),
          handler_(std::move(handler)),
          timer_(stream_->executor()) {}

    void start() {
        if (options_.server_name.empty() || options_.password.empty()) {
            finish(core::fail(restls_error(core::ErrorCode::configuration,
                                           "ResTLS server name and password are required")));
            return;
        }
        if (options_.version_hint != "tls12" && options_.version_hint != "tls13") {
            finish(core::fail(restls_error(
                core::ErrorCode::unsupported,
                "native ResTLS supports only the tls12 and tls13 version hints")));
            return;
        }
        const bool tls13 = options_.version_hint == "tls13";
        tls13_ = tls13;
        auto script = parse_restls_script(options_.restls_script.empty()
                                              ? "250?100<1,350~100<1,600~100,300~200,300~100"
                                              : options_.restls_script);
        if (!script) {
            finish(core::fail(script.error()));
            return;
        }
        script_ = std::move(script.value());
        timer_.expires_after(kHandshakeTimeout);
        auto self = shared_from_this();
        timer_.async_wait([self](const boost::system::error_code& error) {
            if (!error && !self->completed_) {
                self->finish(core::fail(restls_error(core::ErrorCode::timeout,
                                                     "ResTLS TLS handshake timed out")));
            }
        });
        try {
            rng_ = std::make_shared<Botan::AutoSeeded_RNG>();
            const auto secret = derive_restls_secret(options_.password);
            if (!secret) {
                finish(core::fail(secret.error()));
                return;
            }
            secret_ = secret.value();
            callbacks_ = std::make_shared<RestlsCallbacks>(
                rng_, secret_, [self](std::span<const std::uint8_t> data) { self->emit_tls(data); },
                [self](std::span<const std::uint8_t> data) { self->record_received(data); },
                options_.skip_cert_verify, tls13);
            Botan::TLS::Server_Information info(options_.server_name);
            const auto protocol_version = tls13 ? Botan::TLS::Protocol_Version::TLS_V13
                                                : Botan::TLS::Protocol_Version::TLS_V12;
            if (tls13) {
                session_manager_ = std::make_shared<Botan::TLS::Session_Manager_Noop>();
            } else {
                const auto public_keys = callbacks_->public_keys();
                const auto session_id = derive_restls_tls12_session_id(secret_, public_keys);
                if (!session_id) {
                    finish(core::fail(session_id.error()));
                    return;
                }
                Botan::secure_vector<std::uint8_t> master_secret(48, 0);
                Botan::TLS::Session session(master_secret, protocol_version, 0xC02F,
                                            Botan::TLS::Connection_Side::Client, true, false, {},
                                            info, 0, std::chrono::system_clock::now());
                Botan::TLS::Session_Handle handle(Botan::TLS::Session_ID(
                    std::vector<std::uint8_t>(session_id.value().begin(), session_id.value().end())));
                session_manager_ = std::make_shared<RestlsSessionManager>(
                    rng_, std::move(session), std::move(handle));
            }
            policy_ = std::make_shared<RestlsPolicy>(tls13);
            credentials_ = std::make_shared<RestlsCredentials>();
            tls_client_ = std::make_unique<Botan::TLS::Client>(
                callbacks_, session_manager_, credentials_, policy_, rng_, info,
                protocol_version, std::vector<std::string>{});
            read_tls_records();
        } catch (const std::exception& exception) {
            finish(core::fail(restls_exception("failed to initialize native ResTLS", exception)));
        }
    }

  private:
    void emit_tls(std::span<const std::uint8_t> data) {
        const auto bytes = to_bytes(data);
        if (!tls_client_ || !tls_client_->is_handshake_complete()) {
            remember_finished_record(bytes);
        }
        tls_write_queue_.push_back(bytes);
        start_tls_write();
    }

    void record_received(std::span<const std::uint8_t>) {}

    void remember_finished_record(const std::vector<std::uint8_t>& bytes) {
        std::size_t offset = 0;
        while (offset + kTlsRecordHeaderLength <= bytes.size()) {
            const auto size = (static_cast<std::size_t>(bytes[offset + 3]) << 8) |
                              bytes[offset + 4];
            if (size > kMaxTlsRecordPayload || offset + kTlsRecordHeaderLength + size > bytes.size()) {
                break;
            }
            const auto type = bytes[offset];
            if (type == 22 || type == 23) {
                last_client_finished_.assign(
                    bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                    bytes.begin() + static_cast<std::ptrdiff_t>(offset + kTlsRecordHeaderLength + size));
            }
            offset += kTlsRecordHeaderLength + size;
        }
    }

    void start_tls_write() {
        if (tls_write_in_progress_ || tls_write_queue_.empty() || completed_) {
            return;
        }
        tls_write_in_progress_ = true;
        tls_write_current_ = std::move(tls_write_queue_.front());
        tls_write_queue_.erase(tls_write_queue_.begin());
        auto self = shared_from_this();
        stream_->async_write(boost::asio::buffer(tls_write_current_),
                             [self](const boost::system::error_code& error, std::size_t) {
                                 self->tls_write_in_progress_ = false;
                                 if (error) {
                                     self->finish(core::fail(restls_io_error(
                                         "failed to write ResTLS TLS handshake", error)));
                                     return;
                                 }
                                 self->start_tls_write();
                             });
    }

    void read_tls_records() {
        if (completed_ || read_in_progress_) {
            return;
        }
        read_in_progress_ = true;
        auto self = shared_from_this();
        stream_->async_read_some(
            boost::asio::buffer(read_temp_),
            [self](const boost::system::error_code& error, std::size_t size) {
                self->read_in_progress_ = false;
                if (error) {
                    self->finish(core::fail(restls_io_error(
                        "failed to read ResTLS TLS handshake", error)));
                    return;
                }
                if (size == 0) {
                    self->finish(core::fail(restls_error(
                        core::ErrorCode::transport_io, "ResTLS TLS handshake reached EOF")));
                    return;
                }
                self->tls_input_.insert(self->tls_input_.end(), self->read_temp_.begin(),
                                       self->read_temp_.begin() + static_cast<std::ptrdiff_t>(size));
                self->process_tls_records();
                if (!self->completed_ && !self->tls_client_->is_handshake_complete()) {
                    self->read_tls_records();
                }
            });
    }

    void process_tls_records() {
        while (!completed_ && tls_input_.size() >= kTlsRecordHeaderLength) {
            const auto payload_size = (static_cast<std::size_t>(tls_input_[3]) << 8) |
                                       tls_input_[4];
            if (payload_size > kMaxTlsRecordPayload) {
                finish(core::fail(restls_error(core::ErrorCode::protocol_framing,
                                               "invalid ResTLS TLS record length")));
                return;
            }
            if (tls_input_.size() < kTlsRecordHeaderLength + payload_size) {
                return;
            }
            std::vector<std::uint8_t> record(
                tls_input_.begin(),
                tls_input_.begin() + static_cast<std::ptrdiff_t>(kTlsRecordHeaderLength + payload_size));
            tls_input_.erase(tls_input_.begin(),
                             tls_input_.begin() + static_cast<std::ptrdiff_t>(record.size()));
            remember_server_random(record);
            if (server_ccs_seen_ && !server_auth_unmasked_ &&
                (record[0] == 22 || record[0] == 23)) {
                unmask_server_auth(record);
                server_auth_unmasked_ = true;
            }
            if (record[0] == 20) {
                server_ccs_seen_ = true;
            }
            try {
                tls_client_->received_data(record);
            } catch (const std::exception& exception) {
                finish(core::fail(restls_exception("ResTLS TLS handshake failed", exception)));
                return;
            } catch (...) {
                finish(core::fail(restls_error(core::ErrorCode::carrier_handshake,
                                               "ResTLS TLS handshake failed with unknown exception")));
                return;
            }
            if (tls_client_->is_handshake_complete()) {
                open_restls_stream();
                return;
            }
        }
    }

    void remember_server_random(const std::vector<std::uint8_t>& record) {
        if (!server_random_.empty() || record.size() < 5 + 4 + 2 + 32 || record[0] != 22 ||
            record[5] != 2) {
            return;
        }
        server_random_.assign(record.begin() + 5 + 4 + 2,
                              record.begin() + 5 + 4 + 2 + 32);
        const auto session_id_offset = 5 + 4 + 2 + 32;
        if (record.size() > session_id_offset) {
            const auto session_id_length = static_cast<std::size_t>(record[session_id_offset]);
            const auto cipher_offset = session_id_offset + 1 + session_id_length;
            if (cipher_offset + 2 <= record.size()) {
                const auto cipher_suite =
                    (static_cast<std::uint16_t>(record[cipher_offset]) << 8) |
                    record[cipher_offset + 1];
                server_tls12_gcm_ = is_tls12_gcm_cipher(cipher_suite);
            }
        }
    }

    static bool is_tls12_gcm_cipher(std::uint16_t cipher_suite) noexcept {
        return cipher_suite == 0xC02F || cipher_suite == 0xC02B || cipher_suite == 0xC030 ||
               cipher_suite == 0xC02C;
    }

    void unmask_server_auth(std::vector<std::uint8_t>& record) {
        if (server_random_.size() != 32 || record.size() <= kTlsRecordHeaderLength) {
            return;
        }
        const auto mask = restls_hmac(
            secret_, std::array<std::span<const std::uint8_t>, 1>{server_random_});
        if (!mask) {
            return;
        }
        std::size_t offset = kTlsRecordHeaderLength;
        if (server_tls12_gcm_ && record.size() >= kTlsRecordHeaderLength + 8) {
            std::uint64_t explicit_nonce = 0;
            for (std::size_t index = 0; index < 8; ++index) {
                explicit_nonce = (explicit_nonce << 8) | record[kTlsRecordHeaderLength + index];
            }
            if (explicit_nonce == 0) {
                offset += 8;
            }
        }
        const auto count = std::min<std::size_t>(16, record.size() - offset);
        for (std::size_t index = 0; index < count; ++index) {
            record[offset + index] ^= mask.value()[index];
        }
    }

    void open_restls_stream() {
        if (server_random_.size() != 32 || last_client_finished_.empty()) {
            finish(core::fail(restls_error(
                core::ErrorCode::protocol_framing,
                "ResTLS TLS handshake did not expose ServerHello and Finished records")));
            return;
        }
        (void)timer_.cancel();
        auto adapter = std::make_shared<RestlsStream>(
            std::move(stream_), secret_, std::move(server_random_), rng_, std::move(script_),
            std::move(tls_input_), server_tls12_gcm_,
            tls13_ ? std::move(last_client_finished_) : std::vector<std::uint8_t>{});
        finish(core::Result<std::unique_ptr<core::StreamHandle>>(
            std::make_unique<RestlsStreamHandle>(std::move(adapter))));
    }

    void finish(core::Result<std::unique_ptr<core::StreamHandle>> result) {
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

    void finish(std::unique_ptr<core::StreamHandle> stream) {
        finish(core::Result<std::unique_ptr<core::StreamHandle>>(std::move(stream)));
    }

    std::unique_ptr<core::StreamHandle> stream_;
    RestlsClientOptions options_;
    RestlsOpenHandler handler_;
    boost::asio::steady_timer timer_;
    std::shared_ptr<Botan::RandomNumberGenerator> rng_;
    std::shared_ptr<RestlsCallbacks> callbacks_;
    std::shared_ptr<Botan::TLS::Session_Manager> session_manager_;
    std::shared_ptr<RestlsPolicy> policy_;
    std::shared_ptr<RestlsCredentials> credentials_;
    std::unique_ptr<Botan::TLS::Client> tls_client_;
    std::array<std::uint8_t, 32> secret_{};
    std::vector<RestlsScriptLine> script_;
    std::vector<std::uint8_t> server_random_;
    bool server_tls12_gcm_ = false;
    bool server_ccs_seen_ = false;
    bool server_auth_unmasked_ = false;
    bool tls13_ = false;
    std::vector<std::uint8_t> last_client_finished_;
    std::vector<std::uint8_t> tls_input_;
    std::vector<std::uint8_t> read_temp_ = std::vector<std::uint8_t>(16 * 1024);
    std::vector<std::vector<std::uint8_t>> tls_write_queue_;
    std::vector<std::uint8_t> tls_write_current_;
    bool tls_write_in_progress_ = false;
    bool read_in_progress_ = false;
    bool completed_ = false;
};

} // namespace

void async_open_restls(std::unique_ptr<core::StreamHandle> stream, RestlsClientOptions options,
                       RestlsOpenHandler handler) {
    if (!stream || !handler) {
        if (stream) {
            stream->close();
        }
        if (handler) {
            handler(core::fail(restls_error(
                core::ErrorCode::configuration,
                "ResTLS requires a stream and completion handler")));
        }
        return;
    }
    std::make_shared<RestlsOpenOperation>(std::move(stream), std::move(options),
                                          std::move(handler))
        ->start();
}

} // namespace clash_native::transport::shadowsocks
