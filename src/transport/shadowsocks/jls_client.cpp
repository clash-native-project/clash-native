#include <clash_native/transport/shadowsocks/jls_client.hpp>

#include <clash_native/transport/shadowsocks/jls.hpp>

#include <botan/auto_rng.h>
#include <botan/credentials_manager.h>
#include <botan/tls_callbacks.h>
#include <botan/tls_client.h>
#include <botan/tls_exceptn.h>
#include <botan/tls_messages.h>
#include <botan/tls_policy.h>
#include <botan/tls_server_info.h>
#include <botan/tls_session_manager_noop.h>

#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace clash_native::transport::shadowsocks {

namespace {

constexpr std::size_t kHelloRandomOffset = 6;
constexpr std::size_t kHelloRandomLength = 32;
constexpr std::size_t kHelloRandomSeedLength = 16;
constexpr std::size_t kTlsRecordBufferSize = 16 * 1024;
constexpr auto kHandshakeTimeout = std::chrono::seconds(10);

constexpr std::array<std::uint8_t, 8> kTls12DowngradeCanary{0x44, 0x4f, 0x57, 0x4e,
                                                            0x47, 0x52, 0x44, 0x01};
constexpr std::array<std::uint8_t, 8> kTls11DowngradeCanary{0x44, 0x4f, 0x57, 0x4e,
                                                            0x47, 0x52, 0x44, 0x00};
constexpr std::array<std::uint8_t, 8> kHelloRetryRequestSuffix{0x07, 0x9e, 0x09, 0xe2,
                                                               0xc8, 0xa8, 0x33, 0x9c};

std::vector<std::uint8_t> handshake_wire(std::uint8_t type, std::span<const std::uint8_t> body) {
    if (body.size() > 0xFFFFFFU) {
        return {};
    }
    std::vector<std::uint8_t> wire;
    wire.reserve(4 + body.size());
    wire.push_back(type);
    wire.push_back(static_cast<std::uint8_t>((body.size() >> 16) & 0xFFU));
    wire.push_back(static_cast<std::uint8_t>((body.size() >> 8) & 0xFFU));
    wire.push_back(static_cast<std::uint8_t>(body.size() & 0xFFU));
    wire.insert(wire.end(), body.begin(), body.end());
    return wire;
}

core::Error jls_error(core::ErrorCode code, std::string message) {
    return {code, std::move(message), {}};
}

core::Error jls_io_error(std::string context, const boost::system::error_code &error) {
    return {core::ErrorCode::transport_io, std::move(context),
            std::error_code(error.value(), std::system_category())};
}

core::Error jls_exception(std::string context, const std::exception &exception) {
    context.append(": ");
    context.append(exception.what());
    return jls_error(core::ErrorCode::carrier_handshake, std::move(context));
}

bool has_forbidden_random_suffix(std::span<const std::uint8_t> random) {
    if (random.size() < kTls12DowngradeCanary.size()) {
        return false;
    }
    const auto suffix = random.last(kTls12DowngradeCanary.size());
    return std::equal(suffix.begin(), suffix.end(), kTls12DowngradeCanary.begin()) ||
           std::equal(suffix.begin(), suffix.end(), kTls11DowngradeCanary.begin()) ||
           std::equal(suffix.begin(), suffix.end(), kHelloRetryRequestSuffix.begin());
}

class JlsPolicy final : public Botan::TLS::Text_Policy {
  public:
    JlsPolicy() : Botan::TLS::Text_Policy("") {}

    bool allow_tls12() const override { return false; }
    bool allow_tls13() const override { return true; }

    std::vector<Botan::TLS::Group_Params> key_exchange_groups() const override {
        return {Botan::TLS::Group_Params::X25519};
    }

    std::vector<Botan::TLS::Group_Params> key_exchange_groups_to_offer() const override {
        return key_exchange_groups();
    }

    std::vector<std::string> allowed_key_exchange_methods() const override { return {"ECDH"}; }

    bool negotiate_encrypt_then_mac() const override { return false; }
    bool require_extended_master_secret() const override { return false; }
};

class JlsCredentials final : public Botan::Credentials_Manager {
  public:
    std::vector<Botan::Certificate_Store *>
    trusted_certificate_authorities(const std::string &, const std::string &) override {
        return {};
    }

    std::vector<Botan::X509_Certificate> find_cert_chain(
        const std::vector<std::string> &, const std::vector<Botan::AlgorithmIdentifier> &,
        const std::vector<Botan::X509_DN> &, const std::string &, const std::string &) override {
        return {};
    }

    std::shared_ptr<Botan::Private_Key> private_key_for(const Botan::X509_Certificate &,
                                                        const std::string &,
                                                        const std::string &) override {
        return {};
    }
};

class JlsCallbacks final : public Botan::TLS::Callbacks {
  public:
    using EmitHandler = std::function<void(std::span<const std::uint8_t>)>;
    using RecordHandler = std::function<void(std::span<const std::uint8_t>)>;

    JlsCallbacks(std::shared_ptr<Botan::RandomNumberGenerator> rng, JlsUser user, EmitHandler emit,
                 RecordHandler record, bool skip_cert_verify)
        : rng_(std::move(rng)), user_(std::move(user)), emit_(std::move(emit)),
          record_(std::move(record)), skip_cert_verify_(skip_cert_verify) {}

    void set_handlers(EmitHandler emit, RecordHandler record) {
        emit_ = std::move(emit);
        record_ = std::move(record);
    }

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

    void tls_alert(Botan::TLS::Alert alert) override { last_alert_ = alert.type_string(); }

    void tls_modify_client_hello_random(std::vector<std::uint8_t> &random,
                                        const Botan::TLS::Client_Hello &hello) override {
        if (random.size() != kHelloRandomLength) {
            throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::IllegalParameter,
                                            "JLS ClientHello random has an invalid length");
        }
        const auto hello_body = hello.serialize();
        const auto hello_wire = handshake_wire(1, hello_body);
        const auto auth_data = jls_client_hello_auth_data(hello_wire);
        if (!auth_data) {
            throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::DecodeError,
                                            auth_data.error().context);
        }
        std::array<std::uint8_t, kHelloRandomSeedLength> seed{};
        std::copy_n(random.begin(), seed.size(), seed.begin());
        for (std::size_t attempt = 0; attempt != 32; ++attempt) {
            const auto fake = build_jls_fake_random(user_, seed, auth_data.value());
            if (!fake) {
                throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::InternalError,
                                                fake.error().context);
            }
            if (!has_forbidden_random_suffix(fake.value())) {
                random = fake.value();
                return;
            }
            const auto next_seed = rng_->random_vec(seed.size());
            std::copy(next_seed.begin(), next_seed.end(), seed.begin());
        }
        throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::InternalError,
                                        "JLS could not generate an acceptable ClientHello random");
    }

    void tls_inspect_handshake_msg(const Botan::TLS::Handshake_Message &message) override {
        if (message.type() != Botan::TLS::Handshake_Type::ServerHello) {
            return;
        }
        const auto *server_hello = dynamic_cast<const Botan::TLS::Server_Hello *>(&message);
        if (server_hello == nullptr) {
            throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::DecodeError,
                                            "JLS received an invalid ServerHello");
        }
        const auto wire = handshake_wire(2, server_hello->serialize());
        if (wire.size() < kHelloRandomOffset + kHelloRandomLength) {
            throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::DecodeError,
                                            "JLS ServerHello is too short");
        }
        const auto auth_data = jls_server_hello_auth_data(wire);
        if (!auth_data) {
            throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::DecodeError,
                                            auth_data.error().context);
        }
        const auto fake_random =
            std::span<const std::uint8_t>(wire).subspan(kHelloRandomOffset, kHelloRandomLength);
        if (!check_jls_fake_random(user_, fake_random, auth_data.value())) {
            throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::HandshakeFailure,
                                            "JLS ServerHello authentication failed");
        }
        jls_authenticated_ = true;
    }

    void tls_verify_cert_chain(const std::vector<Botan::X509_Certificate> &,
                               const std::vector<std::optional<Botan::OCSP::Response>> &,
                               const std::vector<Botan::Certificate_Store *> &, Botan::Usage_Type,
                               std::string_view, const Botan::TLS::Policy &) override {
        // JLS authenticates the peer through the password-derived ServerHello
        // random. Its server certificate is deliberately a camouflage cert.
        if (!jls_authenticated_ && !skip_cert_verify_) {
            throw Botan::TLS::TLS_Exception(Botan::TLS::Alert::BadCertificate,
                                            "JLS peer was not authenticated");
        }
    }

    bool authenticated() const noexcept { return jls_authenticated_; }
    const std::string &last_alert() const noexcept { return last_alert_; }

  private:
    std::shared_ptr<Botan::RandomNumberGenerator> rng_;
    JlsUser user_;
    EmitHandler emit_;
    RecordHandler record_;
    bool skip_cert_verify_ = false;
    bool jls_authenticated_ = false;
    std::string last_alert_;
};

class JlsStream final : public core::StreamHandle, public std::enable_shared_from_this<JlsStream> {
  public:
    static std::shared_ptr<JlsStream> create(std::unique_ptr<core::StreamHandle> lower,
                                             std::unique_ptr<Botan::TLS::Client> tls_client,
                                             std::shared_ptr<JlsCallbacks> callbacks,
                                             std::vector<std::uint8_t> pending_plain) {
        auto stream = std::shared_ptr<JlsStream>(
            new JlsStream(std::move(lower), std::move(tls_client), std::move(callbacks),
                          std::move(pending_plain)));
        stream->bind_callbacks();
        return stream;
    }

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
        if (write_handler_ || shutdown_requested_) {
            post_write(std::move(handler), boost::asio::error::already_started, 0);
            return;
        }
        if (buffer.size() == 0) {
            post_write(std::move(handler), {}, 0);
            return;
        }
        const auto *data = static_cast<const std::uint8_t *>(buffer.data());
        write_handler_ = std::move(handler);
        write_plain_size_ = buffer.size();
        try {
            tls_client_->send(std::span<const std::uint8_t>(data, buffer.size()));
        } catch (const std::exception &exception) {
            finish_write(boost::asio::error::operation_not_supported, 0);
            last_error_ = jls_exception("JLS application write failed", exception);
            close();
            return;
        } catch (...) {
            finish_write(boost::asio::error::operation_not_supported, 0);
            close();
            return;
        }
        start_wire_write();
        maybe_finish_write();
    }

    boost::asio::any_io_executor executor() noexcept override { return lower_->executor(); }

    boost::asio::ip::tcp::endpoint
    local_endpoint(boost::system::error_code &error) const noexcept override {
        return lower_->local_endpoint(error);
    }

    void shutdown_send(boost::system::error_code &error) noexcept override {
        if (closed_) {
            error = boost::asio::error::operation_aborted;
            return;
        }
        shutdown_requested_ = true;
        error.clear();
        maybe_shutdown_send();
    }

    void close() noexcept override {
        if (closed_) {
            return;
        }
        closed_ = true;
        lower_->close();
        finish_read(boost::asio::error::operation_aborted, 0);
        finish_write(boost::asio::error::operation_aborted, 0);
    }

  private:
    JlsStream(std::unique_ptr<core::StreamHandle> lower,
              std::unique_ptr<Botan::TLS::Client> tls_client,
              std::shared_ptr<JlsCallbacks> callbacks, std::vector<std::uint8_t> pending_plain)
        : lower_(std::move(lower)), tls_client_(std::move(tls_client)),
          callbacks_(std::move(callbacks)), pending_plain_(std::move(pending_plain)),
          read_temp_(kTlsRecordBufferSize) {}

    void bind_callbacks() {
        const auto weak = weak_from_this();
        callbacks_->set_handlers(
            [weak](std::span<const std::uint8_t> data) {
                if (const auto self = weak.lock()) {
                    self->emit_tls(data);
                }
            },
            [weak](std::span<const std::uint8_t> data) {
                if (const auto self = weak.lock()) {
                    self->receive_plain(data);
                }
            });
    }

    void emit_tls(std::span<const std::uint8_t> data) {
        if (closed_) {
            return;
        }
        wire_queue_.emplace_back(data.begin(), data.end());
        start_wire_write();
        maybe_finish_write();
    }

    void receive_plain(std::span<const std::uint8_t> data) {
        if (closed_ || data.empty()) {
            return;
        }
        pending_plain_.insert(pending_plain_.end(), data.begin(), data.end());
        if (read_handler_) {
            (void)deliver_pending();
        }
    }

    bool deliver_pending() {
        if (!read_handler_ || pending_plain_.empty()) {
            return false;
        }
        const auto size = std::min(read_buffer_.size(), pending_plain_.size());
        std::memcpy(read_buffer_.data(), pending_plain_.data(), size);
        pending_plain_.erase(pending_plain_.begin(),
                             pending_plain_.begin() + static_cast<std::ptrdiff_t>(size));
        auto handler = std::move(read_handler_);
        post_read(std::move(handler), {}, size);
        return true;
    }

    void pump_read() {
        if (closed_ || !read_handler_ || lower_read_pending_) {
            return;
        }
        lower_read_pending_ = true;
        auto self = shared_from_this();
        lower_->async_read_some(
            boost::asio::buffer(read_temp_),
            [self](const boost::system::error_code &error, std::size_t size) {
                self->lower_read_pending_ = false;
                if (error) {
                    self->finish_read(error, 0);
                    return;
                }
                if (size == 0) {
                    self->finish_read(boost::asio::error::eof, 0);
                    return;
                }
                try {
                    self->tls_client_->received_data(
                        std::span<const std::uint8_t>(self->read_temp_.data(), size));
                } catch (const std::exception &exception) {
                    self->last_error_ =
                        jls_exception("JLS TLS record processing failed", exception);
                    self->finish_read(boost::asio::error::operation_not_supported, 0);
                    return;
                } catch (...) {
                    self->finish_read(boost::asio::error::operation_not_supported, 0);
                    return;
                }
                if (!self->deliver_pending()) {
                    self->pump_read();
                }
            });
    }

    void start_wire_write() {
        if (closed_ || wire_write_in_progress_ || wire_queue_.empty()) {
            return;
        }
        wire_write_in_progress_ = true;
        wire_current_ = std::move(wire_queue_.front());
        wire_queue_.erase(wire_queue_.begin());
        auto self = shared_from_this();
        lower_->async_write(boost::asio::buffer(wire_current_),
                            [self](const boost::system::error_code &error, std::size_t) {
                                self->wire_write_in_progress_ = false;
                                self->wire_current_.clear();
                                if (error) {
                                    self->finish_read(error, 0);
                                    self->finish_write(error, 0);
                                    return;
                                }
                                self->start_wire_write();
                                self->maybe_finish_write();
                            });
    }

    void maybe_finish_write() {
        if (write_handler_ && !wire_write_in_progress_ && wire_queue_.empty()) {
            finish_write({}, write_plain_size_);
        }
        maybe_shutdown_send();
    }

    void maybe_shutdown_send() {
        if (!shutdown_requested_ || wire_write_in_progress_ || !wire_queue_.empty() ||
            write_handler_) {
            return;
        }
        boost::system::error_code ignored;
        lower_->shutdown_send(ignored);
        shutdown_requested_ = false;
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
        write_plain_size_ = 0;
    }

    std::unique_ptr<core::StreamHandle> lower_;
    std::unique_ptr<Botan::TLS::Client> tls_client_;
    std::shared_ptr<JlsCallbacks> callbacks_;
    std::vector<std::uint8_t> pending_plain_;
    std::vector<std::uint8_t> read_temp_;
    std::vector<std::vector<std::uint8_t>> wire_queue_;
    std::vector<std::uint8_t> wire_current_;
    boost::asio::mutable_buffer read_buffer_;
    ReadHandler read_handler_;
    WriteHandler write_handler_;
    std::size_t write_plain_size_ = 0;
    bool lower_read_pending_ = false;
    bool wire_write_in_progress_ = false;
    bool shutdown_requested_ = false;
    bool closed_ = false;
    std::optional<core::Error> last_error_;
};

class JlsStreamHandle final : public core::StreamHandle {
  public:
    explicit JlsStreamHandle(std::shared_ptr<JlsStream> stream) : stream_(std::move(stream)) {}
    ~JlsStreamHandle() override { close(); }

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
    std::shared_ptr<JlsStream> stream_;
};

class JlsOpenOperation final : public std::enable_shared_from_this<JlsOpenOperation> {
  public:
    JlsOpenOperation(std::unique_ptr<core::StreamHandle> stream, JlsClientOptions options,
                     JlsOpenHandler handler)
        : stream_(std::move(stream)), options_(std::move(options)), handler_(std::move(handler)),
          timer_(stream_->executor()) {}

    void start() {
        if (!stream_ || options_.server_name.empty() || options_.username.empty() ||
            options_.password.empty()) {
            finish(core::fail(jls_error(core::ErrorCode::configuration,
                                        "JLS server name, username, and password are required")));
            return;
        }
        timer_.expires_after(kHandshakeTimeout);
        timer_.async_wait([self = shared_from_this()](const boost::system::error_code &error) {
            if (!error && !self->completed_) {
                self->finish(
                    core::fail(jls_error(core::ErrorCode::timeout, "JLS TLS handshake timed out")));
            }
        });
        try {
            rng_ = std::make_shared<Botan::AutoSeeded_RNG>();
            callbacks_ = std::make_shared<JlsCallbacks>(
                rng_, JlsUser{options_.username, options_.password},
                [self = shared_from_this()](std::span<const std::uint8_t> data) {
                    self->emit_tls(data);
                },
                [self = shared_from_this()](std::span<const std::uint8_t> data) {
                    self->record_received(data);
                },
                options_.skip_cert_verify);
            policy_ = std::make_shared<JlsPolicy>();
            credentials_ = std::make_shared<JlsCredentials>();
            session_manager_ = std::make_shared<Botan::TLS::Session_Manager_Noop>();
            Botan::TLS::Server_Information info(options_.server_name);
            auto alpn = options_.alpn;
            if (alpn.empty()) {
                alpn = {"h2", "http/1.1"};
            }
            tls_client_ = std::make_unique<Botan::TLS::Client>(
                callbacks_, session_manager_, credentials_, policy_, rng_, info,
                Botan::TLS::Protocol_Version::TLS_V13, alpn);
            read_tls_records();
            start_tls_write();
        } catch (const std::exception &exception) {
            finish(core::fail(jls_exception("failed to initialize JLS TLS client", exception)));
        } catch (...) {
            finish(core::fail(jls_error(core::ErrorCode::carrier_handshake,
                                        "failed to initialize JLS TLS client")));
        }
    }

  private:
    void emit_tls(std::span<const std::uint8_t> data) {
        if (completed_) {
            return;
        }
        tls_write_queue_.emplace_back(data.begin(), data.end());
        start_tls_write();
        maybe_open();
    }

    void record_received(std::span<const std::uint8_t> data) {
        pending_plain_.insert(pending_plain_.end(), data.begin(), data.end());
    }

    void start_tls_write() {
        if (completed_ || tls_write_in_progress_ || tls_write_queue_.empty()) {
            return;
        }
        tls_write_in_progress_ = true;
        tls_write_current_ = std::move(tls_write_queue_.front());
        tls_write_queue_.erase(tls_write_queue_.begin());
        auto self = shared_from_this();
        stream_->async_write(
            boost::asio::buffer(tls_write_current_),
            [self](const boost::system::error_code &error, std::size_t) {
                self->tls_write_in_progress_ = false;
                self->tls_write_current_.clear();
                if (error) {
                    self->finish(core::fail(jls_io_error("failed to write JLS TLS record", error)));
                    return;
                }
                self->start_tls_write();
                self->maybe_open();
            });
    }

    void read_tls_records() {
        if (completed_ || read_in_progress_ || handshake_complete_) {
            return;
        }
        read_in_progress_ = true;
        auto self = shared_from_this();
        stream_->async_read_some(
            boost::asio::buffer(read_temp_),
            [self](const boost::system::error_code &error, std::size_t size) {
                self->read_in_progress_ = false;
                if (error) {
                    self->finish(core::fail(jls_io_error("failed to read JLS TLS record", error)));
                    return;
                }
                if (size == 0) {
                    self->finish(core::fail(
                        jls_error(core::ErrorCode::transport_io, "JLS TLS handshake reached EOF")));
                    return;
                }
                try {
                    self->tls_client_->received_data(
                        std::span<const std::uint8_t>(self->read_temp_.data(), size));
                } catch (const std::exception &exception) {
                    self->finish(core::fail(jls_exception("JLS TLS handshake failed", exception)));
                    return;
                } catch (...) {
                    self->finish(core::fail(
                        jls_error(core::ErrorCode::carrier_handshake, "JLS TLS handshake failed")));
                    return;
                }
                if (self->tls_client_->is_handshake_complete()) {
                    self->handshake_complete_ = true;
                    self->maybe_open();
                    return;
                }
                self->read_tls_records();
            });
    }

    void maybe_open() {
        if (completed_ || !handshake_complete_ || tls_write_in_progress_ ||
            !tls_write_queue_.empty()) {
            return;
        }
        if (!callbacks_->authenticated()) {
            finish(core::fail(jls_error(core::ErrorCode::authentication,
                                        "JLS TLS handshake did not authenticate the peer")));
            return;
        }
        (void)timer_.cancel();
        completed_ = true;
        auto lower = std::move(stream_);
        auto tls_client = std::move(tls_client_);
        auto callbacks = std::move(callbacks_);
        auto stream = JlsStream::create(std::move(lower), std::move(tls_client),
                                        std::move(callbacks), std::move(pending_plain_));
        auto handler = std::move(handler_);
        if (handler) {
            handler(core::Result<std::unique_ptr<core::StreamHandle>>(
                std::make_unique<JlsStreamHandle>(std::move(stream))));
        }
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

    std::unique_ptr<core::StreamHandle> stream_;
    JlsClientOptions options_;
    JlsOpenHandler handler_;
    boost::asio::steady_timer timer_;
    std::shared_ptr<Botan::RandomNumberGenerator> rng_;
    std::shared_ptr<JlsCallbacks> callbacks_;
    std::shared_ptr<JlsPolicy> policy_;
    std::shared_ptr<JlsCredentials> credentials_;
    std::shared_ptr<Botan::TLS::Session_Manager> session_manager_;
    std::unique_ptr<Botan::TLS::Client> tls_client_;
    std::vector<std::uint8_t> pending_plain_;
    std::vector<std::uint8_t> read_temp_ = std::vector<std::uint8_t>(kTlsRecordBufferSize);
    std::vector<std::vector<std::uint8_t>> tls_write_queue_;
    std::vector<std::uint8_t> tls_write_current_;
    bool tls_write_in_progress_ = false;
    bool read_in_progress_ = false;
    bool handshake_complete_ = false;
    bool completed_ = false;
};

} // namespace

void async_open_jls(std::unique_ptr<core::StreamHandle> stream, JlsClientOptions options,
                    JlsOpenHandler handler) {
    if (!stream || !handler) {
        if (stream) {
            stream->close();
        }
        if (handler) {
            handler(core::fail(jls_error(core::ErrorCode::configuration,
                                         "JLS requires a stream and completion handler")));
        }
        return;
    }
    std::make_shared<JlsOpenOperation>(std::move(stream), std::move(options), std::move(handler))
        ->start();
}

} // namespace clash_native::transport::shadowsocks
