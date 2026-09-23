#pragma once

// Exchange-plane debt: bridges the callback transport::ExchangeSession
// vocabulary to the sender-native io::ExchangeSession vocabulary while the
// session implementations grow native io:: entries and the consumers migrate
// one by one. Delete this header with transport::ExchangeSession.

#include <clash_native/async/callback_sender.hpp>
#include <clash_native/async/oneshot.hpp>
#include <clash_native/async/start_with_receiver.hpp>
#include <clash_native/core/error.hpp>
#include <clash_native/core/result.hpp>
#include <clash_native/io/exchange_session.hpp>
#include <clash_native/io/sender.hpp>
#include <clash_native/net/datagram_handle_adapter.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>
#include <clash_native/transport/exchange_session.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>

#include <stdexec/execution.hpp>

#include <chrono>
#include <exception>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace clash_native::transport {

inline io::ExchangeField to_io_field(const ExchangeField &field) {
    return io::ExchangeField{field.name, field.value};
}

inline ExchangeField to_transport_field(const io::ExchangeField &field) {
    return ExchangeField{field.name, field.value};
}

inline io::ExchangeRequest to_io_request(const ExchangeRequest &request) {
    io::ExchangeRequest converted;
    converted.method = request.method;
    converted.scheme = request.scheme;
    converted.authority = request.authority;
    converted.target = request.target;
    converted.headers.reserve(request.headers.size());
    for (const auto &field : request.headers) {
        converted.headers.push_back(to_io_field(field));
    }
    converted.body = request.body;
    converted.response_body_limit = request.response_body_limit;
    converted.keep_alive = request.keep_alive;
    return converted;
}

inline ExchangeRequest to_transport_request(const io::ExchangeRequest &request) {
    ExchangeRequest converted;
    converted.method = request.method;
    converted.scheme = request.scheme;
    converted.authority = request.authority;
    converted.target = request.target;
    converted.headers.reserve(request.headers.size());
    for (const auto &field : request.headers) {
        converted.headers.push_back(to_transport_field(field));
    }
    converted.body = request.body;
    converted.response_body_limit = request.response_body_limit;
    converted.keep_alive = request.keep_alive;
    return converted;
}

inline io::ExchangeResponse to_io_response(const ExchangeResponse &response) {
    io::ExchangeResponse converted;
    converted.version = response.version;
    converted.status = response.status;
    converted.headers.reserve(response.headers.size());
    for (const auto &field : response.headers) {
        converted.headers.push_back(to_io_field(field));
    }
    converted.body = response.body;
    converted.keep_alive = response.keep_alive;
    return converted;
}

inline ExchangeResponse to_transport_response(const io::ExchangeResponse &response) {
    ExchangeResponse converted;
    converted.version = response.version;
    converted.status = response.status;
    converted.headers.reserve(response.headers.size());
    for (const auto &field : response.headers) {
        converted.headers.push_back(to_transport_field(field));
    }
    converted.body = response.body;
    converted.keep_alive = response.keep_alive;
    return converted;
}

// io:: view over a callback transport:: body stream. Each pull bridges one
// transport read: EOF completes empty (trailers() is then valid), abort maps
// to stopped, any other failure travels as a core::Error.
class TransportBodyStream final : public io::ExchangeBodyStream {
  public:
    explicit TransportBodyStream(std::shared_ptr<transport::ExchangeBodyStream> body)
        : body_(std::move(body)) {}

    io::AnySender<std::optional<std::size_t>>
    async_read_some(boost::asio::mutable_buffer buffer) override {
        using Signatures =
            stdexec::completion_signatures<stdexec::set_value_t(std::optional<std::size_t>),
                                           stdexec::set_error_t(std::exception_ptr),
                                           stdexec::set_stopped_t()>;
        return io::AnySender<std::optional<std::size_t>>{async::callback_sender<Signatures>(
            [body = body_, buffer](auto terminal) mutable {
                body->async_read_some(buffer, std::move(terminal));
            },
            [](auto receiver, const boost::system::error_code &error, std::size_t size) {
                if (!error) {
                    stdexec::set_value(std::move(receiver), std::optional<std::size_t>{size});
                    return;
                }
                if (error == boost::asio::error::eof) {
                    stdexec::set_value(std::move(receiver), std::optional<std::size_t>{});
                    return;
                }
                if (error == boost::asio::error::operation_aborted) {
                    stdexec::set_stopped(std::move(receiver));
                    return;
                }
                stdexec::set_error(std::move(receiver), std::make_exception_ptr(core::Error{
                                                            core::ErrorCode::transport_io,
                                                            "exchange body read failed", error}));
            })};
    }

    std::vector<io::ExchangeField> trailers() const override {
        std::vector<io::ExchangeField> converted;
        const auto fields = body_->trailers();
        converted.reserve(fields.size());
        for (const auto &field : fields) {
            converted.push_back(to_io_field(field));
        }
        return converted;
    }

    void cancel() noexcept override { body_->cancel(); }

  private:
    std::shared_ptr<transport::ExchangeBodyStream> body_;
};

inline std::shared_ptr<io::ExchangeBodyStream>
adapt_transport_body(std::shared_ptr<transport::ExchangeBodyStream> body) {
    if (!body) {
        return {};
    }
    return std::make_shared<TransportBodyStream>(std::move(body));
}

// transport:: view over a sender-native io:: upload body. Each transport
// pull starts one io pull and forwards its terminal into the callback:
// bytes, EOF (trailers are then cached), a packed core::Error unpacked to
// its cause, or aborted on stop. Completions arrive on the io body's
// executor; sessions already tolerate producer-executor completion.
class IoUploadBody final : public transport::ExchangeBodyStream,
                           public std::enable_shared_from_this<IoUploadBody> {
  public:
    explicit IoUploadBody(std::shared_ptr<io::ExchangeBodyStream> body) : body_(std::move(body)) {}

    void async_read_some(boost::asio::mutable_buffer buffer, ReadHandler handler) override {
        struct PullReceiver {
            using receiver_concept = stdexec::receiver_tag;
            std::shared_ptr<IoUploadBody> self;
            ReadHandler handler;
            void set_value(std::optional<std::size_t> size) && noexcept {
                if (size) {
                    auto callback = std::move(handler);
                    callback({}, *size);
                    return;
                }
                {
                    std::lock_guard lock(self->trailers_mutex_);
                    self->trailers_ = self->body_->trailers();
                    self->trailers_ready_ = true;
                }
                auto callback = std::move(handler);
                callback(boost::asio::error::eof, 0);
            }
            void set_error(std::exception_ptr error) && noexcept {
                auto callback = std::move(handler);
                callback(net::unpack_error(std::move(error)), 0);
            }
            void set_stopped() && noexcept {
                auto callback = std::move(handler);
                callback(boost::asio::error::operation_aborted, 0);
            }
        };
        // Shared: PullReceiver must stay alive until the pull settles, and
        // start_with_receiver takes the receiver by value.
        async::start_with_receiver(body_->async_read_some(buffer),
                                   PullReceiver{shared_from_this(), std::move(handler)});
    }

    std::vector<transport::ExchangeField> trailers() const override {
        std::lock_guard lock(trailers_mutex_);
        std::vector<transport::ExchangeField> converted;
        converted.reserve(trailers_.size());
        for (const auto &field : trailers_) {
            converted.push_back(to_transport_field(field));
        }
        return converted;
    }

    void cancel() noexcept override { body_->cancel(); }

  private:
    std::shared_ptr<io::ExchangeBodyStream> body_;
    mutable std::mutex trailers_mutex_;
    std::vector<io::ExchangeField> trailers_;
    bool trailers_ready_ = false;
};

inline io::StreamingExchangeResponse to_io_streaming_response(StreamingExchangeResponse response) {
    io::StreamingExchangeResponse converted;
    converted.response = to_io_response(response.response);
    converted.body = adapt_transport_body(std::move(response.body));
    return converted;
}

inline io::StreamUpgradeResponse to_io_tunnel_response(StreamUpgradeResponse response) {
    io::StreamUpgradeResponse converted;
    converted.response = to_io_response(response.response);
    if (response.stream) {
        converted.stream = net::adapt_core_to_io(std::move(response.stream));
    }
    return converted;
}

// io:: view over a callback transport:: session. Terminals are captured
// into a oneshot and rethrown as core::Error failures; downstream stop
// cancels the in-flight exchange. The multiplexed view is intentionally
// null: logical streams migrate with the multiplexed plane.
class TransportSession final : public io::ExchangeSession {
  public:
    explicit TransportSession(std::shared_ptr<transport::ExchangeSession> inner)
        : inner_(std::move(inner)) {}

    io::AnySender<io::ExchangeResponse>
    exchange(io::ExchangeRequest request, std::chrono::steady_clock::time_point deadline) override {
        auto channel = async::oneshot::channel<core::Result<io::ExchangeResponse>>();
        // Shared: the transport Handler is a std::function and must be copyable.
        auto sender = std::make_shared<async::oneshot::Sender<core::Result<io::ExchangeResponse>>>(
            std::move(channel.sender));
        const auto exchange_id =
            inner_->exchange(to_transport_request(request), deadline,
                             [sender](core::Result<ExchangeResponse> result) mutable {
                                 if (!result) {
                                     sender->send(core::fail(result.error()));
                                     return;
                                 }
                                 sender->send(to_io_response(result.value()));
                             });
        return wrap(exchange_id, std::move(channel.receiver));
    }

    io::AnySender<io::StreamingExchangeResponse>
    exchange_streaming(io::StreamingExchangeRequest request,
                       std::chrono::steady_clock::time_point deadline) override {
        auto channel = async::oneshot::channel<core::Result<io::StreamingExchangeResponse>>();
        auto sender =
            std::make_shared<async::oneshot::Sender<core::Result<io::StreamingExchangeResponse>>>(
                std::move(channel.sender));
        StreamingExchangeRequest transport_request;
        transport_request.request = to_transport_request(request.request);
        // Upload producers still speak transport::; they ride
        // adapt_transport_body into the io:: request and cross back here.
        // Both hops die when the producers flip.
        if (request.body) {
            transport_request.body = std::make_shared<IoUploadBody>(std::move(request.body));
        }
        transport_request.content_length = request.content_length;
        const auto exchange_id = inner_->exchange_streaming(
            std::move(transport_request), deadline,
            [sender](core::Result<StreamingExchangeResponse> result) mutable {
                if (!result) {
                    sender->send(core::fail(result.error()));
                    return;
                }
                sender->send(to_io_streaming_response(std::move(result.value())));
            });
        return wrap_streaming(exchange_id, std::move(channel.receiver));
    }

    io::AnySender<io::StreamUpgradeResponse>
    open_tunnel(io::StreamUpgradeRequest request,
                std::chrono::steady_clock::time_point deadline) override {
        auto channel = async::oneshot::channel<core::Result<io::StreamUpgradeResponse>>();
        auto sender =
            std::make_shared<async::oneshot::Sender<core::Result<io::StreamUpgradeResponse>>>(
                std::move(channel.sender));
        StreamUpgradeRequest transport_request;
        transport_request.mode = request.mode == io::StreamUpgradeMode::upgrade
                                     ? StreamUpgradeMode::upgrade
                                     : StreamUpgradeMode::connect;
        transport_request.scheme = std::move(request.scheme);
        transport_request.authority = std::move(request.authority);
        transport_request.target = std::move(request.target);
        transport_request.protocol = std::move(request.protocol);
        transport_request.headers.reserve(request.headers.size());
        for (const auto &field : request.headers) {
            transport_request.headers.push_back(to_transport_field(field));
        }
        transport_request.rejection_body_limit = request.rejection_body_limit;
        const auto exchange_id =
            inner_->open_tunnel(std::move(transport_request), deadline,
                                [sender](core::Result<StreamUpgradeResponse> result) mutable {
                                    if (!result) {
                                        sender->send(core::fail(result.error()));
                                        return;
                                    }
                                    sender->send(to_io_tunnel_response(std::move(result.value())));
                                });
        return wrap_tunnel(exchange_id, std::move(channel.receiver));
    }

    io::MultiplexedSession *multiplexed_session() noexcept override { return nullptr; }

    std::unique_ptr<io::DatagramHandle> open_datagram() override {
        return net::adapt_core_to_io_datagram(inner_->open_datagram());
    }

    void cancel(ExchangeId exchange_id) noexcept override { inner_->cancel(exchange_id); }

    void stop() noexcept override { inner_->stop(); }

    bool retired() const noexcept override { return inner_->retired(); }

  private:
    template <typename Terminal>
    io::AnySender<typename Terminal::value_type> wrap(ExchangeId exchange_id,
                                                      async::oneshot::Receiver<Terminal> receiver) {
        auto sender =
            std::move(receiver) |
            stdexec::then([](std::optional<Terminal> terminal) -> typename Terminal::value_type {
                if (!terminal) {
                    throw core::Error{core::ErrorCode::cancelled,
                                      "exchange session dropped the terminal"};
                }
                if (!*terminal) {
                    throw terminal->error();
                }
                return std::move(terminal->value());
            }) |
            stdexec::let_stopped([inner = inner_, exchange_id] {
                inner->cancel(exchange_id);
                return stdexec::just_stopped();
            });
        return io::AnySender<typename Terminal::value_type>{std::move(sender)};
    }

    io::AnySender<io::ExchangeResponse>
    wrap(ExchangeId exchange_id,
         async::oneshot::Receiver<core::Result<io::ExchangeResponse>> receiver) {
        return wrap<core::Result<io::ExchangeResponse>>(exchange_id, std::move(receiver));
    }

    io::AnySender<io::StreamingExchangeResponse>
    wrap_streaming(ExchangeId exchange_id,
                   async::oneshot::Receiver<core::Result<io::StreamingExchangeResponse>> receiver) {
        return wrap<core::Result<io::StreamingExchangeResponse>>(exchange_id, std::move(receiver));
    }

    io::AnySender<io::StreamUpgradeResponse>
    wrap_tunnel(ExchangeId exchange_id,
                async::oneshot::Receiver<core::Result<io::StreamUpgradeResponse>> receiver) {
        return wrap<core::Result<io::StreamUpgradeResponse>>(exchange_id, std::move(receiver));
    }

    std::shared_ptr<transport::ExchangeSession> inner_;
};

inline std::shared_ptr<io::ExchangeSession>
adapt_transport_session(std::shared_ptr<transport::ExchangeSession> session) {
    if (!session) {
        return {};
    }
    return std::make_shared<TransportSession>(std::move(session));
}

} // namespace clash_native::transport
