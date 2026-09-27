#include "proxy_session.hpp"

#include "http_proxy_utils.hpp"

#include <clash_native/async/callback_sender.hpp>
#include <clash_native/core/error.hpp>
#include <clash_native/net/stream_handle_adapter.hpp>

#include <boost/asio/error.hpp>
#include <boost/asio/ssl/stream_base.hpp>
#include <boost/asio/write.hpp>
#include <spdlog/spdlog.h>

#include <exec/asio/use_sender.hpp>

#include <exception>
#include <memory>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace clash_native::proxy {
namespace {

core::Error client_error(const char *what, const boost::system::error_code &error) {
    return core::Error{core::ErrorCode::transport_io, what,
                       std::error_code(error.value(), std::system_category())};
}

core::Error null_stream_error(const char *what) {
    return core::Error{core::ErrorCode::transport_io, what,
                       std::error_code(static_cast<int>(boost::asio::error::operation_aborted),
                                       std::system_category())};
}

} // namespace

ProxyStream::ProxyStream(Socket socket, std::shared_ptr<boost::asio::ssl::context> tls_context)
    : executor_(socket.get_executor()), tls_context_(std::move(tls_context)) {
    if (tls_context_) {
        stream_ = std::make_unique<TlsSocket>(std::move(socket), *tls_context_);
    } else {
        stream_ = std::make_unique<Socket>(std::move(socket));
    }
}

ProxyStream::ProxyStream(Stream stream, boost::asio::any_io_executor executor,
                         std::shared_ptr<boost::asio::ssl::context> tls_context)
    : stream_(std::move(stream)), executor_(std::move(executor)),
      tls_context_(std::move(tls_context)) {}

exec::task<void> ProxyStream::async_server_handshake() {
    if (!tls_enabled()) {
        co_return;
    }
    // Narrow-waist leaf: ssl::stream handshake is a void-signature
    // initiation (error only) that use_sender cannot express, so the leaf
    // stays a callback_sender while callers drive it from a task.
    const auto error = co_await async::callback_sender<HandshakeSignatures>(
        [this](auto terminal) mutable -> async::CallbackAbortFn {
            TlsSocket *stream = std::get_if<std::unique_ptr<TlsSocket>>(&stream_) != nullptr
                                    ? std::get<std::unique_ptr<TlsSocket>>(stream_).get()
                                    : nullptr;
            if (stream == nullptr) {
                terminal(boost::asio::error::operation_aborted);
                return async::CallbackAbortFn{[] {}};
            }
            stream->async_handshake(boost::asio::ssl::stream_base::server,
                                    [terminal = std::move(terminal)](
                                        const boost::system::error_code &handshake_error) mutable {
                                        terminal(handshake_error);
                                    });
            return async::CallbackAbortFn{[this] {
                boost::system::error_code ignored;
                cancel(ignored);
            }};
        },
        [](auto receiver, const boost::system::error_code &handshake_error) {
            stdexec::set_value(std::move(receiver), handshake_error);
        });
    if (error) {
        throw boost::system::system_error(error);
    }
}

bool ProxyStream::tls_enabled() const noexcept {
    return std::holds_alternative<std::unique_ptr<TlsSocket>>(stream_);
}

io::AnySender<std::optional<std::size_t>>
ProxyStream::async_read_some(boost::asio::mutable_buffer buffer) {
    // use_sender turns the Asio initiation into a sender (stop wired to
    // Asio cancellation); the adaptors only translate into the
    // io::StreamHandle contract (EOF as empty, failures as core::Error).
    // A detached (null) stream fails fast instead of posting a completion.
    if (const auto *tls = std::get_if<std::unique_ptr<TlsSocket>>(&stream_); tls != nullptr) {
        if (*tls == nullptr) {
            return io::AnySender<std::optional<std::size_t>>{stdexec::just_error(
                std::make_exception_ptr(null_stream_error("proxy client read")))};
        }
        auto &stream = **tls;
        return io::AnySender<std::optional<std::size_t>>{
            stream.async_read_some(buffer, exec::asio::use_sender) |
            stdexec::then([](std::size_t count) { return std::optional<std::size_t>(count); }) |
            stdexec::let_error([](std::exception_ptr error) -> decltype(stdexec::just(
                                                                std::optional<std::size_t>())) {
                try {
                    std::rethrow_exception(error);
                } catch (const boost::system::system_error &failure) {
                    if (failure.code() == boost::asio::error::eof) {
                        return stdexec::just(std::optional<std::size_t>());
                    }
                    std::rethrow_exception(
                        std::make_exception_ptr(client_error("proxy client read", failure.code())));
                }
                std::rethrow_exception(error);
            })};
    }
    auto &plain = std::get<std::unique_ptr<Socket>>(stream_);
    if (plain == nullptr) {
        return io::AnySender<std::optional<std::size_t>>{
            stdexec::just_error(std::make_exception_ptr(null_stream_error("proxy client read")))};
    }
    auto &stream = *plain;
    return io::AnySender<std::optional<std::size_t>>{
        stream.async_read_some(buffer, exec::asio::use_sender) |
        stdexec::then([](std::size_t count) { return std::optional<std::size_t>(count); }) |
        stdexec::let_error(
            [](std::exception_ptr error) -> decltype(stdexec::just(std::optional<std::size_t>())) {
                try {
                    std::rethrow_exception(error);
                } catch (const boost::system::system_error &failure) {
                    if (failure.code() == boost::asio::error::eof) {
                        return stdexec::just(std::optional<std::size_t>());
                    }
                    std::rethrow_exception(
                        std::make_exception_ptr(client_error("proxy client read", failure.code())));
                }
                std::rethrow_exception(error);
            })};
}

io::AnySender<std::size_t> ProxyStream::async_write(boost::asio::const_buffer buffer) {
    if (const auto *tls = std::get_if<std::unique_ptr<TlsSocket>>(&stream_); tls != nullptr) {
        if (*tls == nullptr) {
            return io::AnySender<std::size_t>{stdexec::just_error(
                std::make_exception_ptr(null_stream_error("proxy client write")))};
        }
        auto &stream = **tls;
        return io::AnySender<std::size_t>{
            boost::asio::async_write(stream, buffer, exec::asio::use_sender) |
            stdexec::let_error(
                [](std::exception_ptr error) -> decltype(stdexec::just(std::size_t(0))) {
                    try {
                        std::rethrow_exception(error);
                    } catch (const boost::system::system_error &failure) {
                        std::rethrow_exception(std::make_exception_ptr(
                            client_error("proxy client write", failure.code())));
                    }
                    std::rethrow_exception(error);
                })};
    }
    auto &plain = std::get<std::unique_ptr<Socket>>(stream_);
    if (plain == nullptr) {
        return io::AnySender<std::size_t>{
            stdexec::just_error(std::make_exception_ptr(null_stream_error("proxy client write")))};
    }
    auto &stream = *plain;
    return io::AnySender<std::size_t>{
        boost::asio::async_write(stream, buffer, exec::asio::use_sender) |
        stdexec::let_error([](std::exception_ptr error) -> decltype(stdexec::just(std::size_t(0))) {
            try {
                std::rethrow_exception(error);
            } catch (const boost::system::system_error &failure) {
                std::rethrow_exception(
                    std::make_exception_ptr(client_error("proxy client write", failure.code())));
            }
            std::rethrow_exception(error);
        })};
}

boost::asio::any_io_executor ProxyStream::executor() noexcept { return executor_; }

boost::asio::any_io_executor ProxyStream::get_executor() const noexcept { return executor_; }

boost::asio::ip::tcp::endpoint
ProxyStream::local_endpoint(boost::system::error_code &error) const noexcept {
    return endpoint(
        [](const auto &stream, auto &endpoint_error) {
            return stream->lowest_layer().local_endpoint(endpoint_error);
        },
        error);
}

boost::asio::ip::tcp::endpoint
ProxyStream::remote_endpoint(boost::system::error_code &error) const noexcept {
    return endpoint(
        [](const auto &stream, auto &endpoint_error) {
            return stream->lowest_layer().remote_endpoint(endpoint_error);
        },
        error);
}

void ProxyStream::shutdown_send(boost::system::error_code &error) noexcept {
    shutdown(Socket::shutdown_send, error);
}

void ProxyStream::shutdown_receive(boost::system::error_code &error) noexcept {
    shutdown(Socket::shutdown_receive, error);
}

void ProxyStream::cancel(boost::system::error_code &error) noexcept {
    visit_socket([&](auto &stream) { stream.lowest_layer().cancel(error); });
}

void ProxyStream::close() noexcept {
    if (detached_) {
        return;
    }
    boost::system::error_code ignored;
    cancel(ignored);
    shutdown(Socket::shutdown_both, ignored);
    visit_socket([&](auto &stream) { stream.lowest_layer().close(ignored); });
}

std::unique_ptr<io::StreamHandle> ProxyStream::detach() {
    detached_ = true;
    return std::unique_ptr<io::StreamHandle>(
        new ProxyStream(std::move(stream_), executor_, std::move(tls_context_)));
}

template <typename Function>
boost::asio::ip::tcp::endpoint
ProxyStream::endpoint(Function function, boost::system::error_code &error) const noexcept {
    return std::visit(
        [&function, &error](const auto &stream) {
            if (!stream) {
                error = boost::asio::error::operation_aborted;
                return boost::asio::ip::tcp::endpoint{};
            }
            return function(stream, error);
        },
        stream_);
}

template <typename Function> void ProxyStream::visit_socket(Function function) noexcept {
    std::visit(
        [&function](auto &stream) {
            if (stream) {
                function(*stream);
            }
        },
        stream_);
}

void ProxyStream::shutdown(Socket::shutdown_type direction,
                           boost::system::error_code &error) noexcept {
    visit_socket([&](auto &stream) { stream.lowest_layer().shutdown(direction, error); });
}

ProxyRequestBodyStream::ProxyRequestBodyStream(ProxyStream &socket,
                                               boost::beast::flat_buffer &buffer,
                                               std::shared_ptr<Parser> parser,
                                               std::size_t initial_header_count,
                                               std::unordered_set<std::string> declared_trailers,
                                               ByteHandler byte_handler)
    : socket_(socket), buffer_(buffer), parser_(std::move(parser)),
      executor_(socket_.get_executor()), initial_header_count_(initial_header_count),
      declared_trailers_(std::move(declared_trailers)), byte_handler_(std::move(byte_handler)) {}

io::AnySender<std::optional<std::size_t>>
ProxyRequestBodyStream::async_read_some(boost::asio::mutable_buffer buffer) {
    // Stop races through cancel_read(): the parked Beast completion is
    // retired with operation_aborted while stop completes promptly; a late
    // Beast completion then finds no parked terminal and drops (the pump
    // keeps no stopped flag: `cancelled_` only marks full teardown).
    using Signatures =
        stdexec::completion_signatures<stdexec::set_value_t(std::optional<std::size_t>),
                                       stdexec::set_error_t(std::exception_ptr),
                                       stdexec::set_stopped_t()>;
    return io::AnySender<std::optional<std::size_t>>{async::callback_sender<Signatures>(
        [self = shared_from_this(), buffer](auto terminal) mutable -> async::CallbackAbortFn {
            run_read_some(self, buffer, std::move(terminal));
            return async::CallbackAbortFn{[self] { self->cancel_read(); }};
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
            stdexec::set_error(std::move(receiver),
                               std::make_exception_ptr(
                                   core::Error{core::ErrorCode::transport_io,
                                               "HTTP forward request body read failed", error}));
        })};
}

void ProxyRequestBodyStream::run_read_some(std::shared_ptr<ProxyRequestBodyStream> self,
                                           boost::asio::mutable_buffer buffer,
                                           ReadHandler handler) {
    const auto executor = self->executor_;
    boost::asio::dispatch(executor, [self, buffer, handler = std::move(handler)]() mutable {
        if (self->cancelled_) {
            self->post_read(std::move(handler), boost::asio::error::operation_aborted, 0);
            return;
        }
        if (self->reading_) {
            self->post_read(std::move(handler), boost::asio::error::already_started, 0);
            return;
        }
        if (self->read_abort_) {
            // cancel_read() fired while the pull hopped through a retry
            // post: retire it instead of re-parking. read_abort_ is only
            // ever armed while retry_pending_, so a fresh pull can never
            // observe a stale abort here.
            self->read_abort_ = false;
            self->post_read(std::move(handler), boost::asio::error::operation_aborted, 0);
            return;
        }
        self->reading_ = true;
        self->parked_handler_ = std::move(handler);
        auto &body = self->parser_->get().body();
        body.data = buffer.data();
        body.size = buffer.size();
        boost::beast::http::async_read_some(
            self->socket_, self->buffer_, *self->parser_,
            [self, buffer](const boost::system::error_code &error, std::size_t) mutable {
                auto handler = std::move(self->parked_handler_);
                self->reading_ = false;
                if (!handler) {
                    // Late completion after cancel_read() retired the pull.
                    return;
                }
                auto &parsed_body = self->parser_->get().body();
                const auto size = buffer.size() - parsed_body.size;
                if (size != 0 && self->byte_handler_) {
                    self->byte_handler_(size);
                }
                if (error == boost::beast::http::error::need_buffer) {
                    if (size != 0) {
                        self->post_read(std::move(handler), {}, size);
                    } else {
                        self->retry_read(buffer, std::move(handler));
                    }
                } else if (error) {
                    spdlog::warn("HTTP forward proxy request body parse failed: {}",
                                 error.message());
                    self->post_read(std::move(handler), error, 0);
                } else if (size != 0) {
                    self->post_read(std::move(handler), {}, size);
                } else if (self->parser_->is_done()) {
                    self->post_read(std::move(handler), boost::asio::error::eof, 0);
                } else {
                    self->retry_read(buffer, std::move(handler));
                }
            });
    });
}

std::vector<io::ExchangeField> ProxyRequestBodyStream::trailers() const {
    std::vector<io::ExchangeField> result;
    if (!parser_->is_done()) {
        return result;
    }
    const auto &fields = parser_->get().base();
    auto field = fields.begin();
    for (std::size_t index = 0; index < initial_header_count_ && field != fields.end();
         ++index, ++field) {
    }
    for (; field != fields.end(); ++field) {
        const auto name = http_detail::as_std_view(field->name_string());
        const auto normalized = http_detail::lowercase_ascii(name);
        if (!declared_trailers_.contains(normalized) ||
            http_detail::is_forbidden_trailer_field(normalized)) {
            continue;
        }
        result.push_back(
            {http_detail::copy_view(field->name_string()), http_detail::copy_view(field->value())});
    }
    return result;
}

void ProxyRequestBodyStream::cancel() noexcept {
    const auto self = shared_from_this();
    boost::asio::dispatch(executor_, [self] {
        if (self->cancelled_) {
            return;
        }
        self->cancelled_ = true;
        boost::system::error_code ignored;
        self->socket_.shutdown_receive(ignored);
    });
}

void ProxyRequestBodyStream::cancel_read() noexcept {
    try {
        const auto self = shared_from_this();
        boost::asio::dispatch(executor_, [self] {
            auto handler = std::move(self->parked_handler_);
            if (handler) {
                self->reading_ = false;
                self->post_read(std::move(handler), boost::asio::error::operation_aborted, 0);
                return;
            }
            // No Beast read parked: the pull (if any) is hopping through a
            // retry post. Arm the one-shot so the hop retires instead of
            // re-parking; armed only while a retry is pending, so it cannot
            // poison a later pull.
            if (self->retry_pending_) {
                self->read_abort_ = true;
            }
        });
    } catch (...) {
        // Aborter contract: never throw; the late Beast completion or
        // close() retires the parked handler instead.
    }
}

void ProxyRequestBodyStream::retry_read(boost::asio::mutable_buffer buffer, ReadHandler handler) {
    auto self = shared_from_this();
    self->retry_pending_ = true;
    boost::asio::post(executor_, [self, buffer, handler = std::move(handler)]() mutable {
        self->retry_pending_ = false;
        run_read_some(self, buffer, std::move(handler));
    });
}

void ProxyRequestBodyStream::post_read(ReadHandler handler, boost::system::error_code error,
                                       std::size_t size) {
    boost::asio::post(executor_, [handler = std::move(handler), error, size]() mutable {
        if (handler) {
            handler(error, size);
        }
    });
}

} // namespace clash_native::proxy
