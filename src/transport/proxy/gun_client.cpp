#include <clash_native/transport/proxy/gun_client.hpp>

#include <clash_native/async/callback_sender.hpp>

#include <stdexec/execution.hpp>

#include <exception>
#include <memory>
#include <mutex>
#include <utility>

namespace clash_native::transport::proxy::gun {

GunClient::GunClient(GunClientOptions options, SessionMaker maker)
    : options_(std::move(options)), maker_(std::move(maker)) {
    if (options_.max_connections == 0 && options_.min_streams == 0 && options_.max_streams == 0) {
        options_.max_connections = 1;
    }
}

std::shared_ptr<GunClient::TransportEntry> GunClient::pick_transport() {
    std::lock_guard lock(mutex_);
    if (closed_) {
        return nullptr;
    }
    std::shared_ptr<TransportEntry> lightest;
    for (const auto &entry : transports_) {
        if (!lightest || entry->streams.load(std::memory_order_relaxed) <
                             lightest->streams.load(std::memory_order_relaxed)) {
            lightest = entry;
        }
    }
    if (!lightest) {
        lightest = std::make_shared<TransportEntry>();
        transports_.push_back(lightest);
        return lightest;
    }
    const auto streams = lightest->streams.load(std::memory_order_relaxed);
    if (streams == 0) {
        return lightest;
    }
    if (options_.max_connections > 0) {
        if (static_cast<int>(transports_.size()) >= options_.max_connections ||
            streams < options_.min_streams) {
            return lightest;
        }
    } else {
        if (options_.max_streams > 0 && streams < options_.max_streams) {
            return lightest;
        }
    }
    lightest = std::make_shared<TransportEntry>();
    transports_.push_back(lightest);
    return lightest;
}

stdexec::task<void> GunClient::run_open(std::shared_ptr<GunClient> client,
                                        std::shared_ptr<TransportEntry> entry, SessionMaker maker,
                                        gun::GunStreamOptions options,
                                        std::shared_ptr<DialGuard> guard, OpenHandler done) {
    OpenResult result = core::fail({core::ErrorCode::transport_io, "gun dial failed"});
    try {
        if (!entry->session) {
            // Task-shaped session open: direct co_await on the maker sender
            // (cancellable via scope stop), replacing the HeldOperation +
            // MakerReceiver drive. Errors normalize to core::Error results.
            std::shared_ptr<io::ExchangeSession> opened;
            try {
                opened = co_await maker();
            } catch (const core::Error &failure) {
                result = core::fail(failure);
                done(std::move(result));
                co_return;
            } catch (...) {
                result = core::fail({core::ErrorCode::transport_io, "gun session open failed"});
                done(std::move(result));
                co_return;
            }
            if (!opened) {
                result = core::fail({core::ErrorCode::transport_io, "gun session open failed"});
                done(std::move(result));
                co_return;
            }
            entry->session = std::move(opened);
        }
        auto stream = co_await async::callback_sender<async::BridgeSignatures<OpenResult>>(
            [entry, options](OpenHandler open) mutable {
                std::shared_ptr<gun::GunStreamOpenAborter> handle;
                gun::async_open_gun_stream_abortable(
                    entry->session, options,
                    [open](OpenResult opened) mutable { open(std::move(opened)); }, &handle);
                using AbortFn = async::CallbackAbortFn;
                // Poison the eager stream; the late head drops at the state.
                return AbortFn{[handle] {
                    if (handle) {
                        handle->abort();
                    }
                }};
            },
            async::BridgeTranslate<OpenResult>{});
        if (stream) {
            guard->armed = false;
            result = OpenResult{std::unique_ptr<io::StreamHandle>(
                std::make_unique<CountedStreamHandle>(std::move(stream.value()), entry))};
        } else {
            result = core::fail(stream.error());
        }
    } catch (const core::Error &failure) {
        result = core::fail(failure);
    } catch (...) {
    }
    done(std::move(result));
    (void)client;
}

io::AnySender<std::unique_ptr<io::StreamHandle>> GunClient::dial() {
    auto self = shared_from_this();
    auto entry = pick_transport();
    if (!entry) {
        return io::AnySender<std::unique_ptr<io::StreamHandle>>{
            stdexec::just_error(std::make_exception_ptr(
                core::Error{core::ErrorCode::cancelled, "gun client is closed"}))};
    }
    entry->streams.fetch_add(1, std::memory_order_relaxed);
    // NOTE: fill the shared guard in place; a DialGuard{entry} temporary
    // would run its armed destructor and release the reservation early.
    auto guard = std::make_shared<DialGuard>();
    guard->entry = entry;
    auto maker = maker_;
    auto options = options_.stream;
    options.deadline = std::chrono::steady_clock::now() + options_.open_timeout;
    struct Shared {
        exec::async_scope scope;
    };
    auto shared = std::make_shared<Shared>();
    // Linear open chain as a named-function task spawned into the shared
    // scope (the run() shape): ensure the Transport session, then the Tun
    // stream, and deliver the in-band result through done exactly once.
    // Failures stay values. The aborter stops the scope so the run_open
    // awaits settle promptly; the late terminal then drops at the first-wins
    // guard. The scope dies with the starter captures (never a member), so
    // no #194 shape.
    auto bridged = async::callback_sender<
        async::BridgeSignatures<core::Result<std::unique_ptr<io::StreamHandle>>>>(
        [shared, self, entry, maker = std::move(maker), options = std::move(options), guard](
            async::BridgeHandler<core::Result<std::unique_ptr<io::StreamHandle>>> done) mutable {
            shared->scope.spawn(run_open(self, entry, std::move(maker), std::move(options),
                                         std::move(guard), std::move(done)));
            using AbortFn = async::CallbackAbortFn;
            return AbortFn{[shared] { shared->scope.request_stop(); }};
        },
        async::BridgeTranslate<core::Result<std::unique_ptr<io::StreamHandle>>>{});
    auto sender = std::move(bridged) |
                  stdexec::then([](core::Result<std::unique_ptr<io::StreamHandle>> result) {
                      if (!result) {
                          throw result.error();
                      }
                      return std::move(result.value());
                  });
    return io::AnySender<std::unique_ptr<io::StreamHandle>>{std::move(sender)};
}

void GunClient::close() noexcept {
    std::lock_guard lock(mutex_);
    closed_ = true;
    for (const auto &entry : transports_) {
        if (entry->session) {
            entry->session->stop();
        }
    }
    transports_.clear();
}

} // namespace clash_native::transport::proxy::gun
