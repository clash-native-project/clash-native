#include <clash_native/dns/ech_resolver.hpp>

#include <clash_native/async/bridge.hpp>
#include <clash_native/core/error.hpp>
#include <clash_native/dns/dns_codec.hpp>

#include <atomic>
#include <memory>
#include <utility>

namespace clash_native::dns {

namespace {

constexpr std::uint16_t kEchSvcParamKey = 5;

core::Error cancelled_error() {
    return {core::ErrorCode::cancelled, "DNS ECH query was cancelled"};
}

core::Error not_found_error(const std::string &name) {
    return {core::ErrorCode::resolution, "DNS ECH config not published for " + name};
}

} // namespace

io::AnySender<core::Result<std::vector<std::uint8_t>>>
async_query_ech_config(DnsQueryService &query_service, std::string name,
                       std::optional<std::string> query_server_name) {
    struct Shared {
        DnsQueryService *service = nullptr;
        std::atomic<DnsQueryService::RequestId> query_id{0};
    };
    auto shared = std::make_shared<Shared>();
    shared->service = &query_service;
    const std::string lookup = std::move(query_server_name).value_or(std::move(name));
    return async::bridge_sender<core::Result<std::vector<std::uint8_t>>>(
        [shared, lookup = std::move(lookup)](
            async::BridgeSender<core::Result<std::vector<std::uint8_t>>>::Handler
                terminal) mutable {
            DnsQuestion question{lookup, DnsRecordType::https, 1};
            DnsPacket packet;
            packet.id = 0;
            packet.flags = 0x0100;
            packet.questions.push_back(question);
            const auto encoded = DnsMessageCodec::encode_query_packet(question, packet.id);
            if (!encoded) {
                terminal(core::fail(
                    core::Error{core::ErrorCode::configuration, "failed to encode DNS ECH query"}));
                return async::BridgeSender<core::Result<std::vector<std::uint8_t>>>::AbortFn{};
            }
            packet.wire = encoded.value();
            const auto id = shared->service->query(
                std::move(packet), [shared, lookup, terminal = std::move(terminal)](
                                       core::Result<DnsPacket> result) mutable {
                    if (!result) {
                        terminal(core::fail(result.error()));
                        return;
                    }
                    for (const auto &answer : result.value().answers) {
                        if (answer.type != static_cast<std::uint16_t>(DnsRecordType::https) &&
                            answer.type != static_cast<std::uint16_t>(DnsRecordType::svcb)) {
                            continue;
                        }
                        if (!answer.svcb) {
                            continue;
                        }
                        for (const auto &param : answer.svcb->params) {
                            if (param.code == kEchSvcParamKey && !param.data.empty()) {
                                terminal(core::Result<std::vector<std::uint8_t>>{param.data});
                                return;
                            }
                        }
                    }
                    terminal(core::fail(not_found_error(lookup)));
                });
            shared->query_id.store(id, std::memory_order_release);
            using AbortFn = async::BridgeSender<core::Result<std::vector<std::uint8_t>>>::AbortFn;
            return AbortFn{[shared]() mutable {
                const auto query_id = shared->query_id.load(std::memory_order_acquire);
                if (query_id != 0) {
                    shared->service->cancel(query_id);
                }
            }};
        });
}

} // namespace clash_native::dns
