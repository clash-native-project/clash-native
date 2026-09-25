#include <clash_native/dns/ech_resolver.hpp>

#include <clash_native/async/bridge.hpp>
#include <clash_native/core/error.hpp>
#include <clash_native/dns/dns_codec.hpp>

#include <algorithm>
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

struct EchLookup : public std::enable_shared_from_this<EchLookup> {
    using Handler = async::BridgeSender<core::Result<std::vector<std::uint8_t>>>::Handler;
    using AbortFn = async::BridgeSender<core::Result<std::vector<std::uint8_t>>>::AbortFn;

    DnsQueryService *service = nullptr;
    std::atomic<DnsQueryService::RequestId> query_id{0};
    std::string original;
    std::vector<std::string> visited;
    int follow_ups_remaining = 3;
    Handler terminal;
    bool settled = false;

    void finish(core::Result<std::vector<std::uint8_t>> result) {
        if (settled) {
            return;
        }
        settled = true;
        terminal(std::move(result));
    }

    void issue(const std::string &name) {
        DnsQuestion question{name, DnsRecordType::https, 1};
        const auto encoded = DnsMessageCodec::encode_query_packet(question, 0);
        if (!encoded) {
            finish(core::fail(
                core::Error{core::ErrorCode::configuration, "failed to encode DNS ECH query"}));
            return;
        }
        DnsPacket packet;
        packet.id = 0;
        packet.flags = 0x0100;
        packet.questions.push_back(question);
        packet.wire = encoded.value();
        auto self = shared_from_this();
        const auto id =
            service->query(std::move(packet), [self, name](core::Result<DnsPacket> result) mutable {
                if (!result) {
                    self->finish(core::fail(result.error()));
                    return;
                }
                self->handle(name, result.value());
            });
        query_id.store(id, std::memory_order_release);
    }

    void handle(const std::string &queried, const DnsPacket &packet) {
        // Follow CNAMEs inside this response (mirrors the address path),
        // then accept an HTTPS/SVCB ech param at any name along the chain.
        std::vector<std::string> chain{normalize_name(queried)};
        for (std::size_t depth = 0; depth < 8; ++depth) {
            const auto cname = std::find_if(
                packet.answers.begin(), packet.answers.end(), [&](const DnsResourceRecord &record) {
                    return record.class_code == 1 &&
                           record.type == static_cast<std::uint16_t>(DnsRecordType::cname) &&
                           normalize_name(record.name) == chain.back() && record.target_name;
                });
            if (cname == packet.answers.end()) {
                break;
            }
            const auto next = normalize_name(*cname->target_name);
            if (next.empty() || std::find(chain.begin(), chain.end(), next) != chain.end()) {
                break;
            }
            chain.push_back(next);
        }
        for (const auto &answer : packet.answers) {
            if (answer.class_code != 1 ||
                (answer.type != static_cast<std::uint16_t>(DnsRecordType::https) &&
                 answer.type != static_cast<std::uint16_t>(DnsRecordType::svcb)) ||
                !answer.svcb) {
                continue;
            }
            if (std::find(chain.begin(), chain.end(), normalize_name(answer.name)) == chain.end()) {
                continue;
            }
            for (const auto &param : answer.svcb->params) {
                if (param.code == kEchSvcParamKey && !param.data.empty()) {
                    finish(core::Result<std::vector<std::uint8_t>>{param.data});
                    return;
                }
            }
        }
        // No ech here: chase the chain target with a follow-up query when
        // this response moved us to a name we have not visited yet.
        const auto &target = chain.back();
        if (chain.size() > 1 && follow_ups_remaining > 0 &&
            std::find(visited.begin(), visited.end(), target) == visited.end()) {
            visited.push_back(target);
            --follow_ups_remaining;
            issue(target);
            return;
        }
        finish(core::fail(not_found_error(original)));
    }
};

io::AnySender<core::Result<std::vector<std::uint8_t>>>
async_query_ech_config(DnsQueryService &query_service, std::string name,
                       std::optional<std::string> query_server_name) {
    auto lookup = std::make_shared<EchLookup>();
    lookup->service = &query_service;
    lookup->original = std::move(query_server_name).value_or(std::move(name));
    lookup->visited.push_back(normalize_name(lookup->original));
    return async::bridge_sender<core::Result<std::vector<std::uint8_t>>>(
        [lookup](async::BridgeSender<core::Result<std::vector<std::uint8_t>>>::Handler
                     terminal) mutable {
            lookup->terminal = std::move(terminal);
            lookup->issue(lookup->original);
            using AbortFn = async::BridgeSender<core::Result<std::vector<std::uint8_t>>>::AbortFn;
            return AbortFn{[lookup]() mutable {
                const auto query_id = lookup->query_id.load(std::memory_order_acquire);
                if (query_id != 0) {
                    lookup->service->cancel(query_id);
                }
            }};
        });
}

} // namespace clash_native::dns
