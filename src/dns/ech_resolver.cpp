#include <clash_native/dns/ech_resolver.hpp>

#include <clash_native/async/callback_sender.hpp>
#include <clash_native/async/detached.hpp>
#include <clash_native/core/error.hpp>
#include <clash_native/dns/dns_codec.hpp>

#include <stdexec/execution.hpp>

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
    DnsQueryService *service = nullptr;
    std::string original;

    // ECH follow-up chain as one detached task: co_await each query_sender
    // and scan for the ech SvcParam inline. The task always ends with a
    // value (finish drops late terminals on settled); abort marks settled
    // and the late finish drops.
    static stdexec::task<void>
    run(std::shared_ptr<EchLookup> self,
        async::BridgeHandler<core::Result<std::vector<std::uint8_t>>> terminal) {
        auto finish = [self, terminal = std::move(terminal)](
                          core::Result<std::vector<std::uint8_t>> result) mutable {
            if (self->settled.exchange(true, std::memory_order_acq_rel)) {
                return;
            }
            terminal(std::move(result));
        };
        std::vector<std::string> visited{normalize_name(self->original)};
        std::string current = self->original;
        for (int follow_ups = 3; follow_ups >= 0; --follow_ups) {
            DnsQuestion question{current, DnsRecordType::https, 1};
            const auto encoded = DnsMessageCodec::encode_query_packet(question, 0);
            if (!encoded) {
                finish(core::fail(
                    core::Error{core::ErrorCode::configuration, "failed to encode DNS ECH query"}));
                co_return;
            }
            DnsPacket packet;
            packet.id = 0;
            packet.flags = 0x0100;
            packet.questions.push_back(question);
            packet.wire = encoded.value();
            core::Result<DnsPacket> result = core::fail(cancelled_error());
            try {
                auto sender =
                    self->service->query_sender(std::move(packet)) | stdexec::stopped_as_optional();
                auto outcome = co_await std::move(sender);
                if (!outcome) {
                    result = core::fail(cancelled_error());
                } else {
                    result = std::move(*outcome);
                }
            } catch (const core::Error &failure) {
                result = core::fail(failure);
            } catch (...) {
                try {
                    std::rethrow_exception(std::current_exception());
                } catch (const core::Error &failure) {
                    result = core::fail(failure);
                } catch (...) {
                    result = core::fail(cancelled_error());
                }
            }
            if (self->settled.load(std::memory_order_acquire)) {
                co_return;
            }
            if (!result) {
                finish(core::fail(result.error()));
                co_return;
            }
            const auto &response = result.value();
            // Follow CNAMEs inside this response (mirrors the address
            // path), then accept an HTTPS/SVCB ech param at any name
            // along the chain.
            std::vector<std::string> chain{normalize_name(current)};
            for (std::size_t depth = 0; depth < 8; ++depth) {
                const auto cname = std::find_if(
                    response.answers.begin(), response.answers.end(),
                    [&](const DnsResourceRecord &record) {
                        return record.class_code == 1 &&
                               record.type == static_cast<std::uint16_t>(DnsRecordType::cname) &&
                               normalize_name(record.name) == chain.back() && record.target_name;
                    });
                if (cname == response.answers.end()) {
                    break;
                }
                const auto next = normalize_name(*cname->target_name);
                if (next.empty() || std::find(chain.begin(), chain.end(), next) != chain.end()) {
                    break;
                }
                chain.push_back(next);
            }
            for (const auto &answer : response.answers) {
                if (answer.class_code != 1 ||
                    (answer.type != static_cast<std::uint16_t>(DnsRecordType::https) &&
                     answer.type != static_cast<std::uint16_t>(DnsRecordType::svcb)) ||
                    !answer.svcb) {
                    continue;
                }
                if (std::find(chain.begin(), chain.end(), normalize_name(answer.name)) ==
                    chain.end()) {
                    continue;
                }
                for (const auto &param : answer.svcb->params) {
                    if (param.code == kEchSvcParamKey && !param.data.empty()) {
                        finish(core::Result<std::vector<std::uint8_t>>{param.data});
                        co_return;
                    }
                }
            }
            // No ech here: chase the chain target with a follow-up query
            // when this response moved us to a name we have not visited.
            const auto &target = chain.back();
            if (chain.size() > 1 && follow_ups > 0 &&
                std::find(visited.begin(), visited.end(), target) == visited.end()) {
                visited.push_back(target);
                current = target;
                continue;
            }
            finish(core::fail(not_found_error(self->original)));
            co_return;
        }
        finish(core::fail(not_found_error(self->original)));
        co_return;
    }

    std::atomic_bool settled{false};
};

io::AnySender<core::Result<std::vector<std::uint8_t>>>
async_query_ech_config(DnsQueryService &query_service, std::string name,
                       std::optional<std::string> query_server_name) {
    using Signatures = async::BridgeSignatures<core::Result<std::vector<std::uint8_t>>>;
    auto lookup = std::make_shared<EchLookup>();
    lookup->service = &query_service;
    lookup->original = std::move(query_server_name).value_or(std::move(name));
    return async::callback_sender<Signatures>(
        [lookup](auto terminal) mutable -> async::CallbackAbortFn {
            async::spawn_detached(
                EchLookup::run(lookup, [terminal = std::move(terminal)](
                                           core::Result<std::vector<std::uint8_t>> result) mutable {
                    terminal(std::move(result));
                }));
            return async::CallbackAbortFn{
                [lookup] { lookup->settled.store(true, std::memory_order_release); }};
        },
        async::BridgeTranslate<core::Result<std::vector<std::uint8_t>>>{});
}

} // namespace clash_native::dns
