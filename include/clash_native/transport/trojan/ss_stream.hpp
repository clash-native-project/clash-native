#pragma once

#include <clash_native/core/result.hpp>
#include <clash_native/io/stream_handle.hpp>

#include <memory>
#include <string>
#include <string_view>

namespace clash_native::transport::trojan {

// Shadowsocks AEAD stream framing (the trojan `ss-opts` layer) over an
// established stream: random salt, then length-prefixed chunks sealed with
// incrementing nonces. This is Trojan code written against the SS wire
// spec and the shared transport::proxy crypto primitives; it never
// includes another protocol's transport.
//
// Only classic AEAD methods are accepted (the trojan-go ss tunnel
// predates Shadowsocks 2022); stream-cipher and 2022 methods fail with a
// configuration error.
core::Result<std::unique_ptr<io::StreamHandle>>
make_trojan_ss_stream_handle(std::unique_ptr<io::StreamHandle> stream, std::string_view method,
                             std::string_view password);

} // namespace clash_native::transport::trojan
