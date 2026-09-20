#include <clash_native/transport/shadowsocks/crypto.hpp>

#include <clash_native/core/base64.hpp>

#include <blake3.h>
#include <botan/mac.h>
#include <botan/stream_cipher.h>

#include <openssl/aes.h>
#include <openssl/chacha.h>
#include <openssl/crypto.h>
#include <openssl/digest.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <climits>
#include <cstring>
#include <exception>
#include <memory>
#include <string>
#include <utility>

namespace clash_native::transport::shadowsocks {

namespace {

constexpr std::size_t kAeadTagSize = 16;
constexpr std::size_t kAesBlockSize = 16;

using DigestContext = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using AeadContext = std::unique_ptr<EVP_AEAD_CTX, decltype(&EVP_AEAD_CTX_free)>;
using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

core::Error crypto_error(std::string context) {
    return {core::ErrorCode::authentication, std::move(context)};
}

core::Result<std::vector<std::uint8_t>> md5_chain(std::string_view password,
                                                  std::size_t output_size) {
    std::vector<std::uint8_t> output;
    output.reserve(output_size);
    std::array<std::uint8_t, EVP_MAX_MD_SIZE> previous{};
    unsigned int previous_size = 0;
    while (output.size() < output_size) {
        DigestContext digest(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (!digest || EVP_DigestInit_ex(digest.get(), EVP_md5(), nullptr) != 1 ||
            (previous_size != 0 &&
             EVP_DigestUpdate(digest.get(), previous.data(), previous_size) != 1) ||
            EVP_DigestUpdate(digest.get(), password.data(), password.size()) != 1 ||
            EVP_DigestFinal_ex(digest.get(), previous.data(), &previous_size) != 1) {
            return core::fail(crypto_error("failed to derive Shadowsocks legacy key"));
        }
        const auto append_size = std::min<std::size_t>(output_size - output.size(), previous_size);
        output.insert(output.end(), previous.begin(), previous.begin() + append_size);
    }
    return output;
}

core::Result<std::vector<std::uint8_t>> hkdf_sha1(std::span<const std::uint8_t> input_key,
                                                  std::span<const std::uint8_t> salt,
                                                  std::string_view info, std::size_t output_size) {
    std::array<std::uint8_t, EVP_MAX_MD_SIZE> pseudorandom_key{};
    unsigned int pseudorandom_key_size = 0;
    if (!HMAC(EVP_sha1(), salt.data(), static_cast<int>(salt.size()), input_key.data(),
              input_key.size(), pseudorandom_key.data(), &pseudorandom_key_size)) {
        return core::fail(crypto_error("failed to derive Shadowsocks subkey"));
    }

    std::vector<std::uint8_t> output;
    output.reserve(output_size);
    std::vector<std::uint8_t> previous;
    for (std::uint8_t counter = 1; output.size() < output_size; ++counter) {
        std::vector<std::uint8_t> input;
        input.reserve(previous.size() + info.size() + 1);
        input.insert(input.end(), previous.begin(), previous.end());
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter);

        std::array<std::uint8_t, EVP_MAX_MD_SIZE> block{};
        unsigned int block_size = 0;
        if (!HMAC(EVP_sha1(), pseudorandom_key.data(), static_cast<int>(pseudorandom_key_size),
                  input.data(), input.size(), block.data(), &block_size)) {
            return core::fail(crypto_error("failed to derive Shadowsocks subkey"));
        }
        previous.assign(block.begin(), block.begin() + block_size);
        const auto append_size = std::min(output_size - output.size(), previous.size());
        output.insert(output.end(), previous.begin(), previous.begin() + append_size);
    }
    return output;
}

const EVP_CIPHER *legacy_cipher(std::string_view name) {
    if (name == "aes-128-ctr") {
        return EVP_aes_128_ctr();
    }
    if (name == "aes-192-ctr") {
        return EVP_aes_192_ctr();
    }
    if (name == "aes-256-ctr") {
        return EVP_aes_256_ctr();
    }
    if (name == "aes-128-cfb") {
        return EVP_aes_128_ecb();
    }
    if (name == "aes-192-cfb") {
        return EVP_aes_192_ecb();
    }
    if (name == "aes-256-cfb") {
        return EVP_aes_256_ecb();
    }
    if (name == "rc4-md5") {
        return EVP_rc4();
    }
    return nullptr;
}

std::size_t legacy_key_size(std::string_view name) {
    if (name == "aes-128-ctr" || name == "aes-128-cfb") {
        return 16;
    }
    if (name == "aes-192-ctr" || name == "aes-192-cfb") {
        return 24;
    }
    if (name == "aes-256-ctr" || name == "aes-256-cfb" || name == "rc4-md5") {
        return 32;
    }
    if (name == "chacha20" || name == "chacha20-ietf" || name == "xchacha20") {
        return 32;
    }
    return 0;
}

// The classic Shadowsocks RC4-MD5 construction derives an MD5 key from the
// password-derived key and the per-connection IV. The configured key itself is
// still 16 bytes; the 32-byte value above is only used for the stream cipher
// key after the derivation step.
std::size_t configured_legacy_key_size(std::string_view name) {
    if (name == "rc4-md5") {
        return 16;
    }
    return legacy_key_size(name);
}

std::unique_ptr<Botan::StreamCipher> create_chacha_cipher(
    int rounds, std::span<const std::uint8_t> key, std::span<const std::uint8_t> nonce) {
    auto cipher = Botan::StreamCipher::create("ChaCha(" + std::to_string(rounds) + ")");
    if (!cipher) {
        return nullptr;
    }
    cipher->set_key(key);
    cipher->set_iv(nonce);
    return cipher;
}

std::uint32_t load_little_endian_u32(const std::uint8_t *input) {
    return static_cast<std::uint32_t>(input[0]) |
           (static_cast<std::uint32_t>(input[1]) << 8) |
           (static_cast<std::uint32_t>(input[2]) << 16) |
           (static_cast<std::uint32_t>(input[3]) << 24);
}

void store_little_endian_u32(std::uint8_t *output, std::uint32_t value) {
    output[0] = static_cast<std::uint8_t>(value);
    output[1] = static_cast<std::uint8_t>(value >> 8);
    output[2] = static_cast<std::uint8_t>(value >> 16);
    output[3] = static_cast<std::uint8_t>(value >> 24);
}

std::array<std::uint8_t, 32> hchacha20_subkey(std::span<const std::uint8_t> key,
                                               std::span<const std::uint8_t> nonce) {
    // BoringSSL exposes the standard 20-round ChaCha20 primitive. Its first
    // keystream block is the ChaCha state after feed-forward; subtracting the
    // known initial state words yields the HChaCha20 output words required by
    // XChaCha. This keeps the round function in the crypto library while
    // allowing the Shadowsocks XChaCha8 construction to use its specified
    // 20-round HChaCha20 key derivation and 8-round payload cipher.
    std::array<std::uint8_t, 64> zeros{};
    std::array<std::uint8_t, 64> block{};
    std::array<std::uint8_t, 12> chacha_nonce{};
    std::copy(nonce.begin() + 4, nonce.end(), chacha_nonce.begin());
    const auto counter = load_little_endian_u32(nonce.data());
    CRYPTO_chacha_20(block.data(), zeros.data(), block.size(), key.data(), chacha_nonce.data(),
                     counter);

    constexpr std::array<std::uint32_t, 4> constants{
        0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U};
    std::array<std::uint8_t, 32> subkey{};
    for (std::size_t index = 0; index < constants.size(); ++index) {
        const auto word = load_little_endian_u32(block.data() + index * 4) - constants[index];
        store_little_endian_u32(subkey.data() + index * 4, word);
    }
    for (std::size_t index = 0; index < 4; ++index) {
        const auto word = load_little_endian_u32(block.data() + (12 + index) * 4) -
                          load_little_endian_u32(nonce.data() + index * 4);
        store_little_endian_u32(subkey.data() + (4 + index) * 4, word);
    }
    return subkey;
}

bool is_aes_ccm_method(std::string_view method) {
    return method == "aes-128-ccm" || method == "aes-192-ccm" || method == "aes-256-ccm";
}

bool is_chacha8_method(std::string_view method) {
    return method == "chacha8-ietf-poly1305" || method == "xchacha8-ietf-poly1305";
}

core::Result<std::vector<std::uint8_t>> poly1305_mac(
    std::span<const std::uint8_t> key, std::span<const std::uint8_t> message) {
    if (key.size() != 32) {
        return core::fail({core::ErrorCode::configuration, "invalid Poly1305 key size"});
    }
    try {
        auto mac = Botan::MessageAuthenticationCode::create("Poly1305");
        if (!mac) {
            return core::fail(crypto_error("Botan Poly1305 is unavailable"));
        }
        mac->set_key(key);
        mac->update(message);
        return mac->final_stdvec();
    } catch (const std::exception &error) {
        return core::fail(crypto_error(std::string("failed to compute Poly1305: ") + error.what()));
    }
}

core::Result<std::vector<std::uint8_t>> chacha8_poly1305_crypt(
    std::span<const std::uint8_t> key, std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> input, bool encrypt, int rounds) {
    if (key.size() != 32 || (nonce.size() != 12 && nonce.size() != 24)) {
        return core::fail({core::ErrorCode::configuration, "invalid ChaCha8 parameters"});
    }
    std::array<std::uint8_t, 12> ietf_nonce{};
    std::span<const std::uint8_t> cipher_key = key;
    std::array<std::uint8_t, 32> derived_key{};
    if (nonce.size() == 24) {
        derived_key = hchacha20_subkey(key, nonce.first<16>());
        cipher_key = derived_key;
        std::copy(nonce.begin() + 16, nonce.end(), ietf_nonce.begin() + 4);
    } else {
        std::copy(nonce.begin(), nonce.end(), ietf_nonce.begin());
    }

    std::unique_ptr<Botan::StreamCipher> cipher;
    try {
        cipher = create_chacha_cipher(rounds, cipher_key, ietf_nonce);
        if (!cipher) {
            return core::fail(crypto_error("Botan ChaCha is unavailable"));
        }
    } catch (const std::exception &error) {
        return core::fail(crypto_error(std::string("failed to initialize ChaCha: ") + error.what()));
    }
    std::array<std::uint8_t, 64> poly_block{};
    try {
        cipher->write_keystream(poly_block);
        cipher->seek(64);
    } catch (const std::exception &error) {
        return core::fail(crypto_error(std::string("failed to generate ChaCha keystream: ") +
                                       error.what()));
    }
    std::vector<std::uint8_t> ciphertext;
    if (encrypt) {
        ciphertext.assign(input.begin(), input.end());
        try {
            cipher->cipher1(ciphertext);
        } catch (const std::exception &error) {
            return core::fail(crypto_error(std::string("failed to encrypt ChaCha data: ") +
                                           error.what()));
        }
    } else {
        if (input.size() < 16) {
            return core::fail({core::ErrorCode::protocol_framing,
                               "ChaCha8 ciphertext is shorter than its authentication tag"});
        }
        ciphertext.assign(input.begin(), input.end() - 16);
    }

    std::vector<std::uint8_t> authenticated;
    authenticated.reserve(ciphertext.size() + 32);
    authenticated.insert(authenticated.end(), ciphertext.begin(), ciphertext.end());
    authenticated.insert(authenticated.end(), (16 - ciphertext.size() % 16) % 16, 0);
    for (int index = 0; index < 8; ++index) {
        authenticated.push_back(0);
    }
    const auto ciphertext_size = static_cast<std::uint64_t>(ciphertext.size());
    for (int index = 0; index < 8; ++index) {
        authenticated.push_back(static_cast<std::uint8_t>(ciphertext_size >> (index * 8)));
    }
    const auto tag = poly1305_mac(std::span<const std::uint8_t>(poly_block).first<32>(),
                                  authenticated);
    if (!tag) {
        return core::fail(tag.error());
    }
    if (!encrypt && CRYPTO_memcmp(tag.value().data(), input.data() + ciphertext.size(), 16) != 0) {
        return core::fail({core::ErrorCode::authentication,
                           "ChaCha8-Poly1305 authentication failed"});
    }
    if (!encrypt) {
        try {
            cipher->cipher1(ciphertext);
        } catch (const std::exception &error) {
            return core::fail(crypto_error(std::string("failed to decrypt ChaCha data: ") +
                                           error.what()));
        }
    } else {
        ciphertext.insert(ciphertext.end(), tag.value().begin(), tag.value().end());
    }
    return ciphertext;
}

core::Result<std::vector<std::uint8_t>> aes_ccm_crypt(
    std::span<const std::uint8_t> key, std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> input, bool encrypt) {
    if ((key.size() != 16 && key.size() != 24 && key.size() != 32) || nonce.size() != 12 ||
        input.size() > 0xFFFFFF || (!encrypt && input.size() < 16)) {
        return core::fail({core::ErrorCode::configuration, "invalid AES-CCM parameters"});
    }
    AES_KEY aes_key{};
    if (AES_set_encrypt_key(key.data(), static_cast<int>(key.size() * 8), &aes_key) != 0) {
        return core::fail(crypto_error("failed to initialize AES-CCM key"));
    }
    const auto ciphertext_size = encrypt ? input.size() : input.size() - 16;
    std::array<std::uint8_t, 16> counter{};
    counter[0] = 2; // L = 15 - nonce length = 3, so the counter flag is L - 1.
    std::copy(nonce.begin(), nonce.end(), counter.begin() + 1);
    std::array<std::uint8_t, 16> mac{};
    std::array<std::uint8_t, 16> block{};
    block[0] = static_cast<std::uint8_t>(((16 - 2) / 2) << 3 | 2);
    std::copy(nonce.begin(), nonce.end(), block.begin() + 1);
    for (int index = 0; index < 3; ++index) {
        block[15 - index] = static_cast<std::uint8_t>(ciphertext_size >> (index * 8));
    }
    AES_encrypt(block.data(), mac.data(), &aes_key);

    std::vector<std::uint8_t> output(ciphertext_size);
    for (std::size_t offset = 0; offset < ciphertext_size; offset += 16) {
        const auto count = std::min<std::size_t>(16, ciphertext_size - offset);
        std::array<std::uint8_t, 16> input_block{};
        std::copy_n(input.data() + offset, count, input_block.data());
        const auto block_counter = 1 + offset / 16;
        counter[13] = static_cast<std::uint8_t>(block_counter >> 16);
        counter[14] = static_cast<std::uint8_t>(block_counter >> 8);
        counter[15] = static_cast<std::uint8_t>(block_counter);
        AES_encrypt(counter.data(), block.data(), &aes_key);
        for (std::size_t index = 0; index < count; ++index) {
            output[offset + index] = input_block[index] ^ block[index];
        }
        std::array<std::uint8_t, 16> plaintext_block{};
        if (!encrypt) {
            std::copy_n(output.data() + offset, count, plaintext_block.data());
        }
        for (std::size_t index = 0; index < 16; ++index) {
            mac[index] ^= encrypt ? input_block[index] : plaintext_block[index];
        }
        AES_encrypt(mac.data(), mac.data(), &aes_key);
    }
    counter[13] = counter[14] = counter[15] = 0;
    AES_encrypt(counter.data(), block.data(), &aes_key);
    for (std::size_t index = 0; index < 16; ++index) {
        mac[index] ^= block[index];
    }
    if (!encrypt && CRYPTO_memcmp(mac.data(), input.data() + ciphertext_size, 16) != 0) {
        return core::fail({core::ErrorCode::authentication, "AES-CCM authentication failed"});
    }
    if (encrypt) {
        output.insert(output.end(), mac.begin(), mac.end());
    }
    return output;
}

} // namespace

core::Result<CipherMethod> cipher_method(std::string_view name) {
    std::string canonical;
    canonical.reserve(name.size());
    for (const auto character : name) {
        canonical.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
    }

    if (canonical == "aes-128-gcm") {
        return CipherMethod{CipherKind::aead, EVP_aead_aes_128_gcm(), nullptr, 16, 16, 12,
                            kAeadTagSize, 0, false, "aes-128-gcm"};
    }
    if (canonical == "aes-192-gcm") {
        return CipherMethod{CipherKind::aead, EVP_aead_aes_192_gcm(), nullptr, 24, 24, 12,
                            kAeadTagSize, 0, false, "aes-192-gcm"};
    }
    if (canonical == "aes-256-gcm") {
        return CipherMethod{CipherKind::aead, EVP_aead_aes_256_gcm(), nullptr, 32, 32, 12,
                            kAeadTagSize, 0, false, "aes-256-gcm"};
    }
    if (canonical == "chacha20-ietf-poly1305") {
        return CipherMethod{CipherKind::aead, EVP_aead_chacha20_poly1305(), nullptr, 32, 32, 12,
                            kAeadTagSize, 0, false, "chacha20-ietf-poly1305"};
    }
    if (canonical == "xchacha20-ietf-poly1305") {
        return CipherMethod{CipherKind::aead, EVP_aead_xchacha20_poly1305(), nullptr, 32, 32, 24,
                            kAeadTagSize, 0, false, "xchacha20-ietf-poly1305"};
    }
    if (canonical == "chacha8-ietf-poly1305") {
        return CipherMethod{CipherKind::aead, nullptr, nullptr, 32, 32, 12, kAeadTagSize, 0,
                            false, "chacha8-ietf-poly1305"};
    }
    if (canonical == "xchacha8-ietf-poly1305") {
        return CipherMethod{CipherKind::aead, nullptr, nullptr, 32, 32, 24, kAeadTagSize, 0,
                            false, "xchacha8-ietf-poly1305"};
    }
    if (canonical == "aes-128-ccm") {
        return CipherMethod{CipherKind::aead, nullptr, nullptr, 16, 16, 12, kAeadTagSize, 0,
                            false, "aes-128-ccm"};
    }
    if (canonical == "aes-192-ccm") {
        return CipherMethod{CipherKind::aead, nullptr, nullptr, 24, 24, 12, kAeadTagSize, 0,
                            false, "aes-192-ccm"};
    }
    if (canonical == "aes-256-ccm") {
        return CipherMethod{CipherKind::aead, nullptr, nullptr, 32, 32, 12, kAeadTagSize, 0,
                            false, "aes-256-ccm"};
    }

    if (canonical == "2022-blake3-aes-128-gcm") {
        return CipherMethod{CipherKind::aead, EVP_aead_aes_128_gcm(), nullptr, 16, 16, 12,
                            kAeadTagSize, 0, true, "2022-blake3-aes-128-gcm"};
    }
    if (canonical == "2022-blake3-aes-256-gcm") {
        return CipherMethod{CipherKind::aead, EVP_aead_aes_256_gcm(), nullptr, 32, 32, 12,
                            kAeadTagSize, 0, true, "2022-blake3-aes-256-gcm"};
    }
    if (canonical == "2022-blake3-chacha20-poly1305") {
        return CipherMethod{CipherKind::aead, EVP_aead_chacha20_poly1305(), nullptr, 32, 32, 12,
                            kAeadTagSize, 0, true, "2022-blake3-chacha20-poly1305"};
    }

    if (canonical == "chacha20") {
        return CipherMethod{CipherKind::stream, nullptr, nullptr, 32, 0, 0, 0, 8, false,
                            "chacha20"};
    }
    if (canonical == "chacha20-ietf") {
        return CipherMethod{CipherKind::stream, nullptr, nullptr, 32, 0, 0, 0, 12, false,
                            "chacha20-ietf"};
    }
    if (canonical == "xchacha20") {
        return CipherMethod{CipherKind::stream, nullptr, nullptr, 32, 0, 0, 0, 24, false,
                            "xchacha20"};
    }

    const auto stream = legacy_cipher(canonical);
    if (stream != nullptr) {
        const auto key_size = configured_legacy_key_size(canonical);
        return CipherMethod{CipherKind::stream, nullptr, stream, key_size, 0, 0, 0,
                            kAesBlockSize, false, canonical};
    }

    return core::fail({core::ErrorCode::configuration,
                       "unsupported Shadowsocks cipher method: " + std::string(name)});
}

core::Result<std::vector<std::uint8_t>> derive_aead_subkey(
    std::string_view method, std::string_view password, std::span<const std::uint8_t> salt) {
    const auto method_result = cipher_method(method);
    if (!method_result || method_result.value().kind != CipherKind::aead ||
        method_result.value().shadowsocks_2022) {
        return core::fail(method_result ? core::Error{core::ErrorCode::configuration,
                                                       "Shadowsocks method is not AEAD"}
                                         : method_result.error());
    }
    if (password.empty() || salt.size() != method_result.value().salt_size) {
        return core::fail(
            {core::ErrorCode::configuration, "Shadowsocks password or salt length is invalid"});
    }
    auto master_key = md5_chain(password, method_result.value().key_size);
    if (!master_key) {
        return core::fail(master_key.error());
    }
    return hkdf_sha1(master_key.value(), salt, "ss-subkey", method_result.value().key_size);
}

core::Result<std::vector<std::uint8_t>> derive_shadowsocks_2022_session_key(
    std::string_view method, std::string_view password, std::span<const std::uint8_t> salt) {
    const auto method_result = cipher_method(method);
    if (!method_result || !method_result.value().shadowsocks_2022 ||
        salt.size() != method_result.value().salt_size) {
        return core::fail(method_result ? core::Error{core::ErrorCode::configuration,
                                                       "invalid Shadowsocks 2022 session salt"}
                                         : method_result.error());
    }
    return derive_shadowsocks_2022_subkey(method, password, salt);
}

core::Result<std::vector<std::uint8_t>> decode_shadowsocks_2022_psk(
    std::string_view method, std::string_view password) {
    const auto method_result = cipher_method(method);
    if (!method_result || !method_result.value().shadowsocks_2022) {
        return core::fail(method_result ? core::Error{core::ErrorCode::configuration,
                                                       "Shadowsocks method is not Shadowsocks 2022"}
                                         : method_result.error());
    }
    const auto decoded = core::base64_decode(password);
    if (!decoded || decoded->size() != method_result.value().key_size) {
        return core::fail({core::ErrorCode::configuration,
                           "Shadowsocks 2022 password must be Base64 encoded key material"});
    }
    return std::vector<std::uint8_t>(decoded.value().begin(), decoded.value().end());
}

core::Result<std::vector<std::uint8_t>> derive_shadowsocks_2022_subkey(
    std::string_view method, std::string_view password, std::span<const std::uint8_t> salt) {
    const auto method_result = cipher_method(method);
    if (!method_result || !method_result.value().shadowsocks_2022) {
        return core::fail(method_result ? core::Error{core::ErrorCode::configuration,
                                                       "Shadowsocks method is not Shadowsocks 2022"}
                                         : method_result.error());
    }
    auto decoded = decode_shadowsocks_2022_psk(method, password);
    if (!decoded) {
        return core::fail(decoded.error());
    }

    std::vector<std::uint8_t> input;
    input.reserve(decoded.value().size() + salt.size());
    input.insert(input.end(), decoded.value().begin(), decoded.value().end());
    input.insert(input.end(), salt.begin(), salt.end());

    blake3_hasher hasher;
    blake3_hasher_init_derive_key(&hasher, "shadowsocks 2022 session subkey");
    blake3_hasher_update(&hasher, input.data(), input.size());
    std::vector<std::uint8_t> output(method_result.value().key_size);
    blake3_hasher_finalize(&hasher, output.data(), output.size());
    return output;
}

core::Result<std::vector<std::uint8_t>> derive_legacy_key(std::string_view method,
                                                          std::string_view password,
                                                          std::span<const std::uint8_t> iv) {
    const auto method_result = cipher_method(method);
    if (!method_result || method_result.value().kind != CipherKind::stream) {
        return core::fail(method_result ? core::Error{core::ErrorCode::configuration,
                                                       "Shadowsocks method is not a stream cipher"}
                                         : method_result.error());
    }
    if (password.empty() || iv.size() != method_result.value().iv_size) {
        return core::fail(
            {core::ErrorCode::configuration, "Shadowsocks password or IV length is invalid"});
    }
    auto master_key = md5_chain(password, method_result.value().key_size);
    if (!master_key) {
        return core::fail(master_key.error());
    }
    return master_key;
}

core::Result<std::vector<std::uint8_t>> aead_encrypt(std::string_view method,
                                                     std::span<const std::uint8_t> key,
                                                     std::span<const std::uint8_t> nonce,
                                                     std::span<const std::uint8_t> plaintext) {
    const auto method_result = cipher_method(method);
    if (!method_result || method_result.value().kind != CipherKind::aead) {
        return core::fail(method_result ? core::Error{core::ErrorCode::configuration,
                                                       "Shadowsocks method is not AEAD"}
                                         : method_result.error());
    }
    const auto &spec = method_result.value();
    if (key.size() != spec.key_size || nonce.size() != spec.nonce_size || plaintext.size() > INT_MAX) {
        return core::fail(
            {core::ErrorCode::configuration, "Shadowsocks key, nonce, or plaintext is invalid"});
    }
    if (is_chacha8_method(spec.name)) {
        return chacha8_poly1305_crypt(key, nonce, plaintext, true, 8);
    }
    if (is_aes_ccm_method(spec.name)) {
        return aes_ccm_crypt(key, nonce, plaintext, true);
    }
    AeadContext context(EVP_AEAD_CTX_new(spec.aead, key.data(), key.size(),
                                         EVP_AEAD_DEFAULT_TAG_LENGTH),
                        EVP_AEAD_CTX_free);
    if (!context) {
        return core::fail(crypto_error("failed to initialize Shadowsocks encryption"));
    }
    std::vector<std::uint8_t> output(plaintext.size() + spec.overhead);
    std::size_t written = 0;
    if (EVP_AEAD_CTX_seal(context.get(), output.data(), &written, output.size(), nonce.data(),
                          nonce.size(), plaintext.data(), plaintext.size(), nullptr, 0) != 1) {
        return core::fail(crypto_error("failed to encrypt Shadowsocks data"));
    }
    output.resize(written);
    return output;
}

core::Result<std::vector<std::uint8_t>> aead_decrypt(std::string_view method,
                                                     std::span<const std::uint8_t> key,
                                                     std::span<const std::uint8_t> nonce,
                                                     std::span<const std::uint8_t> ciphertext) {
    const auto method_result = cipher_method(method);
    if (!method_result || method_result.value().kind != CipherKind::aead) {
        return core::fail(method_result ? core::Error{core::ErrorCode::configuration,
                                                       "Shadowsocks method is not AEAD"}
                                         : method_result.error());
    }
    const auto &spec = method_result.value();
    if (key.size() != spec.key_size || nonce.size() != spec.nonce_size ||
        ciphertext.size() < spec.overhead || ciphertext.size() - spec.overhead > INT_MAX) {
        return core::fail(
            {core::ErrorCode::protocol_framing, "Shadowsocks key, nonce, or ciphertext is invalid"});
    }
    if (is_chacha8_method(spec.name)) {
        return chacha8_poly1305_crypt(key, nonce, ciphertext, false, 8);
    }
    if (is_aes_ccm_method(spec.name)) {
        return aes_ccm_crypt(key, nonce, ciphertext, false);
    }
    AeadContext context(EVP_AEAD_CTX_new(spec.aead, key.data(), key.size(),
                                         EVP_AEAD_DEFAULT_TAG_LENGTH),
                        EVP_AEAD_CTX_free);
    if (!context) {
        return core::fail(crypto_error("failed to initialize Shadowsocks decryption"));
    }
    std::vector<std::uint8_t> output(ciphertext.size() - spec.overhead);
    std::size_t written = 0;
    if (EVP_AEAD_CTX_open(context.get(), output.data(), &written, output.size(), nonce.data(),
                          nonce.size(), ciphertext.data(), ciphertext.size(), nullptr, 0) != 1) {
        return core::fail(crypto_error("Shadowsocks authentication tag verification failed"));
    }
    output.resize(written);
    return output;
}

core::Result<std::vector<std::uint8_t>> xchacha20_poly1305_encrypt(
    std::span<const std::uint8_t> key, std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> plaintext) {
    constexpr std::size_t kNonceSize = 24;
    constexpr std::size_t kKeySize = 32;
    if (key.size() != kKeySize || nonce.size() != kNonceSize || plaintext.size() > INT_MAX) {
        return core::fail({core::ErrorCode::configuration,
                           "invalid XChaCha20-Poly1305 parameters"});
    }
    AeadContext context(EVP_AEAD_CTX_new(EVP_aead_xchacha20_poly1305(), key.data(), key.size(),
                                         EVP_AEAD_DEFAULT_TAG_LENGTH),
                        EVP_AEAD_CTX_free);
    if (!context) {
        return core::fail(crypto_error("failed to initialize XChaCha20-Poly1305 encryption"));
    }
    std::vector<std::uint8_t> output(plaintext.size() + kAeadTagSize);
    std::size_t written = 0;
    if (EVP_AEAD_CTX_seal(context.get(), output.data(), &written, output.size(), nonce.data(),
                          nonce.size(), plaintext.data(), plaintext.size(), nullptr, 0) != 1) {
        return core::fail(crypto_error("failed to encrypt XChaCha20-Poly1305 data"));
    }
    output.resize(written);
    return output;
}

core::Result<std::vector<std::uint8_t>> xchacha20_poly1305_decrypt(
    std::span<const std::uint8_t> key, std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> ciphertext) {
    constexpr std::size_t kNonceSize = 24;
    constexpr std::size_t kKeySize = 32;
    if (key.size() != kKeySize || nonce.size() != kNonceSize || ciphertext.size() < kAeadTagSize ||
        ciphertext.size() - kAeadTagSize > INT_MAX) {
        return core::fail({core::ErrorCode::protocol_framing,
                           "invalid XChaCha20-Poly1305 parameters"});
    }
    AeadContext context(EVP_AEAD_CTX_new(EVP_aead_xchacha20_poly1305(), key.data(), key.size(),
                                         EVP_AEAD_DEFAULT_TAG_LENGTH),
                        EVP_AEAD_CTX_free);
    if (!context) {
        return core::fail(crypto_error("failed to initialize XChaCha20-Poly1305 decryption"));
    }
    std::vector<std::uint8_t> output(ciphertext.size() - kAeadTagSize);
    std::size_t written = 0;
    if (EVP_AEAD_CTX_open(context.get(), output.data(), &written, output.size(), nonce.data(),
                          nonce.size(), ciphertext.data(), ciphertext.size(), nullptr, 0) != 1) {
        return core::fail(crypto_error("XChaCha20-Poly1305 authentication failed"));
    }
    output.resize(written);
    return output;
}

struct LegacyStreamCipher::Impl {
    CipherContext context{nullptr, EVP_CIPHER_CTX_free};
    CipherContext block_context{nullptr, EVP_CIPHER_CTX_free};
    std::unique_ptr<Botan::StreamCipher> chacha_cipher;
    std::array<std::uint8_t, kAesBlockSize> feedback{};
    std::size_t feedback_offset = 0;
    std::array<std::uint8_t, 64> keystream{};
    bool chacha = false;
    bool cfb = false;
    bool encrypt = true;
};

LegacyStreamCipher::LegacyStreamCipher(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

LegacyStreamCipher::LegacyStreamCipher(LegacyStreamCipher &&other) noexcept
    : impl_(std::move(other.impl_)) {}

LegacyStreamCipher &LegacyStreamCipher::operator=(LegacyStreamCipher &&other) noexcept {
    impl_ = std::move(other.impl_);
    return *this;
}

LegacyStreamCipher::~LegacyStreamCipher() = default;

core::Result<LegacyStreamCipher> LegacyStreamCipher::create(std::string_view method,
                                                             std::span<const std::uint8_t> key,
                                                             std::span<const std::uint8_t> iv,
                                                             bool encrypt) {
    const auto spec = cipher_method(method);
    if (!spec) {
        return core::fail(spec.error());
    }
    if (spec.value().kind != CipherKind::stream || key.size() != spec.value().key_size ||
        iv.size() != spec.value().iv_size) {
        return core::fail({core::ErrorCode::configuration,
                           "invalid Shadowsocks legacy stream cipher parameters"});
    }
    auto impl = std::make_unique<Impl>();
    impl->encrypt = encrypt;
    impl->context = CipherContext(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!impl->context) {
        return core::fail(crypto_error("failed to allocate Shadowsocks stream cipher"));
    }
    if (spec.value().name == "chacha20" || spec.value().name == "chacha20-ietf" ||
        spec.value().name == "xchacha20") {
        impl->chacha = true;
        try {
            impl->chacha_cipher = create_chacha_cipher(20, key, iv);
            if (!impl->chacha_cipher) {
                return core::fail(crypto_error("Botan ChaCha is unavailable"));
            }
        } catch (const std::exception &error) {
            return core::fail(crypto_error(std::string("failed to initialize ChaCha: ") +
                                           error.what()));
        }
        return LegacyStreamCipher(std::move(impl));
    }
    if (spec.value().name == "rc4-md5") {
        std::array<std::uint8_t, MD5_DIGEST_LENGTH> rc4_key{};
        std::vector<std::uint8_t> input(key.begin(), key.end());
        input.insert(input.end(), iv.begin(), iv.end());
        MD5(input.data(), input.size(), rc4_key.data());
        if (EVP_EncryptInit_ex(impl->context.get(), spec.value().stream, nullptr, rc4_key.data(),
                               nullptr) != 1) {
            return core::fail(crypto_error("failed to initialize RC4-MD5"));
        }
        return LegacyStreamCipher(std::move(impl));
    }
    if (spec.value().name.find("-cfb") != std::string::npos) {
        impl->cfb = true;
        impl->block_context = CipherContext(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if (!impl->block_context ||
            EVP_EncryptInit_ex(impl->block_context.get(), spec.value().stream, nullptr, key.data(),
                               nullptr) != 1 ||
            EVP_CIPHER_CTX_set_padding(impl->block_context.get(), 0) != 1) {
            return core::fail(crypto_error("failed to initialize Shadowsocks CFB cipher"));
        }
        std::copy(iv.begin(), iv.end(), impl->feedback.begin());
        return LegacyStreamCipher(std::move(impl));
    }
    if (EVP_EncryptInit_ex(impl->context.get(), spec.value().stream, nullptr, key.data(),
                           iv.data()) != 1) {
        return core::fail(crypto_error("failed to initialize Shadowsocks legacy cipher"));
    }
    (void)encrypt;
    return LegacyStreamCipher(std::move(impl));
}

core::Status LegacyStreamCipher::update(std::span<std::uint8_t> data) noexcept {
    if (!impl_ || data.size() > INT_MAX) {
        return core::fail({core::ErrorCode::transport_io, "Shadowsocks stream cipher is closed"});
    }
    if (data.empty()) {
        return {};
    }
    if (impl_->chacha) {
        try {
            impl_->chacha_cipher->cipher1(data);
        } catch (const std::exception &error) {
            return core::fail(crypto_error(std::string("failed to process ChaCha data: ") +
                                           error.what()));
        }
        return {};
    }
    if (impl_->cfb) {
        for (auto &byte : data) {
            if (impl_->feedback_offset == 0) {
                int written = 0;
                std::array<std::uint8_t, kAesBlockSize> encrypted{};
                if (EVP_EncryptUpdate(impl_->block_context.get(), encrypted.data(), &written,
                                      impl_->feedback.data(), static_cast<int>(kAesBlockSize)) != 1 ||
                    written != static_cast<int>(kAesBlockSize)) {
                    return core::fail(crypto_error("failed to process Shadowsocks CFB data"));
                }
                std::copy(encrypted.begin(), encrypted.end(), impl_->keystream.begin());
            }
            const auto encrypted = impl_->keystream[impl_->feedback_offset];
            const auto input = byte;
            byte = static_cast<std::uint8_t>(input ^ encrypted);
            impl_->feedback[impl_->feedback_offset] =
                impl_->encrypt ? byte : input;
            impl_->feedback_offset = (impl_->feedback_offset + 1) % kAesBlockSize;
        }
        return {};
    }
    int written = 0;
    if (EVP_EncryptUpdate(impl_->context.get(), data.data(), &written, data.data(),
                          static_cast<int>(data.size())) != 1 ||
        written != static_cast<int>(data.size())) {
        return core::fail(crypto_error("failed to process Shadowsocks stream data"));
    }
    return {};
}

bool random_bytes(std::span<std::uint8_t> bytes) noexcept {
    return bytes.size() <= INT_MAX && RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) == 1;
}

void increment_nonce(std::span<std::uint8_t> nonce) noexcept {
    for (auto &byte : nonce) {
        if (++byte != 0) {
            break;
        }
    }
}

} // namespace clash_native::transport::shadowsocks
