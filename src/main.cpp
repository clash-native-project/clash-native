#include <clash_native/app/application.hpp>
#include <clash_native/core/version.hpp>

#include <boost/asio/ip/address.hpp>

#include <charconv>
#include <cstdint>
#include <exception>
#include <string_view>
#include <utility>

#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

namespace {

void print_usage(std::string_view program_name) {
    spdlog::info("Usage: {} [--help|--version|--listen <address:port>]", program_name);
}

bool parse_port(std::string_view text, std::uint16_t &port) {
    unsigned int value = 0;
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size() || value > 65535) {
        return false;
    }

    port = static_cast<std::uint16_t>(value);
    return true;
}

bool parse_endpoint(std::string_view text, boost::asio::ip::tcp::endpoint &endpoint) {
    std::string_view host;
    std::string_view port_text;

    if (!text.empty() && text.front() == '[') {
        const auto close = text.find(']');
        if (close == std::string_view::npos || close + 1 >= text.size() || text[close + 1] != ':') {
            return false;
        }
        host = text.substr(1, close - 1);
        port_text = text.substr(close + 2);
    } else {
        const auto separator = text.rfind(':');
        if (separator == std::string_view::npos) {
            host = "127.0.0.1";
            port_text = text;
        } else {
            host = text.substr(0, separator);
            port_text = text.substr(separator + 1);
        }
    }

    if (host.empty() || port_text.empty()) {
        return false;
    }

    std::uint16_t port = 0;
    if (!parse_port(port_text, port)) {
        return false;
    }

    boost::system::error_code error;
    const auto address = boost::asio::ip::make_address(host, error);
    if (error) {
        return false;
    }

    endpoint = {address, port};
    return true;
}

} // namespace

int main(int argc, char **argv) {
    auto logger = spdlog::stdout_color_mt("clash-native");
    logger->set_pattern("%v");
    logger->set_level(spdlog::level::info);
    logger->flush_on(spdlog::level::info);
    spdlog::set_default_logger(std::move(logger));

    if (argc > 1) {
        const std::string_view argument{argv[1]};

        if (argument == "--version") {
            spdlog::info("clash-native {}", clash_native::core::version);
            return 0;
        }

        if (argument == "--help") {
            print_usage(argv[0]);
            return 0;
        }

        if (argument == "--listen") {
            if (argc != 3) {
                spdlog::error("--listen requires an address:port value.");
                print_usage(argv[0]);
                return 2;
            }

            boost::asio::ip::tcp::endpoint endpoint;
            if (!parse_endpoint(argv[2], endpoint)) {
                spdlog::error("Invalid listen endpoint: {}", argv[2]);
                print_usage(argv[0]);
                return 2;
            }

            try {
                return clash_native::app::Application{}.run({.listen_endpoint = endpoint});
            } catch (const std::exception &error) {
                spdlog::error("clash-native error: {}", error.what());
                return 1;
            }
        }

        spdlog::error("Unknown argument: {}", argument);
        print_usage(argv[0]);
        return 2;
    }

    try {
        return clash_native::app::Application{}.run();
    } catch (const std::exception &error) {
        spdlog::error("clash-native error: {}", error.what());
        return 1;
    }
}
