#include <clash_native/app/application.hpp>
#include <clash_native/core/version.hpp>

#include <boost/asio/ip/address.hpp>

#include <charconv>
#include <cstdint>
#include <exception>
#include <iostream>
#include <string_view>

namespace {

void print_usage(std::string_view program_name) {
    std::cout << "Usage: " << program_name << " [--help|--version|--listen <address:port>]\n";
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
    if (argc > 1) {
        const std::string_view argument{argv[1]};

        if (argument == "--version") {
            std::cout << "clash-native " << clash_native::core::version << "\n";
            return 0;
        }

        if (argument == "--help") {
            print_usage(argv[0]);
            return 0;
        }

        if (argument == "--listen") {
            if (argc != 3) {
                std::cerr << "--listen requires an address:port value.\n";
                print_usage(argv[0]);
                return 2;
            }

            boost::asio::ip::tcp::endpoint endpoint;
            if (!parse_endpoint(argv[2], endpoint)) {
                std::cerr << "Invalid listen endpoint: " << argv[2] << "\n";
                print_usage(argv[0]);
                return 2;
            }

            try {
                return clash_native::app::Application{}.run({.listen_endpoint = endpoint});
            } catch (const std::exception &error) {
                std::cerr << "clash-native error: " << error.what() << "\n";
                return 1;
            }
        }

        std::cerr << "Unknown argument: " << argument << "\n";
        print_usage(argv[0]);
        return 2;
    }

    try {
        return clash_native::app::Application{}.run();
    } catch (const std::exception &error) {
        std::cerr << "clash-native error: " << error.what() << "\n";
        return 1;
    }
}
