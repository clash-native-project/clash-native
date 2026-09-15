cmake_minimum_required(VERSION 3.24)

project(clash-native VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(boost_asio CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(tl-expected CONFIG REQUIRED)
find_package(Threads REQUIRED)

add_library(clash-native-core STATIC
    src/dns/dns_codec.cpp
    src/dns/dns_policy_router.cpp
    src/dns/resolver_service.cpp
    src/dns/dns_server.cpp
    src/dns/fake_ip_store.cpp
    src/dns/resolver_graph.cpp
    src/dns/system_resolver.cpp
    src/net/tcp_stream.cpp
    src/outbound/builtin_outbound.cpp
    src/outbound/outbound_registry.cpp
    src/observability/connection_registry.cpp
    src/platform/platform_adapter.cpp
    src/proxy/proxy_server.cpp
    src/proxy/tcp_relay.cpp
    src/router/traffic_router.cpp
    src/runtime/asio_runtime.cpp
    src/runtime/runtime_set.cpp
)

target_include_directories(clash-native-core
    PUBLIC
        include
)

target_compile_features(clash-native-core PUBLIC cxx_std_20)

target_link_libraries(clash-native-core
    PUBLIC
        Boost::asio
        Threads::Threads
        tl::expected
    PRIVATE
        fmt::fmt
)

if(WIN32)
    target_link_libraries(clash-native-core PUBLIC ws2_32 mswsock)
endif()

target_compile_definitions(clash-native-core
    PUBLIC
        CLASH_NATIVE_VERSION="${PROJECT_VERSION}"
)

add_executable(clash-native
    src/app/application.cpp
    src/main.cpp
)

target_include_directories(clash-native
    PRIVATE
        include
)

target_compile_features(clash-native PRIVATE cxx_std_20)

target_link_libraries(clash-native
    PRIVATE
        clash-native-core
        spdlog::spdlog_header_only
)

if(BUILD_TESTING)
    find_package(GTest CONFIG REQUIRED)
    include(GoogleTest)

    add_executable(clash-native-test-host
        tests/host/test_host.cpp
    )

    target_include_directories(clash-native-test-host
        PRIVATE
            include
    )

    target_compile_features(clash-native-test-host PRIVATE cxx_std_20)

    target_link_libraries(clash-native-test-host
        PRIVATE
            clash-native-core
    )

    add_executable(clash-native-tests
        tests/core/channel_test.cpp
        tests/core/error_test.cpp
        tests/core/outbound_contract_test.cpp
        tests/core/version_test.cpp
        tests/dns/dns_test.cpp
        tests/dns/dns_server_test.cpp
        tests/dns/resolver_graph_test.cpp
        tests/observability/connection_registry_test.cpp
        tests/outbound/outbound_registry_test.cpp
        tests/platform/platform_adapter_test.cpp
        tests/proxy/proxy_server_test.cpp
        tests/proxy/stage1_proxy_test.cpp
        tests/proxy/socks5_proxy_test.cpp
        tests/router/traffic_router_test.cpp
        tests/runtime/asio_runtime_test.cpp
        tests/runtime/runtime_set_test.cpp
    )

    target_include_directories(clash-native-tests
        PRIVATE
            include
    )

    target_compile_features(clash-native-tests PRIVATE cxx_std_20)

    target_link_libraries(clash-native-tests
        PRIVATE
            clash-native-core
            GTest::gtest_main
    )

    gtest_discover_tests(clash-native-tests)

    add_test(
        NAME clash-native.version
        COMMAND clash-native --version
    )
    add_test(
        NAME clash-native.startup
        COMMAND clash-native
    )
endif()
