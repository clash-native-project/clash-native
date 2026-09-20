cmake_minimum_required(VERSION 3.24)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

project(clash-native VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(boost_asio CONFIG REQUIRED)
find_package(boost_beast CONFIG REQUIRED)
find_package(c-ares CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)
find_package(kcp CONFIG REQUIRED)
find_package(OpenSSL CONFIG REQUIRED)
find_package(blake3 CONFIG REQUIRED)
find_package(botan CONFIG REQUIRED)
find_package(nghttp3 CONFIG REQUIRED)
find_package(protobuf CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(Snappy CONFIG REQUIRED)
find_package(tl-expected CONFIG REQUIRED)
find_package(Threads REQUIRED)

set(CLASH_NATIVE_CA_BUNDLE "${PROJECT_SOURCE_DIR}/third_party/curl-ca/cacert.pem")
set(CLASH_NATIVE_CA_BUNDLE_TEMPLATE
    "${PROJECT_SOURCE_DIR}/cmake/builtin_ca_bundle.cpp.in")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${CLASH_NATIVE_CA_BUNDLE}"
    "${CLASH_NATIVE_CA_BUNDLE_TEMPLATE}"
)
file(READ "${CLASH_NATIVE_CA_BUNDLE}" CLASH_NATIVE_CA_BUNDLE_PEM)
file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/generated")
configure_file(
    "${CLASH_NATIVE_CA_BUNDLE_TEMPLATE}"
    "${PROJECT_BINARY_DIR}/generated/builtin_ca_bundle.cpp"
    @ONLY
)

set(CLASH_NATIVE_VCPKG_TRIPLET_ROOT
    "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}")
find_path(CLASH_NATIVE_NGHTTP2_INCLUDE_DIR
    NAMES nghttp2/nghttp2.h
    PATHS "${CLASH_NATIVE_VCPKG_TRIPLET_ROOT}/include"
    NO_DEFAULT_PATH
    REQUIRED
)
find_library(CLASH_NATIVE_NGHTTP2_LIBRARY_RELEASE
    NAMES nghttp2
    PATHS "${CLASH_NATIVE_VCPKG_TRIPLET_ROOT}/lib"
    NO_DEFAULT_PATH
    REQUIRED
)
find_library(CLASH_NATIVE_NGHTTP2_LIBRARY_DEBUG
    NAMES nghttp2
    PATHS "${CLASH_NATIVE_VCPKG_TRIPLET_ROOT}/debug/lib"
    NO_DEFAULT_PATH
)
if(NOT CLASH_NATIVE_NGHTTP2_LIBRARY_DEBUG)
    set(CLASH_NATIVE_NGHTTP2_LIBRARY_DEBUG
        "${CLASH_NATIVE_NGHTTP2_LIBRARY_RELEASE}")
endif()
add_library(clash-native-nghttp2 UNKNOWN IMPORTED GLOBAL)
set_target_properties(clash-native-nghttp2 PROPERTIES
    IMPORTED_CONFIGURATIONS "DEBUG;RELEASE"
    IMPORTED_LOCATION_DEBUG "${CLASH_NATIVE_NGHTTP2_LIBRARY_DEBUG}"
    IMPORTED_LOCATION_RELEASE "${CLASH_NATIVE_NGHTTP2_LIBRARY_RELEASE}"
    IMPORTED_LOCATION_RELWITHDEBINFO "${CLASH_NATIVE_NGHTTP2_LIBRARY_RELEASE}"
    IMPORTED_LOCATION_MINSIZEREL "${CLASH_NATIVE_NGHTTP2_LIBRARY_RELEASE}"
    INTERFACE_INCLUDE_DIRECTORIES "${CLASH_NATIVE_NGHTTP2_INCLUDE_DIR}"
    INTERFACE_COMPILE_DEFINITIONS "NGHTTP2_NO_SSIZE_T"
)

find_path(CLASH_NATIVE_BORINGSSL_INCLUDE_DIR
    NAMES openssl/base.h
    PATHS "${CLASH_NATIVE_VCPKG_TRIPLET_ROOT}/include"
    NO_DEFAULT_PATH
    REQUIRED
)
set(CLASH_NATIVE_BORINGSSL_LIBRARIES OpenSSL::SSL OpenSSL::Crypto)

add_library(clash-native-boringssl INTERFACE)
target_include_directories(clash-native-boringssl SYSTEM INTERFACE
    "${CLASH_NATIVE_BORINGSSL_INCLUDE_DIR}")
target_link_libraries(clash-native-boringssl INTERFACE
    ${CLASH_NATIVE_BORINGSSL_LIBRARIES})

include(FetchContent)
set(CLASH_NATIVE_BUILD_TESTING "${BUILD_TESTING}")
function(clash_native_add_ngtcp2)
    set(BUILD_TESTING OFF)
    set(ENABLE_LIB_ONLY ON)
    set(ENABLE_STATIC_LIB ON)
    set(ENABLE_SHARED_LIB OFF)
    set(ENABLE_OPENSSL OFF)
    set(ENABLE_BORINGSSL ON)
    set(BORINGSSL_INCLUDE_DIR "${CLASH_NATIVE_BORINGSSL_INCLUDE_DIR}")
    set(BORINGSSL_LIBRARIES ${CLASH_NATIVE_BORINGSSL_LIBRARIES})

    FetchContent_Declare(ngtcp2
        GIT_REPOSITORY https://github.com/ngtcp2/ngtcp2.git
        GIT_TAG 843aa72100b508e192f119439a943028b0c6f030
    )
    FetchContent_MakeAvailable(ngtcp2)
endfunction()
clash_native_add_ngtcp2()
set(BUILD_TESTING "${CLASH_NATIVE_BUILD_TESTING}" CACHE BOOL "Build clash-native tests" FORCE)

add_library(clash-native-core STATIC
    "${PROJECT_BINARY_DIR}/generated/builtin_ca_bundle.cpp"
    src/core/base64.cpp
    src/dns/dns_codec.cpp
    src/dns/dns_policy_router.cpp
    src/dns/dns_query_service.cpp
    src/dns/dns_upstream.cpp
    src/dns/address_resolver.cpp
    src/dns/bootstrap_resolver.cpp
    src/dns/bootstrap_dns_transport.cpp
    src/dns/resolver_service.cpp
    src/dns/dns_transport.cpp
    src/dns/dot_dns_transport.cpp
    src/dns/doh1_dns_transport.cpp
    src/dns/doh2_dns_transport.cpp
    src/dns/doq_dns_transport.cpp
    src/dns/doh3_dns_transport.cpp
    src/dns/quic_dns_transport.cpp
    src/dns/dns_server.cpp
    src/dns/fake_ip_store.cpp
    src/dns/resolver_graph.cpp
    src/dns/system_resolver.cpp
    src/net/tcp_stream.cpp
    src/net/tls_stream.cpp
    src/net/udp_stream.cpp
    src/transport/http1_client.cpp
    src/transport/http2_client.cpp
    src/transport/http3_client.cpp
    src/transport/grpc_client.cpp
    src/transport/kcp_client.cpp
    src/transport/websocket_client.cpp
    src/transport/shadowsocks/crypto.cpp
    src/transport/shadowsocks/aead_packet.cpp
    src/transport/shadowsocks/legacy_packet.cpp
    src/transport/shadowsocks/legacy_stream.cpp
    src/transport/shadowsocks/ss2022_packet.cpp
    src/transport/shadowsocks/ss2022_stream.cpp
    src/transport/shadowsocks/simple_obfs.cpp
    src/transport/shadowsocks/websocket_plugin.cpp
    src/transport/shadowsocks/udp_over_tcp.cpp
    src/transport/shadowsocks/kcptun.cpp
    src/transport/shadowsocks/kcptun_session.cpp
    src/transport/shadowsocks/kcptun_packet_codec.cpp
    src/transport/shadowsocks/kcptun_snappy.cpp
    src/outbound/shadowsocks_legacy_datagram.cpp
    src/transport/endpoint_dialer.cpp
    src/transport/quic_client.cpp
    src/transport/tls_client.cpp
    src/outbound/shadowsocks_outbound.cpp
    src/outbound/trojan_outbound.cpp
    src/outbound/http_proxy_outbound.cpp
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
    PRIVATE
        src
)

target_compile_features(clash-native-core PUBLIC cxx_std_20)

target_link_libraries(clash-native-core
    PUBLIC
        Boost::asio
        Threads::Threads
        protobuf::libprotobuf
        tl::expected
    PRIVATE
        Boost::beast
        c-ares::cares
        clash-native-boringssl
        BLAKE3::blake3
        Botan::Botan-static
        Snappy::snappy
        clash-native-nghttp2
        kcp::kcp
        ngtcp2_static
        ngtcp2_crypto_boringssl_static
        $<IF:$<TARGET_EXISTS:nghttp3::nghttp3>,nghttp3::nghttp3,nghttp3::nghttp3_static>
        fmt::fmt
        spdlog::spdlog_header_only
)

if(WIN32)
    target_compile_definitions(clash-native-core PUBLIC _HAS_ITERATOR_DEBUGGING=0)
    target_link_libraries(clash-native-core PUBLIC ws2_32 mswsock synchronization)
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

    add_executable(clash-native-http-tunnel-client
        tests/host/http_tunnel_client.cpp
    )

    target_compile_features(clash-native-http-tunnel-client PRIVATE cxx_std_20)

    target_link_libraries(clash-native-http-tunnel-client
        PRIVATE
            clash-native-core
    )

    add_executable(clash-native-grpc-client
        tests/host/grpc_client.cpp
    )

    target_compile_features(clash-native-grpc-client PRIVATE cxx_std_20)

    target_link_libraries(clash-native-grpc-client
        PRIVATE
            clash-native-core
    )

    add_executable(clash-native-kcp-client
        tests/host/kcp_client.cpp
    )

    target_compile_features(clash-native-kcp-client PRIVATE cxx_std_20)

    target_link_libraries(clash-native-kcp-client
        PRIVATE
            clash-native-core
    )

    add_executable(clash-native-websocket-client
        tests/host/websocket_client.cpp
    )

    target_compile_features(clash-native-websocket-client PRIVATE cxx_std_20)

    target_link_libraries(clash-native-websocket-client
        PRIVATE
            clash-native-core
    )

    add_executable(clash-native-tests
        tests/core/base64_test.cpp
        tests/core/channel_test.cpp
        tests/core/error_test.cpp
        tests/core/outbound_contract_test.cpp
        tests/core/version_test.cpp
        tests/dns/dns_test.cpp
        tests/dns/bootstrap_resolver_test.cpp
        tests/dns/dns_transport_test.cpp
        tests/dns/dns_packet_test.cpp
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
        tests/runtime/runtime_snapshot_test.cpp
        tests/runtime/runtime_set_test.cpp
        tests/transport/endpoint_dialer_test.cpp
        tests/transport/kcp_client_test.cpp
        tests/transport/websocket_client_test.cpp
        tests/transport/udp_stream_test.cpp
        tests/transport/shadowsocks_transport_test.cpp
    )

    target_include_directories(clash-native-tests
        PRIVATE
            include
    )

    target_compile_features(clash-native-tests PRIVATE cxx_std_20)

    target_link_libraries(clash-native-tests
        PRIVATE
            clash-native-core
            clash-native-nghttp2
            GTest::gtest_main
    )

    gtest_discover_tests(clash-native-tests)

    add_executable(clash-native-http-quic-smoke-tests
        tests/core/http_quic_dependencies_test.cpp
    )

    target_compile_features(clash-native-http-quic-smoke-tests PRIVATE cxx_std_20)
    target_compile_definitions(clash-native-http-quic-smoke-tests
        PRIVATE _HAS_ITERATOR_DEBUGGING=0
    )

    target_link_libraries(clash-native-http-quic-smoke-tests
        PRIVATE
            Boost::beast
            ngtcp2_static
            ngtcp2_crypto_boringssl_static
            clash-native-boringssl
            clash-native-nghttp2
            $<IF:$<TARGET_EXISTS:nghttp3::nghttp3>,nghttp3::nghttp3,nghttp3::nghttp3_static>
            GTest::gtest_main
    )

    gtest_discover_tests(clash-native-http-quic-smoke-tests)

    add_executable(clash-native-protobuf-kcp-smoke-tests
        tests/core/protobuf_kcp_dependencies_test.cpp
    )

    target_compile_features(clash-native-protobuf-kcp-smoke-tests PRIVATE cxx_std_20)

    target_link_libraries(clash-native-protobuf-kcp-smoke-tests
        PRIVATE
            clash-native-core
            GTest::gtest_main
            kcp::kcp
    )

    gtest_discover_tests(clash-native-protobuf-kcp-smoke-tests)

    add_test(
        NAME clash-native.version
        COMMAND clash-native --version
    )
    add_test(
        NAME clash-native.startup
        COMMAND clash-native
    )
endif()
