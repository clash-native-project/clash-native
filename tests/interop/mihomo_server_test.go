package interop

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"clash-native/interop/endpoints"
	"clash-native/interop/harness"
)

const mihomoTestPassword = "clash-native-mihomo-test-password"

// Leave room for Shadowsocks framing within the outbound's 1500-byte encrypted datagram limit.
const mihomoInteropUDPPayloadSize = 1000

func TestMihomoActualServerInteroperability(t *testing.T) {
	mihomoExecutable := os.Getenv("MIHOMO_EXECUTABLE")
	if mihomoExecutable == "" {
		t.Skip("MIHOMO_EXECUTABLE is not set")
	}
	if os.Getenv("CLASH_NATIVE_TEST_HOST") == "" {
		t.Skip("CLASH_NATIVE_TEST_HOST is not set")
	}

	tcpEcho, err := endpoints.StartTCPEcho()
	if err != nil {
		t.Fatal(err)
	}
	defer tcpEcho.Close()
	udpEcho, err := endpoints.StartUDPEcho()
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	udpHost := endpoints.LocalIPv4Host()

	tlsMaterial, err := endpoints.NewTrojanTLSMaterial()
	if err != nil {
		t.Fatal(err)
	}

	methods := []string{
		"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
		"xchacha20-ietf-poly1305", "chacha8-ietf-poly1305", "xchacha8-ietf-poly1305",
		"aes-128-ccm", "aes-192-ccm", "aes-256-ccm", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
		"aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "rc4-md5", "chacha20-ietf",
		"chacha20", "xchacha20",
	}
	shadowsocksAddresses := make(map[string]string, len(methods))
	var listenerConfig strings.Builder
	for _, method := range methods {
		address := reserveMihomoShadowsocksAddressOnHost(t, udpHost)
		shadowsocksAddresses[method] = address
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&listenerConfig, `
  - name: test-%s
    type: shadowsocks
    listen: %s
    port: %s
    udp: true
    password: '%s'
    cipher: %s
`, method, udpHost, port, mihomoTestPassword, method)
	}
	obfsAddress := reserveMihomoShadowsocksAddressOnHost(t, udpHost)
	_, obfsPort, err := net.SplitHostPort(obfsAddress)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(&listenerConfig, `
  - name: test-shadowsocks-obfs-http
    type: shadowsocks
    listen: %s
    port: %s
    udp: true
    password: '%s'
    cipher: chacha20-ietf-poly1305
    simple-obfs:
      enable: true
      mode: http
`, udpHost, obfsPort, mihomoTestPassword)
	tlsObfsAddress := reserveMihomoShadowsocksAddressOnHost(t, udpHost)
	_, tlsObfsPort, err := net.SplitHostPort(tlsObfsAddress)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(&listenerConfig, `
  - name: test-shadowsocks-obfs-tls
    type: shadowsocks
    listen: %s
    port: %s
    udp: true
    password: '%s'
    cipher: chacha20-ietf-poly1305
    simple-obfs:
      enable: true
      mode: tls
`, udpHost, tlsObfsPort, mihomoTestPassword)
	trojanAddress := reserveMihomoTCPAddress(t)
	_, trojanPort, err := net.SplitHostPort(trojanAddress)
	if err != nil {
		t.Fatal(err)
	}

	home := t.TempDir()
	caPath := filepath.Join(home, "test-ca.pem")
	certificatePath := filepath.Join(home, "trojan-cert.pem")
	privateKeyPath := filepath.Join(home, "trojan-key.pem")
	configPath := filepath.Join(home, "config.yaml")
	for path, data := range map[string][]byte{
		caPath:          tlsMaterial.CACertificatePEM,
		certificatePath: tlsMaterial.CertificatePEM,
		privateKeyPath:  tlsMaterial.PrivateKeyPEM,
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	config := fmt.Sprintf(`allow-lan: false
bind-address: 127.0.0.1
mode: rule
log-level: debug
ipv6: false
rules:
  - MATCH,DIRECT
listeners:%s
  - name: test-trojan
    type: trojan
    listen: 127.0.0.1
    port: %s
    users:
      - username: test
        password: '%s'
    certificate: '%s'
    private-key: '%s'
`, listenerConfig.String(), trojanPort, mihomoTestPassword,
		filepath.ToSlash(certificatePath), filepath.ToSlash(privateKeyPath))
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	mihomo := startMihomo(t, mihomoExecutable, home, configPath,
		append([]string{trojanAddress, obfsAddress, tlsObfsAddress}, mapValues(shadowsocksAddresses)...))
	defer stopInteropProcess(t, mihomo)

	for _, method := range methods {
		method := method
		t.Run("Shadowsocks/"+method, func(t *testing.T) {
			t.Cleanup(func() {
				if t.Failed() {
					t.Logf("UDP echo endpoint received %d packets", udpEcho.ReceivedPackets())
				}
			})
			proxyAddress, stopProxy := startOutboundTestHost(t, map[string]string{
				"CLASH_NATIVE_TEST_OUTBOUND":          "shadowsocks",
				"CLASH_NATIVE_TEST_OUTBOUND_SERVER":   shadowsocksAddresses[method],
				"CLASH_NATIVE_TEST_OUTBOUND_PASSWORD": mihomoTestPassword,
				"CLASH_NATIVE_TEST_OUTBOUND_METHOD":   method,
				"CLASH_NATIVE_TEST_PROXY_HOST":        udpHost,
			})
			defer stopProxy()

			client := socks5Connect(t, proxyAddress, tcpEcho.Addr())
			defer client.Close()
			payload := []byte(strings.Repeat("cpp-to-mihomo-shadowsocks-tcp-", 2048))
			writeBytes(t, client, payload)
			if os.Getenv("CLASH_NATIVE_SKIP_INTEROP_HALF_CLOSE") != "1" {
				if err := client.(*net.TCPConn).CloseWrite(); err != nil {
					t.Fatalf("half-close C++ to Mihomo Shadowsocks TCP stream: %v", err)
				}
			}
			echoed := make([]byte, len(payload))
			readBytes(t, client, echoed)
			if string(echoed) != string(payload) {
				t.Fatal("Mihomo Shadowsocks TCP returned different bytes")
			}

			udpPayload := make([]byte, mihomoInteropUDPPayloadSize)
			for index := range udpPayload {
				udpPayload[index] = byte(index % 251)
			}
			testShadowsocksUDPAssociateWithPayload(t, proxyAddress,
				udpEcho.Addr().String(), udpEcho.Addr().IP, udpPayload)
		})
	}

	t.Run("Shadowsocks/simple-obfs-http", func(t *testing.T) {
		proxyAddress, stopProxy := startOutboundTestHost(t, map[string]string{
			"CLASH_NATIVE_TEST_OUTBOUND":             "shadowsocks",
			"CLASH_NATIVE_TEST_OUTBOUND_SERVER":      obfsAddress,
			"CLASH_NATIVE_TEST_OUTBOUND_PASSWORD":    mihomoTestPassword,
			"CLASH_NATIVE_TEST_OUTBOUND_METHOD":      "chacha20-ietf-poly1305",
			"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN":      "obfs",
			"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_MODE": "http",
			"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_HOST": "bing.com",
			"CLASH_NATIVE_TEST_PROXY_HOST":           udpHost,
		})
		defer stopProxy()

		client := socks5Connect(t, proxyAddress, tcpEcho.Addr())
		defer client.Close()
		payload := []byte(strings.Repeat("cpp-to-mihomo-shadowsocks-http-obfs-tcp-", 2048))
		writeBytes(t, client, payload)
		if os.Getenv("CLASH_NATIVE_SKIP_INTEROP_HALF_CLOSE") != "1" {
			if err := client.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatalf("half-close C++ to Mihomo Shadowsocks HTTP obfs stream: %v", err)
			}
		}
		echoed := make([]byte, len(payload))
		readBytes(t, client, echoed)
		if string(echoed) != string(payload) {
			t.Fatal("Mihomo Shadowsocks HTTP obfs returned different bytes")
		}
	})

	t.Run("Shadowsocks/simple-obfs-tls", func(t *testing.T) {
		proxyAddress, stopProxy := startOutboundTestHost(t, map[string]string{
			"CLASH_NATIVE_TEST_OUTBOUND":             "shadowsocks",
			"CLASH_NATIVE_TEST_OUTBOUND_SERVER":      tlsObfsAddress,
			"CLASH_NATIVE_TEST_OUTBOUND_PASSWORD":    mihomoTestPassword,
			"CLASH_NATIVE_TEST_OUTBOUND_METHOD":      "chacha20-ietf-poly1305",
			"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN":      "obfs",
			"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_MODE": "tls",
			"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_HOST": "bing.com",
			"CLASH_NATIVE_TEST_PROXY_HOST":           udpHost,
		})
		defer stopProxy()

		client := socks5Connect(t, proxyAddress, tcpEcho.Addr())
		defer client.Close()
		payload := []byte(strings.Repeat("cpp-to-mihomo-shadowsocks-tls-obfs-tcp-", 2048))
		writeBytes(t, client, payload)
		if os.Getenv("CLASH_NATIVE_SKIP_INTEROP_HALF_CLOSE") != "1" {
			if err := client.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatalf("half-close C++ to Mihomo Shadowsocks TLS obfs stream: %v", err)
			}
		}
		echoed := make([]byte, len(payload))
		readBytes(t, client, echoed)
		if string(echoed) != string(payload) {
			t.Fatal("Mihomo Shadowsocks TLS obfs returned different bytes")
		}
	})

	t.Run("Trojan/TLS", func(t *testing.T) {
		proxyAddress, stopProxy := startOutboundTestHost(t, map[string]string{
			"CLASH_NATIVE_TEST_OUTBOUND":             "trojan",
			"CLASH_NATIVE_TEST_OUTBOUND_SERVER":      trojanAddress,
			"CLASH_NATIVE_TEST_OUTBOUND_PASSWORD":    mihomoTestPassword,
			"CLASH_NATIVE_TEST_OUTBOUND_SERVER_NAME": "localhost",
			"CLASH_NATIVE_TEST_OUTBOUND_CA_FILE":     caPath,
		})
		defer stopProxy()

		client := socks5Connect(t, proxyAddress, tcpEcho.Addr())
		defer client.Close()
		payload := []byte(strings.Repeat("cpp-to-mihomo-trojan-tls-", 2048))
		writeBytes(t, client, payload)
		if err := client.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatalf("half-close C++ to Mihomo Trojan stream: %v", err)
		}
		echoed := make([]byte, len(payload))
		readBytes(t, client, echoed)
		if string(echoed) != string(payload) {
			t.Fatal("Mihomo Trojan returned different bytes")
		}
	})

	t.Run("Trojan/reject-untrusted-certificate", func(t *testing.T) {
		proxyAddress, stopProxy := startOutboundTestHost(t, map[string]string{
			"CLASH_NATIVE_TEST_OUTBOUND":             "trojan",
			"CLASH_NATIVE_TEST_OUTBOUND_SERVER":      trojanAddress,
			"CLASH_NATIVE_TEST_OUTBOUND_PASSWORD":    mihomoTestPassword,
			"CLASH_NATIVE_TEST_OUTBOUND_SERVER_NAME": "localhost",
		})
		defer stopProxy()

		control, err := net.DialTimeout("tcp", proxyAddress, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer control.Close()
		_ = control.SetDeadline(time.Now().Add(5 * time.Second))
		writeBytes(t, control, []byte{5, 1, 0})
		method := make([]byte, 2)
		readBytes(t, control, method)
		if string(method) != string([]byte{5, 0}) {
			t.Fatalf("unexpected SOCKS5 method response: %v", method)
		}
		writeSocksConnectRequest(t, control, tcpEcho.Addr())
		if code := readSocks5ReplyCode(t, control); code == 0 {
			t.Fatal("C++ Trojan outbound accepted Mihomo's untrusted certificate")
		}
	})
}

func TestMihomoActualServerShadowsocksUoT(t *testing.T) {
	mihomoExecutable := os.Getenv("MIHOMO_EXECUTABLE")
	if mihomoExecutable == "" {
		t.Skip("MIHOMO_EXECUTABLE is not set")
	}
	if os.Getenv("CLASH_NATIVE_TEST_HOST") == "" {
		t.Skip("CLASH_NATIVE_TEST_HOST is not set")
	}

	udpHost := endpoints.LocalIPv4Host()
	udpEcho, err := endpoints.StartUDPEchoAt(udpHost)
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	address := reserveMihomoShadowsocksAddress(t)
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	const password = mihomoTestPassword
	config := fmt.Sprintf(`allow-lan: false
bind-address: 127.0.0.1
mode: rule
log-level: debug
ipv6: false
rules:
  - MATCH,DIRECT
listeners:
  - name: test-shadowsocks-uot
    type: shadowsocks
    listen: 127.0.0.1
    port: %s
    udp: true
    password: '%s'
    cipher: chacha20-ietf-poly1305
`, port, password)
	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	mihomo := startMihomo(t, mihomoExecutable, home, configPath, []string{address})
	defer stopInteropProcess(t, mihomo)

	for _, version := range []int{1, 2} {
		version := version
		t.Run(fmt.Sprintf("version-%d", version), func(t *testing.T) {
			proxyAddress, stopProxy := startOutboundTestHost(t, map[string]string{
				"CLASH_NATIVE_TEST_OUTBOUND":                      "shadowsocks",
				"CLASH_NATIVE_TEST_OUTBOUND_SERVER":               address,
				"CLASH_NATIVE_TEST_OUTBOUND_PASSWORD":             password,
				"CLASH_NATIVE_TEST_OUTBOUND_METHOD":               "chacha20-ietf-poly1305",
				"CLASH_NATIVE_TEST_OUTBOUND_UDP_OVER_TCP":         "1",
				"CLASH_NATIVE_TEST_OUTBOUND_UDP_OVER_TCP_VERSION": strconv.Itoa(version),
				"CLASH_NATIVE_TEST_PROXY_HOST":                    udpHost,
			})
			defer stopProxy()
			payload := []byte(strings.Repeat("cpp-to-mihomo-uot-", 64))
			testShadowsocksUDPAssociateWithPayload(t, proxyAddress, udpEcho.Addr().String(),
				udpEcho.Addr().IP, payload)
		})
	}
}

func TestMihomoActualServerShadowsocksKcpTun(t *testing.T) {
	mihomoExecutable := os.Getenv("MIHOMO_EXECUTABLE")
	if mihomoExecutable == "" {
		t.Skip("MIHOMO_EXECUTABLE is not set")
	}
	if os.Getenv("CLASH_NATIVE_TEST_HOST") == "" {
		t.Skip("CLASH_NATIVE_TEST_HOST is not set")
	}

	tcpEcho, err := endpoints.StartTCPEcho()
	if err != nil {
		t.Fatal(err)
	}
	defer tcpEcho.Close()
	udpHost := endpoints.LocalIPv4Host()
	udpEcho, err := endpoints.StartUDPEchoAt(udpHost)
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()

	address := reserveMihomoShadowsocksAddressOnHost(t, udpHost)
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	readinessAddress := reserveMihomoTCPAddress(t)
	_, readinessPort, err := net.SplitHostPort(readinessAddress)
	if err != nil {
		t.Fatal(err)
	}
	const (
		password = mihomoTestPassword
		kcpKey   = "clash-native-kcptun-test-key"
	)
	kcpCrypt := os.Getenv("CLASH_NATIVE_TEST_KCPTUN_CRYPT")
	if kcpCrypt == "" {
		kcpCrypt = "aes"
	}
	kcpDataShard := os.Getenv("CLASH_NATIVE_TEST_KCPTUN_DATASHARD")
	if kcpDataShard == "" {
		kcpDataShard = "10"
	}
	kcpParityShard := os.Getenv("CLASH_NATIVE_TEST_KCPTUN_PARITYSHARD")
	if kcpParityShard == "" {
		kcpParityShard = "3"
	}
	kcpSmuxVersion := os.Getenv("CLASH_NATIVE_TEST_KCPTUN_SMUXVER")
	if kcpSmuxVersion == "" {
		kcpSmuxVersion = "1"
	}
	kcpNoComp := os.Getenv("CLASH_NATIVE_TEST_KCPTUN_NOCOMP") == "1"
	config := fmt.Sprintf(`allow-lan: false
bind-address: 127.0.0.1
mode: rule
log-level: debug
ipv6: false
rules:
  - MATCH,DIRECT
listeners:
  - name: test-shadowsocks-kcptun
    type: shadowsocks
    listen: %s
    port: %s
    udp: true
    password: '%s'
    cipher: chacha20-ietf-poly1305
    kcp-tun:
      enable: true
      key: '%s'
      crypt: '%s'
      datashard: %s
      parityshard: %s
      nocomp: %t
      smuxver: %s
      framesize: 8192
  - name: test-readiness
    type: mixed
    listen: 127.0.0.1
    port: %s
`, udpHost, port, password, kcpKey, kcpCrypt, kcpDataShard, kcpParityShard, kcpNoComp, kcpSmuxVersion, readinessPort)
	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	mihomo := startMihomo(t, mihomoExecutable, home, configPath, []string{readinessAddress})
	defer stopInteropProcess(t, mihomo)

	proxyAddress, stopProxy := startOutboundTestHost(t, map[string]string{
		"CLASH_NATIVE_TEST_OUTBOUND":                    "shadowsocks",
		"CLASH_NATIVE_TEST_OUTBOUND_SERVER":             address,
		"CLASH_NATIVE_TEST_OUTBOUND_PASSWORD":           password,
		"CLASH_NATIVE_TEST_OUTBOUND_METHOD":             "chacha20-ietf-poly1305",
		"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN":             "kcptun",
		"CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_KEY":         kcpKey,
		"CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_CRYPT":       kcpCrypt,
		"CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_NOCOMP":      map[bool]string{true: "1", false: "0"}[kcpNoComp],
		"CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_DATASHARD":   kcpDataShard,
		"CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_PARITYSHARD": kcpParityShard,
		"CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_SMUXVER":     kcpSmuxVersion,
		"CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_CONN":        "2",
		"CLASH_NATIVE_TEST_PROXY_HOST":                  udpHost,
	})
	defer stopProxy()

	t.Run("TCP", func(t *testing.T) {
		client := socks5Connect(t, proxyAddress, tcpEcho.Addr())
		defer client.Close()
		repetitions := 4096
		if os.Getenv("CLASH_NATIVE_TEST_KCPTUN_LARGE") == "1" {
			repetitions = 65536
		}
		payload := []byte(strings.Repeat("cpp-to-mihomo-kcptun-tcp-", repetitions))
		writeBytes(t, client, payload)
		if os.Getenv("CLASH_NATIVE_TEST_KCPTUN_HALF_CLOSE") == "1" {
			if err := client.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatalf("half-close C++ to Mihomo kcptun TCP stream: %v", err)
			}
		}
		echoed := make([]byte, len(payload))
		readBytes(t, client, echoed)
		if string(echoed) != string(payload) {
			t.Fatal("Mihomo kcptun TCP returned different bytes")
		}
	})

	t.Run("UDP-over-TCP", func(t *testing.T) {
		payload := []byte(strings.Repeat("cpp-to-mihomo-kcptun-uot-", 64))
		testShadowsocksUDPAssociateWithPayload(t, proxyAddress, udpEcho.Addr().String(),
			udpEcho.Addr().IP, payload)
	})

	t.Run("Concurrent TCP streams across pooled sessions", func(t *testing.T) {
		const streamCount = 4
		clients := make([]net.Conn, 0, streamCount)
		defer func() {
			for _, client := range clients {
				_ = client.Close()
			}
		}()
		payload := []byte(strings.Repeat("cpp-to-mihomo-kcptun-pooled-", 512))
		for index := 0; index < streamCount; index++ {
			client := socks5Connect(t, proxyAddress, tcpEcho.Addr())
			clients = append(clients, client)
			writeBytes(t, client, payload)
		}
		for _, client := range clients {
			echoed := make([]byte, len(payload))
			readBytes(t, client, echoed)
			if string(echoed) != string(payload) {
				t.Fatal("Mihomo kcptun pooled stream returned different bytes")
			}
		}
	})
}

func TestMihomoActualServerShadowsocks2022TCP(t *testing.T) {
	mihomoExecutable := os.Getenv("MIHOMO_EXECUTABLE")
	if mihomoExecutable == "" {
		t.Skip("MIHOMO_EXECUTABLE is not set")
	}
	if os.Getenv("CLASH_NATIVE_TEST_HOST") == "" {
		t.Skip("CLASH_NATIVE_TEST_HOST is not set")
	}

	tcpEcho, err := endpoints.StartTCPEcho()
	if err != nil {
		t.Fatal(err)
	}
	defer tcpEcho.Close()
	keys := []struct {
		method   string
		password string
	}{
		{"2022-blake3-aes-128-gcm", "AQIDBAUGBwgJCgsMDQ4PEA=="},
		{"2022-blake3-aes-256-gcm", "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="},
		{"2022-blake3-chacha20-poly1305", "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="},
	}
	addresses := make(map[string]string, len(keys))
	var listenerConfig strings.Builder
	for _, key := range keys {
		address := reserveMihomoShadowsocksAddress(t)
		addresses[key.method] = address
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&listenerConfig, `
  - name: test-%s
    type: shadowsocks
    listen: 127.0.0.1
    port: %s
    udp: true
    password: '%s'
    cipher: %s
`, key.method, port, key.password, key.method)
	}
	obfsAddress := reserveMihomoShadowsocksAddress(t)
	_, obfsPort, err := net.SplitHostPort(obfsAddress)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(&listenerConfig, `
  - name: test-2022-shadowsocks-obfs-http
    type: shadowsocks
    listen: 127.0.0.1
    port: %s
    udp: true
    password: '%s'
    cipher: 2022-blake3-aes-128-gcm
    simple-obfs:
      enable: true
      mode: http
`, obfsPort, keys[0].password)
	tlsObfsAddress := reserveMihomoShadowsocksAddress(t)
	_, tlsObfsPort, err := net.SplitHostPort(tlsObfsAddress)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(&listenerConfig, `
  - name: test-2022-shadowsocks-obfs-tls
    type: shadowsocks
    listen: 127.0.0.1
    port: %s
    udp: true
    password: '%s'
    cipher: 2022-blake3-aes-128-gcm
    simple-obfs:
      enable: true
      mode: tls
`, tlsObfsPort, keys[0].password)

	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	config := fmt.Sprintf(`allow-lan: false
bind-address: 127.0.0.1
mode: rule
log-level: debug
ipv6: false
rules:
  - MATCH,DIRECT
listeners:%s
`, listenerConfig.String())
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	addressesList := make([]string, 0, len(addresses)+2)
	for _, address := range addresses {
		addressesList = append(addressesList, address)
	}
	addressesList = append(addressesList, obfsAddress)
	addressesList = append(addressesList, tlsObfsAddress)
	mihomo := startMihomo(t, mihomoExecutable, home, configPath, addressesList)
	defer stopInteropProcess(t, mihomo)

	for _, key := range keys {
		key := key
		t.Run(key.method, func(t *testing.T) {
			proxyAddress, stopProxy := startOutboundTestHost(t, map[string]string{
				"CLASH_NATIVE_TEST_OUTBOUND":          "shadowsocks",
				"CLASH_NATIVE_TEST_OUTBOUND_SERVER":   addresses[key.method],
				"CLASH_NATIVE_TEST_OUTBOUND_PASSWORD": key.password,
				"CLASH_NATIVE_TEST_OUTBOUND_METHOD":   key.method,
			})
			defer stopProxy()
			client := socks5Connect(t, proxyAddress, tcpEcho.Addr())
			defer client.Close()
			payload := []byte(strings.Repeat("cpp-to-mihomo-shadowsocks-2022-tcp-", 64))
			writeBytes(t, client, payload)
			echoed := make([]byte, len(payload))
			readBytes(t, client, echoed)
			if string(echoed) != string(payload) {
				t.Fatal("Mihomo Shadowsocks 2022 TCP returned different bytes")
			}
		})
	}

	t.Run("2022-blake3-aes-128-gcm/simple-obfs-http", func(t *testing.T) {
		proxyAddress, stopProxy := startOutboundTestHost(t, map[string]string{
			"CLASH_NATIVE_TEST_OUTBOUND":             "shadowsocks",
			"CLASH_NATIVE_TEST_OUTBOUND_SERVER":      obfsAddress,
			"CLASH_NATIVE_TEST_OUTBOUND_PASSWORD":    keys[0].password,
			"CLASH_NATIVE_TEST_OUTBOUND_METHOD":      keys[0].method,
			"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN":      "obfs",
			"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_MODE": "http",
			"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_HOST": "bing.com",
		})
		defer stopProxy()
		client := socks5Connect(t, proxyAddress, tcpEcho.Addr())
		defer client.Close()
		payload := []byte(strings.Repeat("cpp-to-mihomo-shadowsocks-2022-http-obfs-tcp-", 64))
		writeBytes(t, client, payload)
		echoed := make([]byte, len(payload))
		readBytes(t, client, echoed)
		if string(echoed) != string(payload) {
			t.Fatal("Mihomo Shadowsocks 2022 HTTP obfs returned different bytes")
		}
	})

	t.Run("2022-blake3-aes-128-gcm/simple-obfs-tls", func(t *testing.T) {
		proxyAddress, stopProxy := startOutboundTestHost(t, map[string]string{
			"CLASH_NATIVE_TEST_OUTBOUND":             "shadowsocks",
			"CLASH_NATIVE_TEST_OUTBOUND_SERVER":      tlsObfsAddress,
			"CLASH_NATIVE_TEST_OUTBOUND_PASSWORD":    keys[0].password,
			"CLASH_NATIVE_TEST_OUTBOUND_METHOD":      keys[0].method,
			"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN":      "obfs",
			"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_MODE": "tls",
			"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_HOST": "bing.com",
		})
		defer stopProxy()
		client := socks5Connect(t, proxyAddress, tcpEcho.Addr())
		defer client.Close()
		payload := []byte(strings.Repeat("cpp-to-mihomo-shadowsocks-2022-tls-obfs-tcp-", 64))
		writeBytes(t, client, payload)
		echoed := make([]byte, len(payload))
		readBytes(t, client, echoed)
		if string(echoed) != string(payload) {
			t.Fatal("Mihomo Shadowsocks 2022 TLS obfs returned different bytes")
		}
	})
}

func TestMihomoActualServerShadowsocks2022UDP(t *testing.T) {
	mihomoExecutable := os.Getenv("MIHOMO_EXECUTABLE")
	if mihomoExecutable == "" {
		t.Skip("MIHOMO_EXECUTABLE is not set")
	}
	testHostExecutable := os.Getenv("CLASH_NATIVE_TEST_HOST")
	if testHostExecutable == "" {
		t.Skip("CLASH_NATIVE_TEST_HOST is not set")
	}
	udpHost := endpoints.LocalIPv4Host()
	udpEcho, err := endpoints.StartUDPEchoAt(udpHost)
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()

	keys := []struct {
		method   string
		password string
	}{
		{"2022-blake3-aes-128-gcm", "AQIDBAUGBwgJCgsMDQ4PEA=="},
		{"2022-blake3-aes-256-gcm", "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="},
		{"2022-blake3-chacha20-poly1305", "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="},
	}
	addresses := make(map[string]string, len(keys))
	var listenerConfig strings.Builder
	for _, key := range keys {
		address := reserveMihomoShadowsocksAddressOnHost(t, udpHost)
		addresses[key.method] = address
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&listenerConfig, `
  - name: test-%s
    type: shadowsocks
    listen: %s
    port: %s
    udp: true
    password: '%s'
    cipher: %s
`, key.method, udpHost, port, key.password, key.method)
	}
	home := t.TempDir()
	configPath := filepath.Join(home, "config.yaml")
	config := fmt.Sprintf(`allow-lan: false
bind-address: 0.0.0.0
mode: rule
log-level: debug
ipv6: false
rules:
  - MATCH,DIRECT
listeners:%s
`, listenerConfig.String())
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	listenerAddresses := make([]string, 0, len(addresses))
	for _, address := range addresses {
		listenerAddresses = append(listenerAddresses, address)
	}
	mihomo := startMihomo(t, mihomoExecutable, home, configPath, listenerAddresses)
	defer stopInteropProcess(t, mihomo)

	for _, key := range keys {
		key := key
		t.Run(key.method, func(t *testing.T) {
			processContext, cancel := context.WithCancel(context.Background())
			process, err := harness.StartWithEnv(processContext, testHostExecutable, map[string]string{
				"CLASH_NATIVE_TEST_RAW_SS2022_UDP":    "1",
				"CLASH_NATIVE_TEST_OUTBOUND_SERVER":   addresses[key.method],
				"CLASH_NATIVE_TEST_OUTBOUND_PASSWORD": key.password,
				"CLASH_NATIVE_TEST_OUTBOUND_METHOD":   key.method,
				"CLASH_NATIVE_TEST_RAW_SS2022_TARGET": udpEcho.Addr().String(),
			})
			if err != nil {
				cancel()
				t.Fatalf("start raw Shadowsocks 2022 UDP test host: %v", err)
			}
			defer cancel()
			readyContext, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, err = harness.WaitForLine(readyContext, process, "clash-native-test-host raw-udp-ready")
			readyCancel()
			if err != nil {
				stdout, stderr := process.Output()
				t.Fatalf("wait for raw Shadowsocks 2022 UDP test host: %v; stdout=%q stderr=%q",
					err, stdout, stderr)
			}
			waitContext, waitCancel := context.WithTimeout(context.Background(), 8*time.Second)
			err = process.Wait(waitContext)
			waitCancel()
			if err != nil {
				stdout, stderr := process.Output()
				t.Fatalf("raw Shadowsocks 2022 UDP test failed: %v; stdout=%q stderr=%q",
					err, stdout, stderr)
			}
		})
	}
}

func startMihomo(t *testing.T, executable, home, config string, listeners []string) *harness.Process {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	process, err := harness.Start(ctx, executable, "-d", home, "-f", config)
	if err != nil {
		cancel()
		t.Fatalf("start Mihomo server: %v", err)
	}
	t.Cleanup(func() { cancel() })
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer waitCancel()
	for {
		ready := true
		for _, address := range listeners {
			conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
			if err != nil {
				ready = false
				break
			}
			_ = conn.Close()
		}
		if ready {
			t.Logf("Mihomo listeners ready: %s", strings.Join(listeners, ", "))
			return process
		}
		probeCtx, probeCancel := context.WithTimeout(waitCtx, 10*time.Millisecond)
		waitErr := process.Wait(probeCtx)
		probeCancel()
		if waitErr == nil {
			t.Fatalf("Mihomo exited before listeners were ready")
		}
		if !errors.Is(waitErr, context.DeadlineExceeded) {
			stdout, stderr := process.Output()
			t.Fatalf("Mihomo exited before listeners were ready: %v; stdout=%q; stderr=%q",
				waitErr, stdout, stderr)
		}
		select {
		case <-waitCtx.Done():
			stdout, stderr := process.Output()
			t.Fatalf("Mihomo listeners did not become ready: %v; stdout=%q; stderr=%q",
				waitCtx.Err(), stdout, stderr)
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func stopInteropProcess(t *testing.T, process *harness.Process) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := process.Stop(ctx); err != nil {
		stdout, stderr := process.Output()
		t.Errorf("stop Mihomo server: %v; stdout=%q; stderr=%q", err, stdout, stderr)
	} else if t.Failed() {
		stdout, stderr := process.Output()
		t.Logf("Mihomo server output: stdout=%q; stderr=%q", stdout, stderr)
	}
}

func reserveMihomoShadowsocksAddress(t *testing.T) string {
	return reserveMihomoShadowsocksAddressOnHost(t, "127.0.0.1")
}

func reserveMihomoShadowsocksAddressOnHost(t *testing.T, host string) string {
	t.Helper()
	var lastErr error
	for range 64 {
		tcp, err := net.Listen("tcp4", net.JoinHostPort(host, "0"))
		if err != nil {
			t.Fatalf("reserve Mihomo Shadowsocks UDP port: %v", err)
		}
		port := tcp.Addr().(*net.TCPAddr).Port
		udp, err := net.ListenPacket("udp4", net.JoinHostPort(host, strconv.Itoa(port)))
		_ = tcp.Close()
		if err != nil {
			lastErr = err
			continue
		}
		_ = udp.Close()
		return net.JoinHostPort(host, strconv.Itoa(port))
	}
	t.Fatalf("reserve a shared TCP/UDP port for Mihomo Shadowsocks: %v", lastErr)
	return ""
}

func reserveMihomoTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve Mihomo Trojan port: %v", err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

func mapValues(values map[string]string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}
