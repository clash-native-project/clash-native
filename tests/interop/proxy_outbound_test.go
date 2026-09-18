package interop

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
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

const testOutboundPassword = "clash-native-test-password"
const maxEncryptedShadowsocksUDPDatagramSize = 1500
const shadowsocksAEADTagSize = 16

func TestShadowsocksAEADTCPAndUDPIndependentGoPeer(t *testing.T) {
	dnsServer, err := endpoints.StartStaticDNSServer(map[string]net.IP{
		"proxy.test": net.IPv4(127, 0, 0, 1),
		"tcp.test":   net.IPv4(127, 0, 0, 1),
		"udp.test":   net.IPv4(127, 0, 0, 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dnsServer.Close()

	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"} {
		t.Run(method, func(t *testing.T) {
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
			server, err := endpoints.StartShadowsocksServer(method, testOutboundPassword)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()

			proxyAddress, stopProxy := startOutboundTestHost(t, map[string]string{
				"CLASH_NATIVE_TEST_OUTBOUND":          "shadowsocks",
				"CLASH_NATIVE_TEST_OUTBOUND_SERVER":   testHostnameAddress(t, "proxy.test", server.Addr()),
				"CLASH_NATIVE_TEST_OUTBOUND_PASSWORD": testOutboundPassword,
				"CLASH_NATIVE_TEST_OUTBOUND_METHOD":   method,
				"CLASH_NATIVE_DNS_UPSTREAM":           dnsServer.Addr(),
			})
			defer stopProxy()

			client := socks5Connect(t, proxyAddress, testHostnameAddress(t, "tcp.test", tcpEcho.Addr()))
			defer client.Close()
			payload := bytes.Repeat([]byte("ss-aead-stream-"), 4096)
			writeBytes(t, client, payload)
			if err := client.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatalf("half-close Shadowsocks TCP stream: %v", err)
			}
			echoed := make([]byte, len(payload))
			readBytes(t, client, echoed)
			if !bytes.Equal(echoed, payload) {
				t.Fatal("Shadowsocks TCP returned different bytes")
			}

			testShadowsocksUDPAssociate(
				t, proxyAddress, testHostnameAddress(t, "udp.test", udpEcho.Addr().String()),
				net.IPv4(127, 0, 0, 1))
			testShadowsocksUDPAssociateAtEncryptedLimit(
				t, proxyAddress, testHostnameAddress(t, "udp.test", udpEcho.Addr().String()),
				net.IPv4(127, 0, 0, 1), method)
			testShadowsocksUDPAssociateOverEncryptedLimit(
				t, proxyAddress, testHostnameAddress(t, "udp.test", udpEcho.Addr().String()), method)
		})
	}
}

func TestTrojanTCPOverTLSWithTrustedAndUntrustedCertificates(t *testing.T) {
	dnsServer, err := endpoints.StartStaticDNSServer(map[string]net.IP{
		"proxy.test": net.IPv4(127, 0, 0, 1),
		"tcp.test":   net.IPv4(127, 0, 0, 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dnsServer.Close()

	echo, err := endpoints.StartTCPEcho()
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	server, certificatePEM, err := endpoints.StartTrojanServer(testOutboundPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	caFile := filepath.Join(t.TempDir(), "trojan-test-ca.pem")
	if err := os.WriteFile(caFile, certificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	environment := map[string]string{
		"CLASH_NATIVE_TEST_OUTBOUND":             "trojan",
		"CLASH_NATIVE_TEST_OUTBOUND_SERVER":      testHostnameAddress(t, "proxy.test", server.Addr()),
		"CLASH_NATIVE_TEST_OUTBOUND_PASSWORD":    testOutboundPassword,
		"CLASH_NATIVE_TEST_OUTBOUND_SERVER_NAME": "localhost",
		"CLASH_NATIVE_TEST_OUTBOUND_CA_FILE":     caFile,
		"CLASH_NATIVE_DNS_UPSTREAM":              dnsServer.Addr(),
	}
	proxyAddress, stopProxy := startOutboundTestHost(t, environment)
	defer stopProxy()
	client := socks5Connect(t, proxyAddress, testHostnameAddress(t, "tcp.test", echo.Addr()))
	payload := bytes.Repeat([]byte("trojan-tls-stream-"), 2048)
	writeBytes(t, client, payload)
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("half-close Trojan TCP/TLS stream: %v", err)
	}
	echoed := make([]byte, len(payload))
	readBytes(t, client, echoed)
	if !bytes.Equal(echoed, payload) {
		t.Fatal("Trojan TLS returned different bytes")
	}
	_ = client.Close()
	stopProxy()

	proxyAddress, stopProxy = startOutboundTestHost(t, map[string]string{
		"CLASH_NATIVE_TEST_OUTBOUND":             "trojan",
		"CLASH_NATIVE_TEST_OUTBOUND_SERVER":      testHostnameAddress(t, "proxy.test", server.Addr()),
		"CLASH_NATIVE_TEST_OUTBOUND_PASSWORD":    testOutboundPassword,
		"CLASH_NATIVE_TEST_OUTBOUND_SERVER_NAME": "localhost",
		"CLASH_NATIVE_DNS_UPSTREAM":              dnsServer.Addr(),
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
	if !bytes.Equal(method, []byte{5, 0}) {
		t.Fatalf("unexpected SOCKS5 method response: %v", method)
	}
	writeSocksConnectRequest(t, control, echo.Addr())
	if code := readSocks5ReplyCode(t, control); code == 0 {
		t.Fatal("Trojan TLS accepted an untrusted certificate")
	}
}

func startOutboundTestHost(t *testing.T, outboundEnvironment map[string]string) (string, func()) {
	t.Helper()
	executable := os.Getenv("CLASH_NATIVE_TEST_HOST")
	if executable == "" {
		t.Skip("CLASH_NATIVE_TEST_HOST is not set")
	}
	processContext, cancelProcess := context.WithCancel(context.Background())
	process, err := harness.StartWithEnv(processContext, executable, outboundEnvironment)
	if err != nil {
		cancelProcess()
		t.Fatalf("start C++ outbound test host: %v", err)
	}
	startupContext, cancelStartup := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelStartup()
	line, err := harness.WaitForLine(startupContext, process, readyPrefix)
	if err != nil {
		cancelProcess()
		t.Fatalf("wait for C++ outbound test host: %v", err)
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		stopContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := process.Stop(stopContext); err != nil {
			stdout, stderr := process.Output()
			t.Errorf("stop C++ outbound test host: %v; stdout=%q; stderr=%q", err, stdout, stderr)
		} else if t.Failed() {
			stdout, stderr := process.Output()
			t.Logf("C++ outbound test host output: stdout=%q; stderr=%q", stdout, stderr)
		}
		cancelProcess()
	}
	return strings.TrimPrefix(line, readyPrefix), stop
}

func socks5Connect(t *testing.T, proxyAddress, targetAddress string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddress, 2*time.Second)
	if err != nil {
		t.Fatalf("connect to proxy: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	writeBytes(t, conn, []byte{5, 1, 0})
	method := make([]byte, 2)
	readBytes(t, conn, method)
	if !bytes.Equal(method, []byte{5, 0}) {
		_ = conn.Close()
		t.Fatalf("unexpected SOCKS5 method response: %v", method)
	}
	writeSocksConnectRequest(t, conn, targetAddress)
	if code := readSocks5ReplyCode(t, conn); code != 0 {
		_ = conn.Close()
		t.Fatalf("SOCKS5 CONNECT failed with reply %d", code)
	}
	return conn
}

func writeSocksConnectRequest(t *testing.T, writer io.Writer, targetAddress string) {
	t.Helper()
	host, portText, err := net.SplitHostPort(targetAddress)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	request := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			request = append(request, 1)
			request = append(request, ipv4...)
		} else {
			request = append(request, 4)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			t.Fatalf("test target hostname has invalid length: %q", host)
		}
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	}
	request = append(request, byte(port>>8), byte(port))
	writeBytes(t, writer, request)
}

func readSocks5ReplyCode(t *testing.T, reader io.Reader) byte {
	t.Helper()
	header := make([]byte, 4)
	readBytes(t, reader, header)
	if header[0] != 5 || header[2] != 0 {
		t.Fatalf("unexpected SOCKS5 reply header: %v", header)
	}
	remaining := 0
	switch header[3] {
	case 1:
		remaining = 6
	case 3:
		length := make([]byte, 1)
		readBytes(t, reader, length)
		remaining = int(length[0]) + 2
	case 4:
		remaining = 18
	default:
		t.Fatalf("unexpected SOCKS5 reply address type: %d", header[3])
	}
	readBytes(t, reader, make([]byte, remaining))
	return header[1]
}

func testHostnameAddress(t *testing.T, host, address string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("invalid test server address %q: %v", address, err)
	}
	return net.JoinHostPort(host, port)
}

func testShadowsocksUDPAssociate(t *testing.T, proxyAddress, targetAddress string, expectedIP net.IP) {
	t.Helper()
	want := bytes.Repeat([]byte("ss-udp-payload-"), 64)
	testShadowsocksUDPAssociateWithPayload(t, proxyAddress, targetAddress, expectedIP, want)
}

func testShadowsocksUDPAssociateAtEncryptedLimit(t *testing.T, proxyAddress, targetAddress string,
	expectedIP net.IP, method string) {
	t.Helper()
	payloadSize := shadowsocksUDPBoundaryPayloadSize(method)
	want := bytes.Repeat([]byte{0x5a}, payloadSize)
	testShadowsocksUDPAssociateWithPayload(t, proxyAddress, targetAddress, expectedIP, want)
}

func testShadowsocksUDPAssociateOverEncryptedLimit(t *testing.T, proxyAddress,
	targetAddress, method string) {
	t.Helper()
	payloadSize := shadowsocksUDPBoundaryPayloadSize(method) + 1
	want := bytes.Repeat([]byte{0x5a}, payloadSize)
	testShadowsocksUDPAssociateWithPayloadResult(t, proxyAddress, targetAddress, nil, want, false)
}

func shadowsocksUDPBoundaryPayloadSize(method string) int {
	keySize := 32
	if method == "aes-128-gcm" {
		keySize = 16
	}
	// The proxy resolves the incoming domain before Shadowsocks encodes an IPv4 target address.
	proxyAddressSize := 1 + net.IPv4len + 2
	return maxEncryptedShadowsocksUDPDatagramSize - keySize - shadowsocksAEADTagSize -
		proxyAddressSize
}

func testShadowsocksUDPAssociateWithPayload(t *testing.T, proxyAddress, targetAddress string,
	expectedIP net.IP, want []byte) {
	testShadowsocksUDPAssociateWithPayloadResult(
		t, proxyAddress, targetAddress, expectedIP, want, true)
}

func testShadowsocksUDPAssociateWithPayloadResult(t *testing.T, proxyAddress, targetAddress string,
	expectedIP net.IP, want []byte, expectResponse bool) {
	t.Helper()
	clientUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer clientUDP.Close()
	control, err := net.DialTimeout("tcp", proxyAddress, 2*time.Second)
	if err != nil {
		t.Fatalf("connect SOCKS5 UDP control channel: %v", err)
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(8 * time.Second))
	writeBytes(t, control, []byte{5, 1, 0})
	method := make([]byte, 2)
	readBytes(t, control, method)
	if !bytes.Equal(method, []byte{5, 0}) {
		t.Fatalf("unexpected SOCKS5 method response: %v", method)
	}
	clientPort := clientUDP.LocalAddr().(*net.UDPAddr).Port
	associate := []byte{5, 3, 0, 1, 0, 0, 0, 0, byte(clientPort >> 8), byte(clientPort)}
	writeBytes(t, control, associate)
	relayAddress := readSocks5UDPAssociateReply(t, control)
	_ = clientUDP.SetDeadline(time.Now().Add(5 * time.Second))

	targetHost, targetPortText, err := net.SplitHostPort(targetAddress)
	if err != nil {
		t.Fatal(err)
	}
	targetPort, err := strconv.Atoi(targetPortText)
	if err != nil {
		t.Fatal(err)
	}
	if len(targetHost) == 0 || len(targetHost) > 255 {
		t.Fatalf("test UDP target hostname has invalid length: %q", targetHost)
	}
	request := []byte{0, 0, 0, 3, byte(len(targetHost))}
	request = append(request, targetHost...)
	request = append(request, byte(targetPort>>8), byte(targetPort))
	request = append(request, want...)
	if _, err := clientUDP.WriteToUDP(request, relayAddress); err != nil {
		t.Fatalf("send SOCKS5 UDP packet: %v", err)
	}
	if !expectResponse {
		_ = clientUDP.SetReadDeadline(time.Now().Add(time.Second))
		response := make([]byte, 65507)
		if _, _, err := clientUDP.ReadFromUDP(response); err == nil {
			t.Fatal("received a response for a Shadowsocks UDP datagram over the encrypted size limit")
		} else if netError, ok := err.(net.Error); !ok || !netError.Timeout() {
			t.Fatalf("unexpected result waiting for rejected oversized UDP response: %v", err)
		}
		return
	}
	response := make([]byte, 65507)
	size, _, err := clientUDP.ReadFromUDP(response)
	if err != nil {
		t.Fatalf("receive SOCKS5 UDP response: %v", err)
	}
	if size < 10 || !bytes.Equal(response[:3], []byte{0, 0, 0}) || response[3] != 1 {
		t.Fatalf("invalid SOCKS5 UDP response header: %v", response[:min(size, 10)])
	}
	if !bytes.Equal(response[4:8], expectedIP.To4()) ||
		binary.BigEndian.Uint16(response[8:10]) != uint16(targetPort) {
		t.Fatalf("unexpected SOCKS5 UDP source address: %v", response[:10])
	}
	if !bytes.Equal(response[10:size], want) {
		t.Fatalf("unexpected SOCKS5 UDP payload size: got %d, want %d", size-10, len(want))
	}
}

func readSocks5UDPAssociateReply(t *testing.T, reader io.Reader) *net.UDPAddr {
	t.Helper()
	header := make([]byte, 4)
	readBytes(t, reader, header)
	if header[0] != 5 || header[1] != 0 || header[2] != 0 {
		t.Fatalf("SOCKS5 UDP ASSOCIATE failed: %v", header)
	}
	var ip net.IP
	switch header[3] {
	case 1:
		bytes := make([]byte, 4)
		readBytes(t, reader, bytes)
		ip = net.IP(bytes)
	case 4:
		bytes := make([]byte, 16)
		readBytes(t, reader, bytes)
		ip = net.IP(bytes)
	case 3:
		length := make([]byte, 1)
		readBytes(t, reader, length)
		domain := make([]byte, int(length[0]))
		readBytes(t, reader, domain)
		resolved, err := net.ResolveIPAddr("ip", string(domain))
		if err != nil {
			t.Fatalf("resolve UDP relay address: %v", err)
		}
		ip = resolved.IP
	default:
		t.Fatalf("unsupported UDP relay address type %d", header[3])
	}
	port := make([]byte, 2)
	readBytes(t, reader, port)
	return &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(port))}
}
