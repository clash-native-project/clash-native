package interop

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"clash-native/interop/endpoints"
	"clash-native/interop/harness"
)

const readyPrefix = "clash-native-test-host ready "
const dnsReadyPrefix = "clash-native-test-host dns-ready "

func TestSocks5ProcessWithIndependentTCPEndpoint(t *testing.T) {
	executable := os.Getenv("CLASH_NATIVE_TEST_HOST")
	if executable == "" {
		t.Skip("CLASH_NATIVE_TEST_HOST is not set")
	}

	echo, err := endpoints.StartTCPEcho()
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	process, err := harness.Start(ctx, executable)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		stopContext, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer stopCancel()
		if err := process.Stop(stopContext); err != nil {
			t.Errorf("stop test host: %v", err)
		}
	}()

	line, err := harness.WaitForLine(ctx, process, readyPrefix)
	if err != nil {
		t.Fatal(err)
	}
	proxyAddress := strings.TrimPrefix(line, readyPrefix)

	client, err := net.DialTimeout("tcp", proxyAddress, 2*time.Second)
	if err != nil {
		t.Fatalf("connect to test host: %v", err)
	}
	defer client.Close()

	writeBytes(t, client, []byte{5, 1, 0})
	methodResponse := make([]byte, 2)
	readBytes(t, client, methodResponse)
	if string(methodResponse) != string([]byte{5, 0}) {
		t.Fatalf("unexpected SOCKS5 method response: %v", methodResponse)
	}

	host, portText, err := net.SplitHostPort(echo.Addr())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Fatalf("TCP endpoint is not IPv4: %q", host)
	}
	request := []byte{5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port)}
	writeBytes(t, client, request)

	readSocks5Reply(t, client)
	payload := []byte("clash-native-independent-endpoint")
	writeBytes(t, client, payload)
	echoed := make([]byte, len(payload))
	readBytes(t, client, echoed)
	if string(echoed) != string(payload) {
		t.Fatalf("unexpected echoed payload: %q", echoed)
	}
}

func TestHTTPConnectProcessWithIndependentTCPEndpoint(t *testing.T) {
	executable := os.Getenv("CLASH_NATIVE_TEST_HOST")
	if executable == "" {
		t.Skip("CLASH_NATIVE_TEST_HOST is not set")
	}

	echo, err := endpoints.StartTCPEcho()
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	process, err := harness.Start(ctx, executable)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		stopContext, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer stopCancel()
		if err := process.Stop(stopContext); err != nil {
			t.Errorf("stop test host: %v", err)
		}
	}()

	line, err := harness.WaitForLine(ctx, process, readyPrefix)
	if err != nil {
		t.Fatal(err)
	}
	proxyAddress := strings.TrimPrefix(line, readyPrefix)

	client, err := net.DialTimeout("tcp", proxyAddress, 2*time.Second)
	if err != nil {
		t.Fatalf("connect to test host: %v", err)
	}
	defer client.Close()

	request := "CONNECT " + echo.Addr() + " HTTP/1.1\r\nHost: " + echo.Addr() + "\r\n\r\n"
	writeBytes(t, client, []byte(request))
	reader := bufio.NewReader(client)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(statusLine, "HTTP/1.1 200 ") {
		t.Fatalf("unexpected HTTP CONNECT response: %q", statusLine)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}

	payload := []byte("clash-native-http-independent-endpoint")
	writeBytes(t, client, payload)
	echoed := make([]byte, len(payload))
	readBytes(t, reader, echoed)
	if string(echoed) != string(payload) {
		t.Fatalf("unexpected echoed payload: %q", echoed)
	}
}

func TestIndependentUDPEndpoint(t *testing.T) {
	echo, err := endpoints.StartUDPEcho()
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	t.Logf("UDP endpoint=%s client=%s", echo.Addr(), client.LocalAddr())

	payload := []byte("independent-udp-endpoint")
	if _, err := client.WriteToUDP(payload, echo.Addr()); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	size, _, err := client.ReadFromUDP(response)
	if err != nil {
		if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
			t.Skipf("UDP loopback is unavailable in this environment: %v", err)
		}
		t.Fatal(err)
	}
	if string(response[:size]) != string(payload) {
		t.Fatalf("unexpected UDP response: %q", response[:size])
	}
}

func TestDNSProcessWithIndependentDnsproxy(t *testing.T) {
	testHost := os.Getenv("CLASH_NATIVE_TEST_HOST")
	if testHost == "" {
		t.Skip("CLASH_NATIVE_TEST_HOST is not set")
	}
	dnsproxy := findDnsproxy(t)

	hostsPath := filepath.Join(t.TempDir(), "hosts.txt")
	hosts := "192.0.2.53 clash-native-dnsproxy-a.test\n" +
		"198.51.100.53 clash-native-dnsproxy-b.test\n"
	if err := os.WriteFile(hostsPath, []byte(hosts), 0o600); err != nil {
		t.Fatalf("write dnsproxy hosts file: %v", err)
	}

	dnsproxyPort := freeDNSPort(t)
	dnsproxyAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(dnsproxyPort))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dnsproxyProcess, err := harness.Start(ctx, dnsproxy,
		"--listen=127.0.0.1",
		"--port="+strconv.Itoa(dnsproxyPort),
		"--upstream=127.0.0.1:9",
		"--hosts-file-enabled",
		"--hosts-files="+hostsPath,
		"--verbose")
	if err != nil {
		t.Fatalf("start dnsproxy: %v", err)
	}
	defer stopProcess(t, dnsproxyProcess, "dnsproxy")
	if err := waitForTCPListener(ctx, dnsproxyAddress); err != nil {
		stdout, stderr := dnsproxyProcess.Output()
		t.Fatalf("wait for dnsproxy listener: %v; stdout=%q stderr=%q", err, stdout, stderr)
	}

	testHostProcess, err := harness.StartWithEnv(ctx, testHost, map[string]string{
		"CLASH_NATIVE_DNS_UPSTREAM": "localhost:" + strconv.Itoa(dnsproxyPort),
	})
	if err != nil {
		t.Fatalf("start test host with DNS upstream: %v", err)
	}
	defer stopProcess(t, testHostProcess, "test host")
	if _, err := harness.WaitForLine(ctx, testHostProcess, readyPrefix); err != nil {
		t.Fatal(err)
	}
	dnsLine, err := harness.WaitForLine(ctx, testHostProcess, dnsReadyPrefix)
	if err != nil {
		t.Fatal(err)
	}
	udpAddress, tcpAddress, err := parseDNSReadyLine(dnsLine)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name     string
		network  string
		endpoint string
	}{
		{name: "clash-native-dnsproxy-a.test", network: "udp", endpoint: udpAddress},
		{name: "clash-native-dnsproxy-b.test", network: "tcp", endpoint: tcpAddress},
	} {
		response := queryDNS(t, test.network, test.endpoint, test.name)
		if response.Rcode != dns.RcodeSuccess {
			t.Fatalf("%s query for %s returned DNS rcode %d", test.network, test.name, response.Rcode)
		}
		if len(response.Answer) != 1 {
			t.Fatalf("%s query for %s returned %d answers", test.network, test.name, len(response.Answer))
		}
		address, ok := response.Answer[0].(*dns.A)
		if !ok {
			t.Fatalf("%s query for %s returned %T instead of A", test.network, test.name,
				response.Answer[0])
		}
		expected := map[string]string{
			"clash-native-dnsproxy-a.test": "192.0.2.53",
			"clash-native-dnsproxy-b.test": "198.51.100.53",
		}[test.name]
		if address.A.String() != expected {
			t.Fatalf("%s query for %s returned %s, expected %s", test.network, test.name,
				address.A, expected)
		}
	}
}

func TestFakeIPProcessWithIndependentDnsproxy(t *testing.T) {
	testHost := os.Getenv("CLASH_NATIVE_TEST_HOST")
	if testHost == "" {
		t.Skip("CLASH_NATIVE_TEST_HOST is not set")
	}
	dnsproxy := findDnsproxy(t)
	echo, err := endpoints.StartTCPEcho()
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()

	hostsPath := filepath.Join(t.TempDir(), "hosts.txt")
	const fakeDomain = "clash-native-fake.test"
	if err := os.WriteFile(hostsPath, []byte("127.0.0.1 "+fakeDomain+"\n"), 0o600); err != nil {
		t.Fatalf("write dnsproxy hosts file: %v", err)
	}

	dnsproxyPort := freeDNSPort(t)
	dnsproxyAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(dnsproxyPort))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dnsproxyProcess, err := harness.Start(ctx, dnsproxy,
		"--listen=127.0.0.1",
		"--port="+strconv.Itoa(dnsproxyPort),
		"--upstream=127.0.0.1:9",
		"--hosts-file-enabled",
		"--hosts-files="+hostsPath,
		"--verbose")
	if err != nil {
		t.Fatalf("start dnsproxy: %v", err)
	}
	defer stopProcess(t, dnsproxyProcess, "dnsproxy")
	if err := waitForTCPListener(ctx, dnsproxyAddress); err != nil {
		stdout, stderr := dnsproxyProcess.Output()
		t.Fatalf("wait for dnsproxy listener: %v; stdout=%q stderr=%q", err, stdout, stderr)
	}

	testHostProcess, err := harness.StartWithEnv(ctx, testHost, map[string]string{
		"CLASH_NATIVE_DNS_UPSTREAM":   "localhost:" + strconv.Itoa(dnsproxyPort),
		"CLASH_NATIVE_FAKE_IP_DOMAIN": fakeDomain,
	})
	if err != nil {
		t.Fatalf("start test host with FakeIP: %v", err)
	}
	defer stopProcess(t, testHostProcess, "test host")
	proxyLine, err := harness.WaitForLine(ctx, testHostProcess, readyPrefix)
	if err != nil {
		t.Fatal(err)
	}
	dnsLine, err := harness.WaitForLine(ctx, testHostProcess, dnsReadyPrefix)
	if err != nil {
		t.Fatal(err)
	}
	udpAddress, _, err := parseDNSReadyLine(dnsLine)
	if err != nil {
		t.Fatal(err)
	}

	response := queryDNS(t, "udp", udpAddress, fakeDomain)
	if len(response.Answer) != 1 {
		t.Fatalf("FakeIP query returned %d answers", len(response.Answer))
	}
	fakeAddress, ok := response.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("FakeIP query returned %T instead of A", response.Answer[0])
	}
	if fakeAddress.A.String() != "198.18.0.1" {
		t.Fatalf("FakeIP query returned %s, expected 198.18.0.1", fakeAddress.A)
	}

	client, err := net.DialTimeout("tcp", strings.TrimPrefix(proxyLine, readyPrefix), 2*time.Second)
	if err != nil {
		t.Fatalf("connect to test host: %v", err)
	}
	defer client.Close()
	writeBytes(t, client, []byte{5, 1, 0})
	methodResponse := make([]byte, 2)
	readBytes(t, client, methodResponse)
	if string(methodResponse) != string([]byte{5, 0}) {
		t.Fatalf("unexpected SOCKS5 method response: %v", methodResponse)
	}
	host, portText, err := net.SplitHostPort(echo.Addr())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	if host != "127.0.0.1" {
		t.Fatalf("TCP endpoint is not loopback IPv4: %q", host)
	}
	writeBytes(t, client, []byte{5, 1, 0, 1, 198, 18, 0, 1, byte(port >> 8), byte(port)})
	replyHeader := make([]byte, 4)
	readBytes(t, client, replyHeader)
	if replyHeader[1] != 0 {
		stdout, stderr := testHostProcess.Output()
		t.Fatalf("unexpected SOCKS5 FakeIP reply header: %v; stdout=%q stderr=%q", replyHeader,
			stdout, stderr)
	}
	readBytes(t, client, make([]byte, 6))
	payload := []byte("clash-native-fake-ip")
	writeBytes(t, client, payload)
	echoed := make([]byte, len(payload))
	readBytes(t, client, echoed)
	if string(echoed) != string(payload) {
		t.Fatalf("unexpected echoed payload: %q", echoed)
	}
}

func TestDNSProcessWithIndependentDnsproxySecureTransports(t *testing.T) {
	testHost := os.Getenv("CLASH_NATIVE_TEST_HOST")
	if testHost == "" {
		t.Skip("CLASH_NATIVE_TEST_HOST is not set")
	}
	dnsproxy := findDnsproxy(t)
	certificatePath, keyPath := writeDnsproxyCertificate(t)

	for _, test := range []struct {
		name     string
		upstream func(int) string
		listener func(int) []string
	}{
		{
			name:     "doh1",
			upstream: func(port int) string { return "doh1://localhost:" + strconv.Itoa(port) + "/dns-query" },
			listener: func(port int) []string { return []string{"--https-port=" + strconv.Itoa(port)} },
		},
		{
			name:     "doq",
			upstream: func(port int) string { return "doq://localhost:" + strconv.Itoa(port) },
			listener: func(port int) []string { return []string{"--quic-port=" + strconv.Itoa(port)} },
		},
		{
			name:     "doh3",
			upstream: func(port int) string { return "doh3://localhost:" + strconv.Itoa(port) + "/dns-query" },
			listener: func(port int) []string {
				return []string{"--https-port=" + strconv.Itoa(port), "--http3"}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			hostsPath := filepath.Join(t.TempDir(), "hosts.txt")
			const domain = "clash-native-secure-dnsproxy.test"
			if err := os.WriteFile(hostsPath, []byte("192.0.2.73 "+domain+"\n"), 0o600); err != nil {
				t.Fatalf("write dnsproxy hosts file: %v", err)
			}

			plainPort := freeDNSPort(t)
			transportPort := freeDNSPort(t)
			plainAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(plainPort))
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			arguments := []string{
				"--listen=127.0.0.1",
				"--port=" + strconv.Itoa(plainPort),
				"--upstream=127.0.0.1:9",
				"--hosts-file-enabled",
				"--hosts-files=" + hostsPath,
				"--tls-crt=" + certificatePath,
				"--tls-key=" + keyPath,
				"--verbose",
			}
			arguments = append(arguments, test.listener(transportPort)...)
			dnsproxyProcess, err := harness.Start(ctx, dnsproxy, arguments...)
			if err != nil {
				t.Fatalf("start dnsproxy: %v", err)
			}
			defer stopProcess(t, dnsproxyProcess, "dnsproxy")
			if err := waitForTCPListener(ctx, plainAddress); err != nil {
				stdout, stderr := dnsproxyProcess.Output()
				t.Fatalf("wait for dnsproxy listener: %v; stdout=%q stderr=%q", err, stdout, stderr)
			}

			for _, verifyPeer := range []bool{false, true} {
				verifyName := "verify-peer-enabled"
				verifyValue := "true"
				if !verifyPeer {
					verifyName = "verify-peer-disabled"
					verifyValue = "false"
				}
				t.Run(verifyName, func(t *testing.T) {
					testHostProcess, err := harness.StartWithEnv(ctx, testHost, map[string]string{
						"CLASH_NATIVE_DNS_UPSTREAM":    test.upstream(transportPort),
						"CLASH_NATIVE_DNS_VERIFY_PEER": verifyValue,
					})
					if err != nil {
						t.Fatalf("start test host with secure DNS upstream: %v", err)
					}
					defer stopProcess(t, testHostProcess, "test host")
					if _, err := harness.WaitForLine(ctx, testHostProcess, readyPrefix); err != nil {
						t.Fatal(err)
					}
					dnsLine, err := harness.WaitForLine(ctx, testHostProcess, dnsReadyPrefix)
					if err != nil {
						t.Fatal(err)
					}
					udpAddress, _, err := parseDNSReadyLine(dnsLine)
					if err != nil {
						t.Fatal(err)
					}
					response := queryDNS(t, "udp", udpAddress, domain)
					if verifyPeer {
						if response.Rcode != dns.RcodeServerFailure {
							t.Fatalf("untrusted dnsproxy certificate returned DNS rcode %d, expected SERVFAIL", response.Rcode)
						}
						return
					}
					if response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
						testHostStdout, testHostStderr := testHostProcess.Output()
						dnsproxyStdout, dnsproxyStderr := dnsproxyProcess.Output()
						t.Fatalf("%s query returned rcode %d and %d answers; test-host stdout=%q stderr=%q; dnsproxy stdout=%q stderr=%q",
							test.name, response.Rcode, len(response.Answer), testHostStdout, testHostStderr, dnsproxyStdout, dnsproxyStderr)
					}
					answer, ok := response.Answer[0].(*dns.A)
					if !ok || answer.A.String() != "192.0.2.73" {
						t.Fatalf("unexpected %s DNS answer: %v", test.name, response.Answer)
					}
				})
			}
		})
	}
}

func writeDnsproxyCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate dnsproxy TLS key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create dnsproxy TLS certificate: %v", err)
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("encode dnsproxy TLS key: %v", err)
	}
	certificatePath := filepath.Join(t.TempDir(), "dnsproxy.crt")
	keyPath := filepath.Join(t.TempDir(), "dnsproxy.key")
	if err := os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: certificate,
	}), 0o600); err != nil {
		t.Fatalf("write dnsproxy TLS certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: privateKey,
	}), 0o600); err != nil {
		t.Fatalf("write dnsproxy TLS key: %v", err)
	}
	return certificatePath, keyPath
}

func findDnsproxy(t *testing.T) string {
	t.Helper()
	if configured := os.Getenv("DNSPROXY_EXECUTABLE"); configured != "" {
		return configured
	}
	for _, name := range []string{"dnsproxy.exe", "dnsproxy"} {
		if executable, err := exec.LookPath(name); err == nil {
			return executable
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		for _, name := range []string{"dnsproxy.exe", "dnsproxy"} {
			candidate := filepath.Join(home, "go", "bin", name)
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
		}
	}
	t.Skip("dnsproxy is not available; set DNSPROXY_EXECUTABLE to enable the independent DNS test")
	return ""
}

func freeDNSPort(t *testing.T) int {
	t.Helper()
	for attempt := 0; attempt < 32; attempt++ {
		udpListener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("allocate DNS proxy UDP port: %v", err)
		}
		port := udpListener.LocalAddr().(*net.UDPAddr).Port
		tcpListener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err == nil {
			_ = tcpListener.Close()
			_ = udpListener.Close()
			return port
		}
		_ = udpListener.Close()
	}
	t.Fatal("could not reserve a shared UDP/TCP DNS proxy port")
	return 0
}

func waitForTCPListener(ctx context.Context, address string) error {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func parseDNSReadyLine(line string) (string, string, error) {
	fields := strings.Fields(strings.TrimPrefix(line, dnsReadyPrefix))
	values := make(map[string]string, len(fields))
	for _, field := range fields {
		key, value, found := strings.Cut(field, "=")
		if !found || value == "" {
			return "", "", strconv.ErrSyntax
		}
		values[key] = value
	}
	udpAddress, udpFound := values["udp"]
	tcpAddress, tcpFound := values["tcp"]
	if !udpFound || !tcpFound {
		return "", "", strconv.ErrSyntax
	}
	return udpAddress, tcpAddress, nil
}

func queryDNS(t *testing.T, network, endpoint, name string) *dns.Msg {
	t.Helper()
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), dns.TypeA)
	client := &dns.Client{Net: network, Timeout: 2 * time.Second}
	response, _, err := client.Exchange(message, endpoint)
	if err != nil {
		t.Fatalf("%s query for %s: %v", network, name, err)
	}
	return response
}

func stopProcess(t *testing.T, process *harness.Process, name string) {
	t.Helper()
	stopContext, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	if err := process.Stop(stopContext); err != nil {
		t.Errorf("stop %s: %v", name, err)
	}
}

func writeBytes(t *testing.T, writer io.Writer, data []byte) {
	t.Helper()
	written := 0
	for written < len(data) {
		size, err := writer.Write(data[written:])
		if err != nil {
			t.Fatalf("write %d bytes: %v", len(data), err)
		}
		written += size
	}
}

func readBytes(t *testing.T, reader io.Reader, data []byte) {
	t.Helper()
	if _, err := io.ReadFull(reader, data); err != nil {
		t.Fatalf("read %d bytes: %v", len(data), err)
	}
}

func readSocks5Reply(t *testing.T, reader io.Reader) {
	t.Helper()
	header := make([]byte, 4)
	readBytes(t, reader, header)
	if header[0] != 5 || header[1] != 0 {
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
		t.Fatalf("unexpected SOCKS5 address type: %d", header[3])
	}

	readBytes(t, reader, make([]byte, remaining))
}
