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
const mihomoInteropUDPPayloadSize = 1200

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

	tlsMaterial, err := endpoints.NewTrojanTLSMaterial()
	if err != nil {
		t.Fatal(err)
	}

	methods := []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"}
	shadowsocksAddresses := make(map[string]string, len(methods))
	var listenerConfig strings.Builder
	for _, method := range methods {
		address := reserveMihomoShadowsocksAddress(t)
		shadowsocksAddresses[method] = address
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
`, method, port, mihomoTestPassword, method)
	}
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
		append([]string{trojanAddress}, mapValues(shadowsocksAddresses)...))
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
			})
			defer stopProxy()

			client := socks5Connect(t, proxyAddress, tcpEcho.Addr())
			defer client.Close()
			payload := []byte(strings.Repeat("cpp-to-mihomo-shadowsocks-tcp-", 2048))
			writeBytes(t, client, payload)
			if err := client.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatalf("half-close C++ to Mihomo Shadowsocks TCP stream: %v", err)
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
				testHostnameAddress(t, "127.0.0.1", udpEcho.Addr().String()),
				net.IPv4(127, 0, 0, 1), udpPayload)
		})
	}

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
	t.Helper()
	var lastErr error
	for range 64 {
		udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("reserve Mihomo Shadowsocks UDP port: %v", err)
		}
		port := udp.LocalAddr().(*net.UDPAddr).Port
		tcp, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		_ = udp.Close()
		if err != nil {
			lastErr = err
			continue
		}
		_ = tcp.Close()
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
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
