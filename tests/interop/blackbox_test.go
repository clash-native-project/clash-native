package interop

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"clash-native/interop/endpoints"
	"clash-native/interop/harness"
)

const readyPrefix = "clash-native-test-host ready "

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
