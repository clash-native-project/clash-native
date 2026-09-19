package interop

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"clash-native/interop/endpoints"
)

type independentHTTPConnectProxy struct {
	listener net.Listener
	target   string
	auth     string
	errors   chan error
}

func startIndependentHTTPConnectProxy(target, username, password string, certificate *tls.Certificate) (*independentHTTPConnectProxy, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	if certificate != nil {
		listener = tls.NewListener(listener, &tls.Config{
			Certificates: []tls.Certificate{*certificate},
			NextProtos:   []string{"http/1.1"},
		})
	}
	proxy := &independentHTTPConnectProxy{
		listener: listener,
		target:   target,
		auth:     "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password)),
		errors:   make(chan error, 8),
	}
	go proxy.accept()
	return proxy, nil
}

func (proxy *independentHTTPConnectProxy) Addr() string { return proxy.listener.Addr().String() }

func (proxy *independentHTTPConnectProxy) Close() error { return proxy.listener.Close() }

func (proxy *independentHTTPConnectProxy) accept() {
	for {
		connection, err := proxy.listener.Accept()
		if err != nil {
			return
		}
		go proxy.handle(connection)
	}
}

func (proxy *independentHTTPConnectProxy) handle(connection net.Conn) {
	defer connection.Close()
	reader := bufio.NewReader(connection)
	request, err := http.ReadRequest(reader)
	if err != nil {
		proxy.report(err)
		return
	}
	if request.Method != http.MethodConnect || request.Host != proxy.target {
		_, _ = io.WriteString(connection, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		proxy.report(io.ErrUnexpectedEOF)
		return
	}
	if proxy.auth != "Basic Og==" && request.Header.Get("Proxy-Authorization") != proxy.auth {
		_, _ = io.WriteString(connection, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	upstream, err := net.DialTimeout("tcp", proxy.target, 2*time.Second)
	if err != nil {
		_, _ = io.WriteString(connection, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		proxy.report(err)
		return
	}
	defer upstream.Close()
	if _, err := io.WriteString(connection, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		proxy.report(err)
		return
	}
	copyDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(upstream, reader)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		close(copyDone)
	}()
	_, _ = io.Copy(connection, upstream)
	<-copyDone
}

func (proxy *independentHTTPConnectProxy) report(err error) {
	select {
	case proxy.errors <- err:
	default:
	}
}

func TestHTTPProxyOutboundConnectPlainAndAuthenticatedTLS(t *testing.T) {
	echo, err := endpoints.StartTCPEcho()
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()

	tlsMaterial, err := endpoints.NewTrojanTLSMaterial()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(tlsMaterial.CertificatePEM, tlsMaterial.PrivateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		tls         bool
		username    string
		password    string
		certificate *tls.Certificate
	}{
		{name: "plain HTTP proxy"},
		{name: "HTTPS proxy with Basic authentication", tls: true, username: "proxy-user", password: "proxy-password", certificate: &certificate},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proxyServer, err := startIndependentHTTPConnectProxy(echo.Addr(), test.username, test.password, test.certificate)
			if err != nil {
				t.Fatal(err)
			}
			defer proxyServer.Close()

			environment := map[string]string{
				"CLASH_NATIVE_TEST_OUTBOUND":          "http",
				"CLASH_NATIVE_TEST_OUTBOUND_SERVER":   proxyServer.Addr(),
				"CLASH_NATIVE_TEST_OUTBOUND_PASSWORD": test.password,
				"CLASH_NATIVE_TEST_OUTBOUND_USERNAME": test.username,
			}
			if test.tls {
				caFile := filepath.Join(t.TempDir(), "http-proxy-test-ca.pem")
				if err := os.WriteFile(caFile, tlsMaterial.CACertificatePEM, 0o600); err != nil {
					t.Fatal(err)
				}
				environment["CLASH_NATIVE_TEST_OUTBOUND_TLS"] = "1"
				environment["CLASH_NATIVE_TEST_OUTBOUND_SERVER_NAME"] = "localhost"
				environment["CLASH_NATIVE_TEST_OUTBOUND_CA_FILE"] = caFile
			}
			proxyAddress, stopProxy := startOutboundTestHost(t, environment)
			defer stopProxy()

			client := socks5Connect(t, proxyAddress, echo.Addr())
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			payload := []byte("clash-native-http-proxy-connect-stream")
			writeBytes(t, client, payload)
			echoed := make([]byte, len(payload))
			readBytes(t, client, echoed)
			if string(echoed) != string(payload) {
				t.Fatalf("HTTP proxy CONNECT returned %q", echoed)
			}
			select {
			case err := <-proxyServer.errors:
				t.Fatalf("independent HTTP proxy rejected the request: %v", err)
			default:
			}
		})
	}
}

func TestHTTPProxyOutboundRejectsInvalidAuthentication(t *testing.T) {
	echo, err := endpoints.StartTCPEcho()
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	proxyServer, err := startIndependentHTTPConnectProxy(echo.Addr(), "expected", "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer proxyServer.Close()

	proxyAddress, stopProxy := startOutboundTestHost(t, map[string]string{
		"CLASH_NATIVE_TEST_OUTBOUND":          "http",
		"CLASH_NATIVE_TEST_OUTBOUND_SERVER":   proxyServer.Addr(),
		"CLASH_NATIVE_TEST_OUTBOUND_USERNAME": "wrong",
		"CLASH_NATIVE_TEST_OUTBOUND_PASSWORD": "credentials",
	})
	defer stopProxy()

	connection, err := net.DialTimeout("tcp", proxyAddress, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	writeBytes(t, connection, []byte{5, 1, 0})
	method := make([]byte, 2)
	readBytes(t, connection, method)
	if string(method) != string([]byte{5, 0}) {
		t.Fatalf("unexpected SOCKS5 method response: %v", method)
	}
	writeSocksConnectRequest(t, connection, echo.Addr())
	if code := readSocks5ReplyCode(t, connection); code == 0 {
		t.Fatal("HTTP proxy accepted invalid Basic credentials")
	}
}

func TestHTTPSProxyOutboundNegotiatesHTTP2(t *testing.T) {
	echo, err := endpoints.StartTCPEcho()
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()

	material, err := endpoints.NewTrojanTLSMaterial()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(material.CertificatePEM, material.PrivateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	const username, password = "h2-user", "h2-password"
	proxyResult := make(chan string, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect || request.Host != echo.Addr() {
			proxyResult <- fmt.Sprintf("unexpected CONNECT method=%q host=%q proto=%q", request.Method,
				request.Host, request.Proto)
			http.Error(writer, "unexpected CONNECT target", http.StatusBadRequest)
			return
		}
		if request.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)) {
			proxyResult <- fmt.Sprintf("unexpected Proxy-Authorization %q", request.Header.Get("Proxy-Authorization"))
			http.Error(writer, "unexpected proxy credentials", http.StatusProxyAuthRequired)
			return
		}
		flusher, ok := writer.(http.Flusher)
		if !ok {
			proxyResult <- "HTTP/2 CONNECT response writer does not support flushing"
			http.Error(writer, "streaming is unavailable", http.StatusInternalServerError)
			return
		}
		writer.WriteHeader(http.StatusOK)
		flusher.Flush()
		buffer := make([]byte, 4096)
		var copied int64
		for {
			count, readErr := request.Body.Read(buffer)
			if count != 0 {
				written, writeErr := writer.Write(buffer[:count])
				copied += int64(written)
				if writeErr != nil {
					proxyResult <- fmt.Sprintf("CONNECT response write failed after %d bytes: %v", copied, writeErr)
					return
				}
				flusher.Flush()
			}
			if readErr != nil {
				proxyResult <- fmt.Sprintf("CONNECT body ended after %d bytes: %v", copied, readErr)
				return
			}
		}
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	defer server.Close()

	caFile := filepath.Join(t.TempDir(), "https-h2-proxy-ca.pem")
	if err := os.WriteFile(caFile, material.CACertificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	proxyAddress, stopProxy := startOutboundTestHost(t, map[string]string{
		"CLASH_NATIVE_TEST_OUTBOUND":             "http",
		"CLASH_NATIVE_TEST_OUTBOUND_SERVER":      server.Listener.Addr().String(),
		"CLASH_NATIVE_TEST_OUTBOUND_PASSWORD":    password,
		"CLASH_NATIVE_TEST_OUTBOUND_USERNAME":    username,
		"CLASH_NATIVE_TEST_OUTBOUND_TLS":         "1",
		"CLASH_NATIVE_TEST_OUTBOUND_SERVER_NAME": "localhost",
		"CLASH_NATIVE_TEST_OUTBOUND_CA_FILE":     caFile,
	})
	defer stopProxy()

	client := socks5Connect(t, proxyAddress, echo.Addr())
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	payload := []byte("clash-native-https-h2-proxy-connect")
	writeBytes(t, client, payload)
	echoed := make([]byte, len(payload))
	if count, readErr := io.ReadFull(client, echoed); readErr != nil {
		_ = client.Close()
		select {
		case detail := <-proxyResult:
			t.Fatalf("read %d of %d echoed bytes through HTTP/2 CONNECT: %v (%s)", count,
				len(echoed), readErr, detail)
		case <-time.After(2 * time.Second):
			t.Fatalf("read %d of %d echoed bytes through HTTP/2 CONNECT: %v (proxy handler did not return)",
				count, len(echoed), readErr)
		}
	}
	if string(echoed) != string(payload) {
		t.Fatalf("HTTP/2 proxy CONNECT returned %q", echoed)
	}
}
