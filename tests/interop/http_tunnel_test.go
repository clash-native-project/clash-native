package interop

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func TestHTTPClientSessionsOpenDuplexTunnels(t *testing.T) {
	executable := os.Getenv("CLASH_NATIVE_HTTP_TUNNEL_CLIENT")
	if executable == "" {
		t.Skip("CLASH_NATIVE_HTTP_TUNNEL_CLIENT is not set")
	}

	http1Address, http2Address, http3Address, closeServers := startHTTPStreamingFixtures(t)
	defer closeServers()

	for _, test := range []struct {
		name     string
		protocol string
		address  string
		mode     string
	}{
		{name: "HTTP1 CONNECT", protocol: "http1", address: http1Address, mode: "connect"},
		{name: "HTTP1 WebSocket Upgrade", protocol: "http1", address: http1Address, mode: "upgrade"},
		{name: "HTTP2 CONNECT", protocol: "http2", address: http2Address, mode: "connect"},
		{name: "HTTP2 Extended CONNECT", protocol: "http2", address: http2Address, mode: "upgrade"},
		{name: "HTTP3 CONNECT", protocol: "http3", address: http3Address, mode: "connect"},
		{name: "HTTP3 Extended CONNECT", protocol: "http3", address: http3Address, mode: "upgrade"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, executable, test.protocol, test.address, test.mode)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("independent tunnel client failed: %v\n%s", err, output)
			}
		})
	}
}

func TestHTTPClientSessionsStreamBodiesAndTrailers(t *testing.T) {
	executable := os.Getenv("CLASH_NATIVE_HTTP_TUNNEL_CLIENT")
	if executable == "" {
		t.Skip("CLASH_NATIVE_HTTP_TUNNEL_CLIENT is not set")
	}

	http1Address, http2Address, http3Address, closeServers := startHTTPStreamingFixtures(t)
	defer closeServers()

	for _, test := range []struct {
		name     string
		protocol string
		address  string
	}{
		{name: "HTTP1 streaming", protocol: "http1", address: http1Address},
		{name: "HTTP2 streaming", protocol: "http2", address: http2Address},
		{name: "HTTP3 streaming", protocol: "http3", address: http3Address},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, executable, test.protocol, test.address, "streaming")
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("independent streaming client failed: %v\n%s", err, output)
			}
		})
	}
}

func startHTTPStreamingFixtures(t *testing.T) (string, string, string, func()) {
	t.Helper()
	http1Address, closeHTTP1 := startHTTP1TunnelFixture(t)
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, "/stream/") {
			serveHTTPStreaming(writer, request)
			return
		}
		serveConnectTunnel(writer, request)
	})
	http2Server := httptest.NewUnstartedServer(handler)
	http2Server.EnableHTTP2 = true
	http2Server.StartTLS()
	http2Address := http2Server.Listener.Addr().String()

	certificatePath, keyPath := writeDnsproxyCertificate(t)
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		t.Fatalf("load HTTP/3 fixture certificate: %v", err)
	}
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for HTTP/3 fixture: %v", err)
	}
	http3Server := &http3.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			NextProtos:   []string{http3.NextProtoH3},
		},
		Handler: handler,
	}
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = http3Server.Serve(packetConn)
	}()
	return http1Address, http2Address, packetConn.LocalAddr().String(), func() {
		_ = http3Server.Close()
		_ = packetConn.Close()
		<-serveDone
		http2Server.Close()
		closeHTTP1()
	}
}

func startHTTP1TunnelFixture(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for HTTP/1.1 tunnel fixture: %v", err)
	}
	stop := make(chan struct{})
	var connections = make(chan net.Conn)
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			select {
			case connections <- connection:
			case <-stop:
				_ = connection.Close()
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case connection := <-connections:
				go serveHTTP1Tunnel(t, connection)
			case <-stop:
				return
			}
		}
	}()
	return listener.Addr().String(), func() {
		close(stop)
		_ = listener.Close()
	}
}

func serveHTTP1Tunnel(t *testing.T, connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(connection)
	for {
		request, err := http.ReadRequest(reader)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.Logf("HTTP/1.1 fixture request read ended: %v", err)
			}
			return
		}
		if request.Method == http.MethodPost && strings.HasPrefix(request.URL.Path, "/stream/") {
			if !serveHTTP1Streaming(t, connection, request) {
				return
			}
			continue
		}
		if request.Method == http.MethodConnect {
			_, _ = io.WriteString(connection, "HTTP/1.1 200 Connection Established\r\n\r\n")
		} else if request.Method == http.MethodGet &&
			strings.EqualFold(request.Header.Get("Upgrade"), "websocket") &&
			strings.Contains(strings.ToLower(request.Header.Get("Connection")), "upgrade") {
			_, _ = io.WriteString(connection,
				"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		} else {
			_, _ = io.WriteString(connection, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
			return
		}
		_, _ = io.Copy(connection, reader)
		return
	}
}

func serveHTTP1Streaming(t *testing.T, connection net.Conn, request *http.Request) bool {
	body, err := io.ReadAll(request.Body)
	_ = request.Body.Close()
	validationErr := validateStreamingRequest(request, body)
	if err != nil || validationErr != nil {
		t.Logf("HTTP/1.1 fixture request validation failed: body_bytes=%d, err=%v, validation=%v",
			len(body), err, validationErr)
		_, _ = io.WriteString(connection, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		return false
	}
	id := strings.TrimPrefix(request.URL.Path, "/stream/")
	writer := bufio.NewWriter(connection)
	_, _ = fmt.Fprintf(writer,
		"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nX-Test-Id: %s\r\nTrailer: X-Response-Trailer\r\nTransfer-Encoding: chunked\r\n\r\n",
		id)
	if err = writer.Flush(); err != nil {
		t.Logf("HTTP/1.1 fixture response header flush failed: %v", err)
		return false
	}
	time.Sleep(100 * time.Millisecond)
	payload := makeInteropPayload("DOWNLOAD-"+id, streamingIndex(id))
	for offset := 0; offset < len(payload); {
		end := min(offset+16*1024, len(payload))
		_, _ = fmt.Fprintf(writer, "%x\r\n", end-offset)
		if _, err = writer.Write(payload[offset:end]); err != nil {
			t.Logf("HTTP/1.1 fixture response write failed at %d bytes: %v", offset, err)
			return false
		}
		if _, err = writer.WriteString("\r\n"); err != nil {
			return false
		}
		offset = end
		if err = writer.Flush(); err != nil {
			t.Logf("HTTP/1.1 fixture response flush failed at %d bytes: %v", end, err)
			return false
		}
	}
	_, _ = fmt.Fprintf(writer, "0\r\nX-Response-Trailer: response-done-%s\r\n\r\n", id)
	if err = writer.Flush(); err != nil {
		t.Logf("HTTP/1.1 fixture response trailer flush failed: %v", err)
		return false
	}
	return true
}

func serveConnectTunnel(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodConnect {
		http.Error(writer, "expected CONNECT", http.StatusMethodNotAllowed)
		return
	}
	if request.Header.Get("x-test-extended-connect") == "1" {
		protocol := request.Header.Get(":protocol")
		if request.ProtoMajor == 3 {
			protocol = request.Proto
		}
		if protocol != "websocket" {
			http.Error(writer, "expected websocket Extended CONNECT", http.StatusBadRequest)
			return
		}
	}
	flusher, ok := writer.(http.Flusher)
	if !ok {
		http.Error(writer, "streaming is unavailable", http.StatusInternalServerError)
		return
	}
	writer.WriteHeader(http.StatusOK)
	flusher.Flush()
	buffer := make([]byte, 4096)
	for {
		count, err := request.Body.Read(buffer)
		if count > 0 {
			if _, writeErr := writer.Write(buffer[:count]); writeErr != nil {
				return
			}
			flusher.Flush()
		}
		if err != nil {
			return
		}
	}
}

func serveHTTPStreaming(writer http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		writer.Header().Set("X-Test-Error", "read request body: "+err.Error())
		http.Error(writer, "streaming request body or trailers did not match", http.StatusBadRequest)
		return
	}
	if err = validateStreamingRequest(request, body); err != nil {
		writer.Header().Set("X-Test-Error", err.Error())
		http.Error(writer, "streaming request body or trailers did not match", http.StatusBadRequest)
		return
	}
	flusher, ok := writer.(http.Flusher)
	if !ok {
		http.Error(writer, "streaming is unavailable", http.StatusInternalServerError)
		return
	}
	id := strings.TrimPrefix(request.URL.Path, "/stream/")
	writer.Header().Set("X-Test-Id", id)
	writer.Header().Set("Trailer", "X-Response-Trailer")
	writer.WriteHeader(http.StatusOK)
	flusher.Flush()
	time.Sleep(100 * time.Millisecond)
	payload := makeInteropPayload("DOWNLOAD-"+id, streamingIndex(id))
	for offset := 0; offset < len(payload); {
		end := min(offset+16*1024, len(payload))
		if _, err = writer.Write(payload[offset:end]); err != nil {
			return
		}
		offset = end
		flusher.Flush()
	}
	writer.Header().Set("X-Response-Trailer", "response-done-"+id)
}

func validateStreamingRequest(request *http.Request, body []byte) error {
	id := strings.TrimPrefix(request.URL.Path, "/stream/")
	index := streamingIndex(id)
	if (id != "A" && id != "B") || request.Method != http.MethodPost ||
		request.Header.Get("X-Test-Id") != id {
		return fmt.Errorf("unexpected streaming request metadata")
	}
	expected := makeInteropPayload("UPLOAD-"+id, index)
	if !bytes.Equal(body, expected) {
		return fmt.Errorf("streaming request body did not match all expected bytes")
	}
	if request.ProtoMajor != 3 {
		if got, expected := request.Trailer.Get("X-Request-Trailer"), "request-done-"+id; got != expected {
			return fmt.Errorf("streaming request trailer was %q, expected %q", got, expected)
		}
	}
	return nil
}

func streamingIndex(id string) int {
	if id == "A" {
		return 0
	}
	return 1
}

func makeInteropPayload(marker string, index int) []byte {
	payload := make([]byte, 2*1024*1024)
	copy(payload, marker)
	for offset := len(marker); offset < len(payload); offset++ {
		payload[offset] = byte((offset*31 + index*17) & 0xff)
	}
	return payload
}
