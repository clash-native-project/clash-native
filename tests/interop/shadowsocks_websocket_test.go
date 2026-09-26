package interop

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"clash-native/interop/endpoints"
	"github.com/gorilla/websocket"
	"github.com/metacubex/smux"
)

type websocketNetConn struct {
	conn   *websocket.Conn
	reader io.Reader
	mu     sync.Mutex
}

func (c *websocketNetConn) Read(p []byte) (int, error) {
	for {
		if c.reader == nil {
			messageType, reader, err := c.conn.NextReader()
			if err != nil {
				return 0, err
			}
			if messageType != websocket.BinaryMessage {
				continue
			}
			c.reader = reader
		}
		n, err := c.reader.Read(p)
		if err == io.EOF {
			c.reader = nil
			if n != 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (c *websocketNetConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *websocketNetConn) Close() error { return c.conn.Close() }

func (c *websocketNetConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (c *websocketNetConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (c *websocketNetConn) SetDeadline(deadline time.Time) error {
	if err := c.conn.SetReadDeadline(deadline); err != nil {
		return err
	}
	return c.conn.SetWriteDeadline(deadline)
}

func (c *websocketNetConn) SetReadDeadline(deadline time.Time) error {
	return c.conn.SetReadDeadline(deadline)
}

func (c *websocketNetConn) SetWriteDeadline(deadline time.Time) error {
	return c.conn.SetWriteDeadline(deadline)
}

// shadowsocksWebSocketServerOptions extends the WebSocket test peer with
// the TLS knobs under test. A nil certificate uses the httptest fixture
// certificate; ExpectedHeaders rejects handshakes missing them (400).
type shadowsocksWebSocketServerOptions struct {
	tls               bool
	expectedHeaders   map[string]string
	requireClientCert bool
	certificatePEM    []byte
	privateKeyPEM     []byte
	// chainPEM, when set, is appended to the presented chain (CA pin tests).
	chainPEM []byte
}

func startShadowsocksWebSocketServer(t *testing.T, method, password string, tlsServer bool) (string, func()) {
	address, _, cleanup := startShadowsocksWebSocketServerEx(t, method, password,
		shadowsocksWebSocketServerOptions{tls: tlsServer})
	return address, cleanup
}

// startShadowsocksWebSocketServerEx also returns the presented
// certificate DER so pin tests can derive the expected SHA-256 pin.
func startShadowsocksWebSocketServerEx(t *testing.T, method, password string,
	options shadowsocksWebSocketServerOptions) (string, []byte, func()) {
	t.Helper()
	shadowsocks, err := endpoints.StartShadowsocksTCPServer(method, password)
	if err != nil {
		t.Fatal(err)
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/ss" {
			http.Error(writer, "unexpected WebSocket path", http.StatusNotFound)
			return
		}
		for name, want := range options.expectedHeaders {
			if request.Header.Get(name) != want {
				http.Error(writer, "missing expected WebSocket header", http.StatusBadRequest)
				return
			}
		}
		connection, upgradeErr := upgrader.Upgrade(writer, request, nil)
		if upgradeErr != nil {
			return
		}
		shadowsocks.ServeTCPConn(&websocketNetConn{conn: connection})
	})

	if !options.tls {
		server := httptest.NewServer(handler)
		address := strings.TrimPrefix(server.URL, "http://")
		return address, nil, func() {
			server.Close()
			_ = shadowsocks.Close()
		}
	}
	if len(options.certificatePEM) == 0 {
		server := httptest.NewTLSServer(handler)
		address := strings.TrimPrefix(server.URL, "https://")
		return address, server.Certificate().Raw, func() {
			server.Close()
			_ = shadowsocks.Close()
		}
	}
	certificate, err := tls.X509KeyPair(options.certificatePEM, options.privateKeyPEM)
	if err == nil && len(options.chainPEM) > 0 {
		block, _ := pem.Decode(options.chainPEM)
		if block == nil {
			_ = shadowsocks.Close()
			t.Fatal("decode WS echo chain certificate")
		} else {
			certificate.Certificate = append(certificate.Certificate, block.Bytes)
		}
	}
	if err != nil {
		_ = shadowsocks.Close()
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{certificate}}
	if options.requireClientCert {
		tlsConfig.ClientAuth = tls.RequireAnyClientCert
	}
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", tlsConfig)
	if err != nil {
		_ = shadowsocks.Close()
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go server.Serve(listener)
	leaf, _ := x509.ParseCertificate(certificate.Certificate[0])
	var raw []byte
	if leaf != nil {
		raw = leaf.Raw
	}
	return listener.Addr().String(), raw, func() {
		_ = server.Close()
		_ = shadowsocks.Close()
	}
}

type v2rayMuxServer struct {
	conn    net.Conn
	mu      sync.Mutex
	muxt    sync.Mutex
	streams map[uint16]*v2rayMuxStream
}

type v2rayMuxStream struct {
	parent *v2rayMuxServer
	id     uint16
	reader *io.PipeReader
	writer *io.PipeWriter
	mu     sync.Once
}

func (s *v2rayMuxServer) writeFrame(id uint16, status, option byte, payload []byte) error {
	frame := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(frame[0:2], 4)
	binary.BigEndian.PutUint16(frame[2:4], id)
	frame[4] = status
	frame[5] = option
	binary.BigEndian.PutUint16(frame[6:8], uint16(len(payload)))
	copy(frame[8:], payload)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.conn.Write(frame)
	return err
}

func (s *v2rayMuxServer) writeEnd(id uint16) error {
	frame := []byte{0, 4, byte(id >> 8), byte(id), 0x03, 0x00}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.conn.Write(frame)
	return err
}

func (s *v2rayMuxStream) Read(p []byte) (int, error) { return s.reader.Read(p) }

func (s *v2rayMuxStream) Write(p []byte) (int, error) {
	if len(p) > 65535 {
		return 0, fmt.Errorf("v2ray mux payload too large: %d", len(p))
	}
	if err := s.parent.writeFrame(s.id, 0x02, 0x01, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *v2rayMuxStream) Close() error {
	var err error
	s.mu.Do(func() {
		_ = s.writer.Close()
		s.parent.muxt.Lock()
		delete(s.parent.streams, s.id)
		s.parent.muxt.Unlock()
		err = s.parent.writeEnd(s.id)
	})
	return err
}

func (s *v2rayMuxStream) LocalAddr() net.Addr              { return s.parent.conn.LocalAddr() }
func (s *v2rayMuxStream) RemoteAddr() net.Addr             { return s.parent.conn.RemoteAddr() }
func (s *v2rayMuxStream) SetDeadline(time.Time) error      { return nil }
func (s *v2rayMuxStream) SetReadDeadline(time.Time) error  { return nil }
func (s *v2rayMuxStream) SetWriteDeadline(time.Time) error { return nil }

func (s *v2rayMuxServer) serve(shadowsocks func(net.Conn)) error {
	defer func() {
		s.muxt.Lock()
		for id, stream := range s.streams {
			_ = stream.writer.CloseWithError(io.ErrClosedPipe)
			delete(s.streams, id)
		}
		s.muxt.Unlock()
	}()
	for {
		header := make([]byte, 2)
		if _, err := io.ReadFull(s.conn, header); err != nil {
			return err
		}
		metadataSize := int(binary.BigEndian.Uint16(header))
		if metadataSize < 4 || metadataSize > 512 {
			return fmt.Errorf("invalid v2ray mux metadata size %d", metadataSize)
		}
		metadata := make([]byte, metadataSize)
		if _, err := io.ReadFull(s.conn, metadata); err != nil {
			return err
		}
		id := binary.BigEndian.Uint16(metadata[0:2])
		status, option := metadata[2], metadata[3]
		switch status {
		case 0x01: // New
			if option != 0 || metadataSize < 12 {
				return fmt.Errorf("invalid v2ray mux new frame")
			}
			reader, writer := io.Pipe()
			stream := &v2rayMuxStream{parent: s, id: id, reader: reader, writer: writer}
			s.muxt.Lock()
			if _, exists := s.streams[id]; exists {
				s.muxt.Unlock()
				return fmt.Errorf("duplicate v2ray mux stream %d", id)
			}
			s.streams[id] = stream
			s.muxt.Unlock()
			go shadowsocks(stream)
		case 0x02: // Keep
			if option == 1 {
				length := make([]byte, 2)
				if _, err := io.ReadFull(s.conn, length); err != nil {
					return err
				}
				payload := make([]byte, int(binary.BigEndian.Uint16(length)))
				if _, err := io.ReadFull(s.conn, payload); err != nil {
					return err
				}
				s.muxt.Lock()
				stream := s.streams[id]
				s.muxt.Unlock()
				if stream != nil {
					if _, err := stream.writer.Write(payload); err != nil {
						return err
					}
				}
			}
		case 0x03: // End
			s.muxt.Lock()
			stream := s.streams[id]
			if stream != nil {
				_ = stream.writer.Close()
			}
			s.muxt.Unlock()
		case 0x04: // KeepAlive
		default:
			return fmt.Errorf("unknown v2ray mux status %d", status)
		}
	}
}

func startShadowsocksWebSocketMuxServer(t *testing.T, method, password string, tlsServer bool,
	plugin string, smuxVersion int) (string, func(), *int32) {
	t.Helper()
	shadowsocks, err := endpoints.StartShadowsocksTCPServer(method, password)
	if err != nil {
		t.Fatal(err)
	}
	var connectionCount int32
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/ss" {
			http.Error(writer, "unexpected WebSocket path", http.StatusNotFound)
			return
		}
		connection, upgradeErr := upgrader.Upgrade(writer, request, nil)
		if upgradeErr != nil {
			return
		}
		atomic.AddInt32(&connectionCount, 1)
		wsConn := &websocketNetConn{conn: connection}
		if plugin == "gost-plugin" {
			config := smux.DefaultConfig()
			config.KeepAliveDisabled = true
			config.Version = smuxVersion
			session, err := smux.Server(wsConn, config)
			if err != nil {
				_ = wsConn.Close()
				return
			}
			defer session.Close()
			for {
				stream, err := session.AcceptStream()
				if err != nil {
					return
				}
				go shadowsocks.ServeTCPConn(stream)
			}
		}
		mux := &v2rayMuxServer{conn: wsConn, streams: make(map[uint16]*v2rayMuxStream)}
		_ = mux.serve(shadowsocks.ServeTCPConn)
	})
	var server *httptest.Server
	if tlsServer {
		server = httptest.NewTLSServer(handler)
	} else {
		server = httptest.NewServer(handler)
	}
	address := strings.TrimPrefix(strings.TrimPrefix(server.URL, "http://"), "https://")
	cleanup := func() {
		server.Close()
		_ = shadowsocks.Close()
	}
	return address, cleanup, &connectionCount
}

func TestShadowsocksWebSocketPlugins(t *testing.T) {
	testHost := os.Getenv("CLASH_NATIVE_TEST_HOST")
	if testHost == "" {
		t.Skip("CLASH_NATIVE_TEST_HOST is not set")
	}

	tcpEcho, err := endpoints.StartTCPEcho()
	if err != nil {
		t.Fatal(err)
	}
	defer tcpEcho.Close()

	for _, test := range []struct {
		plugin string
		tls    bool
	}{
		{plugin: "v2ray-plugin"},
		{plugin: "gost-plugin"},
		{plugin: "v2ray-plugin", tls: true},
	} {
		test := test
		t.Run(test.plugin+"/"+map[bool]string{false: "http", true: "tls"}[test.tls], func(t *testing.T) {
			address, cleanup := startShadowsocksWebSocketServer(
				t, "chacha20-ietf-poly1305", mihomoTestPassword, test.tls)
			defer cleanup()

			env := map[string]string{
				"CLASH_NATIVE_TEST_OUTBOUND":             "shadowsocks",
				"CLASH_NATIVE_TEST_OUTBOUND_SERVER":      address,
				"CLASH_NATIVE_TEST_OUTBOUND_PASSWORD":    mihomoTestPassword,
				"CLASH_NATIVE_TEST_OUTBOUND_METHOD":      "chacha20-ietf-poly1305",
				"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN":      test.plugin,
				"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_MODE": "websocket",
				"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_HOST": "localhost",
				"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_PATH": "/ss",
				"CLASH_NATIVE_TEST_PROXY_HOST":           "127.0.0.1",
			}
			if test.tls {
				env["CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_TLS"] = "1"
				env["CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_SKIP_CERT_VERIFY"] = "1"
			}
			proxyAddress, stopProxy := startOutboundTestHost(t, env)
			defer stopProxy()

			client := socks5Connect(t, proxyAddress, tcpEcho.Addr())
			defer client.Close()
			payload := []byte(strings.Repeat("shadowsocks-websocket-plugin-", 4096))
			writeBytes(t, client, payload)
			echoed := make([]byte, len(payload))
			readBytes(t, client, echoed)
			if string(echoed) != string(payload) {
				t.Fatal("Shadowsocks WebSocket plugin returned different bytes")
			}
		})
	}
}

func TestShadowsocksWebSocketPluginMux(t *testing.T) {
	testHost := os.Getenv("CLASH_NATIVE_TEST_HOST")
	if testHost == "" {
		t.Skip("CLASH_NATIVE_TEST_HOST is not set")
	}
	tcpEcho, err := endpoints.StartTCPEcho()
	if err != nil {
		t.Fatal(err)
	}
	defer tcpEcho.Close()

	for _, test := range []struct {
		plugin      string
		tls         bool
		smuxVersion int
	}{
		{plugin: "v2ray-plugin"},
		{plugin: "gost-plugin", smuxVersion: 1},
		{plugin: "gost-plugin", smuxVersion: 2},
		{plugin: "v2ray-plugin", tls: true},
	} {
		test := test
		name := test.plugin + map[bool]string{false: "/http", true: "/tls"}[test.tls]
		if test.plugin == "gost-plugin" {
			name += fmt.Sprintf("/smux-v%d", test.smuxVersion)
		}
		t.Run(name, func(t *testing.T) {
			address, cleanup, connectionCount := startShadowsocksWebSocketMuxServer(
				t, "chacha20-ietf-poly1305", mihomoTestPassword, test.tls, test.plugin,
				test.smuxVersion)
			defer cleanup()
			env := map[string]string{
				"CLASH_NATIVE_TEST_OUTBOUND":             "shadowsocks",
				"CLASH_NATIVE_TEST_OUTBOUND_SERVER":      address,
				"CLASH_NATIVE_TEST_OUTBOUND_PASSWORD":    mihomoTestPassword,
				"CLASH_NATIVE_TEST_OUTBOUND_METHOD":      "chacha20-ietf-poly1305",
				"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN":      test.plugin,
				"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_MODE": "websocket",
				"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_HOST": "localhost",
				"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_PATH": "/ss",
				"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_MUX":  "1",
				"CLASH_NATIVE_TEST_PROXY_HOST":           "127.0.0.1",
			}
			if test.tls {
				env["CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_TLS"] = "1"
				env["CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_SKIP_CERT_VERIFY"] = "1"
			}
			if test.plugin == "gost-plugin" && test.smuxVersion == 2 {
				env["CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_SMUX_VERSION"] = "2"
			}
			proxyAddress, stopProxy := startOutboundTestHost(t, env)
			defer stopProxy()

			first := socks5Connect(t, proxyAddress, tcpEcho.Addr())
			second := socks5Connect(t, proxyAddress, tcpEcho.Addr())
			defer first.Close()
			defer second.Close()
			payloadRepeat := 1024
			if test.smuxVersion == 2 {
				payloadRepeat = 32 * 1024
			}
			payload := []byte(strings.Repeat("shadowsocks-websocket-mux-", payloadRepeat))
			writeBytes(t, first, payload)
			echoed := make([]byte, len(payload))
			readBytes(t, first, echoed)
			if string(echoed) != string(payload) {
				t.Fatal("first mux stream returned different bytes")
			}
			writeBytes(t, second, payload)
			readBytes(t, second, echoed)
			if string(echoed) != string(payload) {
				t.Fatal("second mux stream returned different bytes")
			}
			if got := atomic.LoadInt32(connectionCount); got != 1 {
				t.Fatalf("expected one WebSocket carrier, got %d", got)
			}
		})
	}
}

func TestShadowsocksWebSocketPluginTLSOptions(t *testing.T) {
	testHost := os.Getenv("CLASH_NATIVE_TEST_HOST")
	if testHost == "" {
		t.Skip("CLASH_NATIVE_TEST_HOST is not set")
	}
	tcpEcho, err := endpoints.StartTCPEcho()
	if err != nil {
		t.Fatal(err)
	}
	defer tcpEcho.Close()

	baseEnvironment := func(address string) map[string]string {
		return map[string]string{
			"CLASH_NATIVE_TEST_OUTBOUND":             "shadowsocks",
			"CLASH_NATIVE_TEST_OUTBOUND_SERVER":      address,
			"CLASH_NATIVE_TEST_OUTBOUND_PASSWORD":    mihomoTestPassword,
			"CLASH_NATIVE_TEST_OUTBOUND_METHOD":      "chacha20-ietf-poly1305",
			"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN":      "v2ray-plugin",
			"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_MODE": "websocket",
			"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_TLS":  "1",
			"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_HOST": "example.com",
			"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_PATH": "/ss",
			"CLASH_NATIVE_TEST_PROXY_HOST":           "127.0.0.1",
		}
	}
	roundTrip := func(t *testing.T, proxyAddress, payload string) {
		t.Helper()
		client := socks5Connect(t, proxyAddress, tcpEcho.Addr())
		defer client.Close()
		data := []byte(strings.Repeat(payload, 4096))
		writeBytes(t, client, data)
		echoed := make([]byte, len(data))
		readBytes(t, client, echoed)
		if string(echoed) != string(data) {
			t.Fatal("Shadowsocks WebSocket plugin returned different bytes")
		}
	}
	expectConnectFailure := func(t *testing.T, proxyAddress string) {
		t.Helper()
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
			t.Fatal("C++ WebSocket plugin outbound accepted a rejected handshake")
		}
	}
	pinOf := func(t *testing.T, raw []byte) string {
		t.Helper()
		sum := sha256.Sum256(raw)
		return hex.EncodeToString(sum[:])
	}

	// startChainServer serves a leaf-plus-CA chain (fixture certificates
	// with localhost/127.0.0.1 SANs) and returns the CA pin: leaf pins skip
	// hostname checks (matching Mihomo), so name-verify needs the CA pin.
	startChainServer := func(t *testing.T) (string, string, func()) {
		t.Helper()
		material, err := endpoints.NewTrojanTLSMaterial()
		if err != nil {
			t.Fatal(err)
		}
		address, _, cleanup := startShadowsocksWebSocketServerEx(t,
			"chacha20-ietf-poly1305", mihomoTestPassword, shadowsocksWebSocketServerOptions{
				tls:            true,
				certificatePEM: material.CertificatePEM,
				privateKeyPEM:  material.PrivateKeyPEM,
				chainPEM:       material.CACertificatePEM,
			})
		block, _ := pem.Decode(material.CACertificatePEM)
		if block == nil {
			t.Fatal("decode chain server CA certificate")
		}
		ca, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return address, pinOf(t, ca.Raw), cleanup
	}

	t.Run("headers", func(t *testing.T) {
		address, _, cleanup := startShadowsocksWebSocketServerEx(t,
			"chacha20-ietf-poly1305", mihomoTestPassword, shadowsocksWebSocketServerOptions{
				tls:             true,
				expectedHeaders: map[string]string{"X-Clash-Native-Test": "ws-plugin"},
			})
		defer cleanup()
		// The peer answers 400 without the custom header, so a round trip
		// proves the header reached the handshake.
		env := baseEnvironment(address)
		env["CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_HEADERS"] = "X-Clash-Native-Test: ws-plugin"
		env["CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_SKIP_CERT_VERIFY"] = "1"
		proxyAddress, stopProxy := startOutboundTestHost(t, env)
		defer stopProxy()
		roundTrip(t, proxyAddress, "shadowsocks-ws-plugin-headers-")
	})

	t.Run("pin", func(t *testing.T) {
		address, raw, cleanup := startShadowsocksWebSocketServerEx(t,
			"chacha20-ietf-poly1305", mihomoTestPassword,
			shadowsocksWebSocketServerOptions{tls: true})
		defer cleanup()
		env := baseEnvironment(address)
		env["CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_FINGERPRINT"] = pinOf(t, raw)
		proxyAddress, stopProxy := startOutboundTestHost(t, env)
		defer stopProxy()
		roundTrip(t, proxyAddress, "shadowsocks-ws-plugin-pin-")
	})

	t.Run("wrong-pin", func(t *testing.T) {
		address, _, cleanup := startShadowsocksWebSocketServerEx(t,
			"chacha20-ietf-poly1305", mihomoTestPassword,
			shadowsocksWebSocketServerOptions{tls: true})
		defer cleanup()
		env := baseEnvironment(address)
		env["CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_FINGERPRINT"] = strings.Repeat("0", 64)
		proxyAddress, stopProxy := startOutboundTestHost(t, env)
		defer stopProxy()
		expectConnectFailure(t, proxyAddress)
	})

	t.Run("name-verify", func(t *testing.T) {
		address, caPin, cleanup := startChainServer(t)
		defer cleanup()
		env := baseEnvironment(address)
		env["CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_HOST"] = "unrelated.invalid"
		env["CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_FINGERPRINT"] = caPin
		env["CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_NAME_CERT_VERIFY"] = "localhost"
		proxyAddress, stopProxy := startOutboundTestHost(t, env)
		defer stopProxy()
		// SNI stays unrelated.invalid (no such SAN); only the override lets
		// the re-rooted chain check pass against the leaf localhost SAN.
		roundTrip(t, proxyAddress, "shadowsocks-ws-plugin-name-verify-")
	})

	t.Run("wrong-name-verify", func(t *testing.T) {
		address, caPin, cleanup := startChainServer(t)
		defer cleanup()
		env := baseEnvironment(address)
		env["CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_HOST"] = "unrelated.invalid"
		env["CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_FINGERPRINT"] = caPin
		proxyAddress, stopProxy := startOutboundTestHost(t, env)
		defer stopProxy()
		expectConnectFailure(t, proxyAddress)
	})

	t.Run("mtls", func(t *testing.T) {
		material, err := endpoints.NewTrojanTLSMaterial()
		if err != nil {
			t.Fatal(err)
		}
		address, raw, cleanup := startShadowsocksWebSocketServerEx(t,
			"chacha20-ietf-poly1305", mihomoTestPassword, shadowsocksWebSocketServerOptions{
				tls:               true,
				requireClientCert: true,
				certificatePEM:    material.CertificatePEM,
				privateKeyPEM:     material.PrivateKeyPEM,
			})
		defer cleanup()
		directory := t.TempDir()
		certificatePath := filepath.Join(directory, "client.pem")
		if err := os.WriteFile(certificatePath, material.CertificatePEM, 0o600); err != nil {
			t.Fatal(err)
		}
		keyPath := filepath.Join(directory, "client.key")
		if err := os.WriteFile(keyPath, material.PrivateKeyPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		env := baseEnvironment(address)
		env["CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_HOST"] = "localhost"
		env["CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_FINGERPRINT"] = pinOf(t, raw)
		env["CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_CERTIFICATE_FILE"] = certificatePath
		env["CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_PRIVATE_KEY_FILE"] = keyPath
		proxyAddress, stopProxy := startOutboundTestHost(t, env)
		defer stopProxy()
		// The peer requires a client certificate; the handshake only
		// completes when the configured identity is actually sent.
		roundTrip(t, proxyAddress, "shadowsocks-ws-plugin-mtls-")
	})

	t.Run("mtls-missing-identity", func(t *testing.T) {
		material, err := endpoints.NewTrojanTLSMaterial()
		if err != nil {
			t.Fatal(err)
		}
		address, raw, cleanup := startShadowsocksWebSocketServerEx(t,
			"chacha20-ietf-poly1305", mihomoTestPassword, shadowsocksWebSocketServerOptions{
				tls:               true,
				requireClientCert: true,
				certificatePEM:    material.CertificatePEM,
				privateKeyPEM:     material.PrivateKeyPEM,
			})
		defer cleanup()
		env := baseEnvironment(address)
		env["CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_HOST"] = "localhost"
		env["CLASH_NATIVE_TEST_OUTBOUND_PLUGIN_FINGERPRINT"] = pinOf(t, raw)
		proxyAddress, stopProxy := startOutboundTestHost(t, env)
		defer stopProxy()
		expectConnectFailure(t, proxyAddress)
	})
}
