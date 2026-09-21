package interop

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
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

func startShadowsocksWebSocketServer(t *testing.T, method, password string, tlsServer bool) (string, func()) {
	t.Helper()
	shadowsocks, err := endpoints.StartShadowsocksServer(method, password)
	if err != nil {
		t.Fatal(err)
	}

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
		shadowsocks.ServeTCPConn(&websocketNetConn{conn: connection})
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
	return address, cleanup
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
	plugin string) (string, func(), *int32) {
	t.Helper()
	shadowsocks, err := endpoints.StartShadowsocksServer(method, password)
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
		plugin string
		tls    bool
	}{
		{plugin: "v2ray-plugin"},
		{plugin: "gost-plugin"},
		{plugin: "v2ray-plugin", tls: true},
	} {
		test := test
		t.Run(test.plugin+map[bool]string{false: "/http", true: "/tls"}[test.tls], func(t *testing.T) {
			address, cleanup, connectionCount := startShadowsocksWebSocketMuxServer(
				t, "chacha20-ietf-poly1305", mihomoTestPassword, test.tls, test.plugin)
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
			proxyAddress, stopProxy := startOutboundTestHost(t, env)
			defer stopProxy()

			first := socks5Connect(t, proxyAddress, tcpEcho.Addr())
			second := socks5Connect(t, proxyAddress, tcpEcho.Addr())
			defer first.Close()
			defer second.Close()
			payload := []byte(strings.Repeat("shadowsocks-websocket-mux-", 1024))
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
