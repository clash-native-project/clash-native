package interop

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"clash-native/interop/endpoints"
	"github.com/gorilla/websocket"
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
