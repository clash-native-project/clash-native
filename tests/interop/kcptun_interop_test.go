package interop

import (
	"bytes"
	"crypto/sha1"
	"io"
	"net"
	"os"
	"sync"
	"testing"

	"clash-native/interop/endpoints"

	kcp "github.com/metacubex/kcp-go"
	"github.com/metacubex/smux"
	"golang.org/x/crypto/pbkdf2"
)

type independentKcptunServer struct {
	packetConn net.PacketConn
	listener   *kcp.Listener
	closed     chan struct{}
	mu         sync.Mutex
	sessions   map[*kcp.UDPSession]*smux.Session
	wg         sync.WaitGroup
}

func startIndependentKcptunServer(t *testing.T, handler func(net.Conn)) *independentKcptunServer {
	t.Helper()
	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen independent kcptun UDP socket: %v", err)
	}
	pass := pbkdf2.Key([]byte("clash-native-kcptun-test-key"), []byte("kcp-go"), 4096, 32, sha1.New)
	block, err := kcp.NewAESGCMCrypt(pass[:16])
	if err != nil {
		_ = packetConn.Close()
		t.Fatalf("create independent kcptun AES-GCM block: %v", err)
	}
	listener, err := kcp.ServeConn(block, 10, 3, packetConn)
	if err != nil {
		_ = packetConn.Close()
		t.Fatalf("start independent kcptun listener: %v", err)
	}
	server := &independentKcptunServer{
		packetConn: packetConn,
		listener:   listener,
		closed:     make(chan struct{}),
		sessions:   make(map[*kcp.UDPSession]*smux.Session),
	}
	server.wg.Add(1)
	go server.accept(t, handler)
	t.Cleanup(server.Close)
	return server
}

func (s *independentKcptunServer) accept(t *testing.T, handler func(net.Conn)) {
	defer s.wg.Done()
	for {
		connection, err := s.listener.AcceptKCP()
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
			}
			t.Errorf("independent kcptun accept: %v", err)
			return
		}
		connection.SetStreamMode(true)
		connection.SetWriteDelay(false)
		connection.SetNoDelay(0, 50, 0, 1)
		connection.SetWindowSize(128, 512)
		connection.SetMtu(1350)
		config := smux.DefaultConfig()
		config.Version = 1
		config.MaxFrameSize = 8192
		session, err := smux.Server(connection, config)
		if err != nil {
			_ = connection.Close()
			continue
		}
		s.mu.Lock()
		s.sessions[connection] = session
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.sessions, connection)
				s.mu.Unlock()
			}()
			for {
				stream, acceptErr := session.AcceptStream()
				if acceptErr != nil {
					return
				}
				handler(stream)
			}
		}()
	}
}

func (s *independentKcptunServer) Addr() string { return s.packetConn.LocalAddr().String() }

func (s *independentKcptunServer) Close() {
	select {
	case <-s.closed:
		return
	default:
		close(s.closed)
	}
	_ = s.listener.Close()
	_ = s.packetConn.Close()
	s.mu.Lock()
	for connection, session := range s.sessions {
		_ = session.Close()
		_ = connection.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func TestShadowsocksKcptunIndependentGoPeerPacketPipeline(t *testing.T) {
	if os.Getenv("CLASH_NATIVE_TEST_HOST") == "" {
		t.Skip("CLASH_NATIVE_TEST_HOST is not set")
	}
	echo, err := endpoints.StartTCPEcho()
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	const password = testOutboundPassword
	shadowsocksServer, err := endpoints.StartShadowsocksServer("chacha20-ietf-poly1305", password)
	if err != nil {
		t.Fatal(err)
	}
	defer shadowsocksServer.Close()
	kcptunServer := startIndependentKcptunServer(t, shadowsocksServer.ServeTCPConn)
	proxyAddress, stopProxy := startOutboundTestHost(t, map[string]string{
		"CLASH_NATIVE_TEST_OUTBOUND":                    "shadowsocks",
		"CLASH_NATIVE_TEST_OUTBOUND_SERVER":             kcptunServer.Addr(),
		"CLASH_NATIVE_TEST_OUTBOUND_PASSWORD":           password,
		"CLASH_NATIVE_TEST_OUTBOUND_METHOD":             "chacha20-ietf-poly1305",
		"CLASH_NATIVE_TEST_OUTBOUND_PLUGIN":             "kcptun",
		"CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_KEY":         "clash-native-kcptun-test-key",
		"CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_CRYPT":       "aes-128-gcm",
		"CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_NOCOMP":      "1",
		"CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_DATASHARD":   "10",
		"CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_PARITYSHARD": "3",
		"CLASH_NATIVE_TEST_OUTBOUND_KCPTUN_SMUXVER":     "1",
		"CLASH_NATIVE_TEST_PROXY_HOST":                  "127.0.0.1",
	})
	defer stopProxy()
	client := socks5Connect(t, proxyAddress, echo.Addr())
	defer client.Close()
	payload := bytes.Repeat([]byte("independent-kcptun-aes-gcm-fec-"), 4096)
	writeBytes(t, client, payload)
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(client, echoed); err != nil {
		t.Fatalf("read independent kcptun echo: %v", err)
	}
	if !bytes.Equal(echoed, payload) {
		t.Fatal("independent kcptun peer returned different bytes")
	}
}
