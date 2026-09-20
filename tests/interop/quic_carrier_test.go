package interop

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestQUICCarrierExposesStreamsAndDatagrams(t *testing.T) {
	executable := os.Getenv("CLASH_NATIVE_HTTP_TUNNEL_CLIENT")
	if executable == "" {
		t.Skip("CLASH_NATIVE_HTTP_TUNNEL_CLIENT is not set")
	}

	certificatePath, keyPath := writeDnsproxyCertificate(t)
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		t.Fatalf("load QUIC carrier certificate: %v", err)
	}
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for QUIC carrier fixture: %v", err)
	}
	listener, err := quic.Listen(packetConn, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"raw-quic"},
	}, &quic.Config{
		EnableDatagrams:                true,
		MaxIncomingStreams:             32,
		MaxIdleTimeout:                 10 * time.Second,
		InitialStreamReceiveWindow:     64 * 1024,
		MaxStreamReceiveWindow:         64 * 1024,
		InitialConnectionReceiveWindow: 128 * 1024,
		MaxConnectionReceiveWindow:     128 * 1024,
	})
	if err != nil {
		_ = packetConn.Close()
		t.Fatalf("start QUIC carrier fixture: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var connections sync.Map
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			connection, acceptErr := listener.Accept(ctx)
			if acceptErr != nil {
				return
			}
			connections.Store(connection, struct{}{})
			go serveRawQUICCarrier(connection, &connections)
		}
	}()

	address := packetConn.LocalAddr().String()
	defer func() {
		cancel()
		_ = listener.Close()
		connections.Range(func(key, _ any) bool {
			_ = key.(*quic.Conn).CloseWithError(0, "test complete")
			return true
		})
		_ = packetConn.Close()
		<-acceptDone
	}()

	commandContext, commandCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer commandCancel()
	command := exec.CommandContext(commandContext, executable, "quic", address)
	if output, commandErr := command.CombinedOutput(); commandErr != nil {
		t.Fatalf("raw QUIC carrier client failed: %v\n%s", commandErr, output)
	}
}

func serveRawQUICCarrier(connection *quic.Conn, connections *sync.Map) {
	defer connections.Delete(connection)
	go func() {
		for {
			payload, err := connection.ReceiveDatagram(connection.Context())
			if err != nil {
				return
			}
			if err := connection.SendDatagram(payload); err != nil {
				return
			}
		}
	}()
	for {
		stream, err := connection.AcceptStream(connection.Context())
		if err != nil {
			return
		}
		go func() {
			_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
			buffer := make([]byte, len("quic-stream-0"))
			count, readErr := io.ReadFull(stream, buffer)
			if readErr != nil || count != len(buffer) {
				return
			}
			_, _ = stream.Write(buffer)
			_ = stream.Close()
		}()
	}
}
