package interop

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	kcp "github.com/xtaci/kcp-go"
)

const kcpInteropPayloadSize = 256 * 1024

func makeKCPInteropPayload() []byte {
	payload := make([]byte, kcpInteropPayloadSize)
	copy(payload, []byte("clash-native-kcp-interop"))
	for index := len("clash-native-kcp-interop"); index < len(payload); index++ {
		payload[index] = byte((index*31 + 17) & 0xff)
	}
	return payload
}

func TestKCPClientInteroperability(t *testing.T) {
	executable := os.Getenv("CLASH_NATIVE_KCP_CLIENT")
	if executable == "" {
		t.Skip("CLASH_NATIVE_KCP_CLIENT is not set")
	}

	listener, err := kcp.ListenWithOptions("127.0.0.1:0", nil, 0, 0)
	if err != nil {
		t.Fatalf("start KCP listener: %v", err)
	}
	defer listener.Close()

	serverResult := make(chan error, 1)
	serverClose := make(chan struct{})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		session, ok := connection.(*kcp.UDPSession)
		if !ok {
			_ = connection.Close()
			serverResult <- &unexpectedKCPConnectionError{}
			return
		}
		session.SetStreamMode(true)
		session.SetNoDelay(1, 20, 2, 1)
		session.SetWindowSize(128, 128)

		payload := make([]byte, kcpInteropPayloadSize)
		if _, readErr := io.ReadFull(session, payload); readErr != nil {
			serverResult <- readErr
			return
		}
		if !bytes.Equal(payload, makeKCPInteropPayload()) {
			serverResult <- &unexpectedKCPPayloadError{}
			return
		}
		_, writeErr := session.Write(payload)
		serverResult <- writeErr
		if writeErr == nil {
			<-serverClose
		}
		_ = connection.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, listener.Addr().String())
	output, commandErr := command.CombinedOutput()
	serverErr := <-serverResult
	close(serverClose)
	if ctx.Err() != nil {
		t.Fatalf("KCP client timed out: %v\n%s", ctx.Err(), output)
	}
	if commandErr != nil {
		t.Fatalf("KCP client failed: %v\n%s", commandErr, output)
	}

	if serverErr != nil {
		t.Fatalf("KCP server failed: %v", serverErr)
	}
}

type unexpectedKCPConnectionError struct{}

func (*unexpectedKCPConnectionError) Error() string {
	return "KCP listener returned an unexpected connection type"
}

type unexpectedKCPPayloadError struct{}

func (*unexpectedKCPPayloadError) Error() string { return "KCP server received an unexpected payload" }
