package interop

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

const websocketInteropPayloadSize = 256 * 1024

func makeWebSocketInteropPayload() []byte {
	payload := make([]byte, websocketInteropPayloadSize)
	copy(payload, []byte("clash-native-websocket-interop"))
	for index := len("clash-native-websocket-interop"); index < len(payload); index++ {
		payload[index] = byte((index*31 + 17) & 0xff)
	}
	return payload
}

func TestWebSocketClientInteroperability(t *testing.T) {
	executable := os.Getenv("CLASH_NATIVE_WEBSOCKET_CLIENT")
	if executable == "" {
		t.Skip("CLASH_NATIVE_WEBSOCKET_CLIENT is not set")
	}

	payload := makeWebSocketInteropPayload()
	serverResult := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.ProtoMajor != 1 || request.ProtoMinor != 1 || request.URL.Path != "/ws" ||
			request.Header.Get("X-Test-WebSocket") != "clash-native" {
			serverResult <- &webSocketInteropError{"unexpected handshake request"}
			return
		}
		upgrader := websocket.Upgrader{
			CheckOrigin: func(*http.Request) bool { return true },
		}
		connection, upgradeErr := upgrader.Upgrade(writer, request, nil)
		if upgradeErr != nil {
			serverResult <- upgradeErr
			return
		}
		defer connection.Close()
		_ = connection.WriteControl(websocket.PingMessage, []byte("interop-ping"), time.Now().Add(5*time.Second))
		messageType, received, readErr := connection.ReadMessage()
		if readErr != nil {
			serverResult <- readErr
			return
		}
		if messageType != websocket.BinaryMessage || !bytes.Equal(received, payload) {
			serverResult <- &webSocketInteropError{"unexpected binary message"}
			return
		}
		if writeErr := connection.WriteMessage(websocket.BinaryMessage, received); writeErr != nil {
			serverResult <- writeErr
			return
		}
		// Keep the connection open until the client has consumed the echo. Closing
		// immediately after WriteMessage can reset unread TCP data on Windows.
		_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _, _ = connection.ReadMessage()
		serverResult <- nil
	}))
	defer server.Close()

	address := strings.TrimPrefix(server.URL, "http://")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, address)
	output, commandErr := command.CombinedOutput()
	serverErr := <-serverResult
	if ctx.Err() != nil {
		t.Fatalf("WebSocket client timed out: %v\n%s", ctx.Err(), output)
	}
	if commandErr != nil {
		t.Fatalf("WebSocket client failed: %v\n%s", commandErr, output)
	}
	if serverErr != nil {
		t.Fatalf("WebSocket server failed: %v", serverErr)
	}
}

type webSocketInteropError struct {
	message string
}

func (e *webSocketInteropError) Error() string { return e.message }
