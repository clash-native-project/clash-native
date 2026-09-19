package interop

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"clash-native/interop/harness"
)

func startHTTPForwardProxy(t *testing.T) string {
	t.Helper()
	executable := os.Getenv("CLASH_NATIVE_TEST_HOST")
	if executable == "" {
		t.Skip("CLASH_NATIVE_TEST_HOST is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	process, err := harness.Start(ctx, executable)
	if err != nil {
		cancel()
		t.Fatalf("start test host: %v", err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			stdout, stderr := process.Output()
			t.Logf("test host output: stdout=%q stderr=%q", stdout, stderr)
		}
		stopContext, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer stopCancel()
		if err := process.Stop(stopContext); err != nil {
			t.Errorf("stop test host: %v", err)
		}
		cancel()
	})

	line, err := harness.WaitForLine(ctx, process, readyPrefix)
	if err != nil {
		t.Fatalf("wait for test host: %v", err)
	}
	return strings.TrimPrefix(line, readyPrefix)
}

type capturedHTTPForwardRequest struct {
	requestLine string
	headers     map[string][]string
	err         error
}

func TestHTTPForwardProxyAbsoluteFormAndHopHeaders(t *testing.T) {
	proxyAddress := startHTTPForwardProxy(t)
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for raw origin: %v", err)
	}
	defer origin.Close()

	captured := make(chan capturedHTTPForwardRequest, 1)
	go func() {
		connection, err := origin.Accept()
		if err != nil {
			captured <- capturedHTTPForwardRequest{err: err}
			return
		}
		defer connection.Close()

		reader := bufio.NewReader(connection)
		requestLine, err := reader.ReadString('\n')
		if err != nil {
			captured <- capturedHTTPForwardRequest{err: err}
			return
		}
		headers := make(map[string][]string)
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				captured <- capturedHTTPForwardRequest{err: readErr}
				return
			}
			if line == "\r\n" {
				break
			}
			name, value, found := strings.Cut(strings.TrimRight(line, "\r\n"), ":")
			if !found {
				captured <- capturedHTTPForwardRequest{err: fmt.Errorf("malformed header %q", line)}
				return
			}
			key := strings.ToLower(strings.TrimSpace(name))
			headers[key] = append(headers[key], strings.TrimSpace(value))
		}
		captured <- capturedHTTPForwardRequest{requestLine: strings.TrimRight(requestLine, "\r\n"),
			headers: headers}
		_, _ = io.WriteString(connection,
			"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	}()

	client, err := net.DialTimeout("tcp", proxyAddress, 2*time.Second)
	if err != nil {
		t.Fatalf("connect to HTTP proxy: %v", err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	authority := origin.Addr().String()
	request := fmt.Sprintf(
		"GET http://%s/path?q=forward HTTP/1.1\r\n"+
			"Host: wrong.invalid\r\n"+
			"Connection: X-Remove, keep-alive\r\n"+
			"X-Remove: must-not-reach-origin\r\n"+
			"Proxy-Connection: keep-alive\r\n"+
			"Proxy-Authorization: Basic c2VjcmV0\r\n\r\n",
		authority)
	writeBytes(t, client, []byte(request))

	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read proxy response: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read proxy response body: %v", err)
	}
	if response.StatusCode != http.StatusAccepted || string(body) != "ok" {
		t.Fatalf("unexpected proxy response: status=%d body=%q", response.StatusCode, body)
	}

	select {
	case request := <-captured:
		if request.err != nil {
			t.Fatalf("capture origin request: %v", request.err)
		}
		if request.requestLine != "GET /path?q=forward HTTP/1.1" {
			t.Errorf("origin received request line %q", request.requestLine)
		}
		if got := request.headers["host"]; len(got) != 1 || got[0] != authority {
			t.Errorf("origin received Host %v, expected %q", got, authority)
		}
		for _, name := range []string{"x-remove", "proxy-authorization", "proxy-connection"} {
			if got := request.headers[name]; len(got) != 0 {
				t.Errorf("origin received stripped header %s: %v", name, got)
			}
		}
		for _, connection := range request.headers["connection"] {
			if strings.Contains(strings.ToLower(connection), "x-remove") {
				t.Errorf("origin received incoming Connection option: %q", connection)
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("origin did not receive the forwarded request")
	}
}

func TestHTTPForwardProxyNoBodyResponseLengthSemantics(t *testing.T) {
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for raw origin: %v", err)
	}
	defer origin.Close()

	go func() {
		for range 4 {
			connection, acceptErr := origin.Accept()
			if acceptErr != nil {
				return
			}
			go func(connection net.Conn) {
				defer connection.Close()
				request, readErr := http.ReadRequest(bufio.NewReader(connection))
				if readErr != nil {
					return
				}
				defer request.Body.Close()
				switch {
				case request.Method == http.MethodHead:
					_, _ = io.WriteString(connection,
						"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\n")
				case request.URL.Path == "/not-modified":
					_, _ = io.WriteString(connection,
						"HTTP/1.1 304 Not Modified\r\nContent-Length: 42\r\nConnection: close\r\n\r\n")
				case request.URL.Path == "/reset":
					_, _ = io.WriteString(connection,
						"HTTP/1.1 205 Reset Content\r\nConnection: close\r\n\r\n")
				default:
					_, _ = io.WriteString(connection,
						"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
				}
			}(connection)
		}
	}()

	proxyAddress := startHTTPForwardProxy(t)
	for _, test := range []struct {
		method            string
		path              string
		status            int
		contentLength     string
		wantContentLength bool
	}{
		{method: http.MethodHead, path: "/head", status: http.StatusOK,
			contentLength: "17", wantContentLength: true},
		{method: http.MethodGet, path: "/not-modified", status: http.StatusNotModified,
			contentLength: "42", wantContentLength: true},
		{method: http.MethodGet, path: "/empty", status: http.StatusNoContent},
		{method: http.MethodGet, path: "/reset", status: http.StatusResetContent},
	} {
		client, dialErr := net.DialTimeout("tcp", proxyAddress, 2*time.Second)
		if dialErr != nil {
			t.Fatalf("connect to HTTP proxy: %v", dialErr)
		}
		_ = client.SetDeadline(time.Now().Add(10 * time.Second))
		target := fmt.Sprintf("http://%s%s", origin.Addr(), test.path)
		_, writeErr := fmt.Fprintf(client,
			"%s %s HTTP/1.1\r\nHost: wrong.invalid\r\nConnection: close\r\n\r\n",
			test.method, target)
		if writeErr != nil {
			client.Close()
			t.Fatalf("write %s request: %v", test.method, writeErr)
		}
		response, readErr := http.ReadResponse(bufio.NewReader(client),
			&http.Request{Method: test.method})
		if readErr != nil {
			client.Close()
			t.Fatalf("read %s response: %v", test.method, readErr)
		}
		if response.StatusCode != test.status {
			client.Close()
			t.Fatalf("%s response status is %d, expected %d", test.method,
				response.StatusCode, test.status)
		}
		if got := response.Header.Get("Content-Length"); test.wantContentLength && got != test.contentLength {
			client.Close()
			t.Errorf("%s Content-Length is %q, expected %q", test.method, got, test.contentLength)
		} else if !test.wantContentLength && got != "" {
			client.Close()
			t.Errorf("%s response unexpectedly contains Content-Length %q", test.method, got)
		}
		if len(response.TransferEncoding) != 0 {
			client.Close()
			t.Errorf("%s no-body response has transfer encoding %v", test.method,
				response.TransferEncoding)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		_ = client.Close()
	}
}

func TestHTTPForwardProxyStreamsRequestResponseAndTrailers(t *testing.T) {
	const chunkSize = 16 * 1024
	const transferSize = 2 * 1024 * 1024
	firstRequestChunkRead := make(chan error, 1)
	firstResponseChunkWritten := make(chan struct{}, 1)
	allowResponseRemainder := make(chan struct{})
	originRequestResult := make(chan error, 1)
	responsePayload := bytes.Repeat([]byte("R"), transferSize)

	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.RequestURI() != "/upload?mode=stream" {
			originRequestResult <- fmt.Errorf("origin received %s %s", request.Method, request.URL)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		first := make([]byte, chunkSize)
		if _, err := io.ReadFull(request.Body, first); err != nil {
			firstRequestChunkRead <- err
			originRequestResult <- err
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		firstRequestChunkRead <- nil
		remaining, err := io.ReadAll(request.Body)
		if err != nil {
			originRequestResult <- fmt.Errorf("read complete request body: %w", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(first)+len(remaining) != transferSize {
			originRequestResult <- fmt.Errorf("origin received %d request bytes, expected %d",
				len(first)+len(remaining), transferSize)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if got := request.Trailer.Get("X-Request-Tag"); got != "request-complete" {
			originRequestResult <- fmt.Errorf("origin received request trailer %q", got)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if got := request.Host; got == "" || got == "wrong.invalid" {
			originRequestResult <- fmt.Errorf("origin received invalid Host %q", got)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		originRequestResult <- nil

		writer.Header().Set("Trailer", "X-Response-Tag")
		writer.WriteHeader(http.StatusOK)
		if _, err := writer.Write(responsePayload[:chunkSize]); err != nil {
			return
		}
		writer.(http.Flusher).Flush()
		firstResponseChunkWritten <- struct{}{}
		select {
		case <-allowResponseRemainder:
		case <-request.Context().Done():
			return
		}
		if _, err := writer.Write(responsePayload[chunkSize:]); err != nil {
			return
		}
		writer.Header().Set("X-Response-Tag", "response-complete")
	}))
	defer origin.Close()

	proxyAddress := startHTTPForwardProxy(t)
	client, err := net.DialTimeout("tcp", proxyAddress, 2*time.Second)
	if err != nil {
		t.Fatalf("connect to HTTP proxy: %v", err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(20 * time.Second))
	serverAuthority := strings.TrimPrefix(origin.URL, "http://")
	_, err = fmt.Fprintf(client,
		"POST http://%s/upload?mode=stream HTTP/1.1\r\n"+
			"Host: wrong.invalid\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Trailer: X-Request-Tag\r\n"+
			"Connection: close\r\n\r\n",
		serverAuthority)
	if err != nil {
		t.Fatalf("write request headers: %v", err)
	}

	requestPayload := bytes.Repeat([]byte("Q"), transferSize)
	writeHTTPChunk(t, client, requestPayload[:chunkSize])
	select {
	case err := <-firstRequestChunkRead:
		if err != nil {
			t.Fatalf("origin did not receive the first request chunk: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("origin did not receive request data before the upload completed")
	}
	for offset := chunkSize; offset < len(requestPayload); offset += chunkSize {
		end := offset + chunkSize
		if end > len(requestPayload) {
			end = len(requestPayload)
		}
		writeHTTPChunk(t, client, requestPayload[offset:end])
	}
	writeBytes(t, client, []byte("0\r\nX-Request-Tag: request-complete\r\n\r\n"))

	select {
	case err := <-originRequestResult:
		if err != nil {
			t.Fatalf("origin request validation failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("origin did not finish reading the forwarded request")
	}

	reader := bufio.NewReader(client)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("read streaming proxy response: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		errorBody, _ := io.ReadAll(response.Body)
		t.Fatalf("unexpected response status %d: %q", response.StatusCode, errorBody)
	}

	select {
	case <-firstResponseChunkWritten:
	case <-time.After(5 * time.Second):
		t.Fatal("origin did not write the first response chunk")
	}
	firstResponse := make([]byte, chunkSize)
	if n, err := io.ReadFull(response.Body, firstResponse); err != nil {
		t.Fatalf("read response before origin completed it: read %d of %d bytes: %v", n, len(firstResponse), err)
	}
	if !bytes.Equal(firstResponse, responsePayload[:chunkSize]) {
		t.Fatal("first streamed response chunk does not match origin payload")
	}
	close(allowResponseRemainder)
	remaining, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read remaining response body: %v", err)
	}
	if !bytes.Equal(remaining, responsePayload[chunkSize:]) {
		t.Fatalf("received %d response bytes after the first chunk, expected %d",
			len(remaining), transferSize-chunkSize)
	}
	if got := response.Trailer.Get("X-Response-Tag"); got != "response-complete" {
		t.Errorf("response trailer is %q", got)
	}
}

func writeHTTPChunk(t *testing.T, writer io.Writer, chunk []byte) {
	t.Helper()
	if _, err := fmt.Fprintf(writer, "%x\r\n", len(chunk)); err != nil {
		t.Fatalf("write HTTP chunk length: %v", err)
	}
	writeBytes(t, writer, chunk)
	writeBytes(t, writer, []byte("\r\n"))
}
