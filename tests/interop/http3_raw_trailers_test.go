package interop

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

type rawHTTP3RequestObservation struct {
	streamID     quic.StreamID
	id           string
	bodyBytes    int
	frameTypes   []uint64
	trailerValue string
}

// quic-go v0.54.0's HTTP/3 server-side Stream.Read discards trailer HEADERS
// frames. This fixture uses the QUIC stream API directly so request trailers
// are observed and validated as actual HTTP/3 frames.
func TestHTTP3ClientSessionStreamsBodiesAndTrailersWithRawPeer(t *testing.T) {
	executable := os.Getenv("CLASH_NATIVE_HTTP_TUNNEL_CLIENT")
	if executable == "" {
		t.Skip("CLASH_NATIVE_HTTP_TUNNEL_CLIENT is not set")
	}

	address, closeFixture, observations := startRawHTTP3StreamingFixture(t)
	defer closeFixture()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "http3", address, "streaming")
	type commandResult struct {
		output []byte
		err    error
	}
	commandDone := make(chan commandResult, 1)
	go func() {
		output, err := command.CombinedOutput()
		commandDone <- commandResult{output: output, err: err}
	}()

	seen := make(map[string]bool, 2)
	for len(seen) < 2 {
		select {
		case observation := <-observations:
			seen[observation.id] = true
			t.Logf("raw HTTP/3 stream %d: frame types %v, DATA bytes %d, request trailer %q",
				observation.streamID, observation.frameTypes, observation.bodyBytes,
				observation.trailerValue)
		case result := <-commandDone:
			t.Fatalf("HTTP/3 client exited before both request trailers arrived: %v\n%s", result.err, result.output)
		case <-ctx.Done():
			t.Fatalf("timed out waiting for request trailers; observed streams: %#v", seen)
		}
	}
	select {
	case result := <-commandDone:
		if result.err != nil {
			t.Fatalf("HTTP/3 streaming client failed against raw peer: %v\n%s", result.err, result.output)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for the HTTP/3 client to consume both response bodies and trailers")
	}
	t.Log("raw peer validated both concurrent 2 MiB request and response bodies with trailers")
}

func startRawHTTP3StreamingFixture(t *testing.T) (string, func(), <-chan rawHTTP3RequestObservation) {
	t.Helper()
	certificatePath, keyPath := writeDnsproxyCertificate(t)
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		t.Fatalf("load raw HTTP/3 fixture certificate: %v", err)
	}
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for raw HTTP/3 fixture: %v", err)
	}
	listener, err := quic.Listen(packetConn, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{http3.NextProtoH3},
	}, &quic.Config{
		MaxIdleTimeout:        20 * time.Second,
		MaxIncomingStreams:    8,
		MaxIncomingUniStreams: 8,
	})
	if err != nil {
		_ = packetConn.Close()
		t.Fatalf("start raw HTTP/3 fixture: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	observations := make(chan rawHTTP3RequestObservation, 2)
	connections := make(map[*quic.Conn]struct{})
	var connectionsMu sync.Mutex
	closing := false
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			connection, acceptErr := listener.Accept(ctx)
			if acceptErr != nil {
				return
			}
			connectionsMu.Lock()
			if closing {
				connectionsMu.Unlock()
				_ = connection.CloseWithError(0, "fixture closed")
				return
			}
			connections[connection] = struct{}{}
			workers.Add(1)
			connectionsMu.Unlock()
			go func() {
				defer workers.Done()
				defer func() {
					connectionsMu.Lock()
					delete(connections, connection)
					connectionsMu.Unlock()
				}()
				serveRawHTTP3StreamingConnection(connection, t.Logf, observations)
			}()
		}
	}()
	return packetConn.LocalAddr().String(), func() {
		cancel()
		_ = listener.Close()
		connectionsMu.Lock()
		closing = true
		for connection := range connections {
			_ = connection.CloseWithError(0, "fixture closed")
		}
		connectionsMu.Unlock()
		_ = packetConn.Close()
		workers.Wait()
	}, observations
}

func serveRawHTTP3StreamingConnection(connection *quic.Conn, logf func(string, ...any), observations chan<- rawHTTP3RequestObservation) {
	logf("raw HTTP/3 peer accepted QUIC connection from %s", connection.RemoteAddr())
	ctx, cancel := context.WithTimeout(connection.Context(), 45*time.Second)
	defer cancel()

	control, err := connection.OpenUniStreamSync(ctx)
	if err != nil {
		return
	}
	if err = writeRawHTTP3Bytes(control, append(quicvarint.Append(nil, 0x00), rawHTTP3SettingsFrame()...)); err != nil {
		logf("raw HTTP/3 peer failed to write server control stream: %v", err)
		return
	}
	logf("raw HTTP/3 peer wrote server control stream and SETTINGS")
	encoderStream, err := connection.OpenUniStreamSync(ctx)
	if err != nil {
		return
	}
	if err = writeRawHTTP3Bytes(encoderStream, quicvarint.Append(nil, 0x02)); err != nil {
		logf("raw HTTP/3 peer failed to write server QPACK encoder stream: %v", err)
		return
	}
	decoderStream, err := connection.OpenUniStreamSync(ctx)
	if err != nil {
		return
	}
	if err = writeRawHTTP3Bytes(decoderStream, quicvarint.Append(nil, 0x03)); err != nil {
		logf("raw HTTP/3 peer failed to write server QPACK decoder stream: %v", err)
		return
	}
	logf("raw HTTP/3 peer wrote server QPACK encoder and decoder stream types")

	settingsReady := make(chan error, 1)
	go consumeRawHTTP3ClientUniStreams(connection, settingsReady, logf)
	select {
	case err = <-settingsReady:
		if err != nil {
			logf("raw HTTP/3 peer failed reading client SETTINGS: %v", err)
			return
		}
		logf("raw HTTP/3 peer received client SETTINGS")
	case <-ctx.Done():
		logf("raw HTTP/3 peer timed out waiting for client SETTINGS: %v", ctx.Err())
		return
	}

	var requests sync.WaitGroup
	for index := 0; index < 2; index++ {
		stream, acceptErr := connection.AcceptStream(ctx)
		if acceptErr != nil {
			logf("raw HTTP/3 peer stopped accepting request stream %d: %v", index, acceptErr)
			break
		}
		logf("raw HTTP/3 peer accepted request stream %d", stream.StreamID())
		requests.Add(1)
		go func() {
			defer requests.Done()
			if requestErr := serveRawHTTP3StreamingRequest(stream, observations); requestErr != nil {
				logf("raw HTTP/3 peer request stream %d failed: %v", stream.StreamID(), requestErr)
				stream.CancelRead(0x0102)
				stream.CancelWrite(0x0102)
			}
		}()
	}
	requests.Wait()
	<-connection.Context().Done()
}

func rawHTTP3SettingsFrame() []byte {
	settings := quicvarint.Append(nil, 0x01) // QPACK max table capacity: zero.
	settings = quicvarint.Append(settings, 0)
	settings = quicvarint.Append(settings, 0x07) // QPACK blocked streams: zero.
	settings = quicvarint.Append(settings, 0)
	frame := quicvarint.Append(nil, 0x04)
	frame = quicvarint.Append(frame, uint64(len(settings)))
	return append(frame, settings...)
}

func consumeRawHTTP3ClientUniStreams(connection *quic.Conn, settingsReady chan<- error, logf func(string, ...any)) {
	var settingsReported sync.Once
	for {
		stream, err := connection.AcceptUniStream(connection.Context())
		if err != nil {
			settingsReported.Do(func() { settingsReady <- err })
			return
		}
		go func() {
			reader := bufio.NewReader(stream)
			streamType, readErr := quicvarint.Read(reader)
			if readErr != nil {
				logf("raw HTTP/3 peer failed reading client unidirectional stream type: %v", readErr)
				settingsReported.Do(func() { settingsReady <- readErr })
				return
			}
			logf("raw HTTP/3 peer received client unidirectional stream type %#x", streamType)
			if streamType == 0x00 {
				frameType, frameErr := quicvarint.Read(reader)
				if frameErr == nil && frameType != 0x04 {
					frameErr = fmt.Errorf("client control stream started with frame %d, expected SETTINGS", frameType)
				}
				var frameLength uint64
				if frameErr == nil {
					frameLength, frameErr = quicvarint.Read(reader)
				}
				if frameErr == nil {
					_, frameErr = io.CopyN(io.Discard, reader, int64(frameLength))
				}
				logf("raw HTTP/3 peer parsed client control SETTINGS frame: payload_bytes=%d err=%v", frameLength, frameErr)
				settingsReported.Do(func() { settingsReady <- frameErr })
			}
			_, _ = io.Copy(io.Discard, reader)
		}()
	}
}

func serveRawHTTP3StreamingRequest(stream *quic.Stream, observations chan<- rawHTTP3RequestObservation) error {
	reader := bufio.NewReader(stream)
	frameType, frameLength, err := readRawHTTP3FrameHeader(reader)
	if err != nil || frameType != 0x01 {
		return fmt.Errorf("read request HEADERS frame: type=%d err=%v", frameType, err)
	}
	frameTypes := []uint64{frameType}
	headerBlock := make([]byte, frameLength)
	if _, err = io.ReadFull(reader, headerBlock); err != nil {
		return fmt.Errorf("read request headers: %w", err)
	}
	fields, err := qpack.NewDecoder(nil).DecodeFull(headerBlock)
	if err != nil {
		return fmt.Errorf("decode request headers: %w", err)
	}
	headers := make(map[string]string, len(fields))
	for _, field := range fields {
		headers[field.Name] = field.Value
	}
	id := headers["x-test-id"]
	index := streamingIndex(id)
	if (id != "A" && id != "B") || headers[":method"] != "POST" ||
		headers[":scheme"] != "http" || headers[":authority"] != "localhost" ||
		headers[":path"] != "/stream/"+id {
		return fmt.Errorf("unexpected request pseudo-headers or X-Test-Id: %#v", headers)
	}
	if declared := strings.ToLower(headers["trailer"]); declared != "x-request-trailer" {
		return fmt.Errorf("request did not declare X-Request-Trailer: %q", declared)
	}

	body := make([]byte, 0, 2*1024*1024)
	var requestTrailer string
	for {
		frameType, frameLength, err = readRawHTTP3FrameHeader(reader)
		if err != nil {
			return fmt.Errorf("read request body frame: %w", err)
		}
		frameTypes = append(frameTypes, frameType)
		switch frameType {
		case 0x00:
			if frameLength > uint64(cap(body)-len(body)) {
				return fmt.Errorf("request body exceeded expected size")
			}
			start := len(body)
			body = body[:start+int(frameLength)]
			if _, err = io.ReadFull(reader, body[start:]); err != nil {
				return fmt.Errorf("read request DATA frame: %w", err)
			}
		case 0x01:
			if len(body) == 0 {
				return fmt.Errorf("received request trailers before DATA")
			}
			trailerBlock := make([]byte, frameLength)
			if _, err = io.ReadFull(reader, trailerBlock); err != nil {
				return fmt.Errorf("read request trailer block: %w", err)
			}
			trailers, decodeErr := qpack.NewDecoder(nil).DecodeFull(trailerBlock)
			if decodeErr != nil {
				return fmt.Errorf("decode request trailers: %w", decodeErr)
			}
			for _, trailer := range trailers {
				if trailer.Name == "x-request-trailer" {
					requestTrailer = trailer.Value
				}
			}
			goto trailersRead
		default:
			return fmt.Errorf("unexpected HTTP/3 request frame type %d", frameType)
		}
	}

trailersRead:
	expectedBody := makeInteropPayload("UPLOAD-"+id, index)
	if !bytes.Equal(body, expectedBody) {
		return fmt.Errorf("request body did not match expected 2 MiB payload")
	}
	if expected := "request-done-" + id; requestTrailer != expected {
		return fmt.Errorf("request trailer was %q, expected %q", requestTrailer, expected)
	}
	observations <- rawHTTP3RequestObservation{
		streamID:     stream.StreamID(),
		id:           id,
		bodyBytes:    len(body),
		frameTypes:   frameTypes,
		trailerValue: requestTrailer,
	}
	if err = writeRawHTTP3Headers(stream, []qpack.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "x-test-id", Value: id},
	}); err != nil {
		return fmt.Errorf("write response headers: %w", err)
	}
	time.Sleep(100 * time.Millisecond)
	responseBody := makeInteropPayload("DOWNLOAD-"+id, index)
	for offset := 0; offset < len(responseBody); {
		end := min(offset+16*1024, len(responseBody))
		if err = writeRawHTTP3Data(stream, responseBody[offset:end]); err != nil {
			return fmt.Errorf("write response DATA frame at %d/%d bytes: %w", offset, len(responseBody), err)
		}
		offset = end
	}
	if err = writeRawHTTP3Headers(stream, []qpack.HeaderField{
		{Name: "x-response-trailer", Value: "response-done-" + id},
	}); err != nil {
		return fmt.Errorf("write response trailers: %w", err)
	}
	return stream.Close()
}

func readRawHTTP3FrameHeader(reader *bufio.Reader) (uint64, uint64, error) {
	frameType, err := quicvarint.Read(reader)
	if err != nil {
		return 0, 0, err
	}
	frameLength, err := quicvarint.Read(reader)
	if err != nil {
		return 0, 0, err
	}
	if frameLength > 4*1024*1024 {
		return 0, 0, fmt.Errorf("HTTP/3 frame is too large: %d", frameLength)
	}
	return frameType, frameLength, nil
}

func writeRawHTTP3Headers(stream *quic.Stream, fields []qpack.HeaderField) error {
	var block bytes.Buffer
	encoder := qpack.NewEncoder(&block)
	for _, field := range fields {
		if err := encoder.WriteField(field); err != nil {
			return err
		}
	}
	if err := encoder.Close(); err != nil {
		return err
	}
	header := quicvarint.Append(nil, 0x01)
	header = quicvarint.Append(header, uint64(block.Len()))
	if err := writeRawHTTP3Bytes(stream, header); err != nil {
		return err
	}
	return writeRawHTTP3Bytes(stream, block.Bytes())
}

func writeRawHTTP3Data(stream *quic.Stream, data []byte) error {
	header := quicvarint.Append(nil, 0x00)
	header = quicvarint.Append(header, uint64(len(data)))
	if err := writeRawHTTP3Bytes(stream, header); err != nil {
		return err
	}
	return writeRawHTTP3Bytes(stream, data)
}

func writeRawHTTP3Bytes(stream io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := stream.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}
