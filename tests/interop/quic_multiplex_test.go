package interop

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"clash-native/interop/harness"
)

const quicDNSConcurrentQueries = 8
const quicDNSRequestPadding = 18000
const quicDNSReceiveWindow = 128 * 1024

type quicDNSMetrics struct {
	connections   atomic.Int64
	streams       atomic.Int64
	requests      atomic.Int64
	bytesRead     atomic.Int64
	readErrors    atomic.Int64
	active        atomic.Int64
	maximumActive atomic.Int64
	badDoQIDs     atomic.Int64
}

func (metrics *quicDNSMetrics) beginRequest() func() {
	metrics.requests.Add(1)
	active := metrics.active.Add(1)
	for {
		maximum := metrics.maximumActive.Load()
		if active <= maximum || metrics.maximumActive.CompareAndSwap(maximum, active) {
			break
		}
	}
	time.Sleep(150 * time.Millisecond)
	return func() { metrics.active.Add(-1) }
}

func (metrics *quicDNSMetrics) dnsResponse(wire []byte, requireZeroID bool) ([]byte, error) {
	finish := metrics.beginRequest()
	defer finish()

	request := new(dns.Msg)
	if err := request.Unpack(wire); err != nil {
		return nil, fmt.Errorf("decode DNS query: %w", err)
	}
	if requireZeroID && request.Id != 0 {
		metrics.badDoQIDs.Add(1)
		return nil, fmt.Errorf("DoQ query DNS ID is %d, want zero", request.Id)
	}
	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = true
	response.Extra = nil
	for _, question := range request.Question {
		if question.Qtype == dns.TypeA {
			response.Answer = append(response.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: question.Qclass, Ttl: 30},
				A:   net.IPv4(192, 0, 2, 77),
			})
		}
	}
	packed, err := response.Pack()
	if err != nil {
		return nil, fmt.Errorf("encode DNS response: %w", err)
	}
	return packed, nil
}

type quicDNSFixture struct {
	address string
	metrics *quicDNSMetrics
	close   func()
}

func startDoQMultiplexFixture(t *testing.T, certificatePath, keyPath string) *quicDNSFixture {
	t.Helper()
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		t.Fatalf("load DoQ fixture certificate: %v", err)
	}
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for DoQ fixture: %v", err)
	}
	listener, err := quic.Listen(packetConn, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"doq"},
	}, &quic.Config{
		MaxIncomingStreams:             64,
		MaxIdleTimeout:                 10 * time.Second,
		InitialStreamReceiveWindow:     64 * 1024,
		MaxStreamReceiveWindow:         64 * 1024,
		InitialConnectionReceiveWindow: quicDNSReceiveWindow,
		MaxConnectionReceiveWindow:     quicDNSReceiveWindow,
	})
	if err != nil {
		_ = packetConn.Close()
		t.Fatalf("start DoQ fixture: %v", err)
	}
	metrics := &quicDNSMetrics{}
	ctx, cancel := context.WithCancel(context.Background())
	var connections sync.Map
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			connection, acceptErr := listener.Accept(ctx)
			if acceptErr != nil {
				return
			}
			metrics.connections.Add(1)
			connections.Store(connection, struct{}{})
			go serveDoQConnection(connection, metrics, &connections)
		}
	}()
	return &quicDNSFixture{
		address: packetConn.LocalAddr().String(),
		metrics: metrics,
		close: func() {
			cancel()
			_ = listener.Close()
			connections.Range(func(key, _ any) bool {
				_ = key.(*quic.Conn).CloseWithError(0, "test complete")
				return true
			})
			_ = packetConn.Close()
			<-acceptDone
		},
	}
}

func serveDoQConnection(connection *quic.Conn, metrics *quicDNSMetrics, connections *sync.Map) {
	defer connections.Delete(connection)
	for {
		stream, err := connection.AcceptStream(connection.Context())
		if err != nil {
			return
		}
		metrics.streams.Add(1)
		go serveDoQStream(stream, metrics)
	}
}

func serveDoQStream(stream *quic.Stream, metrics *quicDNSMetrics) {
	defer stream.Close()
	_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	var prefix [2]byte
	if _, err := io.ReadFull(stream, prefix[:]); err != nil {
		metrics.readErrors.Add(1)
		return
	}
	length := int(prefix[0])<<8 | int(prefix[1])
	if length == 0 {
		return
	}
	request := make([]byte, length)
	if _, err := io.ReadFull(stream, request); err != nil {
		metrics.readErrors.Add(1)
		return
	}
	metrics.bytesRead.Add(int64(length))
	response, err := metrics.dnsResponse(request, true)
	if err != nil || len(response) > 0xffff {
		return
	}
	framed := []byte{byte(len(response) >> 8), byte(len(response))}
	framed = append(framed, response...)
	_ = stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := stream.Write(framed); err != nil {
		return
	}
	_ = stream.Close()
}

func startDoH3MultiplexFixture(t *testing.T, certificatePath, keyPath string) *quicDNSFixture {
	t.Helper()
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		t.Fatalf("load DoH/3 fixture certificate: %v", err)
	}
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for DoH/3 fixture: %v", err)
	}
	metrics := &quicDNSMetrics{}
	server := &http3.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			NextProtos:   []string{http3.NextProtoH3},
		},
		QUICConfig: &quic.Config{
			MaxIncomingStreams:             64,
			MaxIdleTimeout:                 10 * time.Second,
			InitialStreamReceiveWindow:     64 * 1024,
			MaxStreamReceiveWindow:         64 * 1024,
			InitialConnectionReceiveWindow: quicDNSReceiveWindow,
			MaxConnectionReceiveWindow:     quicDNSReceiveWindow,
		},
		ConnContext: func(ctx context.Context, _ *quic.Conn) context.Context {
			metrics.connections.Add(1)
			return ctx
		},
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			metrics.streams.Add(1)
			if request.Method != http.MethodPost || request.URL.Path != "/dns-query" ||
				!strings.HasPrefix(request.Header.Get("Content-Type"), "application/dns-message") {
				http.Error(writer, "unexpected DoH/3 request", http.StatusBadRequest)
				return
			}
			wire, readErr := io.ReadAll(http.MaxBytesReader(writer, request.Body, 0xffff))
			if readErr != nil {
				metrics.readErrors.Add(1)
				http.Error(writer, "invalid DNS request body", http.StatusBadRequest)
				return
			}
			metrics.bytesRead.Add(int64(len(wire)))
			response, responseErr := metrics.dnsResponse(wire, false)
			if responseErr != nil {
				http.Error(writer, "invalid DNS request", http.StatusBadRequest)
				return
			}
			writer.Header().Set("Content-Type", "application/dns-message")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write(response)
		}),
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(packetConn) }()
	return &quicDNSFixture{
		address: packetConn.LocalAddr().String(),
		metrics: metrics,
		close: func() {
			_ = server.Close()
			_ = packetConn.Close()
			<-serveDone
		},
	}
}

func TestQUICDNSMultiplexesConcurrentStreamsOnOneConnection(t *testing.T) {
	testHost := os.Getenv("CLASH_NATIVE_TEST_HOST")
	if testHost == "" {
		t.Skip("CLASH_NATIVE_TEST_HOST is not set")
	}
	certificatePath, keyPath := writeDnsproxyCertificate(t)

	for _, test := range []struct {
		name     string
		start    func(*testing.T, string, string) *quicDNSFixture
		upstream func(string) string
	}{
		{
			name:     "doq",
			start:    startDoQMultiplexFixture,
			upstream: func(address string) string { return "doq://localhost:" + fixturePort(address) },
		},
		{
			name:     "doh3",
			start:    startDoH3MultiplexFixture,
			upstream: func(address string) string { return "doh3://localhost:" + fixturePort(address) + "/dns-query" },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := test.start(t, certificatePath, keyPath)
			defer fixture.close()

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			process, err := harness.StartWithEnv(ctx, testHost, map[string]string{
				"CLASH_NATIVE_DNS_UPSTREAM":    test.upstream(fixture.address),
				"CLASH_NATIVE_DNS_VERIFY_PEER": "false",
			})
			if err != nil {
				t.Fatalf("start test host with %s upstream: %v", test.name, err)
			}
			defer stopProcess(t, process, "test host")
			if _, err := harness.WaitForLine(ctx, process, readyPrefix); err != nil {
				t.Fatal(err)
			}
			dnsLine, err := harness.WaitForLine(ctx, process, dnsReadyPrefix)
			if err != nil {
				t.Fatal(err)
			}
			_, tcpAddress, err := parseDNSReadyLine(dnsLine)
			if err != nil {
				t.Fatalf("parse DNS listener: %v", err)
			}

			type queryResult struct {
				name string
				msg  *dns.Msg
				err  error
			}
			start := make(chan struct{})
			results := make(chan queryResult, quicDNSConcurrentQueries)
			var wait sync.WaitGroup
			for index := 0; index < quicDNSConcurrentQueries; index++ {
				name := fmt.Sprintf("stream-%02d.concurrent.test", index)
				wait.Add(1)
				go func() {
					defer wait.Done()
					<-start
					message := new(dns.Msg)
					message.SetQuestion(dns.Fqdn(name), dns.TypeA)
					message.SetEdns0(65535, true)
					message.IsEdns0().Option = append(message.IsEdns0().Option,
						&dns.EDNS0_PADDING{Padding: []byte(strings.Repeat("p", quicDNSRequestPadding))})
					client := &dns.Client{Net: "tcp", Timeout: 8 * time.Second}
					response, _, queryErr := client.Exchange(message, tcpAddress)
					results <- queryResult{name: name, msg: response, err: queryErr}
				}()
			}
			close(start)
			wait.Wait()
			close(results)
			for result := range results {
				if result.err != nil {
					t.Errorf("query %s: %v", result.name, result.err)
					continue
				}
				if result.msg.Rcode != dns.RcodeSuccess || len(result.msg.Answer) != 1 {
					t.Errorf("query %s returned rcode=%d answers=%d", result.name,
						result.msg.Rcode, len(result.msg.Answer))
					continue
				}
				answer, ok := result.msg.Answer[0].(*dns.A)
				if !ok || answer.A.String() != "192.0.2.77" {
					t.Errorf("query %s returned unexpected answer: %v", result.name, result.msg.Answer)
				}
			}

			if got := fixture.metrics.requests.Load(); got != quicDNSConcurrentQueries {
				t.Errorf("upstream handled %d requests, want %d", got, quicDNSConcurrentQueries)
			}
			if got := fixture.metrics.connections.Load(); got != 1 {
				t.Errorf("upstream accepted %d QUIC connections, want one reused connection", got)
			}
			if got := fixture.metrics.maximumActive.Load(); got < 2 {
				t.Errorf("upstream saw maximum concurrent request count %d, want concurrent streams", got)
			}
			if got := fixture.metrics.badDoQIDs.Load(); got != 0 {
				t.Errorf("upstream received %d nonzero DoQ query IDs", got)
			}
			if stdout, stderr := process.Output(); t.Failed() {
				t.Logf("test-host stdout=%q stderr=%q", stdout, stderr)
				t.Logf("upstream connections=%d streams=%d requests=%d bytes=%d read-errors=%d",
					fixture.metrics.connections.Load(), fixture.metrics.streams.Load(),
					fixture.metrics.requests.Load(), fixture.metrics.bytesRead.Load(),
					fixture.metrics.readErrors.Load())
			}
		})
	}
}

func fixturePort(address string) string {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		panic(err)
	}
	return port
}
