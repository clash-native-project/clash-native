package interop

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clash-native/interop/endpoints"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const grpcInteropServiceName = "clash_native.grpc.InteroperabilityService"

type grpcInteropService interface {
	UnaryEcho(context.Context, *wrapperspb.StringValue) (*wrapperspb.StringValue, error)
	UnaryError(context.Context, *wrapperspb.StringValue) (*wrapperspb.StringValue, error)
	Chat(grpc.ServerStream) error
}

type grpcInteropServer struct {
	unaryRequests chan grpcUnaryRequest
	errorRequests chan string
	chatResults   chan []string
}

type grpcUnaryRequest struct {
	message  string
	metadata metadata.MD
}

func newGRPCInteropServer() *grpcInteropServer {
	return &grpcInteropServer{
		unaryRequests: make(chan grpcUnaryRequest, 1),
		errorRequests: make(chan string, 1),
		chatResults:   make(chan []string, 1),
	}
}

func (server *grpcInteropServer) UnaryEcho(ctx context.Context, request *wrapperspb.StringValue) (*wrapperspb.StringValue, error) {
	server.unaryRequests <- grpcUnaryRequest{
		message:  request.GetValue(),
		metadata: cloneGRPCMetadataFromContext(ctx),
	}
	if err := grpc.SendHeader(ctx, metadata.Pairs("x-server-header", "grpc-header")); err != nil {
		return nil, status.Errorf(codes.Internal, "send response header: %v", err)
	}
	grpc.SetTrailer(ctx, metadata.Pairs(
		"x-server-trailer", "grpc-trailer",
		"x-opaque-bin", string([]byte{0, 1, 0xff}),
	))
	return wrapperspb.String("hello from Go gRPC: " + request.GetValue()), nil
}

func (server *grpcInteropServer) UnaryError(ctx context.Context, request *wrapperspb.StringValue) (*wrapperspb.StringValue, error) {
	server.errorRequests <- request.GetValue()
	return nil, status.Error(codes.PermissionDenied, "fixture rejected request")
}

func (server *grpcInteropServer) Chat(stream grpc.ServerStream) error {
	if err := grpc.SendHeader(stream.Context(), metadata.Pairs("x-stream-header", "bidi-started")); err != nil {
		return status.Errorf(codes.Internal, "send stream header: %v", err)
	}
	var received []string
	for {
		request := new(wrapperspb.StringValue)
		if err := stream.RecvMsg(request); err != nil {
			if errors.Is(err, io.EOF) {
				server.chatResults <- received
				grpc.SetTrailer(stream.Context(), metadata.Pairs("x-stream-trailer", "bidi-complete"))
				return nil
			}
			return status.Errorf(codes.Internal, "receive stream message: %v", err)
		}
		received = append(received, request.GetValue())
		if err := stream.SendMsg(wrapperspb.String("echo:" + request.GetValue())); err != nil {
			return status.Errorf(codes.Internal, "send stream message: %v", err)
		}
	}
}

func cloneGRPCMetadataFromContext(ctx context.Context) metadata.MD {
	values, _ := metadata.FromIncomingContext(ctx)
	return values.Copy()
}

func TestGRPCClientUnaryEchoWithMetadataAndTrailers(t *testing.T) {
	executable := grpcClientExecutable(t)
	fixture := startGRPCInteropFixture(t)
	defer fixture.close(t)

	runGRPCInteropClient(t, executable, fixture, "unary")

	request := receiveGRPCFixtureEvent(t, fixture.server.unaryRequests, "unary request")
	if request.message != "hello from clash-native" {
		t.Fatalf("unary request message = %q, want %q", request.message, "hello from clash-native")
	}
	if got := request.metadata.Get("x-client-tag"); len(got) != 1 || got[0] != "clash-native-grpc-test" {
		t.Fatalf("unary request x-client-tag metadata = %v, want [clash-native-grpc-test]", got)
	}
	if got := request.metadata.Get("x-opaque-bin"); len(got) != 1 || got[0] != string([]byte{0, 0x7f, 0xff}) {
		t.Fatalf("unary request x-opaque-bin metadata = %q, want %q", got, string([]byte{0, 0x7f, 0xff}))
	}
}

func TestGRPCClientHandlesTrailersOnlyNonOKStatus(t *testing.T) {
	executable := grpcClientExecutable(t)
	fixture := startGRPCInteropFixture(t)
	defer fixture.close(t)

	runGRPCInteropClient(t, executable, fixture, "trailers-only")
	if got := receiveGRPCFixtureEvent(t, fixture.server.errorRequests, "trailers-only request"); got != "trigger-error" {
		t.Fatalf("trailers-only request = %q, want %q", got, "trigger-error")
	}
}

func TestGRPCClientBidirectionalStreamMultipleMessagesAndHalfClose(t *testing.T) {
	executable := grpcClientExecutable(t)
	fixture := startGRPCInteropFixture(t)
	defer fixture.close(t)

	runGRPCInteropClient(t, executable, fixture, "bidi")
	got := receiveGRPCFixtureEvent(t, fixture.server.chatResults, "bidirectional stream completion")
	want := []string{"message-1", "message-2", "message-3"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("bidirectional stream messages = %q, want %q", got, want)
	}
}

type grpcInteropFixture struct {
	address    string
	caFile     string
	server     *grpcInteropServer
	grpcServer *grpc.Server
	serveDone  chan error
}

func startGRPCInteropFixture(t *testing.T) *grpcInteropFixture {
	t.Helper()
	material, err := endpoints.NewTrojanTLSMaterial()
	if err != nil {
		t.Fatalf("create gRPC fixture TLS material: %v", err)
	}
	certificate, err := tls.X509KeyPair(material.CertificatePEM, material.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("load gRPC fixture TLS certificate: %v", err)
	}
	caFile := filepath.Join(t.TempDir(), "grpc-test-ca.pem")
	if err := os.WriteFile(caFile, material.CACertificatePEM, 0o600); err != nil {
		t.Fatalf("write gRPC fixture test CA: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for gRPC fixture: %v", err)
	}
	server := newGRPCInteropServer()
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
	})))
	grpcServer.RegisterService(&grpc.ServiceDesc{
		ServiceName: grpcInteropServiceName,
		HandlerType: (*grpcInteropService)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "UnaryEcho",
				Handler:    grpcUnaryEchoHandler,
			},
			{
				MethodName: "UnaryError",
				Handler:    grpcUnaryErrorHandler,
			},
		},
		Streams: []grpc.StreamDesc{{
			StreamName:    "Chat",
			Handler:       grpcChatHandler,
			ServerStreams: true,
			ClientStreams: true,
		}},
	}, server)
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- grpcServer.Serve(listener)
	}()
	return &grpcInteropFixture{
		address:    listener.Addr().String(),
		caFile:     caFile,
		server:     server,
		grpcServer: grpcServer,
		serveDone:  serveDone,
	}
}

func (fixture *grpcInteropFixture) close(t *testing.T) {
	t.Helper()
	fixture.grpcServer.Stop()
	if err := <-fixture.serveDone; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		t.Errorf("stop gRPC fixture: %v", err)
	}
}

func grpcUnaryEchoHandler(server any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	request := new(wrapperspb.StringValue)
	if err := decode(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return server.(grpcInteropService).UnaryEcho(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: server, FullMethod: "/" + grpcInteropServiceName + "/UnaryEcho"}
	handler := func(ctx context.Context, request any) (any, error) {
		return server.(grpcInteropService).UnaryEcho(ctx, request.(*wrapperspb.StringValue))
	}
	return interceptor(ctx, request, info, handler)
}

func grpcUnaryErrorHandler(server any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	request := new(wrapperspb.StringValue)
	if err := decode(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return server.(grpcInteropService).UnaryError(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: server, FullMethod: "/" + grpcInteropServiceName + "/UnaryError"}
	handler := func(ctx context.Context, request any) (any, error) {
		return server.(grpcInteropService).UnaryError(ctx, request.(*wrapperspb.StringValue))
	}
	return interceptor(ctx, request, info, handler)
}

func grpcChatHandler(server any, stream grpc.ServerStream) error {
	return server.(grpcInteropService).Chat(stream)
}

func grpcClientExecutable(t *testing.T) string {
	t.Helper()
	executable := os.Getenv("CLASH_NATIVE_GRPC_CLIENT")
	if executable == "" {
		t.Skip("CLASH_NATIVE_GRPC_CLIENT is not set")
	}
	return executable
}

func runGRPCInteropClient(t *testing.T, executable string, fixture *grpcInteropFixture, mode string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, fixture.address, mode)
	command.Env = appendEnvironmentOverride(os.Environ(), "CLASH_NATIVE_TEST_OUTBOUND_CA_FILE", fixture.caFile)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("gRPC client timed out in %q mode: %v\n%s", mode, ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("gRPC client failed in %q mode: %v\n%s", mode, err, output)
	}
}

func appendEnvironmentOverride(environment []string, key, value string) []string {
	prefix := strings.ToUpper(key) + "="
	filtered := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if !strings.HasPrefix(strings.ToUpper(entry), prefix) {
			filtered = append(filtered, entry)
		}
	}
	return append(filtered, key+"="+value)
}

func receiveGRPCFixtureEvent[T any](t *testing.T, events <-chan T, eventName string) T {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(2 * time.Second):
		var empty T
		t.Fatalf("Go gRPC server did not receive %s", eventName)
		return empty
	}
}
