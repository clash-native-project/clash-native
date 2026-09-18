package endpoints

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"crypto/tls"
)

// TrojanServer is an independent, test-only Trojan TCP/TLS peer.
type TrojanServer struct {
	listener net.Listener
	key      []byte

	mu    sync.Mutex
	conns map[net.Conn]struct{}
	wg    sync.WaitGroup
	once  sync.Once
}

// TrojanTLSMaterial contains a test CA and a localhost server certificate.
type TrojanTLSMaterial struct {
	CACertificatePEM []byte
	CertificatePEM   []byte
	PrivateKeyPEM    []byte
}

func NewTrojanTLSMaterial() (*TrojanTLSMaterial, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate Trojan test CA key: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "clash-native test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate,
		&caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create Trojan test CA: %w", err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("parse Trojan test CA: %w", err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate Trojan server certificate key: %w", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCertificate,
		&serverKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create Trojan test server certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return nil, fmt.Errorf("encode Trojan test private key: %w", err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return &TrojanTLSMaterial{
		CACertificatePEM: caPEM,
		CertificatePEM:   certificatePEM,
		PrivateKeyPEM:    keyPEM,
	}, nil
}

func StartTrojanServer(password string) (*TrojanServer, []byte, error) {
	material, err := NewTrojanTLSMaterial()
	if err != nil {
		return nil, nil, err
	}
	tlsCertificate, err := tls.X509KeyPair(material.CertificatePEM, material.PrivateKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("load Trojan test key pair: %w", err)
	}
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCertificate},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("listen for Trojan TLS: %w", err)
	}
	hash := sha256.Sum224([]byte(password))
	key := []byte(hex.EncodeToString(hash[:]))
	server := &TrojanServer{listener: listener, key: key, conns: make(map[net.Conn]struct{})}
	server.wg.Add(1)
	go server.accept()
	return server, material.CACertificatePEM, nil
}

func (s *TrojanServer) Addr() string { return s.listener.Addr().String() }

func (s *TrojanServer) Close() error {
	var closeErr error
	s.once.Do(func() {
		closeErr = s.listener.Close()
		s.mu.Lock()
		for conn := range s.conns {
			_ = conn.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return closeErr
}

func (s *TrojanServer) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go s.serve(conn)
	}
}

func (s *TrojanServer) serve(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
	}()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	key := make([]byte, 56)
	if _, err := io.ReadFull(conn, key); err != nil || string(key) != string(s.key) {
		return
	}
	var delimiter [2]byte
	if _, err := io.ReadFull(conn, delimiter[:]); err != nil || delimiter != [2]byte{'\r', '\n'} {
		return
	}
	var command [1]byte
	if _, err := io.ReadFull(conn, command[:]); err != nil || command[0] != 0x01 {
		return
	}
	address, _, err := decodeAddressReader(conn)
	if err != nil {
		return
	}
	if _, err := io.ReadFull(conn, delimiter[:]); err != nil || delimiter != [2]byte{'\r', '\n'} {
		return
	}
	resolvedTarget, err := resolveTestTarget(address)
	if err != nil {
		return
	}
	upstream, err := net.DialTimeout("tcp", resolvedTarget, 2*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	_ = conn.SetDeadline(time.Time{})

	finished := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, conn)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		finished <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, upstream)
		finished <- struct{}{}
	}()
	<-finished
	<-finished
	_ = conn.Close()
	_ = upstream.Close()
}

func decodeAddressReader(reader io.Reader) (string, int, error) {
	var addressType [1]byte
	if _, err := io.ReadFull(reader, addressType[:]); err != nil {
		return "", 0, err
	}
	address := []byte{addressType[0]}
	switch addressType[0] {
	case 1:
		address = append(address, make([]byte, 4)...)
		if _, err := io.ReadFull(reader, address[1:]); err != nil {
			return "", 0, err
		}
	case 4:
		address = append(address, make([]byte, 16)...)
		if _, err := io.ReadFull(reader, address[1:]); err != nil {
			return "", 0, err
		}
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil || length[0] == 0 {
			return "", 0, fmt.Errorf("invalid Trojan domain address")
		}
		address = append(address, length[0])
		domain := make([]byte, int(length[0]))
		if _, err := io.ReadFull(reader, domain); err != nil {
			return "", 0, err
		}
		address = append(address, domain...)
	default:
		return "", 0, fmt.Errorf("unsupported Trojan address type %d", addressType[0])
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(reader, port); err != nil {
		return "", 0, err
	}
	address = append(address, port...)
	target, consumed, err := decodeAddress(address)
	return target, consumed, err
}
