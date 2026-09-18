package endpoints

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// ShadowsocksServer is an independent, test-only AEAD Shadowsocks TCP/UDP peer.
type ShadowsocksServer struct {
	method   string
	password string
	tcp      net.Listener
	udp      *net.UDPConn

	mu    sync.Mutex
	conns map[net.Conn]struct{}
	wg    sync.WaitGroup
	once  sync.Once
}

func StartShadowsocksServer(method, password string) (*ShadowsocksServer, error) {
	if _, err := makeAEAD(method, make([]byte, keySize(method))); err != nil {
		return nil, err
	}

	var listener net.Listener
	var udpConn *net.UDPConn
	var lastListenError error
	for range 32 {
		udpConn, lastListenError = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if lastListenError != nil {
			return nil, fmt.Errorf("listen for Shadowsocks UDP: %w", lastListenError)
		}
		port := udpConn.LocalAddr().(*net.UDPAddr).Port
		listener, lastListenError = net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if lastListenError == nil {
			break
		}
		_ = udpConn.Close()
		udpConn = nil
	}
	if listener == nil {
		return nil, fmt.Errorf("listen for Shadowsocks TCP on selected UDP port: %w", lastListenError)
	}

	server := &ShadowsocksServer{
		method: method, password: password, tcp: listener, udp: udpConn,
		conns: make(map[net.Conn]struct{}),
	}
	server.wg.Add(2)
	go server.acceptTCP()
	go server.serveUDP()
	return server, nil
}

func (s *ShadowsocksServer) Addr() string { return s.tcp.Addr().String() }

func (s *ShadowsocksServer) Close() error {
	var closeErr error
	s.once.Do(func() {
		closeErr = s.tcp.Close()
		_ = s.udp.Close()
		s.mu.Lock()
		for conn := range s.conns {
			_ = conn.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return closeErr
}

func (s *ShadowsocksServer) acceptTCP() {
	defer s.wg.Done()
	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go s.serveTCP(conn)
	}
}

func (s *ShadowsocksServer) serveTCP(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
	}()

	keyLength := keySize(s.method)
	clientSalt := make([]byte, keyLength)
	if _, err := io.ReadFull(conn, clientSalt); err != nil {
		return
	}
	readAEAD, err := makeAEAD(s.method, deriveSubkey(s.password, clientSalt, keyLength))
	if err != nil {
		return
	}
	var readNonce [12]byte
	address, err := readTCPRecord(conn, readAEAD, &readNonce)
	if err != nil {
		return
	}
	target, consumed, err := decodeAddress(address)
	if err != nil || consumed != len(address) {
		return
	}
	resolvedTarget, err := resolveTestTarget(target)
	if err != nil {
		return
	}
	upstream, err := net.DialTimeout("tcp", resolvedTarget, 2*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()

	stream := &shadowsocksStream{
		Conn: conn, method: s.method, password: s.password,
		readAEAD: readAEAD, readNonce: readNonce,
	}
	finished := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, stream)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		finished <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(stream, upstream)
		finished <- struct{}{}
	}()
	<-finished
	<-finished
	_ = conn.Close()
	_ = upstream.Close()
}

func (s *ShadowsocksServer) serveUDP() {
	defer s.wg.Done()
	buffer := make([]byte, 65507)
	for {
		size, client, err := s.udp.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		packet := append([]byte(nil), buffer[:size]...)
		go s.handleUDP(packet, client)
	}
}

func (s *ShadowsocksServer) handleUDP(packet []byte, client *net.UDPAddr) {
	keyLength := keySize(s.method)
	if len(packet) < keyLength+chacha20poly1305.Overhead {
		return
	}
	aead, err := makeAEAD(s.method, deriveSubkey(s.password, packet[:keyLength], keyLength))
	if err != nil {
		return
	}
	var nonce [12]byte
	plaintext, err := aead.Open(nil, nonce[:], packet[keyLength:], nil)
	if err != nil {
		return
	}
	target, consumed, err := decodeAddress(plaintext)
	if err != nil {
		return
	}
	resolvedTarget, err := resolveTestTarget(target)
	if err != nil {
		return
	}
	remote, err := net.ResolveUDPAddr("udp", resolvedTarget)
	if err != nil {
		return
	}
	targetConn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		return
	}
	defer targetConn.Close()
	_ = targetConn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := targetConn.Write(plaintext[consumed:]); err != nil {
		return
	}
	response := make([]byte, 65507)
	size, source, err := targetConn.ReadFromUDP(response)
	if err != nil {
		return
	}
	address, err := encodeAddress(source.IP.String(), uint16(source.Port))
	if err != nil {
		return
	}
	address = append(address, response[:size]...)
	serverSalt := make([]byte, keyLength)
	if _, err := rand.Read(serverSalt); err != nil {
		return
	}
	writeAEAD, err := makeAEAD(s.method, deriveSubkey(s.password, serverSalt, keyLength))
	if err != nil {
		return
	}
	ciphertext := writeAEAD.Seal(nil, nonce[:], address, nil)
	serverPacket := append(serverSalt, ciphertext...)
	_, _ = s.udp.WriteToUDP(serverPacket, client)
}

type shadowsocksStream struct {
	net.Conn
	method   string
	password string

	readAEAD      cipher.AEAD
	readNonce     [12]byte
	writeAEAD     cipher.AEAD
	writeNonce    [12]byte
	writeSaltSent bool
	pending       []byte
	writeMu       sync.Mutex
}

func (s *shadowsocksStream) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	if len(s.pending) > 0 {
		n := copy(buffer, s.pending)
		s.pending = s.pending[n:]
		return n, nil
	}
	chunk, err := readTCPRecord(s.Conn, s.readAEAD, &s.readNonce)
	if err != nil {
		return 0, err
	}
	n := copy(buffer, chunk)
	s.pending = chunk[n:]
	return n, nil
}

func (s *shadowsocksStream) Write(buffer []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if !s.writeSaltSent {
		keyLength := keySize(s.method)
		salt := make([]byte, keyLength)
		if _, err := rand.Read(salt); err != nil {
			return 0, err
		}
		s.writeAEAD, _ = makeAEAD(s.method, deriveSubkey(s.password, salt, keyLength))
		if _, err := ssWriteAll(s.Conn, salt); err != nil {
			return 0, err
		}
		s.writeSaltSent = true
	}
	written := 0
	for len(buffer) > 0 {
		chunkSize := len(buffer)
		if chunkSize > 0x3fff {
			chunkSize = 0x3fff
		}
		if err := writeTCPRecord(s.Conn, s.writeAEAD, &s.writeNonce, buffer[:chunkSize]); err != nil {
			return written, err
		}
		written += chunkSize
		buffer = buffer[chunkSize:]
	}
	return written, nil
}

func readTCPRecord(reader io.Reader, aead cipher.AEAD, nonce *[12]byte) ([]byte, error) {
	lengthWire := make([]byte, 2+aead.Overhead())
	if _, err := io.ReadFull(reader, lengthWire); err != nil {
		return nil, err
	}
	length, err := aead.Open(nil, nonce[:], lengthWire, nil)
	if err != nil || len(length) != 2 {
		return nil, fmt.Errorf("decrypt Shadowsocks TCP length: %w", err)
	}
	incrementNonce(nonce)
	chunkSize := int(binary.BigEndian.Uint16(length))
	if chunkSize == 0 || chunkSize > 0x3fff {
		return nil, fmt.Errorf("invalid Shadowsocks TCP chunk size %d", chunkSize)
	}
	chunkWire := make([]byte, chunkSize+aead.Overhead())
	if _, err := io.ReadFull(reader, chunkWire); err != nil {
		return nil, err
	}
	chunk, err := aead.Open(nil, nonce[:], chunkWire, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt Shadowsocks TCP chunk: %w", err)
	}
	incrementNonce(nonce)
	return chunk, nil
}

func writeTCPRecord(writer io.Writer, aead cipher.AEAD, nonce *[12]byte, payload []byte) error {
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(payload)))
	if _, err := ssWriteAll(writer, aead.Seal(nil, nonce[:], size[:], nil)); err != nil {
		return err
	}
	incrementNonce(nonce)
	if _, err := ssWriteAll(writer, aead.Seal(nil, nonce[:], payload, nil)); err != nil {
		return err
	}
	incrementNonce(nonce)
	return nil
}

func deriveSubkey(password string, salt []byte, keyLength int) []byte {
	var master, previous []byte
	for len(master) < keyLength {
		hash := md5.New()
		_, _ = hash.Write(previous)
		_, _ = hash.Write([]byte(password))
		previous = hash.Sum(nil)
		master = append(master, previous...)
	}
	key := make([]byte, keyLength)
	reader := hkdf.New(sha1.New, master[:keyLength], salt, []byte("ss-subkey"))
	_, _ = io.ReadFull(reader, key)
	return key
}

func makeAEAD(method string, key []byte) (cipher.AEAD, error) {
	switch method {
	case "aes-128-gcm", "aes-256-gcm":
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case "chacha20-ietf-poly1305":
		return chacha20poly1305.New(key)
	default:
		return nil, fmt.Errorf("unsupported test Shadowsocks method %q", method)
	}
}

func keySize(method string) int {
	if method == "aes-128-gcm" {
		return 16
	}
	return 32
}

func encodeAddress(host string, port uint16) ([]byte, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			result := append([]byte{1}, ip4...)
			return appendPort(result, port), nil
		}
		result := append([]byte{4}, ip.To16()...)
		return appendPort(result, port), nil
	}
	if len(host) == 0 || len(host) > 255 {
		return nil, fmt.Errorf("invalid proxy domain length")
	}
	result := append([]byte{3, byte(len(host))}, []byte(host)...)
	return appendPort(result, port), nil
}

func decodeAddress(data []byte) (string, int, error) {
	if len(data) < 1 {
		return "", 0, fmt.Errorf("proxy address is truncated")
	}
	addressType := data[0]
	offset := 1
	var host string
	switch addressType {
	case 1:
		if len(data) < offset+4+2 {
			return "", 0, fmt.Errorf("IPv4 proxy address is truncated")
		}
		host = net.IP(data[offset : offset+4]).String()
		offset += 4
	case 4:
		if len(data) < offset+16+2 {
			return "", 0, fmt.Errorf("IPv6 proxy address is truncated")
		}
		host = net.IP(data[offset : offset+16]).String()
		offset += 16
	case 3:
		if len(data) < offset+1 {
			return "", 0, fmt.Errorf("domain proxy address is truncated")
		}
		domainLength := int(data[offset])
		offset++
		if domainLength == 0 || len(data) < offset+domainLength+2 {
			return "", 0, fmt.Errorf("domain proxy address has invalid length")
		}
		host = string(data[offset : offset+domainLength])
		offset += domainLength
	default:
		return "", 0, fmt.Errorf("unsupported proxy address type %d", addressType)
	}
	port := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	return net.JoinHostPort(host, strconv.Itoa(int(port))), offset, nil
}

func appendPort(data []byte, port uint16) []byte {
	return binary.BigEndian.AppendUint16(data, port)
}

func incrementNonce(nonce *[12]byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}

func ssWriteAll(writer io.Writer, data []byte) (int, error) {
	written := 0
	for written < len(data) {
		n, err := writer.Write(data[written:])
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}
