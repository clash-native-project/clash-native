package endpoints

import (
	"fmt"
	"net"
	"sync"
)

type TCPEcho struct {
	listener net.Listener

	mu    sync.Mutex
	conns map[net.Conn]struct{}
	wg    sync.WaitGroup
	once  sync.Once
}

func StartTCPEcho() (*TCPEcho, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for TCP echo endpoint: %w", err)
	}

	echo := &TCPEcho{listener: listener, conns: make(map[net.Conn]struct{})}
	echo.wg.Add(1)
	go echo.accept()
	return echo, nil
}

func (e *TCPEcho) Addr() string { return e.listener.Addr().String() }

func (e *TCPEcho) accept() {
	defer e.wg.Done()
	for {
		conn, err := e.listener.Accept()
		if err != nil {
			return
		}

		e.mu.Lock()
		e.conns[conn] = struct{}{}
		e.mu.Unlock()

		e.wg.Add(1)
		go e.serve(conn)
	}
}

func (e *TCPEcho) serve(conn net.Conn) {
	defer e.wg.Done()
	defer conn.Close()
	defer func() {
		e.mu.Lock()
		delete(e.conns, conn)
		e.mu.Unlock()
	}()

	buffer := make([]byte, 4096)
	for {
		size, err := conn.Read(buffer)
		if size > 0 {
			if writeErr := writeAll(conn, buffer[:size]); writeErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func writeAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		written, err := conn.Write(data)
		if err != nil {
			return err
		}
		data = data[written:]
	}
	return nil
}

func (e *TCPEcho) Close() error {
	var closeErr error
	e.once.Do(func() {
		closeErr = e.listener.Close()
		e.mu.Lock()
		for conn := range e.conns {
			_ = conn.Close()
		}
		e.mu.Unlock()
		e.wg.Wait()
	})
	return closeErr
}
