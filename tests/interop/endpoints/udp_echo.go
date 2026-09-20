package endpoints

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
)

type UDPEcho struct {
	conn    *net.UDPConn
	wg      sync.WaitGroup
	once    sync.Once
	packets atomic.Uint64
}

func StartUDPEcho() (*UDPEcho, error) {
	return StartUDPEchoAt(LocalIPv4Host())
}

// LocalIPv4Host returns the local IPv4 address selected for a non-loopback UDP
// route. Windows test environments can disable UDP loopback while still
// allowing local interface traffic, so UDP integration tests should use this
// address when they need two independent processes to exchange datagrams.
func LocalIPv4Host() string {
	probe, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   net.IPv4(192, 0, 2, 1),
		Port: 9,
	})
	if err == nil {
		address := probe.LocalAddr().(*net.UDPAddr).IP
		_ = probe.Close()
		if address != nil && !address.IsUnspecified() && !address.IsLoopback() {
			return address.String()
		}
	}
	return "127.0.0.1"
}

func StartUDPEchoAt(host string) (*UDPEcho, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(host)})
	if err != nil {
		return nil, fmt.Errorf("listen for UDP echo endpoint: %w", err)
	}

	echo := &UDPEcho{conn: conn}
	echo.wg.Add(1)
	go echo.serve()
	return echo, nil
}

func (e *UDPEcho) Addr() *net.UDPAddr { return e.conn.LocalAddr().(*net.UDPAddr) }

func (e *UDPEcho) ReceivedPackets() uint64 { return e.packets.Load() }

func (e *UDPEcho) serve() {
	defer e.wg.Done()
	buffer := make([]byte, 65535)
	for {
		size, peer, err := e.conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		e.packets.Add(1)
		if _, err := e.conn.WriteToUDP(buffer[:size], peer); err != nil {
			return
		}
	}
}

func (e *UDPEcho) Close() error {
	var closeErr error
	e.once.Do(func() {
		closeErr = e.conn.Close()
		e.wg.Wait()
	})
	return closeErr
}
