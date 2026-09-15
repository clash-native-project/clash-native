package endpoints

import (
	"fmt"
	"net"
	"sync"
)

type UDPEcho struct {
	conn *net.UDPConn
	wg   sync.WaitGroup
	once sync.Once
}

func StartUDPEcho() (*UDPEcho, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, fmt.Errorf("listen for UDP echo endpoint: %w", err)
	}

	echo := &UDPEcho{conn: conn}
	echo.wg.Add(1)
	go echo.serve()
	return echo, nil
}

func (e *UDPEcho) Addr() *net.UDPAddr { return e.conn.LocalAddr().(*net.UDPAddr) }

func (e *UDPEcho) serve() {
	defer e.wg.Done()
	buffer := make([]byte, 65535)
	for {
		size, peer, err := e.conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
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
