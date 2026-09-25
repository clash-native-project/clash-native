package endpoints

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"sync"
)

// TLSChainEcho is a TLS server presenting a leaf-plus-CA chain (stable,
// fixture-controlled certificates for pin tests) that echoes bytes.
type TLSChainEcho struct {
	listener net.Listener
	wg       sync.WaitGroup
}

// StartTLSChainEcho serves TLS with the given chain on loopback.
func StartTLSChainEcho(leafPEM, keyPEM, caPEM []byte) (*TLSChainEcho, error) {
	leafBlock, _ := pem.Decode(leafPEM)
	if leafBlock == nil {
		return nil, fmt.Errorf("decode TLS echo leaf certificate")
	}
	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		return nil, fmt.Errorf("decode TLS echo CA certificate")
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("decode TLS echo private key")
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse TLS echo leaf certificate: %w", err)
	}
	key, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
		pem.EncodeToMemory(keyBlock),
	)
	if err != nil {
		return nil, fmt.Errorf("load TLS echo key pair: %w", err)
	}
	key.Certificate = append(key.Certificate, caBlock.Bytes)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for TLS echo endpoint: %w", err)
	}
	echo := &TLSChainEcho{listener: listener}
	echo.wg.Add(1)
	go echo.accept(key)
	return echo, nil
}

// Addr returns the echo endpoint address.
func (e *TLSChainEcho) Addr() string { return e.listener.Addr().String() }

// Close stops the echo endpoint.
func (e *TLSChainEcho) Close() error {
	err := e.listener.Close()
	e.wg.Wait()
	return err
}

func (e *TLSChainEcho) accept(key tls.Certificate) {
	defer e.wg.Done()
	config := &tls.Config{Certificates: []tls.Certificate{key}}
	for {
		conn, err := e.listener.Accept()
		if err != nil {
			return
		}
		e.wg.Add(1)
		go func(raw net.Conn) {
			defer e.wg.Done()
			defer raw.Close()
			server := tls.Server(raw, config)
			if err := server.Handshake(); err != nil {
				return
			}
			_, _ = io.Copy(server, server)
		}(conn)
	}
}
