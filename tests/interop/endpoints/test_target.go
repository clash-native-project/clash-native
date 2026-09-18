package endpoints

import (
	"net"
	"strings"
)

func resolveTestTarget(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}
	if strings.HasSuffix(strings.ToLower(host), ".test") {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}
