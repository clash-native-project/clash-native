package endpoints

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// StaticDNSServer answers test hostnames with loopback addresses over UDP.
type StaticDNSServer struct {
	server *dns.Server
	addr   string
}

func StartStaticDNSServer(records map[string]net.IP) (*StaticDNSServer, error) {
	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for test DNS queries: %w", err)
	}
	handler := dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		if len(request.Question) != 1 {
			response.Rcode = dns.RcodeFormatError
			_ = writer.WriteMsg(response)
			return
		}

		question := request.Question[0]
		address, exists := records[strings.TrimSuffix(strings.ToLower(question.Name), ".")]
		if !exists {
			response.Rcode = dns.RcodeNameError
		} else {
			switch question.Qtype {
			case dns.TypeA:
				if ipv4 := address.To4(); ipv4 != nil {
					response.Answer = append(response.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
						A:   ipv4,
					})
				}
			case dns.TypeAAAA:
				if ipv6 := address.To16(); ipv6 != nil && address.To4() == nil {
					response.Answer = append(response.Answer, &dns.AAAA{
						Hdr:  dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 30},
						AAAA: ipv6,
					})
				}
			}
		}
		_ = writer.WriteMsg(response)
	})
	server := &dns.Server{PacketConn: packetConn, Handler: handler}
	go func() { _ = server.ActivateAndServe() }()
	return &StaticDNSServer{server: server, addr: packetConn.LocalAddr().String()}, nil
}

func (s *StaticDNSServer) Addr() string { return s.addr }

func (s *StaticDNSServer) Close() error { return s.server.Shutdown() }
