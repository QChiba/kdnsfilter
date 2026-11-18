package app

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestSafeResolverHonorsTTL(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var exchanges atomic.Int32
	ready := make(chan struct{})
	server := &dns.Server{
		PacketConn:        conn,
		NotifyStartedFunc: func() { close(ready) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
			n := exchanges.Add(1)
			r := new(dns.Msg)
			r.SetReply(q)
			r.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, byte(n)),
			}}
			if err := w.WriteMsg(r); err != nil {
				t.Error(err)
			}
		}),
	}
	go func() {
		if err := server.ActivateAndServe(); err != nil {
			t.Error(err)
		}
	}()
	<-ready
	t.Cleanup(func() { server.Shutdown() })
	s := newSafeResolver(conn.LocalAddr().String())
	check := func(want string) {
		t.Helper()
		got, err := s.lookup("target.example", dns.TypeA)
		if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr(want) {
			t.Fatalf("lookup returned %v, %v; want %s", got, err, want)
		}
	}
	check("192.0.2.1")
	check("192.0.2.1")
	key := "target.example/1"
	entry := s.cache[key]
	entry.expires = time.Now().Add(-time.Second)
	s.cache[key] = entry
	check("192.0.2.2")
}
