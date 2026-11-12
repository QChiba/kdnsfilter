package dnspkt

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func buildPacket(t *testing.T, src, dst netip.Addr, payload []byte) []byte {
	t.Helper()
	p := &Packet{Src: src, Dst: dst}
	if src.Is4() {
		p.ipHdr = 20
		p.raw = make([]byte, 28)
		p.raw[0] = 0x45
		p.raw[8] = 64
		p.raw[9] = protoUDP
		copy(p.raw[12:16], src.AsSlice())
		copy(p.raw[16:20], dst.AsSlice())
	} else {
		p.v6 = true
		p.ipHdr = 40
		p.raw = make([]byte, 48)
		p.raw[0] = 0x60
		p.raw[6] = protoUDP
		p.raw[7] = 64
		copy(p.raw[8:24], src.AsSlice())
		copy(p.raw[24:40], dst.AsSlice())
	}
	binary.BigEndian.PutUint16(p.raw[p.ipHdr:], 53)
	binary.BigEndian.PutUint16(p.raw[p.ipHdr+2:], 40000)
	return p.WithPayload(payload)
}

func answer(t *testing.T) []byte {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion("tracker.example.com.", dns.TypeA)
	q.SetEdns0(1232, false)
	r := new(dns.Msg)
	r.SetReply(q)
	r.SetEdns0(1232, false)
	rr, _ := dns.NewRR("tracker.example.com. 300 IN A 192.0.2.10")
	r.Answer = []dns.RR{rr}
	b, err := r.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// verify checks checksums the way a receiving host would: summing the header
// (or pseudo-header + datagram) including the checksum field must give 0xffff.
func verify(t *testing.T, pkt []byte) {
	t.Helper()
	p, err := Parse(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !p.v6 && checksum(pkt[:p.ipHdr], 0) != 0 {
		t.Error("bad IPv4 header checksum")
	}
	udp := pkt[p.ipHdr:]
	var pseudo uint32
	pseudo = sum(p.Src.AsSlice(), pseudo)
	pseudo = sum(p.Dst.AsSlice(), pseudo)
	pseudo += protoUDP + uint32(len(udp))
	if checksum(udp, pseudo) != 0 {
		t.Error("bad UDP checksum")
	}
}

func TestRewriteToNXDOMAIN(t *testing.T) {
	for _, tc := range []struct{ src, dst string }{
		{"192.168.1.1", "192.168.1.10"},
		{"fd12:3456:789a::1", "fd12:3456:789a::10"},
	} {
		src, dst := netip.MustParseAddr(tc.src), netip.MustParseAddr(tc.dst)
		orig := buildPacket(t, src, dst, answer(t))
		verify(t, orig)

		p, err := Parse(orig)
		if err != nil {
			t.Fatal(err)
		}
		if p.Src != src || p.Dst != dst || p.SrcPort != 53 || p.DstPort != 40000 {
			t.Fatalf("parsed %+v", p)
		}
		var m dns.Msg
		if err := m.Unpack(p.Payload); err != nil {
			t.Fatal(err)
		}
		reply := Reply(&m)
		reply.Rcode = dns.RcodeNameError
		blocked, err := reply.Pack()
		if err != nil {
			t.Fatal(err)
		}
		out := p.WithPayload(blocked)
		verify(t, out)

		p2, _ := Parse(out)
		var r dns.Msg
		if err := r.Unpack(p2.Payload); err != nil {
			t.Fatal(err)
		}
		if r.Id != m.Id || r.Rcode != dns.RcodeNameError || len(r.Answer) != 0 ||
			r.Question[0].Name != "tracker.example.com." || r.IsEdns0() == nil {
			t.Errorf("unexpected reply: %v", &r)
		}
	}
}
