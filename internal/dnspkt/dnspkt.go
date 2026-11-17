// Package dnspkt parses DNS-over-UDP packets captured from NFQUEUE and
// rebuilds them with a replacement DNS payload (fixed lengths and checksums).
package dnspkt

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/miekg/dns"
)

const protoUDP = 17

var ErrNotDNS = errors.New("not a UDP DNS packet")

// Packet is a raw IPv4/IPv6 packet carrying a single UDP datagram.
type Packet struct {
	raw     []byte
	v6      bool
	ipHdr   int // length of the IP header
	Src     netip.Addr
	Dst     netip.Addr
	SrcPort uint16
	DstPort uint16
	Payload []byte // UDP payload (aliases raw)
}

// Parse decodes an IP packet as delivered by NFQUEUE.
func Parse(raw []byte) (*Packet, error) {
	if len(raw) < 1 {
		return nil, ErrNotDNS
	}
	p := &Packet{raw: raw}
	switch raw[0] >> 4 {
	case 4:
		if len(raw) < 20 {
			return nil, ErrNotDNS
		}
		p.ipHdr = int(raw[0]&0x0f) * 4
		if raw[9] != protoUDP || len(raw) < p.ipHdr+8 {
			return nil, ErrNotDNS
		}
		// Fragmented datagrams can't be rewritten in place.
		if binary.BigEndian.Uint16(raw[6:8])&0x3fff != 0 {
			return nil, ErrNotDNS
		}
		p.Src = netip.AddrFrom4([4]byte(raw[12:16]))
		p.Dst = netip.AddrFrom4([4]byte(raw[16:20]))
	case 6:
		p.v6 = true
		p.ipHdr = 40
		// Extension headers are not expected on locally generated DNS replies.
		if len(raw) < p.ipHdr+8 || raw[6] != protoUDP {
			return nil, ErrNotDNS
		}
		p.Src = netip.AddrFrom16([16]byte(raw[8:24]))
		p.Dst = netip.AddrFrom16([16]byte(raw[24:40]))
	default:
		return nil, ErrNotDNS
	}
	udp := raw[p.ipHdr:]
	p.SrcPort = binary.BigEndian.Uint16(udp[0:2])
	p.DstPort = binary.BigEndian.Uint16(udp[2:4])
	ulen := int(binary.BigEndian.Uint16(udp[4:6]))
	if ulen < 8 || ulen > len(udp) {
		return nil, ErrNotDNS
	}
	p.Payload = udp[8:ulen]
	return p, nil
}

// WithPayload returns a new packet with the same addressing and a new UDP
// payload, with IP length, IPv4 header checksum and UDP checksum recomputed.
func (p *Packet) WithPayload(payload []byte) []byte {
	ulen := 8 + len(payload)
	out := make([]byte, p.ipHdr+ulen)
	copy(out, p.raw[:p.ipHdr+8])
	copy(out[p.ipHdr+8:], payload)

	if p.v6 {
		binary.BigEndian.PutUint16(out[4:6], uint16(ulen))
	} else {
		binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
		out[10], out[11] = 0, 0
		binary.BigEndian.PutUint16(out[10:12], checksum(out[:p.ipHdr], 0))
	}

	udp := out[p.ipHdr:]
	binary.BigEndian.PutUint16(udp[4:6], uint16(ulen))
	udp[6], udp[7] = 0, 0
	var pseudo uint32
	pseudo = sum(p.Src.AsSlice(), pseudo)
	pseudo = sum(p.Dst.AsSlice(), pseudo)
	pseudo += protoUDP + uint32(ulen)
	c := checksum(udp, pseudo)
	if c == 0 {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], c)
	return out
}

func sum(b []byte, acc uint32) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		acc += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		acc += uint32(b[len(b)-1]) << 8
	}
	return acc
}

func checksum(b []byte, acc uint32) uint16 {
	acc = sum(b, acc)
	for acc>>16 != 0 {
		acc = acc&0xffff + acc>>16
	}
	return ^uint16(acc)
}

// Reply returns an empty reply to the same query as resp: same ID, flags,
// question and EDNS0 record, so the client accepts it in place of resp.
func Reply(resp *dns.Msg) *dns.Msg {
	r := new(dns.Msg)
	r.Id = resp.Id
	r.Response = true
	r.Opcode = resp.Opcode
	r.RecursionDesired = resp.RecursionDesired
	// RFC 4035: a validating stub that set CD=1 on its query expects it
	// echoed in the reply it receives.
	r.CheckingDisabled = resp.CheckingDisabled
	r.RecursionAvailable = true
	r.Question = resp.Question
	if opt := resp.IsEdns0(); opt != nil {
		r.Extra = []dns.RR{opt}
	}
	return r
}
