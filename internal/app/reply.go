package app

import (
	"net"
	"net/netip"

	"github.com/miekg/dns"

	"github.com/QChiba/kdnsfilter/internal/config"
	"github.com/QChiba/kdnsfilter/internal/dnspkt"
	"github.com/QChiba/kdnsfilter/internal/filtering"
)

// blockedReply answers a blocked query according to the blocking mode.
func blockedReply(resp *dns.Msg, mode string, ttl uint32) *dns.Msg {
	r := dnspkt.Reply(resp)
	q := resp.Question[0]
	switch mode {
	case config.BlockRefused:
		r.Rcode = dns.RcodeRefused
	case config.BlockNullIP:
		switch q.Qtype {
		case dns.TypeA:
			r.Answer = []dns.RR{&dns.A{Hdr: hdr(q.Name, dns.TypeA, ttl), A: net.IPv4zero}}
		case dns.TypeAAAA:
			r.Answer = []dns.RR{&dns.AAAA{Hdr: hdr(q.Name, dns.TypeAAAA, ttl), AAAA: net.IPv6zero}}
		default:
			r.Ns = []dns.RR{soa(q.Name, ttl)}
		}
	default:
		r.Rcode = dns.RcodeNameError
		r.Ns = []dns.RR{soa(q.Name, ttl)}
	}
	return r
}

// safeReply answers with a CNAME to the safe search host (if any) followed by
// the addresses of the requested family. Other query types get an empty
// NOERROR so clients fall back to A/AAAA.
func safeReply(resp *dns.Msg, t filtering.SafeTarget, addrs []netip.Addr, ttl uint32) *dns.Msg {
	r := dnspkt.Reply(resp)
	q := resp.Question[0]
	owner := q.Name
	if t.CNAME != "" {
		target := dns.Fqdn(t.CNAME)
		r.Answer = append(r.Answer, &dns.CNAME{Hdr: hdr(q.Name, dns.TypeCNAME, ttl), Target: target})
		owner = target
	}
	for _, a := range addrs {
		switch {
		case q.Qtype == dns.TypeA && a.Is4():
			r.Answer = append(r.Answer, &dns.A{Hdr: hdr(owner, dns.TypeA, ttl), A: a.AsSlice()})
		case q.Qtype == dns.TypeAAAA && a.Is6() && !a.Is4In6():
			r.Answer = append(r.Answer, &dns.AAAA{Hdr: hdr(owner, dns.TypeAAAA, ttl), AAAA: a.AsSlice()})
		}
	}
	return r
}

// rewriteReply answers with a DNS rewrite: its response code, or its CNAME
// chain followed by the addresses of the queried family. With no records it
// is an empty NOERROR carrying an SOA, so clients cache it for ttl.
func rewriteReply(resp *dns.Msg, rw *filtering.Rewritten, addrs []netip.Addr, ttl uint32) *dns.Msg {
	r := dnspkt.Reply(resp)
	q := resp.Question[0]
	if rw.RCode != dns.RcodeSuccess {
		r.Rcode = rw.RCode
		if rw.RCode == dns.RcodeNameError {
			r.Ns = []dns.RR{soa(q.Name, ttl)}
		}
		return r
	}
	owner := q.Name
	for _, c := range rw.CNAMEs {
		target := dns.Fqdn(c)
		r.Answer = append(r.Answer, &dns.CNAME{Hdr: hdr(owner, dns.TypeCNAME, ttl), Target: target})
		owner = target
	}
	for _, a := range addrs {
		switch {
		case q.Qtype == dns.TypeA && a.Is4():
			r.Answer = append(r.Answer, &dns.A{Hdr: hdr(owner, dns.TypeA, ttl), A: a.AsSlice()})
		case q.Qtype == dns.TypeAAAA && a.Is6() && !a.Is4In6():
			r.Answer = append(r.Answer, &dns.AAAA{Hdr: hdr(owner, dns.TypeAAAA, ttl), AAAA: a.AsSlice()})
		}
	}
	if len(r.Answer) == 0 {
		r.Ns = []dns.RR{soa(q.Name, ttl)}
	}
	return r
}

func hdr(name string, t uint16, ttl uint32) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: t, Class: dns.ClassINET, Ttl: ttl}
}

// soa lets clients cache the negative answer for ttl seconds.
func soa(name string, ttl uint32) *dns.SOA {
	return &dns.SOA{
		Hdr:     hdr(name, dns.TypeSOA, ttl),
		Ns:      "fake-for-negative-caching.kdnsfilter.",
		Mbox:    "hostmaster.kdnsfilter.",
		Serial:  1,
		Refresh: 1800,
		Retry:   900,
		Expire:  604800,
		Minttl:  ttl,
	}
}
