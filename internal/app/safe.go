package app

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/QChiba/kdnsfilter/internal/filtering"
)

const (
	safeMinTTL = 60 * time.Second
	safeMaxTTL = 10 * time.Minute
)

// safeResolver resolves safe search and DNS rewrite CNAME targets through
// the router's DNS and caches the results. Its own queries go over loopback, which the
// NFQUEUE rules exclude, so they're never filtered.
type safeResolver struct {
	client *dns.Client
	mu     sync.Mutex
	addr   string
	cache  map[string]safeEntry // key: name + "/" + qtype
}

type safeEntry struct {
	addrs   []netip.Addr
	expires time.Time
}

func newSafeResolver(addr string) *safeResolver {
	return &safeResolver{
		client: &dns.Client{Net: "udp", Timeout: 2 * time.Second},
		addr:   addr,
		cache:  map[string]safeEntry{},
	}
}

func (s *safeResolver) setAddr(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.addr != addr {
		s.addr, s.cache = addr, map[string]safeEntry{}
	}
}

// addrs returns addresses for the target for an A or AAAA query.
func (s *safeResolver) addrs(t filtering.SafeTarget, qtype uint16) ([]netip.Addr, error) {
	if t.IP.IsValid() {
		return []netip.Addr{t.IP}, nil
	}
	return s.lookup(t.CNAME, qtype)
}

// lookup returns the addresses of name for an A or AAAA query.
func (s *safeResolver) lookup(name string, qtype uint16) ([]netip.Addr, error) {
	if qtype != dns.TypeA && qtype != dns.TypeAAAA {
		return nil, nil
	}
	key := fmt.Sprintf("%s/%d", name, qtype)
	now := time.Now()
	s.mu.Lock()
	e, ok := s.cache[key]
	addr := s.addr
	s.mu.Unlock()
	if ok && now.Before(e.expires) {
		return e.addrs, nil
	}

	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	r, _, err := s.client.Exchange(q, addr)
	if err != nil {
		if ok { // serve stale rather than fail
			return e.addrs, nil
		}
		return nil, fmt.Errorf("resolve %s: %w", name, err)
	}
	ttl := safeMaxTTL
	var out []netip.Addr
	for _, rr := range r.Answer {
		var a netip.Addr
		switch v := rr.(type) {
		case *dns.A:
			a, _ = netip.AddrFromSlice(v.A.To4())
		case *dns.AAAA:
			a, _ = netip.AddrFromSlice(v.AAAA)
		default:
			continue
		}
		out = append(out, a)
		ttl = min(ttl, time.Duration(rr.Header().Ttl)*time.Second)
	}
	ttl = max(ttl, safeMinTTL)
	s.mu.Lock()
	s.cache[key] = safeEntry{addrs: out, expires: now.Add(ttl)}
	s.mu.Unlock()
	return out, nil
}
