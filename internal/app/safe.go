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
	// safeTimeout bounds one upstream exchange on the NFQUEUE callback
	// thread; a stalled resolver must not hold back every other reply for
	// long. The resolver is the router's own, so healthy answers are much
	// faster than this.
	safeTimeout = time.Second
	// safeCacheMax bounds the cache; pruning drops expired entries when it
	// is exceeded.
	safeCacheMax = 4096
)

// safeResolver resolves safe search and DNS rewrite CNAME targets through
// the router's DNS and caches the results. Its own queries go over loopback, which the
// NFQUEUE rules exclude, so they're never filtered.
type safeResolver struct {
	client *dns.Client
	mu     sync.Mutex
	addr   string
	cache  map[string]safeEntry // key: name + "/" + qtype
	// inflight collapses concurrent lookups of the same target into one
	// exchange, so a burst of queries for one cache miss stalls the queue
	// only once.
	inflight map[string]*safeCall
}

type safeEntry struct {
	addrs   []netip.Addr
	expires time.Time
}

type safeCall struct {
	wg    sync.WaitGroup
	addrs []netip.Addr
	err   error
}

func newSafeResolver(addr string) *safeResolver {
	return &safeResolver{
		client:   &dns.Client{Net: "udp", Timeout: safeTimeout},
		addr:     addr,
		cache:    map[string]safeEntry{},
		inflight: map[string]*safeCall{},
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

// lookup returns the addresses of name for an A or AAAA query. Concurrent
// lookups of the same target share one exchange (single-flight).
func (s *safeResolver) lookup(name string, qtype uint16) ([]netip.Addr, error) {
	if qtype != dns.TypeA && qtype != dns.TypeAAAA {
		return nil, nil
	}
	key := fmt.Sprintf("%s/%d", name, qtype)
	var call *safeCall
	leader := false
	s.mu.Lock()
	e, ok := s.cache[key]
	addr := s.addr
	if call = s.inflight[key]; call == nil {
		call = &safeCall{}
		call.wg.Add(1)
		s.inflight[key] = call
		leader = true
	}
	s.mu.Unlock()
	if !leader {
		call.wg.Wait()
		return call.addrs, call.err
	}

	addrs, err := s.resolve(name, qtype, addr, e, ok)
	s.mu.Lock()
	delete(s.inflight, key)
	s.mu.Unlock()
	call.addrs, call.err = addrs, err
	call.wg.Done()
	return addrs, err
}

// resolve does the exchange and fills the cache; serving stale beats
// failing. Called by the single leader of each target.
func (s *safeResolver) resolve(name string, qtype uint16, addr string, e safeEntry, cached bool) ([]netip.Addr, error) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	r, _, err := s.client.Exchange(q, addr)
	if err != nil {
		if cached { // serve stale rather than fail
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
	key := fmt.Sprintf("%s/%d", name, qtype)
	s.mu.Lock()
	s.cache[key] = safeEntry{addrs: out, expires: time.Now().Add(ttl)}
	if len(s.cache) > safeCacheMax {
		for k, v := range s.cache {
			if !time.Now().Before(v.expires) {
				delete(s.cache, k)
			}
		}
	}
	s.mu.Unlock()
	return out, nil
}
