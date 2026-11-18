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
		s.addr = addr
		s.cache = map[string]safeEntry{}
		s.inflight = map[string]*safeCall{}
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
	s.mu.Lock()
	cached, ok := s.cache[key]
	if ok && time.Now().Before(cached.expires) {
		s.mu.Unlock()
		return cached.addrs, nil
	}
	if call := s.inflight[key]; call != nil {
		s.mu.Unlock()
		call.wg.Wait()
		return call.addrs, call.err
	}
	addr := s.addr
	call := &safeCall{}
	call.wg.Add(1)
	s.inflight[key] = call
	s.mu.Unlock()

	entry, err := s.resolve(name, qtype, addr)
	s.mu.Lock()
	if s.inflight[key] == call { // the configured resolver is still current
		delete(s.inflight, key)
		if err == nil {
			s.cache[key] = entry
			if len(s.cache) > safeCacheMax {
				now := time.Now()
				for k, v := range s.cache {
					if !now.Before(v.expires) {
						delete(s.cache, k)
					}
				}
			}
		}
	}
	if err != nil && ok {
		entry, err = cached, nil // use the stale answer on an upstream error
	}
	call.addrs, call.err = entry.addrs, err
	call.wg.Done()
	s.mu.Unlock()
	return call.addrs, call.err
}

func (s *safeResolver) resolve(name string, qtype uint16, addr string) (safeEntry, error) {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	r, _, err := s.client.Exchange(q, addr)
	if err != nil {
		return safeEntry{}, fmt.Errorf("resolve %s: %w", name, err)
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
	return safeEntry{addrs: out, expires: time.Now().Add(ttl)}, nil
}
