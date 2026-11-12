package app

import (
	"log"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/QChiba/kdnsfilter/internal/config"
	"github.com/QChiba/kdnsfilter/internal/firewall"
	"github.com/QChiba/kdnsfilter/internal/ipset"
	"github.com/QChiba/kdnsfilter/internal/querylog"
	"github.com/QChiba/kdnsfilter/internal/routing"
)

// Overridden in tests: the kernel side of routing and the firewall.
var (
	newRoutingBackend = func() (routing.Backend, error) { return ipset.Dial() }
	applyRules        = func(remove, ensure []firewall.Rule) error {
		firewall.Remove(remove)
		return firewall.Ensure(ensure, "")
	}
)

// prefillMaxResolve bounds the lookups one change makes; a bigger change
// relies on the query log and on the next answers instead.
const prefillMaxResolve = 500

// newRouter creates the router and applies cfg; without netlink (e.g. not
// root) domains are still matched, but no sets are filled.
func newRouter(cfg *config.Config) *routing.Router {
	b, err := newRoutingBackend()
	if err != nil {
		log.Printf("routing: %v", err)
		b = nil // not a typed nil pointer
	}
	r := routing.New(b, filepath.Join(cfg.DataDir, "routing.json"))
	r.Configure(cfg.Routing, time.Now())
	return r
}

// routingChanged applies a changed routing config: sets, entries, the
// firewall rules (when kdnsfilter manages the firewall) and a prefill of
// the domains just added. Callers hold a.mu.
func (a *App) routingChanged(prev, next *config.Config) {
	if reflect.DeepEqual(prev.Routing, next.Routing) {
		return
	}
	added := a.Routing.Configure(next.Routing, time.Now())
	if next.NFQueue.ManageFirewall {
		old, cur := firewall.RoutingRules(prev.Routing), firewall.RoutingRules(next.Routing)
		if err := applyRules(firewall.Diff(old, cur), cur); err != nil {
			log.Printf("routing firewall: %v", err)
		}
	}
	if len(added) > 0 {
		go a.prefill(added)
	}
}

// prefill routes the addresses clients may already have cached for newly
// listed domains — the answers in the query log — and resolves the domains
// themselves, so adding a domain takes effect without waiting for clients
// to look it up again.
func (a *App) prefill(added map[string][]string) {
	resolved := 0
	for list, domains := range added {
		m := routing.NewMatcher([]config.RouteList{{Domains: domains}})
		type hit struct {
			name  string
			addrs []netip.Addr
		}
		var hits []hit
		a.Log.Recent(func(e *querylog.Entry) bool {
			name := ""
			if _, ok := m.Match(e.Host); ok {
				name = e.Host
			}
			var addrs []netip.Addr
			for _, s := range e.Answers {
				if t, isCNAME := strings.CutPrefix(s, "CNAME "); isCNAME {
					if _, ok := m.Match(t); ok && name == "" {
						name = t
					}
				} else if ip, err := netip.ParseAddr(s); err == nil {
					addrs = append(addrs, ip)
				}
			}
			if name != "" && len(addrs) > 0 {
				hits = append(hits, hit{name, addrs})
			}
			return true
		})
		for _, h := range hits {
			a.Routing.Prefill(list, h.name, h.addrs, time.Now())
		}
		for _, d := range domains {
			if resolved >= prefillMaxResolve {
				break
			}
			resolved++
			for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
				if addrs, err := a.safe.lookup(d, qt); err == nil {
					a.Routing.Prefill(list, d, addrs, time.Now())
				}
			}
		}
	}
}
