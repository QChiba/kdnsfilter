package app

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/QChiba/kdnsfilter/internal/config"
	"github.com/QChiba/kdnsfilter/internal/firewall"
	"github.com/QChiba/kdnsfilter/internal/querylog"
	"github.com/QChiba/kdnsfilter/internal/routing"
)

type fakeSets struct {
	mu   sync.Mutex
	sets map[string]map[netip.Addr]bool
}

func (f *fakeSets) Create(name string, v6 bool, _ time.Duration, _ uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sets[name] == nil {
		f.sets[name] = map[netip.Addr]bool{}
	}
	return nil
}

func (f *fakeSets) Add(set string, a netip.Addr, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sets[set][a] = true
	return nil
}

func (f *fakeSets) Del(set string, a netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.sets[set], a)
	return nil
}

func (f *fakeSets) has(set, addr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sets[set][netip.MustParseAddr(addr)]
}

// withFakeKernel swaps the ipset backend and the firewall for recorders.
func withFakeKernel(t *testing.T) (*fakeSets, *[][2][]firewall.Rule) {
	t.Helper()
	f := &fakeSets{sets: map[string]map[netip.Addr]bool{}}
	var applied [][2][]firewall.Rule
	oldB, oldR := newRoutingBackend, applyRules
	newRoutingBackend = func() (routing.Backend, error) { return f, nil }
	applyRules = func(remove, ensure []firewall.Rule) error {
		applied = append(applied, [2][]firewall.Rule{remove, ensure})
		return nil
	}
	t.Cleanup(func() { newRoutingBackend, applyRules = oldB, oldR })
	return f, &applied
}

func enableRouting(t *testing.T, a *App, domains ...string) {
	t.Helper()
	err := a.Update(func(c *config.Config) error {
		c.Resolver = "127.0.0.1:1" // nothing listens: prefill lookups fail fast
		c.Routing.Enabled = true
		c.Routing.Lists = []config.RouteList{{Name: "bypass", Chain: "MY_PROXY", OutputChain: "MY_PROXY_OUT", Domains: domains}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestProcessRoutesBeforeVerdict(t *testing.T) {
	f, applied := withFakeKernel(t)
	a := newTestApp(t, config.BlockNXDomain)
	enableRouting(t, a, "youtube.com", "ads.example.com")

	if len(*applied) != 1 || len((*applied)[0][1]) != 4 || len((*applied)[0][0]) != 0 {
		t.Fatalf("firewall %v", *applied)
	}
	if got := (*applied)[0][1][0].String(); got != "iptables -t mangle -A PREROUTING -m set --match-set kdf_bypass4 dst -j MY_PROXY" {
		t.Errorf("rule %s", got)
	}

	out, e := a.process(replyPacket(t, [4]byte{192, 168, 1, 10}, "www.youtube.com", dns.TypeA, "www.youtube.com. 300 IN A 142.250.1.1"), time.Now())
	if out != nil {
		t.Error("routed reply was modified")
	}
	if e.Route != "bypass" || !f.has("kdf_bypass4", "142.250.1.1") {
		t.Errorf("route %q, sets %v", e.Route, f.sets)
	}
	// A blocked name is answered with NXDOMAIN and never routed.
	_, e = a.process(replyPacket(t, [4]byte{192, 168, 1, 10}, "ads.example.com", dns.TypeA, "ads.example.com. 300 IN A 203.0.113.9"), time.Now())
	if e.Action != "block" || e.Route != "" || f.has("kdf_bypass4", "203.0.113.9") {
		t.Errorf("blocked reply routed: %+v", e)
	}

	// Removing the domain takes its address out and keeps the rules.
	if err := a.Update(func(c *config.Config) error {
		c.Routing.Lists[0].Domains = []string{"x.com"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if f.has("kdf_bypass4", "142.250.1.1") {
		t.Error("removed domain still routed")
	}
	if len(*applied) != 2 || len((*applied)[1][0]) != 0 {
		t.Errorf("firewall %v", *applied)
	}
	// Changing the chain swaps its rules.
	if err := a.Update(func(c *config.Config) error {
		c.Routing.Lists[0].OutputChain = ""
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if last := (*applied)[2]; len(last[0]) != 2 || last[0][0].Chain != "OUTPUT" || len(last[1]) != 2 {
		t.Errorf("chain change %v", last)
	}
}

func TestAddedDomainIsPrefilledFromQueryLog(t *testing.T) {
	f, _ := withFakeKernel(t)
	a := newTestApp(t, config.BlockNXDomain)
	enableRouting(t, a, "youtube.com")
	a.Record(querylog.Entry{Time: time.Now(), Host: "pbs.twimg.com", Action: "pass", Answers: []string{"151.101.1.1"}})
	a.Record(querylog.Entry{Time: time.Now(), Host: "t.co", Action: "pass", Answers: []string{"CNAME edge.twimg.com", "151.101.2.2"}})
	a.Record(querylog.Entry{Time: time.Now(), Host: "example.org", Action: "pass", Answers: []string{"93.184.215.14"}})

	if err := a.Update(func(c *config.Config) error {
		c.Routing.Lists[0].Domains = append(c.Routing.Lists[0].Domains, "twimg.com")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !(f.has("kdf_bypass4", "151.101.1.1") && f.has("kdf_bypass4", "151.101.2.2")) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !f.has("kdf_bypass4", "151.101.1.1") || !f.has("kdf_bypass4", "151.101.2.2") || f.has("kdf_bypass4", "93.184.215.14") {
		t.Errorf("sets %v", f.sets)
	}
}
