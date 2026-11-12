package routing

import (
	"net/netip"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/QChiba/kdnsfilter/internal/config"
)

// fakeSets records what the router asks the kernel to do.
type fakeSets struct {
	sets    map[string]map[netip.Addr]time.Duration
	adds    int
	created []string
}

func newFakeSets() *fakeSets { return &fakeSets{sets: map[string]map[netip.Addr]time.Duration{}} }

func (f *fakeSets) Create(name string, v6 bool, timeout time.Duration, maxElem uint32) error {
	f.created = append(f.created, name)
	if f.sets[name] == nil {
		f.sets[name] = map[netip.Addr]time.Duration{}
	}
	return nil
}

func (f *fakeSets) Add(set string, a netip.Addr, timeout time.Duration) error {
	f.adds++
	f.sets[set][a] = timeout
	return nil
}

func (f *fakeSets) Del(set string, a netip.Addr) error {
	delete(f.sets[set], a)
	return nil
}

func (f *fakeSets) has(set, addr string) bool {
	_, ok := f.sets[set][netip.MustParseAddr(addr)]
	return ok
}

func rrs(t *testing.T, recs ...string) []dns.RR {
	t.Helper()
	var out []dns.RR
	for _, s := range recs {
		rr, err := dns.NewRR(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, rr)
	}
	return out
}

func routingCfg(domains ...string) config.Routing {
	l := config.RouteList{Name: "bypass", Domains: domains}
	l.Normalize()
	return config.Routing{Enabled: true, MinTimeout: config.Duration(time.Hour), Lists: []config.RouteList{l}}
}

func TestMatcher(t *testing.T) {
	m := NewMatcher([]config.RouteList{
		{Name: "a", Domains: []string{"youtube.com", "!music.youtube.com", "googlevideo.com"}},
		{Name: "b", Domains: []string{"x.com", "youtube.com"}}, // youtube.com stays in list a
	})
	for host, want := range map[string]int{
		"youtube.com": 0, "www.youtube.com": 0, "rr1---sn.googlevideo.com": 0, "api.x.com": 1,
		"music.youtube.com": -1, "a.music.youtube.com": -1, "notyoutube.com": -1, "com": -1,
	} {
		i, ok := m.Match(host)
		if got := map[bool]int{true: i, false: -1}[ok]; got != want {
			t.Errorf("%s: list %d, want %d", host, got, want)
		}
	}
	for host, want := range map[string]struct {
		entry        string
		ok, excluded bool
	}{
		"www.youtube.com":     {"youtube.com", true, false},
		"a.music.youtube.com": {"!music.youtube.com", false, true},
		"notyoutube.com":      {"", false, false},
	} {
		_, entry, ok, excluded := m.Lookup(host)
		if entry != want.entry || ok != want.ok || excluded != want.excluded {
			t.Errorf("Lookup(%s) = %q %v %v, want %+v", host, entry, ok, excluded, want)
		}
	}
}

func TestRouteFillsSetsAndRefreshesLazily(t *testing.T) {
	f := newFakeSets()
	r := New(f, "")
	r.Configure(routingCfg("youtube.com", "l.google.com"), time.Now())
	if !slices.Equal(f.created, []string{"kdf_bypass4", "kdf_bypass6"}) {
		t.Fatalf("created %v", f.created)
	}
	now := time.Now()
	ans := rrs(t, "www.youtube.com. 300 IN CNAME youtube-ui.l.google.com.",
		"youtube-ui.l.google.com. 300 IN A 142.250.1.1",
		"youtube-ui.l.google.com. 300 IN AAAA 2a00:1450::1")
	if got := r.Route("www.youtube.com", ans, now).List; got != "bypass" {
		t.Fatalf("route %q", got)
	}
	if !f.has("kdf_bypass4", "142.250.1.1") || !f.has("kdf_bypass6", "2a00:1450::1") {
		t.Fatalf("sets %v", f.sets)
	}
	if to := f.sets["kdf_bypass4"][netip.MustParseAddr("142.250.1.1")]; to != time.Hour {
		t.Errorf("timeout %s, want the 1h minimum over a 300 s TTL", to)
	}
	// Repeated answers don't go to the kernel until half the lifetime is left.
	adds := f.adds
	r.Route("www.youtube.com", ans, now.Add(10*time.Minute))
	if f.adds != adds {
		t.Errorf("refreshed too early: %d adds", f.adds-adds)
	}
	r.Route("www.youtube.com", ans, now.Add(40*time.Minute))
	if f.adds != adds+2 {
		t.Errorf("not refreshed after half the lifetime: %d adds", f.adds-adds)
	}

	// Only the CNAME target is listed.
	if got := r.Route("tv.example.net", rrs(t, "tv.example.net. 60 IN CNAME ytimg.l.google.com.", "ytimg.l.google.com. 60 IN A 142.250.2.2"), now).List; got != "bypass" {
		t.Errorf("CNAME target not matched: %q", got)
	}
	// HTTPS address hints count; blocked (0.0.0.0) and private answers never do.
	r.Route("youtube.com", rrs(t, `youtube.com. 60 IN HTTPS 1 . alpn="h2" ipv4hint="142.250.3.3" ipv6hint="2a00:1450::3"`), now)
	r.Route("youtube.com", rrs(t, "youtube.com. 60 IN A 0.0.0.0", "youtube.com. 60 IN A 192.168.1.5"), now)
	for _, a := range []string{"142.250.2.2", "142.250.3.3"} {
		if !f.has("kdf_bypass4", a) {
			t.Errorf("%s missing", a)
		}
	}
	if !f.has("kdf_bypass6", "2a00:1450::3") || f.has("kdf_bypass4", "0.0.0.0") || f.has("kdf_bypass4", "192.168.1.5") {
		t.Errorf("sets %v", f.sets)
	}
	if got := r.Route("example.org", rrs(t, "example.org. 60 IN A 93.184.215.14"), now).List; got != "" {
		t.Errorf("unlisted host routed to %q", got)
	}
}

// A list holding a hosting provider (amazonaws.com) routes every site behind
// it through CNAMEs; a "!" exception for the site must keep it out.
func TestExceptionBeatsCNAMEMatch(t *testing.T) {
	f := newFakeSets()
	r := New(f, "")
	r.Configure(routingCfg("amazonaws.com", "!utorrent.com", "cdn.example", "!edge.cdn.example", "other.net"), time.Now())
	now := time.Now()
	elb := func(host string) []dns.RR {
		return rrs(t, host+". 60 IN CNAME bench.utp.st.",
			"bench.utp.st. 60 IN CNAME prod-bench.us-east-1.elb.amazonaws.com.",
			"prod-bench.us-east-1.elb.amazonaws.com. 60 IN A 52.20.243.232")
	}
	if got := r.Route("i-1.bench.utorrent.com", elb("i-1.bench.utorrent.com"), now); got != (Routed{}) {
		t.Errorf("excluded site routed: %+v", got)
	}
	if f.has("kdf_bypass4", "52.20.243.232") {
		t.Fatal("excluded site's address added")
	}

	want := Routed{List: "bypass", Entry: "amazonaws.com", Via: "prod-bench.us-east-1.elb.amazonaws.com"}
	if got := r.Route("app.example.org", elb("app.example.org"), now); got != want {
		t.Errorf("via CNAME: %+v, want %+v", got, want)
	}
	want = Routed{List: "bypass", Entry: "amazonaws.com"}
	if got := r.Route("s3.amazonaws.com", rrs(t, "s3.amazonaws.com. 60 IN A 52.216.1.1"), now); got != want {
		t.Errorf("direct: %+v, want %+v", got, want)
	}
	// An excluded CNAME target is skipped; a later listed one still routes.
	want = Routed{List: "bypass", Entry: "other.net", Via: "b.other.net"}
	got := r.Route("www.example.com", rrs(t, "www.example.com. 60 IN CNAME a.edge.cdn.example.",
		"a.edge.cdn.example. 60 IN CNAME b.other.net.", "b.other.net. 60 IN A 198.51.100.7"), now)
	if got != want {
		t.Errorf("excluded target: %+v, want %+v", got, want)
	}
}

func TestConfigureRemovesUnlistedAddresses(t *testing.T) {
	f := newFakeSets()
	r := New(f, "")
	now := time.Now()
	r.Configure(routingCfg("youtube.com", "x.com"), now)
	r.Route("www.youtube.com", rrs(t, "www.youtube.com. 60 IN A 142.250.1.1"), now)
	r.Route("api.x.com", rrs(t, "api.x.com. 60 IN A 104.244.42.1"), now)
	// A shared address stays while another listed name still uses it.
	r.Route("x.com", rrs(t, "x.com. 60 IN A 142.250.1.1"), now)

	added := r.Configure(routingCfg("x.com", "twimg.com"), now)
	if !slices.Equal(added["bypass"], []string{"twimg.com"}) {
		t.Errorf("added %v", added)
	}
	if !f.has("kdf_bypass4", "142.250.1.1") || !f.has("kdf_bypass4", "104.244.42.1") {
		t.Errorf("x.com addresses lost: %v", f.sets)
	}
	// An exception removes the addresses of the excluded name only.
	r.Configure(routingCfg("x.com", "!api.x.com", "twimg.com"), now)
	if !f.has("kdf_bypass4", "142.250.1.1") || f.has("kdf_bypass4", "104.244.42.1") {
		t.Errorf("exception: %v", f.sets)
	}
	r.Configure(routingCfg("twimg.com"), now)
	if f.has("kdf_bypass4", "142.250.1.1") || f.has("kdf_bypass4", "104.244.42.1") {
		t.Errorf("removed domains still routed: %v", f.sets)
	}

	r.Route("pbs.twimg.com", rrs(t, "pbs.twimg.com. 60 IN A 151.101.1.1"), now)
	r.Configure(config.Routing{Enabled: false, MinTimeout: config.Duration(time.Hour)}, now)
	if len(f.sets["kdf_bypass4"]) != 0 {
		t.Errorf("disabling left %v", f.sets)
	}
	if got := r.Route("pbs.twimg.com", rrs(t, "pbs.twimg.com. 60 IN A 151.101.1.1"), now).List; got != "" {
		t.Errorf("routed while disabled: %q", got)
	}
}

func TestSnapshotRestoresAfterReboot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routing.json")
	now := time.Now()
	f := newFakeSets()
	r := New(f, path)
	r.Configure(routingCfg("youtube.com"), now)
	r.Route("youtube.com", rrs(t, "youtube.com. 60 IN A 142.250.1.1", "youtube.com. 60 IN AAAA 2a00:1450::1"), now)
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}

	// A reboot empties the kernel's sets; the snapshot puts the entries back
	// with their remaining lifetime.
	f2 := newFakeSets()
	r2 := New(f2, path)
	r2.Configure(routingCfg("youtube.com"), now.Add(20*time.Minute))
	if to := f2.sets["kdf_bypass4"][netip.MustParseAddr("142.250.1.1")]; to < 39*time.Minute || to > 41*time.Minute {
		t.Errorf("restored with %s left, want ~40m", to)
	}
	if !f2.has("kdf_bypass6", "2a00:1450::1") {
		t.Errorf("IPv6 entry not restored")
	}
	lists, _ := r2.Status()
	if len(lists) != 1 || lists[0].Count4 != 1 || lists[0].Count6 != 1 {
		t.Errorf("status %+v", lists)
	}

	// Expired entries are not restored.
	f3 := newFakeSets()
	New(f3, path).Configure(routingCfg("youtube.com"), now.Add(2*time.Hour))
	if len(f3.sets["kdf_bypass4"]) != 0 {
		t.Errorf("expired entries restored: %v", f3.sets)
	}
}

func TestPrefillOnlyForItsList(t *testing.T) {
	f := newFakeSets()
	r := New(f, "")
	now := time.Now()
	r.Configure(routingCfg("youtube.com"), now)
	r.Prefill("bypass", "m.youtube.com", []netip.Addr{netip.MustParseAddr("142.250.9.9")}, now)
	r.Prefill("bypass", "example.org", []netip.Addr{netip.MustParseAddr("93.184.215.14")}, now)
	r.Prefill("other", "youtube.com", []netip.Addr{netip.MustParseAddr("142.250.8.8")}, now)
	if !f.has("kdf_bypass4", "142.250.9.9") || len(f.sets["kdf_bypass4"]) != 1 {
		t.Errorf("sets %v", f.sets)
	}
	r.Prune(now.Add(2 * time.Hour))
	if lists, _ := r.Status(); lists[0].Count4 != 0 {
		t.Errorf("prune kept %d", lists[0].Count4)
	}
}
