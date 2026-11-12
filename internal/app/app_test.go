package app

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/QChiba/kdnsfilter/internal/config"
	"github.com/QChiba/kdnsfilter/internal/dnspkt"
)

func newTestApp(t *testing.T, mode string) *App {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = dir
	cfg.Hostmap = ""
	cfg.Filters = nil
	cfg.Filtering.BlockingMode = mode
	cfg.UserRules = []string{"||ads.example.com^", "||tracker.cloaked^"}
	cfg.Clients = []config.Client{{
		Name: "kid", IDs: []string{"192.168.1.16"}, FilteringEnabled: true,
		SafeSearch: config.SafeSearch{Enabled: true, Yandex: true},
	}}
	a, err := New(filepath.Join(dir, "kdnsfilter.yaml"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// replyPacket builds an IPv4 UDP packet from 192.168.1.1:53 to dst carrying a
// reply for name with the given answers.
func replyPacket(t *testing.T, dst [4]byte, name string, qtype uint16, answers ...string) []byte {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	r := new(dns.Msg)
	r.SetReply(q)
	for _, a := range answers {
		rr, err := dns.NewRR(a)
		if err != nil {
			t.Fatal(err)
		}
		r.Answer = append(r.Answer, rr)
	}
	payload, err := r.Pack()
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 28)
	raw[0], raw[8], raw[9] = 0x45, 64, 17
	copy(raw[12:16], []byte{192, 168, 1, 1})
	copy(raw[16:20], dst[:])
	binary.BigEndian.PutUint16(raw[20:22], 53)
	binary.BigEndian.PutUint16(raw[22:24], 40000)
	binary.BigEndian.PutUint16(raw[24:26], 8)
	p, err := dnspkt.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return p.WithPayload(payload)
}

func decode(t *testing.T, pkt []byte) *dns.Msg {
	t.Helper()
	p, err := dnspkt.Parse(pkt)
	if err != nil {
		t.Fatal(err)
	}
	var m dns.Msg
	if err := m.Unpack(p.Payload); err != nil {
		t.Fatal(err)
	}
	return &m
}

func TestProcess(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	adult, kid := [4]byte{192, 168, 1, 50}, [4]byte{192, 168, 1, 16}

	a := newTestApp(t, config.BlockNXDomain)

	// Allowed: passes unchanged.
	out, e := a.process(replyPacket(t, adult, "example.org", dns.TypeA, "example.org. 60 IN A 192.0.2.1"), now)
	if out != nil || e.Action != "pass" || e.Answers[0] != "192.0.2.1" {
		t.Errorf("pass: out=%v entry=%+v", out != nil, e)
	}

	// Blocked by user rule: NXDOMAIN with SOA.
	out, e = a.process(replyPacket(t, adult, "x.ads.example.com", dns.TypeA, "x.ads.example.com. 60 IN A 192.0.2.2"), now)
	if out == nil || e.Action != "block" || e.Rule != "||ads.example.com^" {
		t.Fatalf("block: %+v", e)
	}
	if m := decode(t, out); m.Rcode != dns.RcodeNameError || len(m.Answer) != 0 || len(m.Ns) != 1 {
		t.Errorf("block reply: %v", m)
	}

	// CNAME cloaking: allowed name whose CNAME target is blocked.
	out, e = a.process(replyPacket(t, adult, "metrics.shop.example", dns.TypeA,
		"metrics.shop.example. 60 IN CNAME tracker.cloaked.",
		"tracker.cloaked. 60 IN A 192.0.2.3"), now)
	if out == nil || e.Action != "block" || e.CNAME != "tracker.cloaked" {
		t.Errorf("cname: %+v", e)
	}

	// Safe search (Yandex uses a fixed address, no resolver needed).
	out, e = a.process(replyPacket(t, kid, "www.yandex.ru", dns.TypeA, "www.yandex.ru. 60 IN A 5.255.255.77"), now)
	if out == nil || e.Action != "rewrite" || e.ClientName != "kid" {
		t.Fatalf("safe search: %+v", e)
	}
	if m := decode(t, out); len(m.Answer) != 1 || m.Answer[0].(*dns.A).A.String() != "213.180.193.56" {
		t.Errorf("safe search reply: %v", m)
	}
	// ...but not for other clients.
	if out, _ = a.process(replyPacket(t, adult, "www.yandex.ru", dns.TypeA, "www.yandex.ru. 60 IN A 5.255.255.77"), now); out != nil {
		t.Error("safe search applied to a client without it")
	}

	// Not DNS.
	if out, e = a.process([]byte{0x45, 0, 0, 20}, now); out != nil || e != nil {
		t.Error("garbage must pass silently")
	}
}

func TestBlockingModes(t *testing.T) {
	now := time.Now()
	dst := [4]byte{192, 168, 1, 50}
	for _, tc := range []struct {
		mode  string
		qtype uint16
		check func(*dns.Msg) bool
	}{
		{config.BlockNullIP, dns.TypeA, func(m *dns.Msg) bool {
			return m.Rcode == dns.RcodeSuccess && len(m.Answer) == 1 && m.Answer[0].(*dns.A).A.IsUnspecified()
		}},
		{config.BlockNullIP, dns.TypeAAAA, func(m *dns.Msg) bool {
			return m.Rcode == dns.RcodeSuccess && len(m.Answer) == 1 && m.Answer[0].(*dns.AAAA).AAAA.IsUnspecified()
		}},
		{config.BlockNullIP, dns.TypeHTTPS, func(m *dns.Msg) bool {
			return m.Rcode == dns.RcodeSuccess && len(m.Answer) == 0 && len(m.Ns) == 1
		}},
		{config.BlockRefused, dns.TypeA, func(m *dns.Msg) bool { return m.Rcode == dns.RcodeRefused }},
	} {
		a := newTestApp(t, tc.mode)
		out, _ := a.process(replyPacket(t, dst, "ads.example.com", tc.qtype), now)
		if out == nil || !tc.check(decode(t, out)) {
			t.Errorf("%s/%s: unexpected reply", tc.mode, dns.TypeToString[tc.qtype])
		}
	}
}

func TestDoHCanaryIsNXDomain(t *testing.T) {
	a := newTestApp(t, config.BlockNullIP)
	pkt := replyPacket(t, [4]byte{192, 168, 1, 50}, "use-application-dns.net", dns.TypeA, "use-application-dns.net. 300 IN A 35.190.14.201")
	out, e := a.process(pkt, time.Now())
	if out == nil || decode(t, out).Rcode != dns.RcodeNameError {
		t.Fatal("canary must get NXDOMAIN even in null_ip mode")
	}
	if e.Reason != "doh_canary" {
		t.Errorf("reason %q", e.Reason)
	}
}

func TestRewriteReplies(t *testing.T) {
	a := newTestApp(t, config.BlockNXDomain)
	if err := a.Update(func(c *config.Config) error {
		c.Filtering.Rewrites = []config.Rewrite{
			{Domain: "media.home", Answer: "192.168.1.5", Enabled: true},
			{Domain: "www.media.home", Answer: "media.home", Enabled: true},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	dst := [4]byte{192, 168, 1, 50}

	// The upstream didn't know the name; the rewrite answers anyway.
	pkt := replyPacket(t, dst, "media.home", dns.TypeA)
	out, e := a.process(pkt, time.Now())
	if out == nil {
		t.Fatal("A query not rewritten")
	}
	m := decode(t, out)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 || m.Answer[0].(*dns.A).A.String() != "192.168.1.5" {
		t.Errorf("A reply: %v", m)
	}
	if e.Action != "rewrite" || e.Reason != "rewrite" || e.Rule != "media.home → 192.168.1.5" {
		t.Errorf("log entry: %+v", e)
	}

	// Other types get an empty NOERROR, so HTTPS hints can't leak real addresses.
	out, _ = a.process(replyPacket(t, dst, "media.home", dns.TypeHTTPS, `media.home. 300 IN HTTPS 1 . alpn="h2" ipv4hint="203.0.113.9"`), time.Now())
	if m := decode(t, out); m.Rcode != dns.RcodeSuccess || len(m.Answer) != 0 || len(m.Ns) != 1 {
		t.Errorf("HTTPS reply: %v", m)
	}

	// A CNAME rewrite to another rewrite answers the whole chain locally.
	out, _ = a.process(replyPacket(t, dst, "www.media.home", dns.TypeA), time.Now())
	m = decode(t, out)
	if len(m.Answer) != 2 || m.Answer[0].(*dns.CNAME).Target != "media.home." ||
		m.Answer[1].Header().Name != "media.home." || m.Answer[1].(*dns.A).A.String() != "192.168.1.5" {
		t.Errorf("CNAME reply: %v", m)
	}
}

// Config is read on every API request; it must not allocate (a deep copy per
// request kept the GC — which scans the whole rule index — permanently busy).
func TestConfigDoesNotAllocate(t *testing.T) {
	a := newTestApp(t, config.BlockNXDomain)
	if n := testing.AllocsPerRun(100, func() { _ = a.Config() }); n != 0 {
		t.Errorf("Config() allocates %v times per call", n)
	}
	before := a.Config()
	if err := a.Update(func(c *config.Config) error { c.UserRules = append(c.UserRules, "||x.example^"); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(before.UserRules) != 2 || len(a.Config().UserRules) != 3 {
		t.Errorf("Update must replace the snapshot, not modify it: before=%d after=%d", len(before.UserRules), len(a.Config().UserRules))
	}
}

// Settings that don't touch lists or user rules must not recompile the rules
// (seconds on a router); rule edits and list downloads must.
func TestRulesReusedUnlessInputsChange(t *testing.T) {
	a := newTestApp(t, config.BlockNXDomain)
	if a.rulesBuilds != 1 {
		t.Fatalf("initial builds: %d", a.rulesBuilds)
	}
	same := []func(*config.Config){
		func(c *config.Config) { c.Filtering.ProtectionEnabled = false },
		func(c *config.Config) { c.Filtering.BlockingMode = config.BlockNullIP },
		func(c *config.Config) {
			c.Clients = append(c.Clients, config.Client{Name: "x", IDs: []string{"192.168.1.99"}})
		},
		func(c *config.Config) { c.Filtering.SafeSearch.Enabled = true },
	}
	for i, fn := range same {
		if err := a.Update(func(c *config.Config) error { fn(c); return nil }); err != nil {
			t.Fatal(err)
		}
		if a.rulesBuilds != 1 {
			t.Errorf("change %d recompiled the rules", i)
		}
	}
	// The cheap path still applies the change.
	if a.Filter().BlockingMode != config.BlockNullIP {
		t.Error("blocking mode not applied")
	}

	if err := a.Update(func(c *config.Config) error { c.UserRules = append(c.UserRules, "||new.example^"); return nil }); err != nil {
		t.Fatal(err)
	}
	if a.rulesBuilds != 2 {
		t.Errorf("user rule edit: builds %d, want 2", a.rulesBuilds)
	}
	if err := a.Update(func(c *config.Config) error { c.Filtering.ProtectionEnabled = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if r := a.Filter().Check(filteringReq("new.example"), time.Now()); r.Action != 1 {
		t.Errorf("rule added earlier lost after a cheap rebuild: %+v", r)
	}

	// A downloaded/changed list file forces a recompile.
	if err := a.Update(func(c *config.Config) error {
		c.Filters = []config.Filter{{ID: 5, Name: "local", URL: "/dev/null", Enabled: true}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	builds := a.rulesBuilds
	if err := os.WriteFile(a.listPath(5), []byte("||fromlist.example^\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	err := a.rebuild(a.cfg.Load())
	a.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if a.rulesBuilds != builds+1 {
		t.Errorf("list change: builds %d, want %d", a.rulesBuilds, builds+1)
	}
	if r := a.Filter().Check(filteringReq("fromlist.example"), time.Now()); r.Action != 1 {
		t.Errorf("list rule not active: %+v", r)
	}
}

func TestUpdatePersists(t *testing.T) {
	a := newTestApp(t, config.BlockNXDomain)
	err := a.Update(func(c *config.Config) error {
		c.UserRules = append(c.UserRules, "||new.example^")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := a.Filter().Check(filteringReq("new.example"), time.Now()); r.Action != 1 {
		t.Errorf("new rule not applied: %+v", r)
	}
	back, err := config.Load(a.cfgPath)
	if err != nil || len(back.UserRules) != 3 {
		t.Errorf("not saved: %v %v", back, err)
	}
	// Invalid change is rejected and nothing changes.
	if err := a.Update(func(c *config.Config) error { c.Filtering.BlockingMode = "bogus"; return nil }); err == nil {
		t.Error("invalid config accepted")
	}
	if a.Config().Filtering.BlockingMode != config.BlockNXDomain {
		t.Error("invalid config applied")
	}
}
