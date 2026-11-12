package filtering

import (
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/QChiba/kdnsfilter/internal/config"
	"github.com/QChiba/kdnsfilter/internal/schedule"
)

func testFilter(t *testing.T) *Filter {
	t.Helper()
	cfg := config.Default()
	cfg.UserRules = []string{
		"||ads.example.com^",
		"@@||good.ads.example.com^",
		"||only-kid.example^$client='kid'",
		"||v6only.example^$dnstype=AAAA",
		"! a comment",
	}
	cfg.Clients = []config.Client{
		{
			Name: "kid", IDs: []string{"192.168.1.16", "aa:bb:cc:dd:ee:ff"},
			FilteringEnabled: true,
			SafeSearch:       config.SafeSearch{Enabled: true, YouTube: true, Google: true, Yandex: true},
			BlockedServices: config.BlockedServices{
				IDs: []string{"tiktok", "nonexistent"},
				Schedule: &schedule.Weekly{TimeZone: "UTC",
					Mon: &schedule.Range{Start: schedule.Duration(9 * time.Hour), End: schedule.Duration(21 * time.Hour)}},
			},
		},
		{Name: "unfiltered", IDs: []string{"192.168.1.20"}, FilteringEnabled: false},
		{Name: "lan", IDs: []string{"192.168.1.0/24"}, UseGlobalSettings: true, UseGlobalBlockedServices: true},
	}
	lists := []ListSource{{ID: 7, Rules: []byte("0.0.0.0 hosts.example.net\n||list.example.org^\n")}}
	f, err := Build(cfg, lists, LoadCatalog(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Warnings) != 1 {
		t.Errorf("warnings: %q", f.Warnings)
	}
	return f
}

func TestCheck(t *testing.T) {
	f := testFilter(t)
	kid := netip.MustParseAddr("192.168.1.16")
	other := netip.MustParseAddr("192.168.1.50")
	monNight := time.Date(2026, 10, 19, 22, 0, 0, 0, time.UTC) // services blocked
	monDay := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)   // services paused

	for _, tc := range []struct {
		name   string
		req    Request
		now    time.Time
		action Action
		reason string
		client string
	}{
		{"user rule", Request{Host: "ads.example.com", ClientIP: other}, monDay, Block, ReasonFilter, "lan"},
		{"subdomain", Request{Host: "x.ads.example.com", ClientIP: other}, monDay, Block, ReasonFilter, "lan"},
		{"allowlist", Request{Host: "good.ads.example.com", ClientIP: other}, monDay, Pass, ReasonAllowlist, "lan"},
		{"hosts list", Request{Host: "hosts.example.net", ClientIP: other}, monDay, Block, ReasonFilter, "lan"},
		{"adblock list", Request{Host: "a.list.example.org", ClientIP: other}, monDay, Block, ReasonFilter, "lan"},
		{"clean", Request{Host: "example.org", ClientIP: other}, monDay, Pass, "", "lan"},
		{"$client other", Request{Host: "only-kid.example", ClientIP: other}, monDay, Pass, "", "lan"},
		{"$client kid", Request{Host: "only-kid.example", ClientIP: kid}, monDay, Block, ReasonFilter, "kid"},
		{"$dnstype A", Request{Host: "v6only.example", QType: dns.TypeA, ClientIP: other}, monDay, Pass, "", "lan"},
		{"$dnstype AAAA", Request{Host: "v6only.example", QType: dns.TypeAAAA, ClientIP: other}, monDay, Block, ReasonFilter, "lan"},
		{"filtering off", Request{Host: "ads.example.com", ClientIP: netip.MustParseAddr("192.168.1.20")}, monDay, Pass, "", "unfiltered"},
		{"service blocked", Request{Host: "www.tiktok.com", ClientIP: kid}, monNight, Block, ReasonService, "kid"},
		{"service paused", Request{Host: "www.tiktok.com", ClientIP: kid}, monDay, Pass, "", "kid"},
		{"service other client", Request{Host: "www.tiktok.com", ClientIP: other}, monNight, Pass, "", "lan"},
		{"safe youtube", Request{Host: "www.youtube.com", ClientIP: kid}, monDay, Rewrite, ReasonSafeSearch, "kid"},
		{"safe google", Request{Host: "www.google.co.uk", ClientIP: kid}, monDay, Rewrite, ReasonSafeSearch, "kid"},
		{"safe off for others", Request{Host: "www.youtube.com", ClientIP: other}, monDay, Pass, "", "lan"},
		{"mac match", Request{Host: "www.youtube.com", ClientIP: netip.MustParseAddr("fd00::5"), ClientMAC: "aa:bb:cc:dd:ee:ff"}, monDay, Rewrite, ReasonSafeSearch, "kid"},
		{"unknown client", Request{Host: "ads.example.com", ClientIP: netip.MustParseAddr("172.16.9.1")}, monDay, Block, ReasonFilter, ""},
		{"doh canary", Request{Host: DoHCanary, ClientIP: other}, monDay, Block, ReasonDoHCanary, "lan"},
		{"doh canary unfiltered", Request{Host: DoHCanary, ClientIP: netip.MustParseAddr("192.168.1.20")}, monDay, Block, ReasonDoHCanary, "unfiltered"},
	} {
		r := f.Check(tc.req, tc.now)
		if r.Action != tc.action || r.Reason != tc.reason || r.ClientName != tc.client {
			t.Errorf("%s: got %v/%q/%q (rule %q), want %v/%q/%q", tc.name, r.Action, r.Reason, r.ClientName, r.Rule, tc.action, tc.reason, tc.client)
		}
	}

	if r := f.CheckCNAME(Request{Host: "www.youtube.com", ClientIP: kid}, monDay); r.Action != Pass {
		t.Errorf("CNAME targets must not be rewritten: %+v", r)
	}
}

func TestClientForPrefersMAC(t *testing.T) {
	cfg := config.Default()
	cfg.Clients = []config.Client{
		{Name: "stale-ip", IDs: []string{"192.168.1.11"}},
		{Name: "console", IDs: []string{"02:00:00:00:AB:43"}},
		{Name: "lan", IDs: []string{"192.168.1.0/24"}},
	}
	f, err := Build(cfg, nil, LoadCatalog(""))
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr
	for _, tc := range []struct {
		ip, mac, want string
	}{
		// DHCP moved the console to .67 and gave .11 to someone else.
		{"192.168.1.67", "02:00:00:00:ab:43", "console"},
		{"fd12::1234", "02:00:00:00:ab:43", "console"},    // any IPv6 address of the device
		{"192.168.1.11", "02:00:00:00:ab:43", "console"},  // MAC beats a stale IP id
		{"192.168.1.11", "", "stale-ip"},                  // unknown MAC: IP id still works
		{"192.168.1.11", "00:00:00:00:00:01", "stale-ip"}, // unbound MAC: falls back to IP
		{"192.168.1.99", "00:00:00:00:00:01", "lan"},
	} {
		c := f.ClientFor(ip(tc.ip), tc.mac)
		if c == nil || c.Name != tc.want {
			t.Errorf("%s/%s: got %v, want %s", tc.ip, tc.mac, c, tc.want)
		}
	}
}

func TestSafeSearchHosts(t *testing.T) {
	all := config.SafeSearch{Enabled: true, Google: true, YouTube: true, Bing: true, DuckDuckGo: true, Yandex: true, Pixabay: true, Ecosia: true}
	for host, want := range map[string]string{
		"www.google.com":        "forcesafesearch.google.com",
		"www.google.de":         "forcesafesearch.google.com",
		"www.google.com.br":     "forcesafesearch.google.com",
		"www.google.cat":        "forcesafesearch.google.com",
		"m.youtube.com":         "restrictmoderate.youtube.com",
		"edgeservices.bing.com": "strict.bing.com",
		"duckduckgo.com":        "safe.duckduckgo.com",
		"pixabay.com":           "safesearch.pixabay.com",
		"www.ecosia.org":        "strict-safe-search.ecosia.org",
		"www.yandex.ru":         "213.180.193.56",
		"www.yandex.com.tr":     "213.180.193.56",
		"www.ya.ru":             "213.180.193.56",
		"mail.google.com":       "",
		"www.google.evil.com":   "",
		"google.com":            "",
		"yandex.ru":             "",
	} {
		got := ""
		if st, ok := safeSearch(host, all); ok {
			got = st.CNAME
			if st.IP.IsValid() {
				got = st.IP.String()
			}
		}
		if got != want {
			t.Errorf("%s: got %q, want %q", host, got, want)
		}
	}
	if _, ok := safeSearch("www.google.com", config.SafeSearch{Google: true}); ok {
		t.Error("disabled safe search must not rewrite")
	}
}

func TestEmbeddedCatalog(t *testing.T) {
	c := LoadCatalog("")
	for _, id := range []string{"youtube", "tiktok", "nintendo", "steam"} {
		if s, ok := c.Get(id); !ok || len(s.Rules) == 0 {
			t.Errorf("service %s missing", id)
		}
	}
}
