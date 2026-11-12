package filtering

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/QChiba/kdnsfilter/internal/config"
)

func rewriteFilter(t *testing.T, protection bool) *Filter {
	t.Helper()
	cfg := config.Default()
	cfg.Filtering.ProtectionEnabled = protection
	cfg.UserRules = []string{
		"||rule.example^$dnsrewrite=10.1.1.1",
		"||rule.example^$dnsrewrite=NOERROR;AAAA;fd00::1",
		"||nx.example^$dnsrewrite=NXDOMAIN",
		"||alias.example^$dnsrewrite=target.example",
		"||kid.example^$client=kid,dnsrewrite=10.2.2.2",
		"10.3.3.3 hosts.example",
		"||blocked.example^",
	}
	cfg.Clients = []config.Client{{Name: "kid", IDs: []string{"192.168.1.16"}, FilteringEnabled: true}}
	on := func(d, a string) config.Rewrite { return config.Rewrite{Domain: d, Answer: a, Enabled: true} }
	cfg.Filtering.Rewrites = []config.Rewrite{
		on("media.home", "192.168.1.5"), on("media.home", "fd00::5"),
		on("*.lan.example", "192.168.1.7"), on("*.deep.lan.example", "192.168.1.8"), on("exact.lan.example", "192.168.1.9"),
		on("v4only.example", "192.168.1.10"),
		on("keep6.example", "192.168.1.11"), on("keep6.example", "AAAA"),
		on("www.alias.home", "media.home"), on("cdn.alias.home", "cdn.example.net"),
		{Domain: "off.example", Answer: "192.168.1.12"},
		on("blocked.example", "192.168.1.13"),
		on("loop1.example", "loop2.example"), on("loop2.example", "loop1.example"),
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	f, err := Build(cfg, nil, LoadCatalog(""))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestRewrites(t *testing.T) {
	ip := netip.MustParseAddr
	other, kid := ip("192.168.1.50"), ip("192.168.1.16")
	type want struct {
		reason  string // "" = not rewritten
		addrs   []string
		cnames  []string
		resolve string
		rcode   int
	}
	for _, tc := range []struct {
		host       string
		qtype      uint16
		client     netip.Addr
		protection bool
		want       want
	}{
		{"media.home", dns.TypeA, other, true, want{reason: ReasonRewrite, addrs: []string{"192.168.1.5"}}},
		{"media.home", dns.TypeAAAA, other, true, want{reason: ReasonRewrite, addrs: []string{"fd00::5"}}},
		{"media.home", dns.TypeHTTPS, other, true, want{reason: ReasonRewrite}},
		{"a.lan.example", dns.TypeA, other, true, want{reason: ReasonRewrite, addrs: []string{"192.168.1.7"}}},
		{"x.deep.lan.example", dns.TypeA, other, true, want{reason: ReasonRewrite, addrs: []string{"192.168.1.8"}}},
		{"exact.lan.example", dns.TypeA, other, true, want{reason: ReasonRewrite, addrs: []string{"192.168.1.9"}}},
		{"lan.example", dns.TypeA, other, true, want{}}, // a wildcard doesn't cover the apex
		{"v4only.example", dns.TypeAAAA, other, true, want{reason: ReasonRewrite}},
		{"keep6.example", dns.TypeAAAA, other, true, want{}},
		{"keep6.example", dns.TypeA, other, true, want{reason: ReasonRewrite, addrs: []string{"192.168.1.11"}}},
		{"www.alias.home", dns.TypeA, other, true, want{reason: ReasonRewrite, cnames: []string{"media.home"}, addrs: []string{"192.168.1.5"}}},
		{"www.alias.home", dns.TypeAAAA, other, true, want{reason: ReasonRewrite, cnames: []string{"media.home"}, addrs: []string{"fd00::5"}}},
		{"www.alias.home", dns.TypeHTTPS, other, true, want{reason: ReasonRewrite, cnames: []string{"media.home"}}},
		{"cdn.alias.home", dns.TypeA, other, true, want{reason: ReasonRewrite, cnames: []string{"cdn.example.net"}, resolve: "cdn.example.net"}},
		{"off.example", dns.TypeA, other, true, want{}},
		{"blocked.example", dns.TypeA, other, true, want{reason: ReasonRewrite, addrs: []string{"192.168.1.13"}}},
		{"media.home", dns.TypeA, other, false, want{reason: ReasonRewrite, addrs: []string{"192.168.1.5"}}},
		{"rule.example", dns.TypeA, other, false, want{}}, // rules are filtering: off with protection
		{"rule.example", dns.TypeA, other, true, want{reason: ReasonDNSRewrite, addrs: []string{"10.1.1.1"}}},
		{"rule.example", dns.TypeAAAA, other, true, want{reason: ReasonDNSRewrite, addrs: []string{"fd00::1"}}},
		{"nx.example", dns.TypeA, other, true, want{reason: ReasonDNSRewrite, rcode: dns.RcodeNameError}},
		{"alias.example", dns.TypeA, other, true, want{reason: ReasonDNSRewrite, cnames: []string{"target.example"}, resolve: "target.example"}},
		{"kid.example", dns.TypeA, kid, true, want{reason: ReasonDNSRewrite, addrs: []string{"10.2.2.2"}}},
		{"kid.example", dns.TypeA, other, true, want{}},
		{"hosts.example", dns.TypeA, other, true, want{reason: ReasonDNSRewrite, addrs: []string{"10.3.3.3"}}},
		{"hosts.example", dns.TypeAAAA, other, true, want{reason: ReasonDNSRewrite}},
	} {
		f := rewriteFilter(t, tc.protection)
		name := tc.host + "/" + dns.TypeToString[tc.qtype]
		res := f.Check(Request{Host: tc.host, QType: tc.qtype, ClientIP: tc.client}, time.Now())
		if tc.want.reason == "" {
			if res.Action == Rewrite {
				t.Errorf("%s: rewritten by %q (%+v)", name, res.Rule, res.Rewrite)
			}
			continue
		}
		if res.Action != Rewrite || res.Reason != tc.want.reason || res.Rewrite == nil {
			t.Errorf("%s: got %v/%q, want rewrite/%q", name, res.Action, res.Reason, tc.want.reason)
			continue
		}
		rw := res.Rewrite
		var addrs []string
		for _, a := range rw.Addrs {
			addrs = append(addrs, a.String())
		}
		if !slices.Equal(addrs, tc.want.addrs) || !slices.Equal(rw.CNAMEs, tc.want.cnames) ||
			rw.Resolve != tc.want.resolve || rw.RCode != tc.want.rcode {
			t.Errorf("%s: got %+v, want %+v", name, *rw, tc.want)
		}
		if res.Rule == "" {
			t.Errorf("%s: no rule text", name)
		}
	}
}

func TestRewriteLoopStops(t *testing.T) {
	res := rewriteFilter(t, true).Check(Request{Host: "loop1.example", QType: dns.TypeA}, time.Now())
	if res.Rewrite == nil || len(res.Rewrite.CNAMEs) != maxCNAMEChain || res.Rewrite.Resolve == "" {
		t.Fatalf("loop: %+v", res.Rewrite)
	}
}

// A $dnsrewrite rule matched on a CNAME target must not block it.
func TestDNSRewriteRuleIsNotABlock(t *testing.T) {
	res := rewriteFilter(t, true).CheckCNAME(Request{Host: "rule.example", QType: dns.TypeA}, time.Now())
	if res.Action != Pass {
		t.Errorf("CNAME target with a $dnsrewrite rule: %v %q", res.Action, res.Reason)
	}
}
