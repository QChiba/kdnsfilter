package firewall

import (
	"net/netip"
	"testing"

	"github.com/QChiba/kdnsfilter/internal/config"
)

func TestRoutingRules(t *testing.T) {
	rt := config.Routing{Enabled: true, Lists: []config.RouteList{
		{Name: "bypass", Chain: "MY_PROXY", OutputChain: "MY_PROXY_OUT"},
		{Name: "unrouted"}, // sets only, routed by the user's own rules
	}}
	rules := RoutingRules(rt)
	want := []string{
		"iptables -t mangle -A PREROUTING -m set --match-set kdf_bypass4 dst -j MY_PROXY",
		"ip6tables -t mangle -A PREROUTING -m set --match-set kdf_bypass6 dst -j MY_PROXY",
		"iptables -t mangle -A OUTPUT -m set --match-set kdf_bypass4 dst -j MY_PROXY_OUT",
		"ip6tables -t mangle -A OUTPUT -m set --match-set kdf_bypass6 dst -j MY_PROXY_OUT",
	}
	if len(rules) != len(want) {
		t.Fatalf("%v", rules)
	}
	for i, w := range want {
		if rules[i].String() != w {
			t.Errorf("got  %s\nwant %s", rules[i], w)
		}
	}
	rt.Lists[0].OutputChain = ""
	if gone := Diff(rules, RoutingRules(rt)); len(gone) != 2 || gone[0].Chain != "OUTPUT" {
		t.Errorf("diff %v", gone)
	}
	rt.Enabled = false
	if RoutingRules(rt) != nil {
		t.Error("rules while disabled")
	}
}

func TestRules(t *testing.T) {
	all := Rules(4242, nil)
	if len(all) != 2 || all[0].Family != "iptables" || all[1].Family != "ip6tables" {
		t.Fatalf("%v", all)
	}
	want := "iptables -t mangle -A POSTROUTING -p udp --sport 53 ! -o lo -j NFQUEUE --queue-num 4242 --queue-bypass"
	if all[0].String() != want {
		t.Errorf("got  %s\nwant %s", all[0], want)
	}

	scoped := Rules(7, []netip.Prefix{netip.MustParsePrefix("192.168.1.10/32"), netip.MustParsePrefix("fd12::/64")})
	if len(scoped) != 2 || scoped[1].Family != "ip6tables" || scoped[1].Spec[7] != "-d" || scoped[1].Spec[8] != "fd12::/64" {
		t.Errorf("%v", scoped)
	}
}
