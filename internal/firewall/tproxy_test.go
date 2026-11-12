package firewall

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/QChiba/kdnsfilter/internal/config"
)

// fakeKernel records commands and emulates the parts of iptables/ip that
// ApplyRouting inspects: chains (-S, -C) and ip rules.
type fakeKernel struct {
	cmds   []string
	chains map[string][]string // "iptables KDF_..." -> rule specs
	jumps  map[string]bool     // "iptables PREROUTING spec"
	rules  map[string]bool     // "-4 fwmark 0x2dd lookup 733"
}

func withFakeKernel(t *testing.T) *fakeKernel {
	t.Helper()
	k := &fakeKernel{chains: map[string][]string{}, jumps: map[string]bool{}, rules: map[string]bool{}}
	oldRun, oldRead, oldStat := runCmd, readTextFile, statModule
	readTextFile = func(path string) (string, error) {
		switch path {
		case procModules:
			return "xt_socket 16384 0 - Live 0x0\n", nil
		case osRelease:
			return "4.9-ndm-5\n", nil
		}
		return "", errors.New("no such file")
	}
	statModule = func(string) error { return nil }
	runCmd = func(name string, args ...string) ([]byte, error) {
		base := name[strings.LastIndex(name, "/")+1:]
		k.cmds = append(k.cmds, base+" "+strings.Join(args, " "))
		switch base {
		case "iptables", "ip6tables":
			if len(args) == 4 && args[3] == "-S" { // the whole mangle table
				var out string
				for key := range k.chains {
					if fam, name, _ := strings.Cut(key, " "); fam == base {
						out += "-N " + name + "\n"
					}
				}
				for key := range k.jumps {
					if fam, rule, _ := strings.Cut(key, " "); fam == base {
						out += "-A " + rule + "\n"
					}
				}
				return []byte(out), nil
			}
			op, chain, spec := args[3], args[4], strings.Join(args[5:], " ")
			key := base + " " + chain
			switch {
			case strings.HasPrefix(chain, "KDF_"):
				rules, exists := k.chains[key]
				switch op {
				case "-N":
					if exists {
						return []byte("Chain already exists."), errors.New("exit 1")
					}
					k.chains[key] = nil
				case "-F":
					if !exists {
						return nil, errors.New("no chain")
					}
					k.chains[key] = nil
				case "-X":
					delete(k.chains, key)
				case "-A":
					k.chains[key] = append(rules, spec)
				case "-C":
					if !slices.Contains(rules, spec) {
						return nil, errors.New("no rule")
					}
				case "-S":
					if !exists {
						return nil, errors.New("no chain")
					}
					out := "-N " + chain + "\n"
					for _, r := range rules {
						out += "-A " + chain + " " + r + "\n"
					}
					return []byte(out), nil
				}
			default:
				jk := key + " " + spec
				switch op {
				case "-C":
					if !k.jumps[jk] {
						return nil, errors.New("no rule")
					}
				case "-A":
					k.jumps[jk] = true
				case "-D":
					if !k.jumps[jk] {
						return nil, errors.New("no rule")
					}
					delete(k.jumps, jk)
				}
			}
		case "ip":
			f := args[0]
			switch strings.Join(args[1:3], " ") {
			case "rule show":
				var out string
				for r := range k.rules {
					if strings.HasPrefix(r, f+" ") {
						out += "733:\tfrom all " + strings.TrimPrefix(r, f+" ") + "\n"
					}
				}
				return []byte(out), nil
			case "rule add":
				k.rules[f+" fwmark "+args[4]+" lookup "+args[6]] = true
			case "rule del":
				r := f + " fwmark " + args[4] + " lookup " + args[6]
				if !k.rules[r] {
					return nil, errors.New("no such rule")
				}
				delete(k.rules, r)
			}
		}
		return nil, nil
	}
	t.Cleanup(func() { runCmd, readTextFile, statModule = oldRun, oldRead, oldStat })
	return k
}

func (k *fakeKernel) ran(prefix string) int {
	n := 0
	for _, c := range k.cmds {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func tproxyRouting(port uint16, router bool) config.Routing {
	rt := config.Default().Routing
	rt.Enabled = true
	rt.TProxy.Router, rt.TProxy.ProxyGroup = router, "proxy"
	rt.Lists = []config.RouteList{{Name: "bypass", TProxyPort: port}, {Name: "own", Chain: "MY_PROXY"}}
	return rt
}

func TestTProxyRules(t *testing.T) {
	rt := tproxyRouting(12345, false)
	jumps := RoutingRules(rt)
	want := []string{
		"iptables -t mangle -A PREROUTING -m set --match-set kdf_bypass4 dst -j KDF_TPROXY_12345",
		"ip6tables -t mangle -A PREROUTING -m set --match-set kdf_bypass6 dst -j KDF_TPROXY_12345",
		"iptables -t mangle -A PREROUTING -m set --match-set kdf_own4 dst -j MY_PROXY",
		"ip6tables -t mangle -A PREROUTING -m set --match-set kdf_own6 dst -j MY_PROXY",
	}
	if len(jumps) != len(want) {
		t.Fatalf("%v", jumps)
	}
	for i, w := range want {
		if jumps[i].String() != w {
			t.Errorf("got  %s\nwant %s", jumps[i], w)
		}
	}
	chains := TProxyChains(rt)
	if len(chains) != 2 || chains[0].Name != "KDF_TPROXY_12345" || chains[1].Family != "ip6tables" {
		t.Fatalf("%+v", chains)
	}
	if got := strings.Join(chains[0].Rules[3], " "); got != "-p tcp -j TPROXY --on-port 12345 --on-ip 127.0.0.1 --tproxy-mark 0x2dd" {
		t.Errorf("v4 tproxy %s", got)
	}
	if got := strings.Join(chains[1].Rules[4], " "); got != "-p udp -j TPROXY --on-port 12345 --on-ip ::1 --tproxy-mark 0x2dd" {
		t.Errorf("v6 tproxy %s", got)
	}

	// The router's own traffic: OUTPUT marks it unless the proxy sent it.
	rt = tproxyRouting(1080, true)
	rt.TProxy.ProxyMark = 0xff
	chains = TProxyChains(rt)
	if len(chains) != 4 || chains[1].Name != "KDF_TPROXY_OUT_1080" {
		t.Fatalf("%+v", chains)
	}
	out := chains[1].Rules
	if strings.Join(out[0], " ") != "-m owner --gid-owner proxy -j RETURN" || strings.Join(out[1], " ") != "-m mark --mark 0xff -j RETURN" ||
		strings.Join(out[2], " ") != "-p tcp -j MARK --set-mark 0x2dd" {
		t.Errorf("output chain %v", out)
	}
	if j := RoutingRules(rt); len(j) != 6 || j[2].String() != "iptables -t mangle -A OUTPUT -m set --match-set kdf_bypass4 dst -j KDF_TPROXY_OUT_1080" {
		t.Errorf("jumps %v", j)
	}
	if r := PolicyRoutes(rt); len(r) != 2 || r[0] != (PolicyRoute{"iptables", 0x2dd, 733}) {
		t.Errorf("routes %v", r)
	}
	rt.Enabled = false
	if TProxyChains(rt) != nil || PolicyRoutes(rt) != nil {
		t.Error("tproxy while routing is disabled")
	}
}

func TestApplyRouting(t *testing.T) {
	k := withFakeKernel(t)
	rt := tproxyRouting(12345, false)
	if err := ApplyRouting(config.Routing{}, rt, ""); err != nil {
		t.Fatal(err)
	}
	if k.ran("insmod /lib/modules/4.9-ndm-5/xt_TPROXY.ko") != 1 || k.ran("insmod /lib/modules/4.9-ndm-5/xt_socket.ko") != 0 {
		t.Errorf("modules: %v", k.cmds)
	}
	if !k.rules["-4 fwmark 0x2dd lookup 733"] || !k.rules["-6 fwmark 0x2dd lookup 733"] ||
		k.ran("ip -4 route replace local default dev lo table 733") != 1 {
		t.Errorf("ip rules %v", k.rules)
	}
	if len(k.chains["iptables KDF_TPROXY_12345"]) != 5 || len(k.chains["ip6tables KDF_TPROXY_12345"]) != 5 || len(k.jumps) != 4 {
		t.Fatalf("chains %v jumps %v", k.chains, k.jumps)
	}

	// An ndm hook run for one family with everything in place changes nothing.
	k.cmds = nil
	if err := ApplyRouting(config.Routing{}, rt, "iptables"); err != nil {
		t.Fatal(err)
	}
	if k.ran("iptables -w -t mangle -A") != 0 || k.ran("iptables -w -t mangle -F") != 0 || k.ran("ip6tables") != 0 || k.ran("ip -4 rule add") != 0 {
		t.Errorf("idempotent run changed things: %v", k.cmds)
	}

	// A rule lost from the chain gets it rebuilt.
	k.chains["iptables KDF_TPROXY_12345"] = k.chains["iptables KDF_TPROXY_12345"][1:]
	ApplyRouting(config.Routing{}, rt, "iptables")
	if len(k.chains["iptables KDF_TPROXY_12345"]) != 5 {
		t.Errorf("chain not rebuilt: %v", k.chains)
	}

	// Moving to another port replaces the chains and jumps, keeps the ip rules.
	next := tproxyRouting(7890, false)
	if err := ApplyRouting(rt, next, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := k.chains["iptables KDF_TPROXY_12345"]; ok || len(k.chains["iptables KDF_TPROXY_7890"]) != 5 {
		t.Errorf("chains %v", k.chains)
	}
	if !k.jumps["iptables PREROUTING -m set --match-set kdf_bypass4 dst -j KDF_TPROXY_7890"] || len(k.jumps) != 4 {
		t.Errorf("jumps %v", k.jumps)
	}
	if len(k.rules) != 2 || k.ran("ip -4 route flush") != 0 {
		t.Errorf("ip rules %v", k.rules)
	}

	// The port was changed in the YAML while kdnsfilter was stopped: the
	// next start (prev unknown) drops the old port's jumps and chains.
	if err := ApplyRouting(config.Routing{}, tproxyRouting(9000, false), ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := k.chains["iptables KDF_TPROXY_7890"]; ok || len(k.chains["ip6tables KDF_TPROXY_9000"]) != 5 || len(k.jumps) != 4 ||
		k.jumps["iptables PREROUTING -m set --match-set kdf_bypass4 dst -j KDF_TPROXY_7890"] {
		t.Errorf("stale port kept: %v %v", k.chains, k.jumps)
	}
	next = tproxyRouting(9000, false)

	// Uninstall removes everything kdnsfilter added.
	if err := ApplyRouting(next, config.Routing{}, ""); err != nil {
		t.Fatal(err)
	}
	if len(k.chains) != 0 || len(k.jumps) != 0 || len(k.rules) != 0 || k.ran("ip -6 route flush table 733") != 1 {
		t.Errorf("left behind: %v %v %v", k.chains, k.jumps, k.rules)
	}
}
