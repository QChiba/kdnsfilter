package firewall

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/QChiba/kdnsfilter/internal/config"
)

// TPROXY routing for lists with a tproxy_port, built the way transparent
// proxies are usually wired up on Keenetic:
//
//	PREROUTING -m set --match-set <set> dst -j KDF_TPROXY_<port>
//	  packets of connections the proxy already holds: mark, deliver locally
//	  new TCP/UDP: TPROXY --on-port <port> --tproxy-mark <mark>
//	OUTPUT -m set --match-set <set> dst -j KDF_TPROXY_OUT_<port> (tproxy.router)
//	  the proxy's own packets (proxy_group / proxy_mark): untouched
//	  others: mark, so they are rerouted via lo into PREROUTING above
//	ip rule fwmark <mark> lookup main suppress_prefixlength 0 (priority table-1)
//	ip rule fwmark <mark> lookup <table>; table <table>: local default dev lo
//
// The first rule matters because KeeneticOS sets tcp_fwmark_accept: the
// proxy's accepted sockets inherit the mark, so its replies to LAN devices
// carry it too and must still leave by the main table's LAN routes; only
// what main would send to the default route is delivered locally.
//
// kdnsfilter owns these chains: it rebuilds them when their rules differ
// and deletes them when no list uses the port any more.

// Chain is a mangle chain kdnsfilter owns.
type Chain struct {
	Family string // "iptables" or "ip6tables"
	Name   string
	Rules  [][]string
}

// PolicyRoute makes packets with Mark use table Table, which delivers them
// to the local host — how TPROXY'd packets reach the proxy's socket.
type PolicyRoute struct {
	Family      string // "iptables" or "ip6tables", as in hook calls
	Mark, Table uint32
}

// Kernel modules the rules need; KeeneticOS ships them but loads them only
// on demand. Built-in ones have no .ko and are skipped.
var (
	QueueModules  = []string{"nfnetlink_queue", "xt_NFQUEUE"}
	TProxyModules = []string{"xt_socket", "xt_TPROXY"}
)

var families = []string{"iptables", "ip6tables"}

// TProxyChainNames returns the chains for a TPROXY port.
func TProxyChainNames(port uint16) (pre, out string) {
	return fmt.Sprintf("KDF_TPROXY_%d", port), fmt.Sprintf("KDF_TPROXY_OUT_%d", port)
}

// tproxyPorts returns the ports routed lists use, sorted.
func tproxyPorts(rt config.Routing) []uint16 {
	if !rt.Enabled {
		return nil
	}
	var ports []uint16
	for _, l := range rt.Lists {
		if l.TProxyPort != 0 && !slices.Contains(ports, l.TProxyPort) {
			ports = append(ports, l.TProxyPort)
		}
	}
	slices.Sort(ports)
	return ports
}

func hex(v uint32) string { return fmt.Sprintf("0x%x", v) }

// TProxyChains returns the chains the config's TPROXY ports need.
func TProxyChains(rt config.Routing) []Chain {
	var out []Chain
	t := rt.TProxy
	mark := hex(t.Mark)
	for _, fam := range families {
		local := "127.0.0.1"
		if fam == "ip6tables" {
			local = "::1"
		}
		for _, p := range tproxyPorts(rt) {
			pre, post := TProxyChainNames(p)
			port := strconv.Itoa(int(p))
			out = append(out, Chain{fam, pre, [][]string{
				{"-p", "tcp", "-m", "socket", "--transparent", "-j", "MARK", "--set-mark", mark},
				{"-p", "udp", "-m", "socket", "--transparent", "-j", "MARK", "--set-mark", mark},
				{"-m", "socket", "-j", "RETURN"},
				{"-p", "tcp", "-j", "TPROXY", "--on-port", port, "--on-ip", local, "--tproxy-mark", mark},
				{"-p", "udp", "-j", "TPROXY", "--on-port", port, "--on-ip", local, "--tproxy-mark", mark},
			}})
			if !t.Router {
				continue
			}
			var rules [][]string
			if t.ProxyGroup != "" {
				rules = append(rules, []string{"-m", "owner", "--gid-owner", t.ProxyGroup, "-j", "RETURN"})
			}
			if t.ProxyMark != 0 {
				rules = append(rules, []string{"-m", "mark", "--mark", hex(t.ProxyMark), "-j", "RETURN"})
			}
			rules = append(rules,
				[]string{"-p", "tcp", "-j", "MARK", "--set-mark", mark},
				[]string{"-p", "udp", "-j", "MARK", "--set-mark", mark})
			out = append(out, Chain{fam, post, rules})
		}
	}
	return out
}

// PolicyRoutes returns the ip rules and tables TPROXY needs.
func PolicyRoutes(rt config.Routing) []PolicyRoute {
	if len(tproxyPorts(rt)) == 0 {
		return nil
	}
	var out []PolicyRoute
	for _, fam := range families {
		out = append(out, PolicyRoute{fam, rt.TProxy.Mark, rt.TProxy.Table})
	}
	return out
}

// ApplyRouting moves the firewall from the routing config prev to next:
// next's routes, chains and jumps are ensured, then what only prev had is
// removed. prev may be the zero Routing (start, ndm hooks) and next too
// (uninstall). family limits the work to one family; empty means both.
func ApplyRouting(prev, next config.Routing, family string) error {
	var errs []error
	if len(tproxyPorts(next)) > 0 {
		errs = append(errs, LoadModules(TProxyModules...))
	}
	routes, chains := PolicyRoutes(next), TProxyChains(next)
	for _, r := range routes {
		if family == "" || r.Family == family {
			errs = append(errs, ensureRoute(r))
		}
	}
	for _, c := range chains {
		if family == "" || c.Family == family {
			errs = append(errs, ensureChain(c))
		}
	}
	jumps := RoutingRules(next)
	Remove(only(Diff(RoutingRules(prev), jumps), family))
	errs = append(errs, Ensure(jumps, family))

	for _, c := range TProxyChains(prev) {
		kept := slices.ContainsFunc(chains, func(n Chain) bool { return n.Family == c.Family && n.Name == c.Name })
		if !kept && (family == "" || c.Family == family) {
			removeChain(c)
		}
	}
	for _, r := range PolicyRoutes(prev) {
		if (family == "" || r.Family == family) && !slices.Contains(routes, r) {
			tableUsed := slices.ContainsFunc(routes, func(n PolicyRoute) bool { return n.Family == r.Family && n.Table == r.Table })
			removeRoute(r, !tableUsed)
		}
	}
	pruneTProxy(jumps, chains, family)
	return errors.Join(errs...)
}

// pruneTProxy removes TPROXY jumps and chains other than the given ones:
// leftovers of a config edited while kdnsfilter was stopped, which would
// otherwise keep sending a set to the old port.
func pruneTProxy(jumps []Rule, chains []Chain, family string) {
	want := map[string]bool{}
	for _, r := range jumps {
		want[r.Family+" "+r.Chain+" "+strings.Join(r.Spec, " ")] = true
	}
	for _, fam := range families {
		if family != "" && fam != family {
			continue
		}
		out, err := command(fam, "-w", "-t", "mangle", "-S")
		if err != nil {
			continue
		}
		var stale []string
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			switch {
			case len(f) > 4 && f[0] == "-A" && (f[1] == "PREROUTING" || f[1] == "OUTPUT") &&
				f[len(f)-2] == "-j" && strings.HasPrefix(f[len(f)-1], "KDF_TPROXY_"):
				if !want[fam+" "+f[1]+" "+strings.Join(f[2:], " ")] {
					run(fam, "-D", f[1], f[2:])
				}
			case len(f) == 2 && f[0] == "-N" && strings.HasPrefix(f[1], "KDF_TPROXY_"):
				if !slices.ContainsFunc(chains, func(c Chain) bool { return c.Family == fam && c.Name == f[1] }) {
					stale = append(stale, f[1])
				}
			}
		}
		for _, name := range stale {
			removeChain(Chain{Family: fam, Name: name})
		}
	}
}

// ensureChain creates or rebuilds c unless it already holds exactly its
// rules (ndm hooks call this on every firewall rebuild).
func ensureChain(c Chain) error {
	if chainMatches(c) {
		return nil
	}
	run(c.Family, "-N", c.Name, nil) // fails if it exists, which is fine
	if err := run(c.Family, "-F", c.Name, nil); err != nil {
		return fmt.Errorf("%s chain %s: %w", c.Family, c.Name, err)
	}
	for _, r := range c.Rules {
		if err := run(c.Family, "-A", c.Name, r); err != nil {
			return fmt.Errorf("%s: %w", Rule{c.Family, c.Name, r}, err)
		}
	}
	return nil
}

func chainMatches(c Chain) bool {
	out, err := command(c.Family, "-w", "-t", "mangle", "-S", c.Name)
	if err != nil {
		return false
	}
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "-A ") {
			n++
		}
	}
	if n != len(c.Rules) {
		return false
	}
	for _, r := range c.Rules {
		if run(c.Family, "-C", c.Name, r) != nil {
			return false
		}
	}
	return true
}

func removeChain(c Chain) {
	if run(c.Family, "-F", c.Name, nil) == nil {
		run(c.Family, "-X", c.Name, nil)
	}
}

func ipFamily(family string) string {
	if family == "ip6tables" {
		return "-6"
	}
	return "-4"
}

// ipRules returns the ip rules of r with their priorities.
func ipRules(r PolicyRoute) []struct {
	spec []string
	prio string
} {
	table := strconv.FormatUint(uint64(r.Table), 10)
	return []struct {
		spec []string
		prio string
	}{
		{[]string{"fwmark", hex(r.Mark), "lookup", "main", "suppress_prefixlength", "0"}, strconv.FormatUint(uint64(r.Table-1), 10)},
		{[]string{"fwmark", hex(r.Mark), "lookup", table}, table},
	}
}

func ensureRoute(r PolicyRoute) error {
	f, table := ipFamily(r.Family), strconv.FormatUint(uint64(r.Table), 10)
	rules, err := command("ip", f, "rule", "show")
	if err != nil {
		return fmt.Errorf("ip rule: %w", err)
	}
	for _, rule := range ipRules(r) {
		if strings.Contains(rules, strings.Join(rule.spec, " ")+" \n") || strings.Contains(rules, strings.Join(rule.spec, " ")+"\n") {
			continue
		}
		args := append(append([]string{f, "rule", "add"}, rule.spec...), "priority", rule.prio)
		if _, err := command("ip", args...); err != nil {
			return fmt.Errorf("ip %s rule add: %w", f, err)
		}
	}
	if _, err := command("ip", f, "route", "replace", "local", "default", "dev", "lo", "table", table); err != nil {
		return fmt.Errorf("ip %s route table %s: %w", f, table, err)
	}
	return nil
}

func removeRoute(r PolicyRoute, flushTable bool) {
	f, table := ipFamily(r.Family), strconv.FormatUint(uint64(r.Table), 10)
	for _, rule := range ipRules(r) {
		for i := 0; i < 10; i++ {
			if _, err := command("ip", append(append([]string{f, "rule", "del"}, rule.spec...), "priority", rule.prio)...); err != nil {
				break
			}
		}
	}
	if flushTable {
		command("ip", f, "route", "flush", "table", table)
	}
}

// Paths read by LoadModules; tests point them elsewhere.
var (
	procModules  = "/proc/modules"
	osRelease    = "/proc/sys/kernel/osrelease"
	modulesDir   = "/lib/modules"
	statModule   = func(path string) error { _, err := os.Stat(path); return err }
	readTextFile = func(path string) (string, error) { b, err := os.ReadFile(path); return string(b), err }
)

// LoadModules insmods the named modules that aren't loaded yet and exist
// as /lib/modules/<release>/<name>.ko (others are built in, or the
// firmware lacks them and the rules that need them will fail).
func LoadModules(names ...string) error {
	mods, err := readTextFile(procModules)
	if err != nil {
		return nil // not Linux, or no module support
	}
	loaded := map[string]bool{}
	for _, line := range strings.Split(mods, "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			loaded[f[0]] = true
		}
	}
	rel, err := readTextFile(osRelease)
	if err != nil {
		return err
	}
	var errs []error
	for _, name := range names {
		path := modulesDir + "/" + strings.TrimSpace(rel) + "/" + name + ".ko"
		if loaded[name] || statModule(path) != nil {
			continue
		}
		if _, err := command("insmod", path); err != nil {
			errs = append(errs, fmt.Errorf("insmod %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}
