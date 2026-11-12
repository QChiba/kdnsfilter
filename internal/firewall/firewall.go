// Package firewall installs the NFQUEUE rules that hand DNS replies leaving
// the router to the filter, and the rules that route the sets of routing
// lists. NFQUEUE rules are appended to mangle POSTROUTING so no other mangle
// rule is skipped when the filter accepts a packet, and use --queue-bypass so
// DNS keeps working if the filter isn't running.
package firewall

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/QChiba/kdnsfilter/internal/config"
)

type Rule struct {
	Family string // "iptables" or "ip6tables"
	Chain  string // mangle chain the rule is appended to
	Spec   []string
}

func (r Rule) String() string {
	return r.Family + " -t mangle -A " + r.Chain + " " + strings.Join(r.Spec, " ")
}

// Rules returns one rule per family, or one per destination when
// destinations are given.
func Rules(queue uint16, dests []netip.Prefix) []Rule {
	base := func(dst string) []string {
		s := []string{"-p", "udp", "--sport", "53", "!", "-o", "lo"}
		if dst != "" {
			s = append(s, "-d", dst)
		}
		return append(s, "-j", "NFQUEUE", "--queue-num", strconv.Itoa(int(queue)), "--queue-bypass")
	}
	if len(dests) == 0 {
		return []Rule{{"iptables", "POSTROUTING", base("")}, {"ip6tables", "POSTROUTING", base("")}}
	}
	var out []Rule
	for _, d := range dests {
		fam := "iptables"
		if d.Addr().Is6() && !d.Addr().Is4In6() {
			fam = "ip6tables"
		}
		out = append(out, Rule{fam, "POSTROUTING", base(d.String())})
	}
	return out
}

// RoutingRules jumps from PREROUTING (forwarded traffic) and OUTPUT (the
// router's own) to each list's chains for packets to its sets' members. The
// chains belong to whoever routes the traffic (e.g. a proxy's own netfilter hooks).
func RoutingRules(rt config.Routing) []Rule {
	if !rt.Enabled {
		return nil
	}
	var out []Rule
	for _, l := range rt.Lists {
		v4, v6 := l.SetNames()
		for _, hook := range []struct{ from, to string }{{"PREROUTING", l.Chain}, {"OUTPUT", l.OutputChain}} {
			if hook.to == "" {
				continue
			}
			out = append(out,
				Rule{"iptables", hook.from, []string{"-m", "set", "--match-set", v4, "dst", "-j", hook.to}},
				Rule{"ip6tables", hook.from, []string{"-m", "set", "--match-set", v6, "dst", "-j", hook.to}})
		}
	}
	return out
}

// Diff returns the rules of prev that next doesn't have.
func Diff(prev, next []Rule) []Rule {
	keep := map[string]bool{}
	for _, r := range next {
		keep[r.String()] = true
	}
	var out []Rule
	for _, r := range prev {
		if !keep[r.String()] {
			out = append(out, r)
		}
	}
	return out
}

// Ensure appends rules that aren't present yet. family limits the work to
// "iptables" or "ip6tables" (as passed by Keenetic netfilter.d hooks); empty
// means both.
func Ensure(rules []Rule, family string) error {
	var errs []error
	for _, r := range rules {
		if family != "" && r.Family != family {
			continue
		}
		if run(r.Family, "-C", r.Chain, r.Spec) == nil {
			continue
		}
		if err := run(r.Family, "-A", r.Chain, r.Spec); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r, err))
		}
	}
	return errors.Join(errs...)
}

// Remove deletes all copies of rules.
func Remove(rules []Rule) {
	for _, r := range rules {
		for i := 0; i < 10 && run(r.Family, "-D", r.Chain, r.Spec) == nil; i++ {
		}
	}
}

func run(family, op, chain string, spec []string) error {
	args := append([]string{"-w", "-t", "mangle", op, chain}, spec...)
	out, err := exec.Command(binary(family), args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// binary prefers the firmware's iptables over Entware's.
func binary(name string) string {
	for _, dir := range []string{"/usr/sbin/", "/sbin/", "/opt/sbin/"} {
		if _, err := os.Stat(dir + name); err == nil {
			return dir + name
		}
	}
	return name
}
