package config

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Routing puts the addresses that listed domains resolve to into ipsets,
// which the router's firewall routes (e.g. through a VPN). Addresses are added
// before the DNS reply reaches the client, so its first connection already
// takes the route.
type Routing struct {
	Enabled bool `yaml:"enabled"`
	// MinTimeout is the shortest time an address stays in a set; every
	// answer for it refreshes it (to its TTL if that is longer).
	MinTimeout Duration    `yaml:"min_timeout"`
	Lists      []RouteList `yaml:"lists"`
}

// RouteList is one named domain list and the ipsets it fills.
type RouteList struct {
	Name string `yaml:"name" json:"name"`
	// Set4/Set6 are the ipset names; empty means kdf_<name>4 / kdf_<name>6.
	Set4 string `yaml:"set4,omitempty" json:"set4"`
	Set6 string `yaml:"set6,omitempty" json:"set6"`
	// Chain is a mangle chain that PREROUTING jumps to for packets to a
	// set's members (e.g. one that TPROXYs them to a proxy); OutputChain is the
	// same for the router's own traffic (OUTPUT). Empty: no rule, route the
	// sets yourself.
	Chain       string `yaml:"chain,omitempty" json:"chain"`
	OutputChain string `yaml:"output_chain,omitempty" json:"output_chain"`
	// Domains match themselves and all their subdomains, like Keenetic's
	// domain lists; "!sub.example.com" excludes a subtree.
	Domains []string `yaml:"domains" json:"domains"`
}

// Limits for Routing.MinTimeout (the kernel caps ipset timeouts at ~24 days).
const (
	MinRouteTimeout = time.Minute
	MaxRouteTimeout = 7 * 24 * time.Hour
)

const DefaultRouteTimeout = 3 * time.Hour

var (
	listNameRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,23}$`)
	setNameRe   = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,31}$`)
	chainNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,28}$`)
)

// SetNames returns the list's ipset names, defaults applied.
func (l RouteList) SetNames() (v4, v6 string) {
	v4, v6 = l.Set4, l.Set6
	if v4 == "" {
		v4 = "kdf_" + l.Name + "4"
	}
	if v6 == "" {
		v6 = "kdf_" + l.Name + "6"
	}
	return v4, v6
}

// NormalizeDomain lower-cases a list entry and strips "*." and dots
// ("*.example.com" and ".example.com" mean example.com and its subdomains
// anyway). The "!" exception prefix is kept.
func NormalizeDomain(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	neg := strings.HasPrefix(s, "!")
	s = strings.TrimSpace(strings.TrimPrefix(s, "!"))
	s = strings.TrimPrefix(s, "*")
	s = strings.Trim(s, ".")
	if neg {
		return "!" + s
	}
	return s
}

// Normalize cleans the domains: normalized, no blanks or comments, no
// duplicates, sorted by name ("!name" right after name).
func (l *RouteList) Normalize() {
	seen := map[string]bool{}
	var out []string
	for _, d := range l.Domains {
		if t := strings.TrimSpace(d); t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		d = NormalizeDomain(d)
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	slices.SortFunc(out, func(a, b string) int {
		an, aExcept := strings.CutPrefix(a, "!")
		bn, bExcept := strings.CutPrefix(b, "!")
		if c := strings.Compare(an, bn); c != 0 {
			return c
		}
		switch {
		case aExcept == bExcept:
			return 0
		case aExcept:
			return 1
		}
		return -1
	})
	l.Domains = out
}

func (r *Routing) Validate() error {
	var errs []error
	if d := time.Duration(r.MinTimeout); d < MinRouteTimeout || d > MaxRouteTimeout {
		errs = append(errs, fmt.Errorf("routing.min_timeout %s: want 1m up to 7d", r.MinTimeout))
	}
	names, sets := map[string]bool{}, map[string]bool{}
	for _, l := range r.Lists {
		if !listNameRe.MatchString(l.Name) {
			errs = append(errs, fmt.Errorf("routing list %q: name must be 1-24 of a-z, 0-9, _ and -", l.Name))
			continue
		}
		if names[l.Name] {
			errs = append(errs, fmt.Errorf("routing list %q: duplicate name", l.Name))
		}
		names[l.Name] = true
		v4, v6 := l.SetNames()
		for _, s := range []string{v4, v6} {
			if !setNameRe.MatchString(s) {
				errs = append(errs, fmt.Errorf("routing list %q: bad ipset name %q", l.Name, s))
			} else if sets[s] {
				errs = append(errs, fmt.Errorf("routing list %q: ipset %q is used twice", l.Name, s))
			}
			sets[s] = true
		}
		for _, c := range []string{l.Chain, l.OutputChain} {
			if c != "" && !chainNameRe.MatchString(c) {
				errs = append(errs, fmt.Errorf("routing list %q: bad chain name %q", l.Name, c))
			}
		}
		for _, d := range l.Domains {
			if !IsHostname(strings.TrimPrefix(d, "!")) {
				errs = append(errs, fmt.Errorf("routing list %q: %q is not a domain name", l.Name, d))
			}
		}
	}
	return errors.Join(errs...)
}
