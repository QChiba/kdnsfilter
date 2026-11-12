package config

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rewrite is a DNS rewrite in AdGuard Home's shape. Domain is a name or a
// wildcard "*.example.com", which matches its subdomains (not example.com
// itself). Answer is an IP address, a domain name (answered as a CNAME), or
// "A" / "AAAA" to keep the upstream records of that type.
type Rewrite struct {
	Domain  string `yaml:"domain" json:"domain"`
	Answer  string `yaml:"answer" json:"answer"`
	Enabled bool   `yaml:"enabled" json:"enabled"`
}

// UnmarshalYAML treats a missing "enabled" as true, as older AdGuard Home
// configs have no such field.
func (r *Rewrite) UnmarshalYAML(n *yaml.Node) error {
	type plain Rewrite
	p := plain{Enabled: true}
	if err := n.Decode(&p); err != nil {
		return err
	}
	*r = Rewrite(p)
	return nil
}

// Rewrite answer kinds.
const (
	RewriteIP    = "ip"
	RewriteKeep  = "keep"
	RewriteCNAME = "cname"
)

var hostname = regexp.MustCompile(`^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)*[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?$`)

// IsHostname reports whether s is a lower-case domain name without the
// trailing dot.
func IsHostname(s string) bool {
	return len(s) <= 253 && hostname.MatchString(s)
}

// Normalize trims the rewrite, lower-cases names and drops trailing dots.
func (r *Rewrite) Normalize() {
	r.Domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.Domain)), ".")
	a := strings.TrimSpace(r.Answer)
	switch up := strings.ToUpper(a); {
	case up == "A" || up == "AAAA":
		r.Answer = up
	default:
		if ip, err := netip.ParseAddr(a); err == nil {
			r.Answer = ip.String()
		} else {
			r.Answer = strings.TrimSuffix(strings.ToLower(a), ".")
		}
	}
}

// Kind tells what the answer is: RewriteIP, RewriteKeep or RewriteCNAME.
func (r Rewrite) Kind() string {
	if r.Answer == "A" || r.Answer == "AAAA" {
		return RewriteKeep
	}
	if _, err := netip.ParseAddr(r.Answer); err == nil {
		return RewriteIP
	}
	return RewriteCNAME
}

func (r Rewrite) Validate() error {
	if !IsHostname(strings.TrimPrefix(r.Domain, "*.")) {
		return fmt.Errorf("rewrite %q: want a domain like example.com or *.example.com", r.Domain)
	}
	if r.Kind() == RewriteCNAME {
		if !IsHostname(r.Answer) {
			return fmt.Errorf("rewrite %s: answer %q: want an IP address, a domain name, A or AAAA", r.Domain, r.Answer)
		}
		if r.Answer == r.Domain {
			return fmt.Errorf("rewrite %s: points to itself", r.Domain)
		}
	}
	return nil
}

// ValidateRewrites checks each rewrite and that a domain answered with a
// CNAME has no other enabled answers (a CNAME can't coexist with records).
func ValidateRewrites(rws []Rewrite) error {
	var errs []error
	kinds := map[string]map[string]bool{}
	for _, r := range rws {
		if err := r.Validate(); err != nil {
			errs = append(errs, err)
			continue
		}
		if !r.Enabled {
			continue
		}
		if kinds[r.Domain] == nil {
			kinds[r.Domain] = map[string]bool{}
		}
		kinds[r.Domain][r.Kind()] = true
	}
	for d, k := range kinds {
		if k[RewriteCNAME] && len(k) > 1 {
			errs = append(errs, fmt.Errorf("rewrite %s: a domain name answer (CNAME) can't be combined with other answers", d))
		}
	}
	return errors.Join(errs...)
}
