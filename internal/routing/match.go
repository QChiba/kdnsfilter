// Package routing fills ipsets with the addresses of listed domains as their
// DNS replies pass through, so the firewall can route them (e.g. through a
// VPN) from the client's first connection.
package routing

import (
	"strings"

	"github.com/QChiba/kdnsfilter/internal/config"
)

// Matcher maps a name to the routing list of its most specific listed
// suffix. Lists are matched like Keenetic's domain lists: an entry covers the
// name and all its subdomains; "!name" entries exclude a subtree.
type Matcher struct {
	byName map[string]rule
}

type rule struct {
	list   int // index into the lists
	except bool
}

// NewMatcher compiles normalized lists; for a domain listed more than once
// the first list wins.
func NewMatcher(lists []config.RouteList) *Matcher {
	m := &Matcher{byName: map[string]rule{}}
	for i, l := range lists {
		for _, d := range l.Domains {
			name, except := strings.CutPrefix(d, "!")
			if _, dup := m.byName[name]; !dup && name != "" {
				m.byName[name] = rule{list: i, except: except}
			}
		}
	}
	return m
}

// Match returns the list index for host (lower case, no trailing dot); ok
// is false if the host isn't routed.
func (m *Matcher) Match(host string) (list int, ok bool) {
	list, _, ok, _ = m.Lookup(host)
	return list, ok
}

// Lookup is Match that also returns the list entry that decided and whether
// that entry is a "!" exception (excluded), as opposed to no entry at all.
func (m *Matcher) Lookup(host string) (list int, entry string, ok, excluded bool) {
	if m == nil || len(m.byName) == 0 {
		return 0, "", false, false
	}
	for name := host; ; {
		if r, found := m.byName[name]; found {
			if r.except {
				return 0, "!" + name, false, true
			}
			return r.list, name, true, false
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return 0, "", false, false
		}
		name = name[i+1:]
	}
}
