package routing

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/QChiba/kdnsfilter/internal/config"
	"github.com/QChiba/kdnsfilter/internal/disk"
	"github.com/QChiba/kdnsfilter/internal/ipset"
)

// Backend is the kernel side: *ipset.Conn, or a fake in tests.
type Backend interface {
	Create(name string, v6 bool, timeout time.Duration, maxElem uint32) error
	Add(set string, addr netip.Addr, timeout time.Duration) error
	Del(set string, addr netip.Addr) error
}

// MaxElem is the capacity of each set (Keenetic's own sets stop at 16384).
const MaxElem = 65536

// maxNames bounds the names remembered per address (shared CDN addresses).
const maxNames = 4

// Router keeps the sets of every routing list in step with DNS answers. It
// remembers which names put each address in a set, so removing a domain
// removes its addresses right away instead of when they time out.
type Router struct {
	backend Backend // nil: routing unavailable (no netlink); answers are only matched
	path    string  // snapshot of the entries, for restoring the sets after a reboot

	mu      sync.Mutex
	enabled bool
	min     time.Duration
	lists   []*list
	match   *Matcher
	saved   map[string]*snapList // loaded snapshot, adopted by the first Configure
	errMsg  string
	errAt   time.Time
}

type list struct {
	cfg        config.RouteList
	set4, set6 string
	entries    map[netip.Addr]*entry
	// fullUntil: the set is at maxelem; retrying the add on every answer
	// would cost a netlink round trip per reply, so put() backs off until
	// this (entries expire and make room on their own).
	fullUntil time.Time
}

type entry struct {
	Names   []string  `json:"names"` // routed names whose answers added it, newest last
	Expires time.Time `json:"expires"`
}

// ListStatus describes one list for the UI.
type ListStatus struct {
	config.RouteList
	Count4 int `json:"count4"`
	Count6 int `json:"count6"`
}

// New creates a router; backend may be nil. Entries saved at path are
// restored to the sets by the first Configure.
func New(backend Backend, path string) *Router {
	r := &Router{backend: backend, path: path}
	r.load()
	return r
}

// Configure applies the routing config: creates missing sets, carries over
// the entries of unchanged lists and deletes the addresses of names that are
// no longer routed. It returns the domains added to each list (by list
// name), for Prefill.
func (r *Router) Configure(cfg config.Routing, now time.Time) map[string][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.min = time.Duration(cfg.MinTimeout)
	if r.min <= 0 {
		r.min = config.DefaultRouteTimeout
	}
	old := map[string]*list{}
	for _, l := range r.lists {
		old[l.cfg.Name] = l
	}
	added := map[string][]string{}
	var next []*list
	if cfg.Enabled {
		for _, c := range cfg.Lists {
			v4, v6 := c.SetNames()
			l := &list{cfg: c, set4: v4, set6: v6, entries: map[netip.Addr]*entry{}}
			r.createSets(l)
			if o := old[c.Name]; o != nil && o.set4 == v4 && o.set6 == v6 {
				l.entries = o.entries
				delete(old, c.Name)
				if d := newDomains(o.cfg.Domains, c.Domains); len(d) > 0 {
					added[c.Name] = d
				}
			} else {
				if s := r.saved[c.Name]; s != nil && s.Set4 == v4 && s.Set6 == v6 {
					r.restore(l, s.Entries, now)
				}
				added[c.Name] = newDomains(nil, c.Domains)
			}
			next = append(next, l)
		}
	}
	r.saved = nil
	// Lists that are gone (or disabled, or moved to other sets) leave nothing behind.
	for _, o := range old {
		for a := range o.entries {
			r.del(o, a)
		}
	}
	r.lists, r.match = next, NewMatcher(nil)
	if cfg.Enabled {
		r.match = NewMatcher(cfg.Lists) // list indices match r.lists
	}
	r.enabled = cfg.Enabled
	// Drop the addresses of names that no longer route to their list.
	for i, l := range r.lists {
		for a, e := range l.entries {
			e.Names = slices.DeleteFunc(e.Names, func(n string) bool {
				li, ok := r.match.Match(n)
				return !ok || li != i
			})
			if len(e.Names) == 0 {
				r.del(l, a)
			}
		}
	}
	return added
}

func (r *Router) createSets(l *list) {
	if r.backend == nil {
		return
	}
	for _, s := range []struct {
		name string
		v6   bool
	}{{l.set4, false}, {l.set6, true}} {
		if err := r.backend.Create(s.name, s.v6, r.min, MaxElem); err != nil {
			r.fail(fmt.Errorf("create %s: %w", s.name, err))
		}
	}
}

func (r *Router) restore(l *list, saved map[netip.Addr]*entry, now time.Time) {
	n := 0
	for a, e := range saved {
		left := e.Expires.Sub(now)
		if left < time.Minute || len(e.Names) == 0 {
			continue
		}
		if r.add(l, a, left, now) {
			l.entries[a] = e
			n++
		}
	}
	if n > 0 {
		log.Printf("routing: restored %d addresses of list %s", n, l.cfg.Name)
	}
}

// newDomains returns the routed (non-"!") domains of next that aren't in prev.
func newDomains(prev, next []string) []string {
	var out []string
	for _, d := range next {
		if !strings.HasPrefix(d, "!") && !slices.Contains(prev, d) {
			out = append(out, d)
		}
	}
	return out
}

// Match tells which list routes host, without touching the sets.
func (r *Router) Match(host string) (listName string, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.enabled {
		return "", false
	}
	if i, ok := r.match.Match(host); ok {
		return r.lists[i].cfg.Name, true
	}
	return "", false
}

// Routed tells which list routed a reply and why.
type Routed struct {
	List  string // "" if not routed
	Entry string // the list entry that matched, e.g. "amazonaws.com"
	Via   string // the CNAME target that matched, when the queried name didn't
}

// Route puts the addresses in answers into the sets of the list that host —
// or, failing that, one of the CNAME targets in answers — belongs to. A "!"
// exception covering host stops routing altogether, so a site can be kept
// out of a list that holds its hosting provider. It runs before the reply
// is released, so the client can't connect before its address is routed.
func (r *Router) Route(host string, answers []dns.RR, now time.Time) Routed {
	if r == nil {
		return Routed{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.enabled || len(r.lists) == 0 {
		return Routed{}
	}
	// The entries remember the name that matched, so a later "!" exception
	// for it removes its addresses.
	name, via := host, ""
	i, entry, ok, excluded := r.match.Lookup(host)
	if excluded {
		return Routed{}
	}
	if !ok {
		for _, rr := range answers {
			if c, isCNAME := rr.(*dns.CNAME); isCNAME {
				t := strings.TrimSuffix(strings.ToLower(c.Target), ".")
				if i, entry, ok, _ = r.match.Lookup(t); ok {
					name, via = t, t
					break
				}
			}
		}
		if !ok {
			return Routed{}
		}
	}
	l := r.lists[i]
	for _, rr := range answers {
		ttl := time.Duration(rr.Header().Ttl) * time.Second
		for _, a := range addrsOf(rr) {
			r.put(l, a, name, ttl, now)
		}
	}
	return Routed{List: l.cfg.Name, Entry: entry, Via: via}
}

// Prefill adds addrs for name (a listed domain or one of its subdomains) to
// a list's sets, e.g. the answers clients may still have cached when the
// domain was just added.
func (r *Router) Prefill(listName, name string, addrs []netip.Addr, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.enabled {
		return
	}
	i, ok := r.match.Match(name)
	if !ok || r.lists[i].cfg.Name != listName {
		return
	}
	for _, a := range addrs {
		r.put(r.lists[i], a, name, 0, now)
	}
}

// put adds or refreshes one address for name. Netlink is only used when the
// entry is new or past half its lifetime, so repeated answers cost a map
// lookup.
func (r *Router) put(l *list, a netip.Addr, name string, ttl time.Duration, now time.Time) {
	a = a.Unmap()
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsPrivate() || a.IsLinkLocalUnicast() {
		return // blocked/rewritten answers and LAN addresses are never routed
	}
	if now.Before(l.fullUntil) {
		return
	}
	timeout := min(max(ttl, r.min), ipset.MaxTimeout)
	e := l.entries[a]
	if e == nil || e.Expires.Sub(now) < timeout/2 {
		if !r.add(l, a, timeout, now) {
			return
		}
		if e == nil {
			e = &entry{}
			l.entries[a] = e
		}
		e.Expires = now.Add(timeout)
	}
	if !slices.Contains(e.Names, name) {
		e.Names = append(e.Names, name)
		if len(e.Names) > maxNames {
			e.Names = e.Names[len(e.Names)-maxNames:]
		}
	}
}

func (r *Router) add(l *list, a netip.Addr, timeout time.Duration, now time.Time) bool {
	if r.backend == nil {
		return true // tracked only
	}
	set := l.set4
	if a.Is6() {
		set = l.set6
	}
	err := r.backend.Add(set, a, timeout)
	if errors.Is(err, ipset.ErrHashFull) {
		// The set is full: back off instead of failing on every answer, and
		// retry when the next entry expires.
		l.fullUntil = now.Add(time.Minute)
	}
	if err != nil {
		r.fail(fmt.Errorf("add %s to %s: %w", a, set, err))
		return false
	}
	return true
}

func (r *Router) del(l *list, a netip.Addr) {
	delete(l.entries, a)
	if r.backend == nil {
		return
	}
	set := l.set4
	if a.Is6() {
		set = l.set6
	}
	if err := r.backend.Del(set, a); err != nil {
		r.fail(fmt.Errorf("delete %s from %s: %w", a, set, err))
	}
}

// fail records an error for the UI and logs it at most once a minute.
func (r *Router) fail(err error) {
	now := time.Now()
	if r.errMsg == "" || now.Sub(r.errAt) > time.Minute {
		log.Printf("routing: %v", err)
	}
	r.errMsg, r.errAt = err.Error(), now
}

// addrsOf returns the addresses an answer record makes clients connect to:
// A/AAAA, and the address hints of HTTPS/SVCB records.
func addrsOf(rr dns.RR) []netip.Addr {
	var out []netip.Addr
	add := func(ips ...[]byte) {
		for _, ip := range ips {
			if a, ok := netip.AddrFromSlice(ip); ok {
				out = append(out, a)
			}
		}
	}
	var kv []dns.SVCBKeyValue
	switch v := rr.(type) {
	case *dns.A:
		add(v.A)
	case *dns.AAAA:
		add(v.AAAA)
	case *dns.HTTPS:
		kv = v.Value
	case *dns.SVCB:
		kv = v.Value
	}
	for _, p := range kv {
		switch h := p.(type) {
		case *dns.SVCBIPv4Hint:
			for _, ip := range h.Hint {
				add(ip)
			}
		case *dns.SVCBIPv6Hint:
			for _, ip := range h.Hint {
				add(ip)
			}
		}
	}
	return out
}

// Prune forgets entries the kernel has already expired.
func (r *Router) Prune(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range r.lists {
		for a, e := range l.entries {
			if !e.Expires.After(now) {
				delete(l.entries, a)
			}
		}
	}
}

// Status returns the lists with their entry counts and the last error.
func (r *Router) Status() (lists []ListStatus, lastErr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range r.lists {
		s := ListStatus{RouteList: l.cfg}
		s.Set4, s.Set6 = l.set4, l.set6
		for a := range l.entries {
			if a.Is4() {
				s.Count4++
			} else {
				s.Count6++
			}
		}
		lists = append(lists, s)
	}
	if r.backend == nil {
		lastErr = "ipset netlink unavailable: domains are matched but no sets are filled"
	} else if r.errMsg != "" && time.Since(r.errAt) < time.Hour {
		lastErr = r.errMsg
	}
	return lists, lastErr
}

// --- snapshot ---

type snapList struct {
	Set4    string                `json:"set4"`
	Set6    string                `json:"set6"`
	Entries map[netip.Addr]*entry `json:"entries"`
}

// Save writes the entries so a reboot (which empties the kernel's sets)
// doesn't lose them.
func (r *Router) Save() error {
	if r.path == "" {
		return nil
	}
	r.mu.Lock()
	snap := map[string]*snapList{}
	for _, l := range r.lists {
		s := &snapList{Set4: l.set4, Set6: l.set6, Entries: make(map[netip.Addr]*entry, len(l.entries))}
		for a, e := range l.entries {
			c := *e
			c.Names = slices.Clone(e.Names)
			s.Entries[a] = &c
		}
		snap[l.cfg.Name] = s
	}
	r.mu.Unlock()
	b, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o755); err != nil {
		return err
	}
	return disk.Write(r.path, b, 0o644)
}

func (r *Router) load() {
	if r.path == "" {
		return
	}
	b, err := os.ReadFile(r.path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err == nil {
		err = json.Unmarshal(b, &r.saved)
	}
	if err != nil {
		log.Printf("routing: ignoring %s: %v", r.path, err)
		r.saved = nil
	}
}
