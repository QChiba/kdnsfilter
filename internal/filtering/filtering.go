// Package filtering decides what to do with a DNS name for a given client,
// following AdGuard Home's semantics: filter lists and user rules (AdGuard
// syntax via urlfilter), per-client settings, blocked services with pause
// schedules, safe search and DNS rewrites.
package filtering

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"

	"github.com/QChiba/kdnsfilter/internal/config"
	"github.com/QChiba/kdnsfilter/internal/schedule"
)

type Action uint8

const (
	Pass Action = iota
	Block
	Rewrite
)

func (a Action) String() string {
	return [...]string{"pass", "block", "rewrite"}[a]
}

// Reasons reported in Result.Reason.
const (
	ReasonAllowlist  = "allowlist"
	ReasonFilter     = "filter"
	ReasonService    = "service"
	ReasonSafeSearch = "safe_search"
	ReasonDoHCanary  = "doh_canary"
	ReasonRewrite    = "rewrite"    // Filtering.Rewrites
	ReasonDNSRewrite = "dnsrewrite" // $dnsrewrite or hosts-style rules
)

// DoHCanary is Firefox's DoH canary domain. Answering it with NXDOMAIN makes
// Firefox keep the network's resolver instead of switching to its default
// DoH, so the router still sees (and routes by) every lookup. Like AdGuard
// Home, it's answered for every client, filtered or not.
const DoHCanary = "use-application-dns.net"

// UserRulesID is the list id of the user rules.
const UserRulesID = 0

type Request struct {
	Host      string // lower case, no trailing dot
	QType     uint16
	ClientIP  netip.Addr
	ClientMAC string // lower case, may be empty
}

type Result struct {
	Action     Action
	Reason     string
	Rule       string
	ListID     uint64
	Service    string
	Safe       SafeTarget
	Rewrite    *Rewritten
	ClientName string
}

// ListSource is the content of one enabled filter list; it must not be
// modified after Build.
type ListSource struct {
	ID    uint64
	Rules []byte
}

type clientMatcher struct {
	cfg      *config.Client
	prefixes []netip.Prefix
	macs     map[string]bool
}

type settings struct {
	name      string
	filtering bool
	safe      config.SafeSearch
	services  []string
	pause     *schedule.Weekly
}

// Filter is an immutable snapshot built from the config; rebuild to change.
type Filter struct {
	protection bool
	global     settings
	engine     *urlfilter.DNSEngine
	services   map[string]*urlfilter.DNSEngine
	clients    []clientMatcher
	// ids holds the $client identifier set of every named client, built
	// once per snapshot so MatchRequest doesn't allocate per query.
	ids      map[string]*container.SortedSliceSet[string]
	rewrites *rewriteTable
	// BlockingMode and BlockedTTL shape the replies to blocked queries.
	BlockingMode string
	BlockedTTL   uint32
	// Warnings lists problems that didn't prevent building.
	Warnings []string
}

// Rules is the compiled engine for filter lists and user rules. Building it
// takes seconds on a router with large lists, so it is shared between
// Filters and rebuilt only when lists or user rules change.
type Rules struct {
	engine *urlfilter.DNSEngine
}

// BuildRules compiles the user rules and the enabled lists.
func BuildRules(userRules []string, lists []ListSource) (*Rules, error) {
	rl := []filterlist.Interface{filterlist.NewString(&filterlist.StringConfig{
		ID:             UserRulesID,
		RulesText:      strings.Join(userRules, "\n"),
		IgnoreCosmetic: true,
	})}
	for _, l := range lists {
		rl = append(rl, filterlist.NewBytes(&filterlist.BytesConfig{
			ID:             rules.ListID(l.ID),
			RulesText:      l.Rules,
			IgnoreCosmetic: true,
		}))
	}
	storage, err := filterlist.NewRuleStorage(rl)
	if err != nil {
		return nil, fmt.Errorf("rule storage: %w", err)
	}
	return &Rules{engine: urlfilter.NewDNSEngine(storage)}, nil
}

// Build compiles cfg, the enabled lists and the services catalog.
func Build(cfg *config.Config, lists []ListSource, cat *Catalog) (*Filter, error) {
	r, err := BuildRules(cfg.UserRules, lists)
	if err != nil {
		return nil, err
	}
	return Compose(cfg, r, cat)
}

// Compose builds a Filter from cfg on top of already compiled rules (which
// must match cfg's lists and user rules). It is cheap: clients, blocked
// services, safe search and the global switches.
func Compose(cfg *config.Config, r *Rules, cat *Catalog) (*Filter, error) {
	f := &Filter{
		engine:     r.engine,
		protection: cfg.Filtering.ProtectionEnabled,
		global: settings{
			filtering: true, // clients on global settings; protection is the master switch
			safe:      cfg.Filtering.SafeSearch,
			services:  cfg.Filtering.BlockedServices.IDs,
			pause:     cfg.Filtering.BlockedServices.Schedule,
		},
		services:     map[string]*urlfilter.DNSEngine{},
		ids:          map[string]*container.SortedSliceSet[string]{},
		rewrites:     buildRewrites(cfg.Filtering.Rewrites),
		BlockingMode: cfg.Filtering.BlockingMode,
		BlockedTTL:   cfg.Filtering.BlockedResponseTTL,
	}

	used := append([]string(nil), f.global.services...)
	for i := range cfg.Clients {
		c := &cfg.Clients[i]
		m := clientMatcher{cfg: c, macs: map[string]bool{}}
		for _, id := range c.IDs {
			if p, err := config.ParsePrefix(id); err == nil {
				m.prefixes = append(m.prefixes, p)
			} else if strings.Count(id, ":") == 5 {
				m.macs[strings.ToLower(id)] = true
			} else {
				f.Warnings = append(f.Warnings, fmt.Sprintf("client %q: unsupported id %q", c.Name, id))
			}
		}
		f.clients = append(f.clients, m)
		if _, done := f.ids[c.Name]; !done {
			f.ids[c.Name] = container.NewSortedSliceSet(c.Name)
		}
		if !c.UseGlobalBlockedServices {
			used = append(used, c.BlockedServices.IDs...)
		}
	}
	for _, id := range used {
		if _, done := f.services[id]; done {
			continue
		}
		svc, ok := cat.Get(id)
		if !ok {
			f.Warnings = append(f.Warnings, fmt.Sprintf("unknown blocked service %q", id))
			f.services[id] = nil
			continue
		}
		s, err := filterlist.NewRuleStorage([]filterlist.Interface{filterlist.NewString(&filterlist.StringConfig{
			ID: 1, RulesText: strings.Join(svc.Rules, "\n"), IgnoreCosmetic: true,
		})})
		if err != nil {
			return nil, fmt.Errorf("service %s: %w", id, err)
		}
		f.services[id] = urlfilter.NewDNSEngine(s)
	}
	return f, nil
}

// RulesCount is the number of rules in lists and user rules.
func (f *Filter) RulesCount() uint64 { return f.engine.RulesCount() }

// ClientFor finds the configured client for an address. The device's MAC
// (from Keenetic's host map) wins, so a client follows its device across
// DHCP leases and IPv6 address changes and a stale IP id can't capture
// another device; addresses and prefixes (narrowest first) are the fallback
// for hosts Keenetic doesn't list, e.g. VPN peers.
func (f *Filter) ClientFor(ip netip.Addr, mac string) *config.Client {
	if mac != "" {
		for i := range f.clients {
			if f.clients[i].macs[mac] {
				return f.clients[i].cfg
			}
		}
	}
	var best *config.Client
	bestBits := -1
	for i := range f.clients {
		for _, p := range f.clients[i].prefixes {
			if p.Contains(ip) && p.Bits() > bestBits {
				best, bestBits = f.clients[i].cfg, p.Bits()
			}
		}
	}
	return best
}

func (f *Filter) settingsFor(c *config.Client) settings {
	s := f.global
	if c == nil {
		return s
	}
	s.name = c.Name
	if !c.UseGlobalSettings {
		s.filtering = c.FilteringEnabled
		s.safe = c.SafeSearch
	}
	if !c.UseGlobalBlockedServices {
		s.services = c.BlockedServices.IDs
		s.pause = c.BlockedServices.Schedule
	}
	return s
}

// Check decides what to do with a queried name.
func (f *Filter) Check(req Request, now time.Time) Result {
	return f.check(req, now, true)
}

// CheckCNAME decides whether a CNAME target in an answer must be blocked
// (no safe search rewrites for targets).
func (f *Filter) CheckCNAME(req Request, now time.Time) Result {
	return f.check(req, now, false)
}

func (f *Filter) check(req Request, now time.Time, rewrite bool) Result {
	s := f.settingsFor(f.ClientFor(req.ClientIP, req.ClientMAC))
	res := Result{ClientName: s.name}
	if rewrite && req.Host == DoHCanary {
		res.Action, res.Reason = Block, ReasonDoHCanary
		return res
	}
	// Rewrites are local DNS records rather than filtering, so they apply
	// to every client, with protection on or off.
	if rewrite {
		if rw, text, ok := f.rewrites.answer(req.Host, req.QType); ok {
			res.Action, res.Reason, res.Rule, res.Rewrite = Rewrite, ReasonRewrite, text, &rw
			return res
		}
	}
	if !f.protection || !s.filtering || req.Host == "" {
		return res
	}

	m, _ := f.engine.MatchRequest(&urlfilter.DNSRequest{
		Hostname: req.Host,
		ClientIP: req.ClientIP,
		// nil (unnamed client) and per-snapshot sets avoid a heap
		// allocation per query.
		ClientIdentifiers: f.ids[s.name],
		DNSType:           req.QType,
	})
	if rewrite {
		if nrs := m.DNSRewrites(); len(nrs) > 0 {
			rw, nr := ruleRewrite(nrs, req.QType)
			res.Action, res.Reason, res.Rewrite = Rewrite, ReasonDNSRewrite, &rw
			res.Rule, res.ListID = nr.Text(), uint64(nr.GetFilterListID())
			return res
		}
	}
	if nr := m.NetworkRule; nr != nil && nr.DNSRewrite == nil {
		res.Rule, res.ListID = nr.Text(), uint64(nr.GetFilterListID())
		if nr.Whitelist {
			res.Reason = ReasonAllowlist
			return res
		}
		res.Action, res.Reason = Block, ReasonFilter
		return res
	}
	hosts := append(m.HostRulesV4, m.HostRulesV6...)
	for _, hr := range hosts {
		if hr.IP.IsUnspecified() || hr.IP.IsLoopback() {
			res.Action, res.Reason = Block, ReasonFilter
			res.Rule, res.ListID = hr.Text(), uint64(hr.GetFilterListID())
			return res
		}
	}
	// Hosts-style rules with real addresses ("192.168.1.5 media.home") answer
	// with those addresses, as in AdGuard Home.
	if rewrite && len(hosts) > 0 {
		rw := Rewritten{}
		for _, hr := range hosts {
			if ip := hr.IP.Unmap(); (req.QType == dns.TypeA && ip.Is4()) || (req.QType == dns.TypeAAAA && ip.Is6()) {
				rw.Addrs = append(rw.Addrs, ip)
			}
		}
		res.Action, res.Reason, res.Rewrite = Rewrite, ReasonDNSRewrite, &rw
		res.Rule, res.ListID = hosts[0].Text(), uint64(hosts[0].GetFilterListID())
		return res
	}

	if len(s.services) > 0 && !s.pause.Contains(now) {
		for _, id := range s.services {
			e := f.services[id]
			if e == nil {
				continue
			}
			if sm, ok := e.MatchRequest(&urlfilter.DNSRequest{Hostname: req.Host}); ok &&
				sm.NetworkRule != nil && !sm.NetworkRule.Whitelist {
				res.Action, res.Reason, res.Service, res.Rule = Block, ReasonService, id, sm.NetworkRule.Text()
				return res
			}
		}
	}

	if rewrite {
		if t, ok := safeSearch(req.Host, s.safe); ok {
			res.Action, res.Reason, res.Safe = Rewrite, ReasonSafeSearch, t
		}
	}
	return res
}
