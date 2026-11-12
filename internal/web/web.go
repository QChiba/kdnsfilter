// Package web serves the JSON API and the embedded single-page UI.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/QChiba/kdnsfilter/internal/app"
	"github.com/QChiba/kdnsfilter/internal/clients"
	"github.com/QChiba/kdnsfilter/internal/config"
	"github.com/QChiba/kdnsfilter/internal/filtering"
	"github.com/QChiba/kdnsfilter/internal/querylog"
	"github.com/QChiba/kdnsfilter/internal/routing"
	"github.com/QChiba/kdnsfilter/internal/schedule"
)

//go:embed static
var static embed.FS

type Server struct {
	app     *app.App
	version string
}

func New(a *app.App, version string) *Server {
	return &Server{app: a, version: version}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(static, "static")
	mux.Handle("GET /", http.FileServerFS(sub))

	api := func(pattern string, h func(http.ResponseWriter, *http.Request) (any, error)) {
		mux.Handle(pattern, s.guard(func(w http.ResponseWriter, r *http.Request) {
			v, err := h(w, r)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, v)
		}))
	}
	api("GET /api/status", s.status)
	api("POST /api/protection", s.setProtection)
	api("GET /api/stats", s.stats)
	api("POST /api/stats/reset", s.resetStats)
	api("GET /api/querylog", s.querylog)
	api("GET /api/domaininfo", s.domainInfo)
	api("POST /api/querylog/clear", s.clearQuerylog)
	api("GET /api/filters", s.filters)
	api("POST /api/filters", s.addFilter)
	api("PUT /api/filters/{id}", s.updateFilter)
	api("DELETE /api/filters/{id}", s.deleteFilter)
	api("POST /api/filters/refresh", s.refreshFilters)
	api("PUT /api/user_rules", s.setUserRules)
	api("PUT /api/rewrites", s.setRewrites)
	api("POST /api/user_rules/quick", s.quickRule)
	api("GET /api/clients", s.clients)
	api("PUT /api/clients", s.setClients)
	api("GET /api/services", s.services)
	api("POST /api/services/refresh", s.refreshServices)
	api("GET /api/settings", s.settings)
	api("PUT /api/settings", s.setSettings)
	api("GET /api/check", s.check)
	api("GET /api/routing", s.routing)
	api("PUT /api/routing", s.setRouting)
	api("PUT /api/routing/lists/{name}", s.setRouteList)
	api("DELETE /api/routing/lists/{name}", s.deleteRouteList)
	mux.Handle("GET /api/routing/lists/{name}/export", s.guard(s.exportRouteList))
	return s.securityHeaders(mux)
}

func (s *Server) securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.allowedHost(r.Host) {
			http.Error(w, "unknown host name; open the UI by the router's address", http.StatusMisdirectedRequest)
			return
		}
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Embedded files have no modification time; make browsers revalidate
		// so an upgrade never runs a stale UI.
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return errors.New("content type must be application/json")
	}
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 8<<20))
	return dec.Decode(v)
}

// --- request guards (the UI has no login: the router's LAN is trusted) ---

// allowedHost blocks DNS rebinding: a web page can't reach the API through a
// public name that it pointed at the router. Accepted: IP literals,
// single-label names, .local/.lan/.home names and configured hosts.
func (s *Server) allowedHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	if host == "" || host == "localhost" || !strings.Contains(host, ".") ||
		strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".lan") || strings.HasSuffix(host, ".home") {
		return true
	}
	return slices.Contains(s.app.Config().HTTP.AllowedHosts, host)
}

func (s *Server) guard(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mutating requests must be JSON: browsers can't send that cross-site
		// without a CORS preflight, which this server never approves.
		if r.Method != http.MethodGet && r.Method != http.MethodDelete &&
			!strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "JSON required"})
			return
		}
		next(w, r)
	})
}

// --- status & stats ---

func (s *Server) status(_ http.ResponseWriter, _ *http.Request) (any, error) {
	cfg := s.app.Config()
	f := s.app.Filter()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return map[string]any{
		"version":            s.version,
		"started":            s.app.Started,
		"protection_enabled": cfg.Filtering.ProtectionEnabled,
		"rules":              f.RulesCount(),
		"warnings":           f.Warnings,
		"queue":              cfg.NFQueue.Queue,
		"destinations":       cfg.NFQueue.Destinations,
		"manage_firewall":    cfg.NFQueue.ManageFirewall,
		"rss_kb":             rssKB(),
		"heap_kb":            ms.HeapAlloc / 1024,
	}, nil
}

func rssKB() int {
	b, _ := os.ReadFile("/proc/self/status")
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "VmRSS:"); ok {
			n, _ := strconv.Atoi(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), "kB")))
			return n
		}
	}
	return 0
}

func (s *Server) setProtection(_ http.ResponseWriter, r *http.Request) (any, error) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	return ok(s.app.Update(func(c *config.Config) error {
		c.Filtering.ProtectionEnabled = req.Enabled
		return nil
	}))
}

func ok(err error) (any, error) {
	if err != nil {
		return nil, err
	}
	return map[string]bool{"ok": true}, nil
}

func (s *Server) stats(_ http.ResponseWriter, _ *http.Request) (any, error) {
	return s.app.Stats.Summary(time.Now(), 50), nil // top lists scroll in the UI
}

func (s *Server) resetStats(_ http.ResponseWriter, _ *http.Request) (any, error) {
	s.app.Stats.Reset()
	return ok(s.app.Stats.Save())
}

type querylogPage struct {
	Entries []querylog.Entry `json:"entries"`
	// More: older entries may match; request again with before=NextBefore.
	// A page can be short (even empty) with More set when a rare search hit
	// the per-request scan limit.
	More       bool       `json:"more"`
	NextBefore *time.Time `json:"next_before,omitempty"`
}

// querylog pages with ?before=<next_before of the previous page>.
func (s *Server) querylog(_ http.ResponseWriter, r *http.Request) (any, error) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	var before time.Time
	if v := q.Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			return nil, fmt.Errorf("before: %w", err)
		}
		before = t
	}
	res := s.app.Log.Find(querylog.Query{
		Search: q.Get("search"), Action: q.Get("action"), Route: q.Get("route"),
		Limit: min(max(limit, 1), 500), Before: before,
	})
	page := querylogPage{Entries: res.Entries, More: res.More}
	if page.Entries == nil {
		page.Entries = []querylog.Entry{}
	}
	if res.More {
		page.NextBefore = &res.Next
	}
	return page, nil
}

func (s *Server) clearQuerylog(_ http.ResponseWriter, _ *http.Request) (any, error) {
	return ok(s.app.Log.Clear())
}

// --- filters & rules ---

type filterView struct {
	config.Filter
	app.ListStatus
}

func (s *Server) filters(_ http.ResponseWriter, _ *http.Request) (any, error) {
	cfg := s.app.Config()
	st := s.app.ListStatuses()
	views := make([]filterView, 0, len(cfg.Filters))
	for _, f := range cfg.Filters {
		views = append(views, filterView{f, st[f.ID]})
	}
	rules := cfg.UserRules
	if rules == nil {
		rules = []string{}
	}
	rewrites := cfg.Filtering.Rewrites
	if rewrites == nil {
		rewrites = []config.Rewrite{}
	}
	return map[string]any{
		"filters":         views,
		"user_rules":      rules,
		"rewrites":        rewrites,
		"update_interval": cfg.Filtering.UpdateInterval.String(),
	}, nil
}

func (s *Server) addFilter(_ http.ResponseWriter, r *http.Request) (any, error) {
	var f config.Filter
	if err := readJSON(r, &f); err != nil {
		return nil, err
	}
	f.URL, f.Name = strings.TrimSpace(f.URL), strings.TrimSpace(f.Name)
	if !strings.HasPrefix(f.URL, "https://") && !strings.HasPrefix(f.URL, "http://") && !strings.HasPrefix(f.URL, "/") {
		return nil, errors.New("URL must be http(s):// or an absolute path")
	}
	err := s.app.Update(func(c *config.Config) error {
		for _, ex := range c.Filters {
			if ex.URL == f.URL {
				return errors.New("this list is already added")
			}
		}
		f.ID = c.NextFilterID()
		if f.Name == "" {
			f.Name = f.URL
		}
		c.Filters = append(c.Filters, f)
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.refreshAsync()
	return f, nil
}

func (s *Server) updateFilter(_ http.ResponseWriter, r *http.Request) (any, error) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		return nil, err
	}
	var in config.Filter
	if err := readJSON(r, &in); err != nil {
		return nil, err
	}
	err = s.app.Update(func(c *config.Config) error {
		for i := range c.Filters {
			if c.Filters[i].ID == id {
				c.Filters[i].Name, c.Filters[i].Enabled = strings.TrimSpace(in.Name), in.Enabled
				if u := strings.TrimSpace(in.URL); u != "" {
					c.Filters[i].URL = u
				}
				return nil
			}
		}
		return fmt.Errorf("no filter %d", id)
	})
	if err == nil {
		s.refreshAsync()
	}
	return ok(err)
}

func (s *Server) deleteFilter(_ http.ResponseWriter, r *http.Request) (any, error) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		return nil, err
	}
	err = s.app.Update(func(c *config.Config) error {
		n := len(c.Filters)
		c.Filters = slices.DeleteFunc(c.Filters, func(f config.Filter) bool { return f.ID == id })
		if len(c.Filters) == n {
			return fmt.Errorf("no filter %d", id)
		}
		return nil
	})
	if err == nil {
		s.app.RemoveList(id)
	}
	return ok(err)
}

// refreshAsync fetches missing lists after a change without blocking the request.
func (s *Server) refreshAsync() {
	go s.app.UpdateLists(context.Background(), false)
}

func (s *Server) refreshFilters(_ http.ResponseWriter, r *http.Request) (any, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	return ok(s.app.UpdateLists(ctx, true))
}

func (s *Server) setUserRules(_ http.ResponseWriter, r *http.Request) (any, error) {
	var req struct {
		Rules []string `json:"rules"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	var rules []string
	for _, l := range req.Rules {
		if l = strings.TrimSpace(l); l != "" {
			rules = append(rules, l)
		}
	}
	return ok(s.app.Update(func(c *config.Config) error {
		c.UserRules = rules
		return nil
	}))
}

// setRewrites replaces the DNS rewrites.
func (s *Server) setRewrites(_ http.ResponseWriter, r *http.Request) (any, error) {
	var in []config.Rewrite
	if err := readJSON(r, &in); err != nil {
		return nil, err
	}
	for i := range in {
		in[i].Normalize()
	}
	return ok(s.app.Update(func(c *config.Config) error {
		c.Filtering.Rewrites = in
		return nil
	}))
}

// quickRule adds ||host^ (block) or @@||host^ (allow), replacing the
// opposite exact rule; action "remove" just deletes both.
func (s *Server) quickRule(_ http.ResponseWriter, r *http.Request) (any, error) {
	var req struct {
		Host   string `json:"host"`
		Action string `json:"action"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(req.Host)), ".")
	if host == "" || strings.ContainsAny(host, " /|^@$") {
		return nil, errors.New("bad host")
	}
	block, allow := "||"+host+"^", "@@||"+host+"^"
	return ok(s.app.Update(func(c *config.Config) error {
		c.UserRules = slices.DeleteFunc(c.UserRules, func(l string) bool { return l == block || l == allow })
		switch req.Action {
		case "block":
			c.UserRules = append(c.UserRules, block)
		case "allow":
			c.UserRules = append(c.UserRules, allow)
		case "remove":
		default:
			return errors.New("action must be block, allow or remove")
		}
		return nil
	}))
}

// --- clients & services ---

type deviceView struct {
	MAC    string   `json:"mac"`
	Name   string   `json:"name"`
	IPs    []string `json:"ips"`
	Client string   `json:"client"`
}

type clientView struct {
	config.Client
	// Addresses are the device's current addresses from Keenetic (for MAC
	// ids), followed by any fixed addresses/prefixes from the config.
	Addresses []string `json:"addresses"`
	// IPOnly marks clients identified only by single addresses, which DHCP
	// may hand to another device; Suggestions propose a MAC to bind instead.
	IPOnly      bool                 `json:"ip_only"`
	Suggestions []clients.Suggestion `json:"suggestions"`
}

func isMAC(id string) bool { return strings.Count(id, ":") == 5 && !strings.Contains(id, "::") }

func (s *Server) clients(_ http.ResponseWriter, _ *http.Request) (any, error) {
	cfg := s.app.Config()
	f := s.app.Filter()
	devs := s.app.Hosts.Devices()
	byMAC := map[string]clients.Device{}
	for _, d := range devs {
		byMAC[d.MAC] = d
	}
	taken := map[string]bool{}
	for _, c := range cfg.Clients {
		for _, id := range c.IDs {
			if isMAC(id) {
				taken[strings.ToLower(id)] = true
			}
		}
	}

	views := make([]clientView, 0, len(cfg.Clients))
	for _, c := range cfg.Clients {
		v := clientView{Client: c, Addresses: []string{}, Suggestions: []clients.Suggestion{}}
		var single []netip.Addr
		hasMAC := false
		for _, id := range c.IDs {
			if isMAC(id) {
				hasMAC = true
				for _, ip := range byMAC[strings.ToLower(id)].IPs {
					v.Addresses = append(v.Addresses, ip.String())
				}
				continue
			}
			v.Addresses = append(v.Addresses, id)
			if p, err := config.ParsePrefix(id); err == nil && p.IsSingleIP() && !p.Addr().IsLoopback() {
				single = append(single, p.Addr())
			}
		}
		if !hasMAC && len(single) > 0 {
			v.IPOnly = true
			v.Suggestions = append(v.Suggestions, clients.Suggest(c.Name, single, devs, taken)...)
		}
		views = append(views, v)
	}

	known := make([]deviceView, 0, len(devs))
	for _, d := range devs {
		dv := deviceView{MAC: d.MAC, Name: d.Name, IPs: []string{}}
		for _, ip := range d.IPs {
			dv.IPs = append(dv.IPs, ip.String())
		}
		if len(d.IPs) > 0 {
			if c := f.ClientFor(d.IPs[0], d.MAC); c != nil {
				dv.Client = c.Name
			}
		}
		known = append(known, dv)
	}
	return map[string]any{"clients": views, "known": known}, nil
}

func (s *Server) setClients(_ http.ResponseWriter, r *http.Request) (any, error) {
	var in []config.Client
	if err := readJSON(r, &in); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for i := range in {
		c := &in[i]
		c.Name = strings.TrimSpace(c.Name)
		if seen[strings.ToLower(c.Name)] {
			return nil, fmt.Errorf("duplicate client name %q", c.Name)
		}
		seen[strings.ToLower(c.Name)] = true
		var ids []string
		for _, id := range c.IDs {
			if id = strings.TrimSpace(id); id != "" {
				ids = append(ids, strings.ToLower(id))
			}
		}
		c.IDs = ids
	}
	return ok(s.app.Update(func(c *config.Config) error {
		c.Clients = in
		return nil
	}))
}

func (s *Server) services(_ http.ResponseWriter, _ *http.Request) (any, error) {
	type svc struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Group string `json:"group"`
	}
	cat := s.app.Catalog()
	out := make([]svc, 0, len(cat.Services))
	for _, v := range cat.Services {
		out = append(out, svc{v.ID, v.Name, v.Group})
	}
	return out, nil
}

func (s *Server) refreshServices(_ http.ResponseWriter, r *http.Request) (any, error) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	return ok(s.app.UpdateServices(ctx))
}

// --- settings ---

type settingsView struct {
	ProtectionEnabled  bool                   `json:"protection_enabled"`
	BlockingMode       string                 `json:"blocking_mode"`
	BlockedResponseTTL uint32                 `json:"blocked_response_ttl"`
	SafeSearch         config.SafeSearch      `json:"safe_search"`
	BlockedServices    config.BlockedServices `json:"blocked_services"`
	UpdateInterval     string                 `json:"update_interval"`
	QueryLogEnabled    bool                   `json:"querylog_enabled"`
	QueryLogSize       int                    `json:"querylog_size"`
	QueryLogInterval   string                 `json:"querylog_interval"` // "0" = memory only
	StatsInterval      string                 `json:"stats_interval"`
	DomainInfo         string                 `json:"domain_info"`
}

func (s *Server) settings(_ http.ResponseWriter, _ *http.Request) (any, error) {
	c := s.app.Config()
	f := c.Filtering
	if f.BlockedServices.IDs == nil {
		f.BlockedServices.IDs = []string{}
	}
	return settingsView{
		ProtectionEnabled: f.ProtectionEnabled,
		BlockingMode:      f.BlockingMode, BlockedResponseTTL: f.BlockedResponseTTL,
		SafeSearch: f.SafeSearch, BlockedServices: f.BlockedServices,
		UpdateInterval:  f.UpdateInterval.String(),
		QueryLogEnabled: c.QueryLog.Enabled, QueryLogSize: c.QueryLog.Size,
		QueryLogInterval: c.QueryLog.Interval.String(), StatsInterval: c.Stats.Interval.String(),
		DomainInfo: c.DomainInfo,
	}, nil
}

func (s *Server) setSettings(_ http.ResponseWriter, r *http.Request) (any, error) {
	var in settingsView
	if err := readJSON(r, &in); err != nil {
		return nil, err
	}
	iv, err := time.ParseDuration(in.UpdateInterval)
	if err != nil || iv < time.Hour {
		return nil, errors.New("update interval must be a duration of at least 1h, e.g. 24h")
	}
	if in.QueryLogSize < 100 || in.QueryLogSize > 100000 {
		return nil, errors.New("query log size must be between 100 and 100000")
	}
	qlInterval, err := schedule.ParseDuration(in.QueryLogInterval)
	if err != nil {
		return nil, fmt.Errorf("query log retention: %w", err)
	}
	stInterval, err := schedule.ParseDuration(in.StatsInterval)
	if err != nil {
		return nil, fmt.Errorf("statistics retention: %w", err)
	}
	return ok(s.app.Update(func(c *config.Config) error {
		c.QueryLog.Interval, c.Stats.Interval = config.Duration(qlInterval), config.Duration(stInterval)
		f := &c.Filtering
		f.ProtectionEnabled = in.ProtectionEnabled
		f.BlockingMode, f.BlockedResponseTTL = in.BlockingMode, in.BlockedResponseTTL
		f.SafeSearch, f.BlockedServices = in.SafeSearch, in.BlockedServices
		f.UpdateInterval = config.Duration(iv)
		c.QueryLog.Enabled, c.QueryLog.Size = in.QueryLogEnabled, in.QueryLogSize
		c.DomainInfo = strings.TrimRight(strings.TrimSpace(in.DomainInfo), "/")
		return nil
	}))
}

var domainInfoClient = &http.Client{Timeout: 3 * time.Second}

// domainInfo asks the domain info service (Settings) what a host is, for the
// query log popover; {"enabled": false} when none is set. page=0 keeps the
// service from fetching the site's homepage (blocked domains).
func (s *Server) domainInfo(_ http.ResponseWriter, r *http.Request) (any, error) {
	base := s.app.Config().DomainInfo
	if base == "" {
		return map[string]bool{"enabled": false}, nil
	}
	host := r.URL.Query().Get("host")
	q := url.Values{"host": {host}}
	if r.URL.Query().Get("page") == "0" {
		q.Set("page", "0")
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, base+"/api/info?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := domainInfoClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("domain info service: %w", err)
	}
	defer resp.Body.Close()
	var info map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&info); err != nil {
		return nil, fmt.Errorf("domain info service: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("domain info service: %v", info["error"])
	}
	info["enabled"] = true
	info["editor"] = base + "/?" + url.Values{"host": {host}}.Encode()
	return info, nil
}

// check runs a name through the filter as a given client would see it.
func (s *Server) check(_ http.ResponseWriter, r *http.Request) (any, error) {
	q := r.URL.Query()
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(q.Get("host"))), ".")
	if host == "" {
		return nil, errors.New("host is required")
	}
	ip := netip.IPv4Unspecified()
	if v := q.Get("client"); v != "" {
		var err error
		if ip, err = netip.ParseAddr(v); err != nil {
			return nil, err
		}
	}
	h, _ := s.app.Hosts.Lookup(ip)
	// As an A query, so address rewrites show their answer.
	res := s.app.Filter().Check(filtering.Request{Host: host, QType: dns.TypeA, ClientIP: ip, ClientMAC: h.MAC}, time.Now())
	route, _ := s.app.Routing.Match(host)
	return map[string]any{
		"action": res.Action.String(), "reason": res.Reason, "rule": res.Rule,
		"list_id": res.ListID, "service": res.Service, "client": res.ClientName,
		"safe_target": firstNonEmpty(res.Safe.CNAME, ipString(res.Safe.IP)),
		"rewrite":     res.Rewrite,
		"route":       route,
	}, nil
}

// --- routing ---

func (s *Server) routing(_ http.ResponseWriter, _ *http.Request) (any, error) {
	rt := s.app.Config().Routing
	lists, lastErr := s.app.Routing.Status()
	// Status only has the active lists; show configured ones while disabled.
	if len(lists) == 0 {
		for _, l := range rt.Lists {
			st := routing.ListStatus{RouteList: l}
			st.Set4, st.Set6 = l.SetNames()
			lists = append(lists, st)
		}
	}
	for i := range lists {
		if lists[i].Domains == nil {
			lists[i].Domains = []string{}
		}
	}
	if lists == nil {
		lists = []routing.ListStatus{}
	}
	return map[string]any{
		"enabled":       rt.Enabled,
		"min_timeout":   rt.MinTimeout.String(),
		"min_timeout_s": int64(time.Duration(rt.MinTimeout) / time.Second),
		"lists":         lists,
		"tproxy": map[string]any{
			"mark": fmt.Sprintf("0x%x", rt.TProxy.Mark), "table": rt.TProxy.Table, "router": rt.TProxy.Router,
			"proxy_group": rt.TProxy.ProxyGroup, "proxy_mark": proxyMark(rt.TProxy.ProxyMark),
		},
		"manage_firewall": s.app.Config().NFQueue.ManageFirewall,
		"error":           lastErr,
	}, nil
}

func proxyMark(m uint32) string {
	if m == 0 {
		return ""
	}
	return fmt.Sprintf("0x%x", m)
}

// setRouting changes the routing switch, the minimum lifetime and, if
// given, how the router's own traffic reaches TPROXY ports.
func (s *Server) setRouting(_ http.ResponseWriter, r *http.Request) (any, error) {
	var in struct {
		Enabled    bool   `json:"enabled"`
		MinTimeout string `json:"min_timeout"`
		TProxy     *struct {
			Router     bool   `json:"router"`
			ProxyGroup string `json:"proxy_group"`
			ProxyMark  string `json:"proxy_mark"` // "0xff", "255" or ""
		} `json:"tproxy"`
	}
	if err := readJSON(r, &in); err != nil {
		return nil, err
	}
	d, err := schedule.ParseDuration(in.MinTimeout)
	if err != nil {
		return nil, fmt.Errorf("minimum lifetime: %w", err)
	}
	var mark uint64
	if in.TProxy != nil && strings.TrimSpace(in.TProxy.ProxyMark) != "" {
		if mark, err = strconv.ParseUint(strings.TrimSpace(in.TProxy.ProxyMark), 0, 32); err != nil || mark == 0 {
			return nil, fmt.Errorf("proxy mark %q: want a number like 0xff or 255", in.TProxy.ProxyMark)
		}
	}
	return ok(s.app.Update(func(c *config.Config) error {
		c.Routing.Enabled, c.Routing.MinTimeout = in.Enabled, config.Duration(d)
		if t := in.TProxy; t != nil {
			c.Routing.TProxy.Router = t.Router
			c.Routing.TProxy.ProxyGroup = strings.TrimSpace(t.ProxyGroup)
			c.Routing.TProxy.ProxyMark = uint32(mark)
		}
		return nil
	}))
}

// setRouteList replaces the domains of a list (one per line in the UI) and,
// if given, its TPROXY port or chains; a missing list is created.
func (s *Server) setRouteList(_ http.ResponseWriter, r *http.Request) (any, error) {
	var in struct {
		Domains     *[]string `json:"domains"` // omitted: keep the domains
		TProxyPort  *uint16   `json:"tproxy_port"`
		Chain       *string   `json:"chain"`
		OutputChain *string   `json:"output_chain"`
	}
	if err := readJSON(r, &in); err != nil {
		return nil, err
	}
	name := r.PathValue("name")
	return ok(s.app.Update(func(c *config.Config) error {
		i := slices.IndexFunc(c.Routing.Lists, func(l config.RouteList) bool { return l.Name == name })
		if i < 0 {
			c.Routing.Lists = append(c.Routing.Lists, config.RouteList{Name: name, Domains: []string{}})
			i = len(c.Routing.Lists) - 1
		}
		l := &c.Routing.Lists[i]
		if in.Domains != nil {
			l.Domains = *in.Domains
		}
		if in.TProxyPort != nil {
			l.TProxyPort = *in.TProxyPort
		}
		if in.Chain != nil {
			l.Chain = strings.TrimSpace(*in.Chain)
		}
		if in.OutputChain != nil {
			l.OutputChain = strings.TrimSpace(*in.OutputChain)
		}
		return nil
	}))
}

// deleteRouteList removes a list: its addresses leave the sets and its
// firewall rules go. The last list stays, so the page always has one.
func (s *Server) deleteRouteList(_ http.ResponseWriter, r *http.Request) (any, error) {
	name := r.PathValue("name")
	return ok(s.app.Update(func(c *config.Config) error {
		i := slices.IndexFunc(c.Routing.Lists, func(l config.RouteList) bool { return l.Name == name })
		if i < 0 {
			return fmt.Errorf("no routing list %q", name)
		}
		if len(c.Routing.Lists) == 1 {
			return errors.New("the last list can't be removed; clear its domains instead")
		}
		c.Routing.Lists = slices.Delete(c.Routing.Lists, i, i+1)
		return nil
	}))
}

// exportRouteList downloads a list as text, one domain per line — the same
// format the list editor takes, so a backup can be pasted back.
func (s *Server) exportRouteList(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	i := slices.IndexFunc(s.app.Config().Routing.Lists, func(l config.RouteList) bool { return l.Name == name })
	if i < 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("no routing list %q", name)})
		return
	}
	l := s.app.Config().Routing.Lists[i]
	now := time.Now()
	var b strings.Builder
	fmt.Fprintf(&b, "# kdnsfilter routing list %s, %d domains, exported %s\n", l.Name, len(l.Domains), now.Format(time.RFC3339))
	for _, d := range l.Domains {
		b.WriteString(d)
		b.WriteByte('\n')
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="kdnsfilter-%s-%s.txt"`, l.Name, now.Format(time.DateOnly)))
	w.Write([]byte(b.String()))
}

func ipString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
