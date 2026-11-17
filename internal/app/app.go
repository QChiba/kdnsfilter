// Package app wires configuration, filter lists, the filtering engine, the
// query log and the NFQUEUE packet handler together.
package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/QChiba/kdnsfilter/internal/clients"
	"github.com/QChiba/kdnsfilter/internal/config"
	"github.com/QChiba/kdnsfilter/internal/filtering"
	"github.com/QChiba/kdnsfilter/internal/querylog"
	"github.com/QChiba/kdnsfilter/internal/routing"
	"github.com/QChiba/kdnsfilter/internal/stats"
)

const maxListSize = 64 << 20

// ListStatus describes the cached copy of a filter list.
type ListStatus struct {
	Updated time.Time `json:"updated"`
	Rules   int       `json:"rules"`
	Error   string    `json:"error,omitempty"`
}

type App struct {
	cfgPath string
	dataDir string // fixed at start; changing it needs a restart
	Started time.Time
	Log     *querylog.Log
	Stats   *stats.Stats
	Hosts   *clients.HostMap
	Routing *routing.Router

	mu     sync.Mutex                    // serialises config changes and rebuilds
	rtMu   sync.Mutex                    // serialises routing/firewall application
	cfg    atomic.Pointer[config.Config] // immutable snapshot, replaced by Update
	status map[uint64]ListStatus
	filter atomic.Pointer[filtering.Filter]
	// Compiled lists + user rules, reused while their inputs are unchanged
	// (guarded by mu).
	rules       *filtering.Rules
	rulesKey    string
	rulesBuilds int
	catalog     atomic.Pointer[filtering.Catalog]
	safe        *safeResolver
	http        *http.Client
}

// New builds the filter from cached lists; call UpdateLists to fetch
// missing or stale ones.
func New(cfgPath string, cfg *config.Config) (*App, error) {
	a := &App{
		cfgPath: cfgPath,
		dataDir: cfg.DataDir,
		Started: time.Now(),
		Log: querylog.New(filepath.Join(cfg.DataDir, "querylog"), cfg.QueryLog.Size,
			cfg.QueryLog.Enabled, time.Duration(cfg.QueryLog.Interval)),
		Stats:  stats.New(filepath.Join(cfg.DataDir, "stats.json"), time.Duration(cfg.Stats.Interval)),
		Hosts:  clients.NewHostMap(cfg.Hostmap),
		status: map[uint64]ListStatus{},
		safe:   newSafeResolver(cfg.Resolver),
		http:   &http.Client{Timeout: 2 * time.Minute},
	}
	a.cfg.Store(cfg)
	a.catalog.Store(filtering.LoadCatalog(a.servicesPath()))
	if err := os.MkdirAll(a.filtersDir(), 0o755); err != nil {
		return nil, err
	}
	if err := a.rebuild(cfg); err != nil {
		return nil, err
	}
	a.Routing = newRouter(cfg)
	return a, nil
}

func (a *App) filtersDir() string   { return filepath.Join(a.dataDir, "filters") }
func (a *App) servicesPath() string { return filepath.Join(a.dataDir, "services.json") }
func (a *App) listPath(id uint64) string {
	return filepath.Join(a.filtersDir(), fmt.Sprintf("%d.txt", id))
}

// Filter returns the current filter snapshot.
func (a *App) Filter() *filtering.Filter { return a.filter.Load() }

// Catalog returns the blocked services catalog.
func (a *App) Catalog() *filtering.Catalog { return a.catalog.Load() }

// Config returns the current config. It is shared and must not be modified;
// use Update to change it. (Deep-copying it here on every API request used to
// allocate enough to keep the GC — which scans the whole rule index — busy.)
func (a *App) Config() *config.Config { return a.cfg.Load() }

// ListStatuses returns the status of every configured list.
func (a *App) ListStatuses() map[uint64]ListStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[uint64]ListStatus, len(a.status))
	for k, v := range a.status {
		out[k] = v
	}
	return out
}

func clone(c *config.Config) *config.Config {
	b, err := yaml.Marshal(c)
	if err != nil {
		panic(err)
	}
	out := &config.Config{}
	if err := yaml.Unmarshal(b, out); err != nil {
		panic(err)
	}
	return out
}

// Update applies fn to a copy of the config, validates, rebuilds the filter
// and saves. Nothing changes if any step fails: on a save error the previous
// filter and rules stay in place, and the stored config still matches what
// runs.
func (a *App) Update(fn func(*config.Config) error) error {
	a.mu.Lock()
	prev := a.cfg.Load()
	prevFilter, prevRules, prevKey := a.filter.Load(), a.rules, a.rulesKey
	next := clone(prev)
	if err := fn(next); err != nil {
		a.mu.Unlock()
		return err
	}
	for i := range next.Routing.Lists {
		next.Routing.Lists[i].Normalize()
	}
	if err := next.Validate(); err != nil {
		a.mu.Unlock()
		return err
	}
	if err := a.rebuild(next); err != nil {
		a.mu.Unlock()
		return err
	}
	if err := next.Save(a.cfgPath); err != nil {
		// The new filter must not outlive its config.
		a.rules, a.rulesKey = prevRules, prevKey
		a.filter.Store(prevFilter)
		a.mu.Unlock()
		return fmt.Errorf("save config: %w", err)
	}
	a.cfg.Store(next)
	a.Log.Configure(next.QueryLog.Size, next.QueryLog.Enabled, time.Duration(next.QueryLog.Interval))
	a.Stats.SetInterval(time.Duration(next.Stats.Interval))
	a.safe.setAddr(next.Resolver)
	a.mu.Unlock()
	a.routingChanged(prev, next)
	return nil
}

// rebuild compiles cfg with the cached lists and swaps the filter in.
// Callers hold a.mu (or are in New).
func (a *App) rebuild(cfg *config.Config) error {
	// Compiling the lists takes seconds with large lists; most changes
	// (protection, clients, services, safe search, ...) don't touch them.
	key := a.rulesKeyFor(cfg)
	compiled, fresh := a.rules, false
	if compiled == nil || key != a.rulesKey {
		r, err := filtering.BuildRules(cfg.UserRules, a.readLists(cfg))
		if err != nil {
			return err
		}
		compiled, fresh = r, true
	}
	f, err := filtering.Compose(cfg, compiled, a.Catalog())
	if err != nil {
		return err
	}
	for _, w := range f.Warnings {
		log.Printf("warning: %s", w)
	}
	a.filter.Store(f)
	if fresh {
		a.rules, a.rulesKey = compiled, key
		a.rulesBuilds++
		// The previous engine and the build garbage are tens of MB; rule
		// rebuilds are rare, so hand the memory back to the router right away.
		runtime.GC()
		debug.FreeOSMemory()
	}
	return nil
}

// rulesKeyFor identifies the inputs of the compiled rules: the user rules and
// the files of the enabled lists (downloads change their size/mtime).
func (a *App) rulesKeyFor(cfg *config.Config) string {
	var b strings.Builder
	for _, r := range cfg.UserRules {
		b.WriteString(r)
		b.WriteByte('\n')
	}
	for _, f := range cfg.Filters {
		if !f.Enabled {
			continue
		}
		if fi, err := os.Stat(a.listPath(f.ID)); err == nil {
			fmt.Fprintf(&b, "\x00list %d %d %d", f.ID, fi.Size(), fi.ModTime().UnixNano())
		}
	}
	return b.String()
}

// readLists loads the enabled lists that have been downloaded.
func (a *App) readLists(cfg *config.Config) []filtering.ListSource {
	var lists []filtering.ListSource
	for _, f := range cfg.Filters {
		if !f.Enabled {
			continue
		}
		b, err := os.ReadFile(a.listPath(f.ID))
		if err != nil {
			continue // not downloaded yet
		}
		lists = append(lists, filtering.ListSource{ID: f.ID, Rules: b})
		st := a.status[f.ID]
		if st.Rules == 0 {
			st.Rules = countRules(b)
			if fi, err := os.Stat(a.listPath(f.ID)); err == nil {
				st.Updated = fi.ModTime()
			}
			a.status[f.ID] = st
		}
	}
	return lists
}

// UpdateLists downloads enabled lists that are missing or older than the
// update interval (all of them if force), then rebuilds the filter.
func (a *App) UpdateLists(ctx context.Context, force bool) error {
	cfg := a.Config()
	interval := time.Duration(cfg.Filtering.UpdateInterval)
	var errs []error
	changed := false
	for _, f := range cfg.Filters {
		if !f.Enabled {
			continue
		}
		fi, err := os.Stat(a.listPath(f.ID))
		if !force && err == nil && time.Since(fi.ModTime()) < interval {
			continue
		}
		n, err := a.download(ctx, f.URL, a.listPath(f.ID))
		a.mu.Lock()
		st := a.status[f.ID]
		if err != nil {
			st.Error = err.Error()
			errs = append(errs, fmt.Errorf("%s: %w", f.Name, err))
		} else {
			st = ListStatus{Updated: time.Now(), Rules: n}
			changed = true
		}
		a.status[f.ID] = st
		a.mu.Unlock()
	}
	if changed {
		a.mu.Lock()
		err := a.rebuild(a.cfg.Load())
		a.mu.Unlock()
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// UpdateServices refreshes the blocked services catalog.
func (a *App) UpdateServices(ctx context.Context) error {
	cfg := a.Config()
	tmp := a.servicesPath() + ".download"
	if _, err := a.download(ctx, cfg.ServicesURL, tmp); err != nil {
		return err
	}
	defer os.Remove(tmp)
	raw, err := os.ReadFile(tmp)
	if err != nil {
		return err
	}
	stripped, err := filtering.Strip(raw)
	if err != nil {
		return err
	}
	if err := os.WriteFile(a.servicesPath(), stripped, 0o644); err != nil {
		return err
	}
	cat, err := filtering.ParseCatalog(stripped)
	if err != nil {
		return err
	}
	a.catalog.Store(cat)
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.rebuild(a.cfg.Load())
}

// RemoveList deletes a list's cached file and status.
func (a *App) RemoveList(id uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.status, id)
	os.Remove(a.listPath(id))
}

// download fetches url (or copies a local path) to dst and returns the
// number of rules in it.
func (a *App) download(ctx context.Context, url, dst string) (int, error) {
	var r io.ReadCloser
	if strings.HasPrefix(url, "/") {
		f, err := os.Open(url)
		if err != nil {
			return 0, err
		}
		r = f
	} else {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return 0, err
		}
		resp, err := a.http.Do(req)
		if err != nil {
			return 0, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return 0, fmt.Errorf("HTTP %s", resp.Status)
		}
		r = resp.Body
	}
	defer r.Close()
	tmp := dst + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, io.LimitReader(r, maxListSize+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > maxListSize {
		err = fmt.Errorf("larger than %d MB", maxListSize>>20)
	}
	if err != nil {
		os.Remove(tmp)
		return 0, err
	}
	b, err := os.ReadFile(tmp)
	if err != nil {
		return 0, err
	}
	return countRules(b), os.Rename(tmp, dst)
}

// countRules counts non-empty, non-comment lines.
func countRules(b []byte) int {
	n := 0
	for len(b) > 0 {
		line := b
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line, b = b[:i], b[i+1:]
		} else {
			b = nil
		}
		line = bytes.TrimSpace(line)
		if len(line) > 0 && line[0] != '!' && line[0] != '#' {
			n++
		}
	}
	return n
}

// Record logs and counts one decision.
func (a *App) Record(e querylog.Entry) {
	a.Log.Add(e)
	a.Stats.Add(e.Time, e.Host, e.ClientIP, e.ClientName, e.Action == "block", e.Service)
}

// RunPersistence flushes the query log and saves statistics periodically
// until ctx ends; call Close afterwards.
func (a *App) RunPersistence(ctx context.Context) {
	go a.Log.Run(ctx)
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := a.Stats.Save(); err != nil {
				log.Printf("save statistics: %v", err)
			}
			a.Routing.Prune(time.Now())
			if err := a.Routing.Save(); err != nil {
				log.Printf("save routing: %v", err)
			}
		}
	}
}

// Close writes pending query log entries, statistics and routing entries.
func (a *App) Close() {
	a.Log.Close()
	if err := a.Stats.Save(); err != nil {
		log.Printf("save statistics: %v", err)
	}
	if err := a.Routing.Save(); err != nil {
		log.Printf("save routing: %v", err)
	}
}

// RunUpdater refreshes stale lists hourly (each list is refetched once its
// copy is older than the update interval) and the services catalog daily.
func (a *App) RunUpdater(ctx context.Context) {
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	lastServices := time.Time{}
	if fi, err := os.Stat(a.servicesPath()); err == nil {
		lastServices = fi.ModTime()
	}
	for {
		if err := a.UpdateLists(ctx, false); err != nil {
			log.Printf("update lists: %v", err)
		}
		if time.Since(lastServices) > 24*time.Hour {
			if err := a.UpdateServices(ctx); err != nil {
				log.Printf("update services: %v", err)
			} else {
				lastServices = time.Now()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
