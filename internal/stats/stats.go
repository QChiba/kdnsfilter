// Package stats keeps DNS statistics for a configurable retention period and
// persists them across restarts: hourly totals for the whole period (for
// charts) and per-day top lists (queried/blocked domains, clients, services).
// Finished days keep only their top entries so 90 days stay small in RAM.
package stats

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// keepTop is how many entries per top list a finished day keeps.
const keepTop = 100

type hour struct {
	Start   int64  `json:"start"` // unix seconds, start of the hour
	Total   uint64 `json:"total"`
	Blocked uint64 `json:"blocked"`
}

type day struct {
	Start    int64             `json:"start"` // unix seconds, local midnight
	Queried  map[string]uint64 `json:"queried"`
	Blocked  map[string]uint64 `json:"blocked"`
	Clients  map[string]uint64 `json:"clients"`
	Services map[string]uint64 `json:"services"`
}

func newDay(start int64) *day {
	return &day{Start: start, Queried: map[string]uint64{}, Blocked: map[string]uint64{},
		Clients: map[string]uint64{}, Services: map[string]uint64{}}
}

// trim keeps the top entries of each list.
func (d *day) trim() {
	for _, m := range []map[string]uint64{d.Queried, d.Blocked, d.Clients, d.Services} {
		if len(m) <= keepTop {
			continue
		}
		for _, c := range top(m, len(m))[keepTop:] {
			delete(m, c.Name)
		}
	}
}

type Stats struct {
	mu       sync.Mutex
	path     string
	interval time.Duration
	hours    []hour // ascending
	days     []*day // ascending; the last one may be the current day
	names    map[string]string
	dirty    bool
}

type persisted struct {
	Hours []hour            `json:"hours"`
	Days  []*day            `json:"days"`
	Names map[string]string `json:"names"` // client IP -> last known name
}

// New loads statistics from path (empty: memory only). A missing or
// unreadable file starts empty.
func New(path string, interval time.Duration) *Stats {
	s := &Stats{path: path, interval: interval, names: map[string]string{}}
	if path == "" {
		return s
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	var p persisted
	if json.Unmarshal(b, &p) == nil {
		s.hours, s.days = p.Hours, p.Days
		if p.Names != nil {
			s.names = p.Names
		}
		for _, d := range s.days {
			for _, m := range []*map[string]uint64{&d.Queried, &d.Blocked, &d.Clients, &d.Services} {
				if *m == nil {
					*m = map[string]uint64{}
				}
			}
		}
	}
	s.expire(time.Now())
	return s
}

// SetInterval changes the retention and drops data older than it.
func (s *Stats) SetInterval(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.interval = d
	s.expire(time.Now())
	s.dirty = true
}

func midnight(t time.Time) int64 {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location()).Unix()
}

// Add records one answered query.
func (s *Stats) Add(t time.Time, host, clientIP, clientName string, blocked bool, service string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := t.Truncate(time.Hour).Unix()
	if n := len(s.hours); n == 0 || s.hours[n-1].Start < h {
		s.hours = append(s.hours, hour{Start: h})
	}
	hr := &s.hours[len(s.hours)-1]
	hr.Total++

	ds := midnight(t)
	if n := len(s.days); n == 0 || s.days[n-1].Start < ds {
		if n > 0 {
			s.days[n-1].trim()
		}
		s.days = append(s.days, newDay(ds))
		s.expire(t)
	}
	d := s.days[len(s.days)-1]
	d.Queried[host]++
	d.Clients[clientIP]++
	if clientName != "" {
		s.names[clientIP] = clientName
	}
	if blocked {
		hr.Blocked++
		d.Blocked[host]++
		if service != "" {
			d.Services[service]++
		}
	}
	s.dirty = true
}

// expire drops hours and days that ended before the retention window.
func (s *Stats) expire(now time.Time) {
	cut := now.Add(-s.interval).Unix()
	i := 0
	for i < len(s.hours) && s.hours[i].Start+3600 <= cut {
		i++
	}
	s.hours = s.hours[i:]
	j := 0
	for j < len(s.days) && s.days[j].Start+86400 <= cut {
		j++
	}
	s.days = s.days[j:]
}

// Reset clears everything.
func (s *Stats) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hours, s.days, s.names, s.dirty = nil, nil, map[string]string{}, true
}

type Count struct {
	Name  string `json:"name"`
	Count uint64 `json:"count"`
}

type Bucket struct {
	Time    time.Time `json:"time"`
	Total   uint64    `json:"total"`
	Blocked uint64    `json:"blocked"`
}

type Summary struct {
	Interval    string    `json:"interval"`
	Since       time.Time `json:"since"`
	Total       uint64    `json:"total"`
	Blocked     uint64    `json:"blocked"`
	BucketSize  string    `json:"bucket_size"` // "hour" or "day"
	Buckets     []Bucket  `json:"buckets"`     // oldest first, empty ones included
	TopQueried  []Count   `json:"top_queried"`
	TopBlocked  []Count   `json:"top_blocked"`
	TopClients  []Count   `json:"top_clients"`
	TopServices []Count   `json:"top_services"`
}

// Summary aggregates the retention window: hourly buckets up to 48 h,
// daily beyond. Top lists cover the days overlapping the window.
func (s *Stats) Summary(now time.Time, n int) Summary {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire(now)
	sum := Summary{Interval: fmtInterval(s.interval)}
	start := now.Add(-s.interval)
	sum.Since = start

	byDay := s.interval > 48*time.Hour
	sum.BucketSize = "hour"
	// The first bucket is the (partial) hour/day the window starts in, so the
	// buckets add up to the totals.
	step := time.Hour
	first := start.Truncate(time.Hour)
	if byDay {
		sum.BucketSize = "day"
		step = 24 * time.Hour
		first = time.Unix(midnight(start), 0)
	}
	idx := map[int64]int{}
	for t := first; !t.After(now); t = t.Add(step) {
		k := t.Unix()
		if byDay {
			k = midnight(t)
		}
		idx[k] = len(sum.Buckets)
		sum.Buckets = append(sum.Buckets, Bucket{Time: time.Unix(k, 0)})
	}
	for _, h := range s.hours {
		k := h.Start
		if byDay {
			k = midnight(time.Unix(h.Start, 0))
		}
		if i, ok := idx[k]; ok {
			sum.Buckets[i].Total += h.Total
			sum.Buckets[i].Blocked += h.Blocked
		}
		sum.Total += h.Total
		sum.Blocked += h.Blocked
	}

	queried, blocked, clients, services := map[string]uint64{}, map[string]uint64{}, map[string]uint64{}, map[string]uint64{}
	for _, d := range s.days {
		add(queried, d.Queried)
		add(blocked, d.Blocked)
		add(clients, d.Clients)
		add(services, d.Services)
	}
	sum.TopQueried, sum.TopBlocked, sum.TopServices = top(queried, n), top(blocked, n), top(services, n)
	for _, c := range top(clients, n) {
		if name := s.names[c.Name]; name != "" {
			c.Name = name + " (" + c.Name + ")"
		}
		sum.TopClients = append(sum.TopClients, c)
	}
	return sum
}

func add(dst, src map[string]uint64) {
	for k, v := range src {
		dst[k] += v
	}
}

func top(m map[string]uint64, n int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// Save writes the statistics if they changed since the last save.
func (s *Stats) Save() error {
	if s.path == "" {
		return nil
	}
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	b, err := json.Marshal(persisted{Hours: s.hours, Days: s.days, Names: s.names})
	s.dirty = false
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// fmtInterval prints 168h as "7d".
func fmtInterval(d time.Duration) string {
	if d >= 24*time.Hour && d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	return d.String()
}
