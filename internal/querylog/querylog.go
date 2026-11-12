// Package querylog records DNS decisions: the newest entries in a fixed-size
// in-memory ring, and (when a retention is set) every entry in daily
// JSON-lines files that are deleted once older than the retention.
package querylog

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Entry struct {
	Time       time.Time `json:"time"`
	ClientIP   string    `json:"client_ip"`
	ClientName string    `json:"client_name"`
	Host       string    `json:"host"`
	QType      string    `json:"qtype"`
	Rcode      string    `json:"rcode"`
	Answers    []string  `json:"answers,omitempty"`
	Action     string    `json:"action"` // pass, block, rewrite
	Reason     string    `json:"reason,omitempty"`
	Rule       string    `json:"rule,omitempty"`
	ListID     uint64    `json:"list_id,omitempty"`
	Service    string    `json:"service,omitempty"`
	CNAME      string    `json:"cname,omitempty"`       // blocked CNAME target
	Route      string    `json:"route,omitempty"`       // routing list the answer's addresses went to
	RouteEntry string    `json:"route_entry,omitempty"` // the list entry that matched
	RouteVia   string    `json:"route_via,omitempty"`   // CNAME target that matched, if the host didn't
	ElapsedUS  int64     `json:"elapsed_us"`
}

const fileExt = ".jsonl"

type Log struct {
	mu        sync.Mutex
	enabled   bool
	buf       []Entry
	next      int
	full      bool
	dir       string        // "" = memory only
	retention time.Duration // 0 = memory only
	f         *os.File
	w         *bufio.Writer
	fileDay   string
}

// New creates a log keeping size entries in memory and, if dir and
// retention are set, everything on disk for the retention period.
func New(dir string, size int, enabled bool, retention time.Duration) *Log {
	return &Log{buf: make([]Entry, max(size, 1)), enabled: enabled, dir: dir, retention: retention}
}

// Configure applies new settings; resizing the ring drops its contents
// (entries on disk are kept).
func (l *Log) Configure(size int, enabled bool, retention time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.enabled, l.retention = enabled, retention
	if size = max(size, 1); size != len(l.buf) {
		l.buf, l.next, l.full = make([]Entry, size), 0, false
	}
	if !l.persisting() {
		l.closeFile()
	}
}

func (l *Log) persisting() bool { return l.enabled && l.dir != "" && l.retention > 0 }

func (l *Log) Add(e Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.enabled {
		return
	}
	l.buf[l.next] = e
	l.next = (l.next + 1) % len(l.buf)
	if l.next == 0 {
		l.full = true
	}
	if l.persisting() {
		l.write(e)
	}
}

// write appends e to its day's file. Errors only cost the disk copy.
func (l *Log) write(e Entry) {
	day := e.Time.Format(time.DateOnly)
	if day != l.fileDay || l.w == nil {
		l.closeFile()
		if err := os.MkdirAll(l.dir, 0o755); err != nil {
			return
		}
		f, err := os.OpenFile(filepath.Join(l.dir, day+fileExt), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return
		}
		l.f, l.w, l.fileDay = f, bufio.NewWriterSize(f, 32<<10), day
	}
	b, err := json.Marshal(&e)
	if err != nil {
		return
	}
	l.w.Write(append(b, '\n'))
}

func (l *Log) closeFile() {
	if l.w != nil {
		l.w.Flush()
		l.f.Close()
		l.f, l.w, l.fileDay = nil, nil, ""
	}
}

// Flush writes buffered entries to disk.
func (l *Log) Flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.w != nil {
		l.w.Flush()
	}
}

// Close flushes and closes the current file.
func (l *Log) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closeFile()
}

// Clear drops all entries, in memory and on disk.
func (l *Log) Clear() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closeFile()
	l.buf, l.next, l.full = make([]Entry, len(l.buf)), 0, false
	var errs []error
	for _, p := range l.files() {
		errs = append(errs, os.Remove(p))
	}
	return errors.Join(errs...)
}

// Cleanup deletes day files that ended before the retention window.
func (l *Log) Cleanup(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.retention <= 0 {
		return
	}
	cut := now.Add(-l.retention)
	for _, p := range l.files() {
		day, err := time.ParseInLocation(time.DateOnly, strings.TrimSuffix(filepath.Base(p), fileExt), time.Local)
		if err == nil && day.Add(24*time.Hour).Before(cut) && filepath.Base(p) != l.fileDay+fileExt {
			os.Remove(p)
		}
	}
}

// files lists day files, newest first.
func (l *Log) files() []string {
	if l.dir == "" {
		return nil
	}
	m, _ := filepath.Glob(filepath.Join(l.dir, "*"+fileExt))
	sort.Sort(sort.Reverse(sort.StringSlice(m)))
	return m
}

// Run flushes every few seconds and removes expired files hourly; it closes
// the log when ctx ends.
func (l *Log) Run(ctx context.Context) {
	flush := time.NewTicker(5 * time.Second)
	clean := time.NewTicker(time.Hour)
	defer flush.Stop()
	defer clean.Stop()
	l.Cleanup(time.Now())
	for {
		select {
		case <-ctx.Done():
			l.Close()
			return
		case <-flush.C:
			l.Flush()
		case t := <-clean.C:
			l.Cleanup(t)
		}
	}
}

type Query struct {
	Search string    // substring of host, client IP or client name
	Action string    // "", "pass", "block", "rewrite", "filtered" (block+rewrite)
	Route  string    // "", "*" (routed by any list) or a routing list name
	Limit  int       // default 100
	Before time.Time // only entries older than this (paging cursor); zero = newest
}

// ScanBudget caps how many bytes of day files one Find reads, so a search
// with few matches over weeks of log can't hog the router's CPU; the caller
// continues from Result.Next.
var ScanBudget = 8 << 20

// Result is one page of Find.
type Result struct {
	Entries []Entry
	// More reports that older entries may match; continue with
	// Query.Before = Next.
	More bool
	Next time.Time
}

// Find returns matching entries, newest first: from memory, then from the
// day files (read backwards, newest first) for entries older than the
// memory ring, examining at most ScanBudget bytes of them.
func (l *Log) Find(q Query) Result {
	q.Search = strings.ToLower(q.Search)
	if q.Limit <= 0 {
		q.Limit = 100
	}
	var res Result
	full := func() bool { return len(res.Entries) >= q.Limit }

	l.mu.Lock()
	var oldest time.Time
	l.each(func(e *Entry) bool {
		oldest = e.Time
		if (q.Before.IsZero() || e.Time.Before(q.Before)) && matches(e, q) {
			res.Entries = append(res.Entries, *e)
		}
		return !full()
	})
	if full() || l.dir == "" {
		l.mu.Unlock()
		return res.page(full())
	}
	if l.w != nil {
		l.w.Flush()
	}
	files := l.files()
	l.mu.Unlock()

	// The ring holds everything newer than its oldest entry; continue below
	// that (or below the cursor, if older).
	bound := q.Before
	if !oldest.IsZero() && (bound.IsZero() || oldest.Before(bound)) {
		bound = oldest
	}
	pre := prefilter(q)
	budget := ScanBudget
	for _, p := range files {
		if !bound.IsZero() {
			day, err := time.ParseInLocation(time.DateOnly, strings.TrimSuffix(filepath.Base(p), fileExt), time.Local)
			if err == nil && !day.Before(bound) {
				continue // the whole file is newer than the cursor
			}
		}
		stopped := false
		scanBackward(p, bound, func(line []byte) bool {
			if budget -= len(line) + 1; budget < 0 {
				// Out of budget: report how far back this page searched.
				var t struct {
					Time time.Time `json:"time"`
				}
				if json.Unmarshal(line, &t) == nil && (res.Next.IsZero() || t.Time.Before(res.Next)) {
					res.Next = t.Time
				}
				res.More, stopped = true, true
				return false
			}
			if !pre(line) {
				return true
			}
			var e Entry
			if json.Unmarshal(line, &e) != nil {
				return true // e.g. a line still being written
			}
			if (bound.IsZero() || e.Time.Before(bound)) && matches(&e, q) {
				res.Entries = append(res.Entries, e)
				if full() {
					stopped = true
					return false
				}
			}
			return true
		})
		if stopped {
			break
		}
	}
	if full() {
		return res.page(true)
	}
	return res
}

// page sets the continuation cursor for a page that ended at its last entry.
func (r Result) page(more bool) Result {
	if more && len(r.Entries) > 0 {
		r.More, r.Next = true, r.Entries[len(r.Entries)-1].Time
	}
	return r
}

// prefilter returns a cheap test on a raw JSON line that rejects lines that
// can't match q, so only candidates are decoded. It may accept lines that
// don't match (matches() decides), but never rejects a matching one.
func prefilter(q Query) func([]byte) bool {
	var action []byte
	switch q.Action {
	case "", "filtered":
	default:
		action = []byte(`"action":"` + q.Action + `"`)
	}
	notPass := []byte(`"action":"pass"`)
	var route []byte
	switch q.Route {
	case "":
	case "*":
		route = []byte(`"route":"`)
	default:
		name, _ := json.Marshal(q.Route)
		route = append([]byte(`"route":`), name...)
	}
	search := []byte(q.Search) // already lower case
	asciiSearch := true
	for _, c := range search {
		if c >= 0x80 {
			asciiSearch = false // case folding of non-ASCII names needs a full decode
		}
	}
	return func(line []byte) bool {
		if action != nil && !bytes.Contains(line, action) {
			return false
		}
		if q.Action == "filtered" && bytes.Contains(line, notPass) {
			return false
		}
		if route != nil && !bytes.Contains(line, route) {
			return false
		}
		if len(search) > 0 && asciiSearch && !containsFoldASCII(line, search) {
			return false
		}
		return true
	}
}

// containsFoldASCII reports whether s contains lower-case sub, ignoring ASCII
// case in s, without allocating.
func containsFoldASCII(s, sub []byte) bool {
	n := len(sub)
outer:
	for i := 0; i+n <= len(s); i++ {
		for j := 0; j < n; j++ {
			c := s[i+j]
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != sub[j] {
				continue outer
			}
		}
		return true
	}
	return false
}

// scanBlock is the read size of scanBackward (a variable for tests).
var scanBlock int64 = 64 << 10

// scanBackward calls fn for each non-empty line of the file that is older
// than before (all lines if zero), last line first, reading fixed-size blocks
// backwards, until fn returns false. Day files are written in time order, so
// newer lines are skipped by a binary search instead of being read. The slice
// passed to fn is only valid during the call.
func scanBackward(path string, before time.Time, fn func(line []byte) bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	pos := st.Size()
	if !before.IsZero() {
		pos = offsetOf(f, pos, before)
	}
	// Both buffers are reused across blocks; buf has room for a block plus a
	// typical carried-over partial line.
	buf := make([]byte, 0, 2*scanBlock)
	var carry []byte // start of a line whose beginning is in an earlier block
	for pos > 0 {
		n := min(scanBlock, pos)
		pos -= n
		buf = buf[:n]
		if _, err := f.ReadAt(buf, pos); err != nil {
			return err
		}
		data := append(buf, carry...)
		end := len(data)
		for i := len(data) - 1; i >= 0; i-- {
			if data[i] != '\n' {
				continue
			}
			if i+1 < end && !fn(data[i+1:end]) {
				return nil
			}
			end = i
		}
		carry = append(carry[:0], data[:end]...)
		buf = data[:0]
	}
	if len(carry) > 0 {
		fn(carry)
	}
	return nil
}

// offsetOf returns the start of the first line at or after t in a
// time-ordered file of size bytes, to within a few KB (the caller still
// checks each line's time).
func offsetOf(f *os.File, size int64, t time.Time) int64 {
	lo, hi := int64(0), size
	for hi-lo > 4096 {
		mid := lo + (hi-lo)/2
		start, lt, ok := lineAt(f, mid)
		if !ok || start >= hi {
			hi = mid
			continue
		}
		if lt.Before(t) {
			lo = start + 1
		} else {
			hi = start
		}
	}
	return hi
}

// lineAt finds the first complete line starting after off and returns its
// start offset and time.
func lineAt(f *os.File, off int64) (int64, time.Time, bool) {
	buf := make([]byte, 16<<10)
	n, _ := f.ReadAt(buf, off)
	buf = buf[:n]
	i := bytes.IndexByte(buf, '\n')
	if i < 0 {
		return 0, time.Time{}, false
	}
	line := buf[i+1:]
	j := bytes.IndexByte(line, '\n')
	if j < 0 {
		return 0, time.Time{}, false
	}
	var e struct {
		Time time.Time `json:"time"`
	}
	if json.Unmarshal(line[:j], &e) != nil {
		return 0, time.Time{}, false
	}
	return off + int64(i) + 1, e.Time, true
}

func matches(e *Entry, q Query) bool {
	switch q.Action {
	case "":
	case "filtered":
		if e.Action == "pass" {
			return false
		}
	default:
		if e.Action != q.Action {
			return false
		}
	}
	switch q.Route {
	case "":
	case "*":
		if e.Route == "" {
			return false
		}
	default:
		if e.Route != q.Route {
			return false
		}
	}
	return q.Search == "" || strings.Contains(e.Host, q.Search) ||
		strings.Contains(e.ClientIP, q.Search) || strings.Contains(strings.ToLower(e.ClientName), q.Search)
}

// Recent calls fn for the entries in memory, newest first, until it returns
// false. fn must not keep e or call back into the log.
func (l *Log) Recent(fn func(e *Entry) bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.each(fn)
}

// each walks memory entries newest first until fn returns false.
func (l *Log) each(fn func(*Entry) bool) {
	n := l.next
	if l.full {
		n = len(l.buf)
	}
	for i := 1; i <= n; i++ {
		if !fn(&l.buf[(l.next-i+len(l.buf))%len(l.buf)]) {
			return
		}
	}
}
