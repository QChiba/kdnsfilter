// Package querylog records DNS decisions: the newest entries in a fixed-size
// in-memory ring, and (when a retention is set) every entry in daily
// JSON-lines files that are deleted once older than the retention.
//
// The ring is updated synchronously in Add, but the disk copy is written by
// the Run goroutine: a reply must not wait for a marshal or a flash write.
// Before Run has started (tests, or when the caller never starts it) Add
// writes synchronously, so a log without Run behaves as a synchronous one.
package querylog

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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

// chanLen is how many entries the writer may fall behind before Add starts
// dropping the disk copy (the ring keeps them anyway). Only a flash stall
// can fill this up.
const chanLen = 256

type Log struct {
	mu        sync.Mutex // ring and settings; locked before wmu everywhere
	enabled   bool
	buf       []Entry
	next      int
	full      bool
	dir       string        // "" = memory only
	retention time.Duration // 0 = memory only

	// Disk writing. When async (Run is running), Add hands entries to ch
	// and the Run goroutine does the writes under wmu.
	wmu     sync.Mutex
	w       *os.File
	bw      *bufio.Writer
	fileDay string
	async   bool
	ch      chan queued
	gen     uint64 // bumped by Clear/Configure: entries of older generations are dropped
	dropped atomic.Uint64
	idle    *sync.Cond // broadcast under mu whenever ch is empty
}

// queued pairs an entry with the generation it was recorded in.
type queued struct {
	e   Entry
	gen uint64
}

// New creates a log keeping size entries in memory and, if dir and
// retention are set, everything on disk for the retention period.
func New(dir string, size int, enabled bool, retention time.Duration) *Log {
	return &Log{buf: make([]Entry, max(size, 1)), enabled: enabled, dir: dir, retention: retention}
}

// Enabled reports whether entries are recorded at all; when it is false the
// hot path can skip work that only the log consumes.
func (l *Log) Enabled() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.enabled
}

// Configure applies new settings; resizing the ring drops its contents
// (entries on disk are kept).
func (l *Log) Configure(size int, enabled bool, retention time.Duration) {
	l.mu.Lock()
	l.enabled, l.retention = enabled, retention
	if size = max(size, 1); size != len(l.buf) {
		l.buf, l.next, l.full = make([]Entry, size), 0, false
	}
	l.gen++ // the writer drops entries queued for settings that no longer hold
	ch := l.ch
	l.mu.Unlock()
	drain(ch)
	if !l.persisting() {
		l.closeFile()
	}
}

func (l *Log) persisting() bool { return l.enabled && l.dir != "" && l.retention > 0 }

func (l *Log) Add(e Entry) {
	l.mu.Lock()
	if !l.enabled {
		l.mu.Unlock()
		return
	}
	l.buf[l.next] = e
	l.next = (l.next + 1) % len(l.buf)
	if l.next == 0 {
		l.full = true
	}
	var ch chan queued
	gen := l.gen
	if l.persisting() {
		if l.async {
			ch = l.ch
		} else {
			// No writer goroutine: write here, briefly.
			l.wmu.Lock()
			l.write(e)
			l.wmu.Unlock()
		}
	}
	l.mu.Unlock()
	if ch != nil {
		select {
		case ch <- queued{e, gen}:
		default:
			l.dropped.Add(1)
		}
	}
}

// write appends e to its day's file. Callers hold wmu. Errors only cost the
// disk copy.
func (l *Log) write(e Entry) {
	day := e.Time.Format(time.DateOnly)
	if day != l.fileDay || l.bw == nil {
		l.closeFile()
		if err := os.MkdirAll(l.dir, 0o755); err != nil {
			return
		}
		f, err := os.OpenFile(filepath.Join(l.dir, day+fileExt), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return
		}
		l.w, l.bw, l.fileDay = f, bufio.NewWriterSize(f, 32<<10), day
	}
	b, err := json.Marshal(&e)
	if err != nil {
		return
	}
	l.bw.Write(append(b, '\n'))
}

// closeFile flushes and closes the current file; callers hold wmu.
func (l *Log) closeFile() {
	if l.bw != nil {
		l.bw.Flush()
		l.w.Close()
		l.w, l.bw, l.fileDay = nil, nil, ""
	}
}

// drain empties a queue without blocking.
func drain(ch chan queued) {
	if ch == nil {
		return
	}
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// Flush waits until every recorded entry has been written to the day file
// and flushed to the OS.
func (l *Log) Flush() {
	l.mu.Lock()
	if l.async {
		for len(l.ch) > 0 {
			l.idle.Wait()
		}
	}
	l.mu.Unlock()
	l.wmu.Lock()
	defer l.wmu.Unlock()
	if l.bw != nil {
		l.bw.Flush()
	}
}

// Close flushes and closes the current file.
func (l *Log) Close() {
	l.Flush()
	l.closeFile()
}

// Clear drops all entries, in memory and on disk.
func (l *Log) Clear() error {
	l.mu.Lock()
	l.gen++
	l.buf, l.next, l.full = make([]Entry, len(l.buf)), 0, false
	ch := l.ch
	l.mu.Unlock()
	drain(ch) // the writer discards other old-generation entries itself
	l.closeFile()
	l.mu.Lock()
	var errs []error
	for _, p := range l.files() {
		errs = append(errs, os.Remove(p))
	}
	l.mu.Unlock()
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

// Run writes queued entries to disk, flushes every few seconds and removes
// expired files hourly; it closes the log when ctx ends. After Run, Add
// hands entries to the writer instead of writing them itself.
func (l *Log) Run(ctx context.Context) {
	l.mu.Lock()
	l.ch = make(chan queued, chanLen)
	l.idle = sync.NewCond(&l.mu)
	l.async = true
	ch := l.ch
	l.mu.Unlock()

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
			if n := l.dropped.Swap(0); n > 0 {
				log.Printf("querylog: the disk writer fell behind, dropped %d entries", n)
			}
			l.Flush()
		case t := <-clean.C:
			l.Cleanup(t)
		case it := <-ch:
			l.mu.Lock()
			ok := l.persisting() && it.gen == l.gen
			l.mu.Unlock()
			if !ok {
				continue
			}
			l.wmu.Lock()
			l.write(it.e)
			l.wmu.Unlock()
			// Wake a Flush waiting for the queue to drain.
			l.mu.Lock()
			if len(ch) == 0 {
				l.idle.Broadcast()
			}
			l.mu.Unlock()
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
	// Entries not yet written may have already left a small ring; make sure
	// the day files are current before scanning them.
	l.Flush()

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
	files := l.files()
	l.mu.Unlock()
	if full() || l.dir == "" {
		return res.page(full())
	}

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
	return q.Search == "" || strings.Contains(strings.ToLower(e.Host), q.Search) ||
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
