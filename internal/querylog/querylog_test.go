package querylog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRingOnly(t *testing.T) {
	l := New("", 3, true, 0)
	now := time.Now()
	for i := range 5 {
		action := "pass"
		if i%2 == 0 {
			action = "block"
		}
		l.Add(Entry{Time: now.Add(time.Duration(i) * time.Second), Host: fmt.Sprintf("h%d.example", i), ClientIP: "192.168.1.10", Action: action})
	}
	got := l.Find(Query{}).Entries
	if len(got) != 3 || got[0].Host != "h4.example" || got[2].Host != "h2.example" {
		t.Fatalf("ring order: %+v", got)
	}
	if b := l.Find(Query{Action: "block"}).Entries; len(b) != 2 {
		t.Errorf("block filter: %d", len(b))
	}
	if b := l.Find(Query{Search: "h3"}).Entries; len(b) != 1 {
		t.Errorf("search: %d", len(b))
	}
	if b := l.Find(Query{Limit: 1, Before: got[0].Time}).Entries; len(b) != 1 || b[0].Host != "h3.example" {
		t.Errorf("cursor paging: %+v", b)
	}
	l.Configure(3, false, 0)
	l.Add(Entry{Time: now, Host: "ignored"})
	if b := l.Find(Query{Search: "ignored"}).Entries; len(b) != 0 {
		t.Error("disabled log recorded an entry")
	}
}

func TestPersistedAcrossRestartAndPaging(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 10, 21, 23, 59, 50, 0, time.Local)
	l := New(dir, 4, true, 72*time.Hour)
	for i := range 20 { // spans midnight -> two day files
		l.Add(Entry{Time: base.Add(time.Duration(i) * time.Second), Host: fmt.Sprintf("q%02d.example", i), Action: "pass"})
	}
	l.Close()
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if len(files) != 2 {
		t.Fatalf("day files: %v", files)
	}

	// After a restart the ring is empty: everything comes from disk.
	l2 := New(dir, 4, true, 72*time.Hour)
	var all []Entry
	var before time.Time
	for {
		page := l2.Find(Query{Limit: 6, Before: before}).Entries
		if len(page) == 0 {
			break
		}
		all = append(all, page...)
		before = page[len(page)-1].Time
	}
	if len(all) != 20 || all[0].Host != "q19.example" || all[19].Host != "q00.example" {
		t.Fatalf("paged %d entries: first %v last %v", len(all), all[0].Host, all[len(all)-1].Host)
	}

	// New entries: newest from memory, older ones from disk, no duplicates.
	l2.Add(Entry{Time: base.Add(time.Minute), Host: "new.example", Action: "block"})
	got := l2.Find(Query{Limit: 3}).Entries
	if len(got) != 3 || got[0].Host != "new.example" || got[1].Host != "q19.example" || got[2].Host != "q18.example" {
		t.Errorf("memory+disk: %+v", got)
	}
	if b := l2.Find(Query{Action: "block", Limit: 50}).Entries; len(b) != 1 {
		t.Errorf("filtered search across memory and disk: %d", len(b))
	}

	// Retention removes whole expired days; Clear removes everything.
	l2.Cleanup(base.Add(4 * 24 * time.Hour))
	if files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl")); len(files) != 1 {
		t.Errorf("after cleanup: %v (the open day file must stay)", files)
	}
	if err := l2.Clear(); err != nil {
		t.Fatal(err)
	}
	if files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl")); len(files) != 0 || len(l2.Find(Query{}).Entries) != 0 {
		t.Errorf("after clear: %v", files)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Error("log dir removed")
	}
}

func TestScanBackward(t *testing.T) {
	dir := t.TempDir()
	defer func(b int64) { scanBlock = b }(scanBlock)
	for _, content := range []string{
		"a\nbb\nccc\n",
		"first\nsecond\nno-trailing-newline",
		"\n\nx\n\n",
		"one-single-line-longer-than-any-block\n",
		"",
	} {
		p := filepath.Join(dir, "f")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		var want []string
		for _, l := range strings.Split(content, "\n") {
			if l != "" {
				want = append([]string{l}, want...)
			}
		}
		for _, block := range []int64{1, 2, 3, 7, 64 << 10} {
			scanBlock = block
			var got []string
			if err := scanBackward(p, time.Time{}, func(line []byte) bool { got = append(got, string(line)); return true }); err != nil {
				t.Fatal(err)
			}
			if strings.Join(got, "|") != strings.Join(want, "|") {
				t.Errorf("block %d, %q: got %q want %q", block, content, got, want)
			}
		}
	}
}

// A search with few matches must not read unbounded amounts of log per
// request; paging with Next must still reach every match.
func TestFindBudgetAndContinuation(t *testing.T) {
	dir := t.TempDir()
	defer func(b int) { ScanBudget = b }(ScanBudget)
	base := time.Date(2026, 10, 20, 10, 0, 0, 0, time.Local)
	l := New(dir, 10, true, 30*24*time.Hour)
	for i := range 3000 {
		host, action := fmt.Sprintf("noise%04d.example", i), "pass"
		if i%500 == 0 {
			host, action = fmt.Sprintf("needle%04d.example", i), "rewrite"
		}
		l.Add(Entry{Time: base.Add(time.Duration(i) * time.Minute), Host: host, ClientName: "Lenovo", Action: action})
	}
	l.Close()
	l = New(dir, 10, true, 30*24*time.Hour) // empty ring: everything from disk
	ScanBudget = 20 << 10                   // ~20 KB per request

	for _, q := range []Query{{Search: "needle"}, {Action: "rewrite"}, {Search: "NEEDLE"}} {
		var found []Entry
		requests := 0
		var cursor time.Time
		for {
			requests++
			q.Before = cursor
			r := l.Find(q)
			found = append(found, r.Entries...)
			if !r.More {
				break
			}
			if r.Next.IsZero() || (!cursor.IsZero() && !r.Next.Before(cursor)) {
				t.Fatalf("%+v: cursor did not move back: %v", q, r.Next)
			}
			cursor = r.Next
			if requests > 500 {
				t.Fatal("paging does not terminate")
			}
		}
		if len(found) != 6 || found[0].Host != "needle2500.example" || found[5].Host != "needle0000.example" {
			t.Errorf("%+v: found %d over %d requests: %v", q, len(found), requests, found)
		}
		if requests < 5 {
			t.Errorf("%+v: budget not applied (%d requests)", q, requests)
		}
	}
}

func TestPrefilterNeverRejectsMatches(t *testing.T) {
	e := Entry{Time: time.Now(), Host: "www.example.com", ClientIP: "192.168.1.16", ClientName: "SONOFF Кухня", Action: "block", Route: "bypass"}
	line, _ := json.Marshal(&e)
	for _, q := range []Query{
		{Search: "example"}, {Search: "192.168.1.16"}, {Search: "sonoff"}, {Search: "кухня"},
		{Action: "block"}, {Action: "filtered"}, {Action: "block", Search: "www"},
		{Route: "*"}, {Route: "bypass"}, {Route: "bypass", Search: "example"},
	} {
		q.Search = strings.ToLower(q.Search)
		if matches(&e, q) && !prefilter(q)(line) {
			t.Errorf("prefilter rejected a match for %+v", q)
		}
	}
	if prefilter(Query{Action: "pass"})(line) {
		t.Error("prefilter should reject a blocked line for action=pass")
	}
	if prefilter(Query{Route: "vpn"})(line) {
		t.Error("prefilter should reject a line routed by another list")
	}
}

func TestRouteFilter(t *testing.T) {
	routed := Entry{Host: "a.example", Action: "pass", Route: "bypass"}
	direct := Entry{Host: "b.example", Action: "pass"}
	for _, tc := range []struct {
		q              Query
		routed, direct bool
	}{
		{Query{}, true, true},
		{Query{Route: "*"}, true, false},
		{Query{Route: "bypass"}, true, false},
		{Query{Route: "vpn"}, false, false},
		{Query{Route: "*", Action: "block"}, false, false},
	} {
		if got := matches(&routed, tc.q); got != tc.routed {
			t.Errorf("%+v routed: %v", tc.q, got)
		}
		if got := matches(&direct, tc.q); got != tc.direct {
			t.Errorf("%+v direct: %v", tc.q, got)
		}
	}
}
