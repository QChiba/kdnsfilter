package stats

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestSummaryAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.json")
	s := New(path, 24*time.Hour)
	now := time.Now()
	s.Add(now.Add(-30*time.Hour), "old.example", "192.168.1.9", "", true, "") // outside the window
	s.Add(now.Add(-2*time.Hour), "a.example", "192.168.1.10", "lenovo", false, "")
	s.Add(now.Add(-time.Hour), "ads.example", "192.168.1.10", "lenovo", true, "")
	s.Add(now, "www.tiktok.com", "192.168.1.16", "kid", true, "tiktok")
	s.Add(now, "a.example", "192.168.1.16", "kid", false, "")

	check := func(s *Stats) {
		t.Helper()
		sum := s.Summary(now, 10)
		if sum.Total != 4 || sum.Blocked != 2 {
			t.Errorf("totals %d/%d, want 4/2", sum.Total, sum.Blocked)
		}
		var bt, bb uint64
		for _, b := range sum.Buckets {
			bt += b.Total
			bb += b.Blocked
		}
		if bt != sum.Total || bb != sum.Blocked || sum.BucketSize != "hour" || len(sum.Buckets) < 24 {
			t.Errorf("buckets: %d/%d over %d %s buckets", bt, bb, len(sum.Buckets), sum.BucketSize)
		}
		if len(sum.TopQueried) == 0 || sum.TopQueried[0].Name != "a.example" || sum.TopQueried[0].Count != 2 {
			t.Errorf("top queried: %+v", sum.TopQueried)
		}
		if len(sum.TopServices) != 1 || sum.TopServices[0].Name != "tiktok" {
			t.Errorf("top services: %+v", sum.TopServices)
		}
		found := false
		for _, c := range sum.TopClients {
			found = found || c.Name == "kid (192.168.1.16)"
		}
		if !found {
			t.Errorf("client names: %+v", sum.TopClients)
		}
	}
	check(s)

	// Survives a restart.
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	check(New(path, 24*time.Hour))

	// Shorter retention drops older data; longer switches to daily buckets.
	// Data is kept per hour: an entry counts while its hour overlaps the
	// window, so the expectation depends on the current minute.
	s.SetInterval(90 * time.Minute)
	var want uint64
	for _, ts := range []time.Time{now.Add(-2 * time.Hour), now.Add(-time.Hour), now, now} {
		if ts.Truncate(time.Hour).Add(time.Hour).After(now.Add(-90 * time.Minute)) {
			want++
		}
	}
	if sum := s.Summary(now, 10); sum.Total != want {
		t.Errorf("90m window total %d, want %d", sum.Total, want)
	}
	s.SetInterval(7 * 24 * time.Hour)
	if sum := s.Summary(now, 10); sum.BucketSize != "day" || sum.Interval != "7d" {
		t.Errorf("7d window: %s buckets, interval %q", sum.BucketSize, sum.Interval)
	}

	s.Reset()
	if sum := s.Summary(now, 10); sum.Total != 0 || len(sum.TopQueried) != 0 {
		t.Errorf("after reset: %+v", sum)
	}
}

func TestFinishedDaysKeepTopOnly(t *testing.T) {
	s := New("", 72*time.Hour)
	yesterday := time.Now().Add(-24 * time.Hour)
	for i := range 300 {
		for range i % 7 {
			s.Add(yesterday, fmt.Sprintf("d%03d.example", i), "192.168.1.10", "", false, "")
		}
		s.Add(yesterday, fmt.Sprintf("d%03d.example", i), "192.168.1.10", "", false, "")
	}
	s.Add(time.Now(), "today.example", "192.168.1.10", "", false, "") // rolls the day over
	if n := len(s.days[0].Queried); n != keepTop {
		t.Errorf("finished day keeps %d entries, want %d", n, keepTop)
	}
	// Totals stay exact even though the top lists were trimmed.
	if sum := s.Summary(time.Now(), 300); sum.Total != 1198 {
		t.Errorf("total %d, want 1198", sum.Total)
	}
}
