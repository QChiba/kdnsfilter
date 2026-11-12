package schedule

import (
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestContains(t *testing.T) {
	var w Weekly
	err := yaml.Unmarshal([]byte(`
time_zone: Europe/Moscow
mon: {start: 9h, end: 23h30m}
`), &w)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Validate(); err != nil {
		t.Fatal(err)
	}
	msk, _ := time.LoadLocation("Europe/Moscow")
	for _, tc := range []struct {
		t    time.Time
		want bool
	}{
		{time.Date(2026, 10, 19, 8, 59, 0, 0, msk), false}, // Monday
		{time.Date(2026, 10, 19, 9, 0, 0, 0, msk), true},
		{time.Date(2026, 10, 19, 23, 29, 0, 0, msk), true},
		{time.Date(2026, 10, 19, 23, 30, 0, 0, msk), false},
		{time.Date(2026, 10, 20, 12, 0, 0, 0, msk), false}, // Tuesday, no window
		// 06:00 UTC Monday is 09:00 Moscow.
		{time.Date(2026, 10, 19, 6, 0, 0, 0, time.UTC), true},
	} {
		if got := w.Contains(tc.t); got != tc.want {
			t.Errorf("Contains(%s) = %v, want %v", tc.t, got, tc.want)
		}
	}

	out, err := yaml.Marshal(&w)
	if err != nil {
		t.Fatal(err)
	}
	var back Weekly
	if err := yaml.Unmarshal(out, &back); err != nil || back.Mon == nil || back.Mon.End != Duration(23*time.Hour+30*time.Minute) {
		t.Fatalf("round trip: %s %v", out, err)
	}
}

func TestDurationString(t *testing.T) {
	for d, want := range map[time.Duration]string{
		24 * time.Hour:                 "24h",
		9*time.Hour + 30*time.Minute:   "9h30m",
		10 * time.Minute:               "10m",
		30 * time.Second:               "30s",
		time.Hour + 30*time.Second:     "1h0m30s",
		2*time.Minute + 30*time.Second: "2m30s",
	} {
		if got := Duration(d).String(); got != want {
			t.Errorf("%v: %q, want %q", time.Duration(d), got, want)
		}
	}
}

func TestParseDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"30d": 30 * 24 * time.Hour, "1d12h": 36 * time.Hour, "2160h": 90 * 24 * time.Hour, "9h30m": 9*time.Hour + 30*time.Minute,
	} {
		if got, err := ParseDuration(in); err != nil || got != want {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"xd", "-1d", "1dfoo", "abc"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if s := Duration(7 * 24 * time.Hour).String(); s != "7d" {
		t.Errorf("7 days printed as %q", s)
	}
}

func TestValidate(t *testing.T) {
	w := Weekly{Tue: &Range{Start: Duration(10 * time.Hour), End: Duration(9 * time.Hour)}}
	if w.Validate() == nil {
		t.Error("expected error for start >= end")
	}
	if (&Weekly{TimeZone: "Mars/Olympus"}).Validate() == nil {
		t.Error("expected error for unknown time zone")
	}
}
