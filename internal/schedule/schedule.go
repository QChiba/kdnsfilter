// Package schedule implements AdGuard Home compatible weekly schedules:
// per-weekday [start, end) windows given as offsets from local midnight.
package schedule

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Range is a window within one day, as offsets from midnight.
type Range struct {
	Start Duration `yaml:"start" json:"start"`
	End   Duration `yaml:"end" json:"end"`
}

// Weekly is a schedule with an optional window per weekday.
type Weekly struct {
	TimeZone string `yaml:"time_zone,omitempty" json:"time_zone,omitempty"`
	Sun      *Range `yaml:"sun,omitempty" json:"sun,omitempty"`
	Mon      *Range `yaml:"mon,omitempty" json:"mon,omitempty"`
	Tue      *Range `yaml:"tue,omitempty" json:"tue,omitempty"`
	Wed      *Range `yaml:"wed,omitempty" json:"wed,omitempty"`
	Thu      *Range `yaml:"thu,omitempty" json:"thu,omitempty"`
	Fri      *Range `yaml:"fri,omitempty" json:"fri,omitempty"`
	Sat      *Range `yaml:"sat,omitempty" json:"sat,omitempty"`
}

func (w *Weekly) day(d time.Weekday) *Range {
	return [...]*Range{w.Sun, w.Mon, w.Tue, w.Wed, w.Thu, w.Fri, w.Sat}[d]
}

// Location returns the schedule's time zone, falling back to local time.
func (w *Weekly) Location() *time.Location {
	if w == nil || w.TimeZone == "" || w.TimeZone == "Local" {
		return time.Local
	}
	loc, err := time.LoadLocation(w.TimeZone)
	if err != nil {
		return time.Local
	}
	return loc
}

// Contains reports whether t falls inside the window for its weekday.
func (w *Weekly) Contains(t time.Time) bool {
	if w == nil {
		return false
	}
	t = t.In(w.Location())
	r := w.day(t.Weekday())
	if r == nil {
		return false
	}
	midnight := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
	off := t.Sub(midnight)
	return off >= time.Duration(r.Start) && off < time.Duration(r.End)
}

// Validate checks that every window lies within one day.
func (w *Weekly) Validate() error {
	if w == nil {
		return nil
	}
	if w.TimeZone != "" && w.TimeZone != "Local" {
		if _, err := time.LoadLocation(w.TimeZone); err != nil {
			return fmt.Errorf("time zone %q: %w", w.TimeZone, err)
		}
	}
	for d := time.Sunday; d <= time.Saturday; d++ {
		r := w.day(d)
		if r == nil {
			continue
		}
		if r.Start < 0 || r.End > Duration(24*time.Hour) || r.Start >= r.End {
			return fmt.Errorf("%s: bad window %s-%s", d, r.Start, r.End)
		}
	}
	return nil
}

// Duration is a time.Duration that (un)marshals as "9h30m".
type Duration time.Duration

// String formats like time.Duration but drops zero minutes/seconds and
// writes multi-day periods in days: "24h", "9h30m", "45s", "7d".
func (d Duration) String() string {
	if day := 24 * time.Hour; time.Duration(d) > day && time.Duration(d)%day == 0 {
		return strconv.Itoa(int(time.Duration(d)/day)) + "d"
	}
	s := time.Duration(d).String()
	if strings.HasSuffix(s, "m0s") {
		s = s[:len(s)-2]
	}
	if strings.HasSuffix(s, "h0m") {
		s = s[:len(s)-2]
	}
	return s
}

func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseDuration(n.Value)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

func (d *Duration) UnmarshalText(b []byte) error {
	v, err := ParseDuration(string(b))
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// ParseDuration is time.ParseDuration plus a leading day count, as AdGuard
// Home writes retention periods: "30d", "1d12h".
func ParseDuration(s string) (time.Duration, error) {
	days, rest, ok := strings.Cut(s, "d")
	if !ok {
		return time.ParseDuration(s)
	}
	n, err := strconv.Atoi(days)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	d := time.Duration(n) * 24 * time.Hour
	if rest != "" {
		r, err := time.ParseDuration(rest)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		d += r
	}
	return d, nil
}
