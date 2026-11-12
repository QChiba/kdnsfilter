package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRewriteNormalize(t *testing.T) {
	for _, tc := range []struct{ in, want Rewrite }{
		{Rewrite{Domain: " Media.Home. ", Answer: " 192.168.1.5 "}, Rewrite{Domain: "media.home", Answer: "192.168.1.5"}},
		{Rewrite{Domain: "*.Lan.Example", Answer: "aaaa"}, Rewrite{Domain: "*.lan.example", Answer: "AAAA"}},
		{Rewrite{Domain: "x.example", Answer: "FD00:0::5"}, Rewrite{Domain: "x.example", Answer: "fd00::5"}},
		{Rewrite{Domain: "x.example", Answer: "Example.NET."}, Rewrite{Domain: "x.example", Answer: "example.net"}},
	} {
		got := tc.in
		got.Normalize()
		if got != tc.want {
			t.Errorf("%+v: got %+v, want %+v", tc.in, got, tc.want)
		}
	}
}

func TestValidateRewrites(t *testing.T) {
	on := func(d, a string) Rewrite { return Rewrite{Domain: d, Answer: a, Enabled: true} }
	for _, tc := range []struct {
		name string
		rws  []Rewrite
		err  string // "" = valid
	}{
		{"ok", []Rewrite{on("media.home", "192.168.1.5"), on("media.home", "AAAA"), on("*.lan", "media.home")}, ""},
		{"bad domain", []Rewrite{on("bad domain", "192.168.1.5")}, "want a domain"},
		{"bare wildcard", []Rewrite{on("*.", "192.168.1.5")}, "want a domain"},
		{"bad answer", []Rewrite{on("x.example", "not valid!")}, "want an IP address"},
		{"self", []Rewrite{on("x.example", "x.example")}, "points to itself"},
		{"cname and ip", []Rewrite{on("x.example", "y.example"), on("x.example", "192.168.1.5")}, "can't be combined"},
		{"cname and disabled ip", []Rewrite{on("x.example", "y.example"), {Domain: "x.example", Answer: "192.168.1.5"}}, ""},
	} {
		err := ValidateRewrites(tc.rws)
		switch {
		case tc.err == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.err)
		}
	}
}

// AdGuard Home configs from before per-rewrite switches have no "enabled".
func TestRewriteEnabledDefaultsToTrue(t *testing.T) {
	var rws []Rewrite
	src := "- domain: a.example\n  answer: 192.168.1.1\n- domain: b.example\n  answer: 192.168.1.2\n  enabled: false\n"
	if err := yaml.Unmarshal([]byte(src), &rws); err != nil {
		t.Fatal(err)
	}
	if len(rws) != 2 || !rws[0].Enabled || rws[1].Enabled {
		t.Errorf("got %+v", rws)
	}
}
