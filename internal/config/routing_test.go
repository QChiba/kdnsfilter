package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRouteListNormalize(t *testing.T) {
	l := RouteList{Name: "bypass", Domains: []string{
		" YouTube.com ", "*.googlevideo.com", ".ytimg.com.", "# comment", "", "youtube.com", "! Music.YouTube.com",
	}}
	// Sorted by name; an exception sorts with its name.
	x := RouteList{Domains: []string{"!b.com", "b.com", "a.com", "!a.com"}}
	x.Normalize()
	if !slices.Equal(x.Domains, []string{"a.com", "!a.com", "b.com", "!b.com"}) {
		t.Errorf("exceptions: %v", x.Domains)
	}
	l.Normalize()
	want := []string{"googlevideo.com", "!music.youtube.com", "youtube.com", "ytimg.com"}
	if !slices.Equal(l.Domains, want) {
		t.Errorf("got %v\nwant %v", l.Domains, want)
	}
	if v4, v6 := l.SetNames(); v4 != "kdf_bypass4" || v6 != "kdf_bypass6" {
		t.Errorf("sets %s %s", v4, v6)
	}
}

func TestRoutingValidate(t *testing.T) {
	ok := Routing{MinTimeout: Duration(time.Hour), Lists: []RouteList{{Name: "bypass", Chain: "MY_PROXY", Domains: []string{"x.com", "!api.x.com"}}}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]Routing{
		"timeout":   {MinTimeout: Duration(time.Second)},
		"name":      {MinTimeout: Duration(time.Hour), Lists: []RouteList{{Name: "By Pass"}}},
		"duplicate": {MinTimeout: Duration(time.Hour), Lists: []RouteList{{Name: "a"}, {Name: "a"}}},
		"same set":  {MinTimeout: Duration(time.Hour), Lists: []RouteList{{Name: "a", Set4: "s"}, {Name: "b", Set4: "s"}}},
		"set name":  {MinTimeout: Duration(time.Hour), Lists: []RouteList{{Name: "a", Set6: strings.Repeat("x", 32)}}},
		"chain":     {MinTimeout: Duration(time.Hour), Lists: []RouteList{{Name: "a", Chain: "-j ACCEPT"}}},
		"domain":    {MinTimeout: Duration(time.Hour), Lists: []RouteList{{Name: "a", Domains: []string{"http://x.com/"}}}},
	} {
		if err := r.Validate(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestLoadNormalizesRouting(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(p, []byte("routing:\n  enabled: true\n  lists:\n    - name: bypass\n      chain: MY_PROXY\n      domains: [YouTube.com, '*.x.com']\n"), 0o600)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	r := c.Routing
	if !r.Enabled || time.Duration(r.MinTimeout) != DefaultRouteTimeout || !slices.Equal(r.Lists[0].Domains, []string{"x.com", "youtube.com"}) {
		t.Errorf("%+v", r)
	}
}
