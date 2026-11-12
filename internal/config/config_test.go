package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const aghYAML = `
http:
  address: 0.0.0.0:8180
users:
  - name: admin
    password: $2a$10$abcdefghijklmnopqrstuuJ8m0o3U7kM6n9oQ1n2b3c4d5e6f7g8h
filters:
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
    name: AdGuard DNS filter
    id: 1
user_rules:
  - '||tracking.example.com^$important'
  - ""
filtering:
  protection_enabled: true
  filtering_enabled: true
  blocking_mode: nxdomain
  blocked_response_ttl: 10
  safe_search:
    enabled: false
    google: true
  blocked_services:
    schedule:
      time_zone: UTC
    ids: []
clients:
  persistent:
    - name: kid
      ids: [192.168.1.16]
      use_global_settings: false
      filtering_enabled: true
      safe_search: {enabled: true, google: true, youtube: true}
      use_global_blocked_services: false
      blocked_services:
        schedule:
          time_zone: Europe/Moscow
          mon: {start: 9h, end: 22h}
        ids: [youtube, tiktok]
querylog:
  enabled: true
  size_memory: 1000
  interval: 30d
statistics:
  interval: 1
`

func TestImportAdGuardHome(t *testing.T) {
	path := filepath.Join(t.TempDir(), "AdGuardHome.yaml")
	if err := os.WriteFile(path, []byte(aghYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := ImportAdGuardHome(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTP.Address != "0.0.0.0:8190" || len(c.HTTP.AllowedHosts) != 1 {
		t.Errorf("http (users are not imported, the UI has no login): %+v", c.HTTP)
	}
	if time.Duration(c.QueryLog.Interval) != 30*24*time.Hour || time.Duration(c.Stats.Interval) != 24*time.Hour {
		t.Errorf("retention: querylog %s, statistics %s", c.QueryLog.Interval, c.Stats.Interval)
	}
	if len(c.Filters) != 1 || c.Filters[0].ID != 1 || !c.Filters[0].Enabled {
		t.Errorf("filters: %+v", c.Filters)
	}
	if len(c.UserRules) != 1 {
		t.Errorf("user rules (empty lines dropped): %q", c.UserRules)
	}
	if c.Filtering.BlockingMode != BlockNXDomain || !c.Filtering.ProtectionEnabled {
		t.Errorf("filtering: %+v", c.Filtering)
	}
	if len(c.Clients) != 1 {
		t.Fatalf("clients: %+v", c.Clients)
	}
	kid := c.Clients[0]
	if kid.UseGlobalSettings || !kid.SafeSearch.Enabled || !kid.SafeSearch.YouTube ||
		kid.UseGlobalBlockedServices || len(kid.BlockedServices.IDs) != 2 {
		t.Errorf("client: %+v", kid)
	}
	if s := kid.BlockedServices.Schedule; s == nil || s.Mon == nil || time.Duration(s.Mon.End) != 22*time.Hour {
		t.Errorf("schedule: %+v", s)
	}

	// Save and load back.
	out := filepath.Join(t.TempDir(), "kdnsfilter.yaml")
	if err := c.Save(out); err != nil {
		t.Fatal(err)
	}
	back, err := Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if back.Clients[0].BlockedServices.Schedule.Mon.Start != kid.BlockedServices.Schedule.Mon.Start {
		t.Error("schedule lost in save/load round trip")
	}
}

func TestValidate(t *testing.T) {
	c := Default()
	c.Filters = append(c.Filters, Filter{ID: 1, Name: "dup"})
	c.Filtering.BlockingMode = "bogus"
	c.NFQueue.Destinations = []string{"192.168.1.10", "fd00::/64", "nope"}
	c.Stats.Interval = 0
	if err := c.Validate(); err == nil {
		t.Fatal("expected errors")
	}
	if c.NextFilterID() != 2 {
		t.Errorf("NextFilterID = %d", c.NextFilterID())
	}
}
