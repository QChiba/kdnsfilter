package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/QChiba/kdnsfilter/internal/schedule"
)

// adGuardHome is the subset of AdGuardHome.yaml that is imported.
type adGuardHome struct {
	Filters   []Filter `yaml:"filters"`
	UserRules []string `yaml:"user_rules"`
	Filtering struct {
		ProtectionEnabled  bool            `yaml:"protection_enabled"`
		BlockingMode       string          `yaml:"blocking_mode"`
		BlockedResponseTTL uint32          `yaml:"blocked_response_ttl"`
		SafeSearch         SafeSearch      `yaml:"safe_search"`
		BlockedServices    BlockedServices `yaml:"blocked_services"`
	} `yaml:"filtering"`
	Clients struct {
		Persistent []Client `yaml:"persistent"`
	} `yaml:"clients"`
	QueryLog struct {
		Enabled    bool   `yaml:"enabled"`
		SizeMemory int    `yaml:"size_memory"`
		Interval   string `yaml:"interval"`
	} `yaml:"querylog"`
	Statistics struct {
		Interval string `yaml:"interval"`
	} `yaml:"statistics"`
}

// aghInterval reads an AdGuard Home retention: a duration ("2160h", "30d")
// or, in old configs, a number of days.
func aghInterval(s string) (Duration, bool) {
	if s == "" {
		return 0, false
	}
	if n, err := strconv.Atoi(s); err == nil {
		return Duration(time.Duration(n) * 24 * time.Hour), true
	}
	d, err := schedule.ParseDuration(s)
	return Duration(d), err == nil
}

// ImportAdGuardHome builds a config from an AdGuardHome.yaml on top of the
// defaults: filter lists, user rules, filtering/safe search/blocked services
// settings, persistent clients, query log and statistics retention.
// Upstreams, rewrites and DNS settings are left to Keenetic.
func ImportAdGuardHome(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var a adGuardHome
	if err := yaml.Unmarshal(b, &a); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	c := Default()
	if a.Filters != nil {
		c.Filters = a.Filters
	}
	for _, r := range a.UserRules {
		if strings.TrimSpace(r) != "" {
			c.UserRules = append(c.UserRules, r)
		}
	}

	f := &c.Filtering
	// AdGuard's global filtering_enabled has no counterpart: protection is the
	// master switch and clients opt out with their own settings.
	f.ProtectionEnabled = a.Filtering.ProtectionEnabled
	switch a.Filtering.BlockingMode {
	case BlockNXDomain, BlockRefused, BlockNullIP:
		f.BlockingMode = a.Filtering.BlockingMode
	default: // "default", "custom_ip"
		f.BlockingMode = BlockNullIP
	}
	if a.Filtering.BlockedResponseTTL > 0 {
		f.BlockedResponseTTL = a.Filtering.BlockedResponseTTL
	}
	f.SafeSearch = a.Filtering.SafeSearch
	f.BlockedServices = a.Filtering.BlockedServices

	c.Clients = a.Clients.Persistent
	c.QueryLog.Enabled = a.QueryLog.Enabled
	if a.QueryLog.SizeMemory > c.QueryLog.Size {
		c.QueryLog.Size = a.QueryLog.SizeMemory
	}
	if d, ok := aghInterval(a.QueryLog.Interval); ok {
		c.QueryLog.Interval = d
	}
	if d, ok := aghInterval(a.Statistics.Interval); ok {
		c.Stats.Interval = d
	}
	return c, c.Validate()
}
