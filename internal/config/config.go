// Package config holds the on-disk YAML configuration. Client, blocked
// services and safe search sections use AdGuard Home's shapes so its config
// can be imported nearly verbatim.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/QChiba/kdnsfilter/internal/schedule"
)

// Blocking modes for blocked domains.
const (
	BlockNXDomain = "nxdomain" // NXDOMAIN with SOA for negative caching
	BlockNullIP   = "null_ip"  // 0.0.0.0 / :: for A/AAAA, empty NOERROR otherwise
	BlockRefused  = "refused"
)

type Config struct {
	HTTP      HTTP      `yaml:"http"`
	NFQueue   NFQueue   `yaml:"nfqueue"`
	Filtering Filtering `yaml:"filtering"`
	Routing   Routing   `yaml:"routing"`
	Filters   []Filter  `yaml:"filters"`
	UserRules []string  `yaml:"user_rules"`
	Clients   []Client  `yaml:"clients"`
	QueryLog  QueryLog  `yaml:"querylog"`
	Stats     Stats     `yaml:"statistics"`
	Hostmap   string    `yaml:"hostmap"`  // Keenetic ndnproxy host map, for client names
	Resolver  string    `yaml:"resolver"` // used to resolve safe search targets
	DataDir   string    `yaml:"data_dir"`
	// DomainInfo is an optional domain info service (e.g. http://192.168.1.5:8080) the
	// query log asks about companies and apps; empty turns that off.
	DomainInfo  string `yaml:"domain_info"`
	ServicesURL string `yaml:"services_url"`
}

// HTTP configures the web UI. It has no login (the router's LAN is the
// trust boundary); requests must address the router by IP, a single-label
// name, a .local/.lan name or one of AllowedHosts, which blocks DNS
// rebinding attacks from web pages.
type HTTP struct {
	Address      string   `yaml:"address"`
	AllowedHosts []string `yaml:"allowed_hosts"`
}

type NFQueue struct {
	Queue uint16 `yaml:"queue"`
	// Destinations limits interception to these client addresses/prefixes
	// (for testing); empty means all DNS replies leaving the router.
	Destinations []string `yaml:"destinations"`
	// ManageFirewall makes the app add/remove its iptables rules itself.
	ManageFirewall bool `yaml:"manage_firewall"`
}

// Filtering holds the global settings. ProtectionEnabled is the master switch;
// clients using the global settings are always filtered while it is on, and a
// client can opt out with its own settings.
type Filtering struct {
	ProtectionEnabled  bool            `yaml:"protection_enabled"`
	BlockingMode       string          `yaml:"blocking_mode"`
	BlockedResponseTTL uint32          `yaml:"blocked_response_ttl"`
	SafeSearch         SafeSearch      `yaml:"safe_search"`
	BlockedServices    BlockedServices `yaml:"blocked_services"`
	UpdateInterval     Duration        `yaml:"update_interval"`
	// Rewrites answer for every client, whatever its filtering settings.
	Rewrites []Rewrite `yaml:"rewrites"`
}

type SafeSearch struct {
	Enabled    bool `yaml:"enabled" json:"enabled"`
	Bing       bool `yaml:"bing" json:"bing"`
	DuckDuckGo bool `yaml:"duckduckgo" json:"duckduckgo"`
	Ecosia     bool `yaml:"ecosia" json:"ecosia"`
	Google     bool `yaml:"google" json:"google"`
	Pixabay    bool `yaml:"pixabay" json:"pixabay"`
	Yandex     bool `yaml:"yandex" json:"yandex"`
	YouTube    bool `yaml:"youtube" json:"youtube"`
}

// BlockedServices blocks the listed services except while Schedule
// contains the current time (AdGuard Home's "pause" semantics).
type BlockedServices struct {
	IDs      []string         `yaml:"ids" json:"ids"`
	Schedule *schedule.Weekly `yaml:"schedule,omitempty" json:"schedule,omitempty"`
}

type Filter struct {
	ID      uint64 `yaml:"id" json:"id"`
	Name    string `yaml:"name" json:"name"`
	URL     string `yaml:"url" json:"url"`
	Enabled bool   `yaml:"enabled" json:"enabled"`
}

type Client struct {
	Name string `yaml:"name" json:"name"`
	// IDs are IP addresses, CIDR prefixes or MAC addresses.
	IDs                      []string        `yaml:"ids" json:"ids"`
	UseGlobalSettings        bool            `yaml:"use_global_settings" json:"use_global_settings"`
	FilteringEnabled         bool            `yaml:"filtering_enabled" json:"filtering_enabled"`
	SafeSearch               SafeSearch      `yaml:"safe_search" json:"safe_search"`
	UseGlobalBlockedServices bool            `yaml:"use_global_blocked_services" json:"use_global_blocked_services"`
	BlockedServices          BlockedServices `yaml:"blocked_services" json:"blocked_services"`
}

type QueryLog struct {
	Enabled bool `yaml:"enabled"`
	Size    int  `yaml:"size"` // newest entries kept in memory
	// Interval is how long entries are kept on disk; 0 keeps only Size
	// entries in memory.
	Interval Duration `yaml:"interval"`
}

// Stats keeps statistics for Interval; they survive restarts.
type Stats struct {
	Interval Duration `yaml:"interval"`
}

// Retention limits for the query log and statistics.
const (
	MinStatsInterval = time.Hour
	MaxRetention     = 365 * 24 * time.Hour
)

// Duration is a time.Duration that (un)marshals as "24h".
type Duration = schedule.Duration

// Default returns a config with sensible defaults for a Keenetic router.
func Default() *Config {
	return &Config{
		HTTP:    HTTP{Address: "0.0.0.0:8190", AllowedHosts: []string{"my.keenetic.net"}},
		NFQueue: NFQueue{Queue: 4242, ManageFirewall: true},
		Filtering: Filtering{
			ProtectionEnabled:  true,
			BlockingMode:       BlockNXDomain,
			BlockedResponseTTL: 10,
			SafeSearch:         SafeSearch{Bing: true, DuckDuckGo: true, Google: true, Pixabay: true, Yandex: true, YouTube: true},
			UpdateInterval:     Duration(24 * time.Hour),
		},
		Filters: []Filter{{
			ID: 1, Name: "AdGuard DNS filter", Enabled: true,
			URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
		}},
		Routing: Routing{
			MinTimeout: Duration(DefaultRouteTimeout),
			TProxy:     TProxy{Mark: DefaultTProxyMark, Table: DefaultTProxyTable},
		},
		QueryLog:    QueryLog{Enabled: true, Size: 5000, Interval: Duration(7 * 24 * time.Hour)},
		Stats:       Stats{Interval: Duration(7 * 24 * time.Hour)},
		Hostmap:     "/var/ndnproxyhostmap.conf",
		Resolver:    "127.0.0.1:53",
		DataDir:     "/opt/var/kdnsfilter",
		ServicesURL: "https://adguardteam.github.io/HostlistsRegistry/assets/services.json",
	}
}

// Load reads path on top of the defaults.
func Load(path string) (*Config, error) {
	c := Default()
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for i := range c.Routing.Lists {
		c.Routing.Lists[i].Normalize()
	}
	return c, c.Validate()
}

// Save writes the config atomically.
func (c *Config) Save(path string) error {
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (c *Config) Validate() error {
	var errs []error
	switch c.Filtering.BlockingMode {
	case BlockNXDomain, BlockNullIP, BlockRefused:
	default:
		errs = append(errs, fmt.Errorf("blocking_mode %q: want nxdomain, null_ip or refused", c.Filtering.BlockingMode))
	}
	if d := time.Duration(c.QueryLog.Interval); d < 0 || d > MaxRetention {
		errs = append(errs, fmt.Errorf("querylog.interval %s: want 0 (memory only) up to 365d", c.QueryLog.Interval))
	}
	if d := time.Duration(c.Stats.Interval); d < MinStatsInterval || d > MaxRetention {
		errs = append(errs, fmt.Errorf("statistics.interval %s: want 1h up to 365d", c.Stats.Interval))
	}
	if err := c.Filtering.BlockedServices.Schedule.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("global blocked services schedule: %w", err))
	}
	for _, d := range c.NFQueue.Destinations {
		if _, err := ParsePrefix(d); err != nil {
			errs = append(errs, fmt.Errorf("nfqueue destination: %w", err))
		}
	}
	ids := map[uint64]bool{0: true} // 0 is reserved for user rules
	for _, f := range c.Filters {
		if ids[f.ID] {
			errs = append(errs, fmt.Errorf("filter %q: duplicate or reserved id %d", f.Name, f.ID))
		}
		ids[f.ID] = true
	}
	for _, cl := range c.Clients {
		if err := cl.Validate(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := ValidateRewrites(c.Filtering.Rewrites); err != nil {
		errs = append(errs, err)
	}
	if c.DomainInfo != "" {
		u, err := url.Parse(c.DomainInfo)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || (u.Path != "" && u.Path != "/") {
			errs = append(errs, fmt.Errorf("domain_info %q: want http://host:port", c.DomainInfo))
		}
	}
	if err := c.Routing.Validate(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (cl *Client) Validate() error {
	if strings.TrimSpace(cl.Name) == "" {
		return errors.New("client with empty name")
	}
	if err := cl.BlockedServices.Schedule.Validate(); err != nil {
		return fmt.Errorf("client %q schedule: %w", cl.Name, err)
	}
	return nil
}

// ParsePrefix accepts an address or a CIDR prefix.
func ParsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// NextFilterID returns an unused filter list id.
func (c *Config) NextFilterID() uint64 {
	var last uint64
	for _, f := range c.Filters {
		last = max(last, f.ID)
	}
	return last + 1
}
