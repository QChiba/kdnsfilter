package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/QChiba/kdnsfilter/internal/app"
	"github.com/QChiba/kdnsfilter/internal/config"
	"github.com/QChiba/kdnsfilter/internal/querylog"
)

func newServer(t *testing.T) (*httptest.Server, *app.App) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir, cfg.Hostmap, cfg.Filters = dir, "", nil
	a, err := app.New(filepath.Join(dir, "c.yaml"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(a, "test").Handler())
	t.Cleanup(srv.Close)
	return srv, a
}

func do(t *testing.T, c *http.Client, method, url, body string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var v map[string]any
	json.NewDecoder(resp.Body).Decode(&v)
	return resp, v
}

func TestNoLoginGuardsAndQuickRule(t *testing.T) {
	srv, a := newServer(t)
	c := http.DefaultClient

	if r, v := do(t, c, "GET", srv.URL+"/api/status", ""); r.StatusCode != http.StatusOK || v["version"] != "test" {
		t.Fatalf("status without login: %d %v", r.StatusCode, v)
	}

	// DNS rebinding: requests for a public name pointed at the router are refused.
	for host, want := range map[string]int{
		"evil.example.com": http.StatusMisdirectedRequest,
		"192.168.1.1:8190": http.StatusOK,
		"router":           http.StatusOK,
		"router.lan":       http.StatusOK,
		"my.keenetic.net":  http.StatusOK, // allowed_hosts default
		"[fd12::1]:8190":   http.StatusOK,
	} {
		req, _ := http.NewRequest("GET", srv.URL+"/api/status", nil)
		req.Host = host
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("Host %s: %d, want %d", host, resp.StatusCode, want)
		}
	}

	// Mutations must be JSON.
	req, _ := http.NewRequest("POST", srv.URL+"/api/user_rules/quick", strings.NewReader("host=x.example&action=block"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if resp, _ := c.Do(req); resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("form post accepted: %d", resp.StatusCode)
	}

	if r, v := do(t, c, "POST", srv.URL+"/api/user_rules/quick", `{"host":"Tracker.Example.","action":"block"}`); r.StatusCode != http.StatusOK {
		t.Fatalf("quick block: %d %v", r.StatusCode, v)
	}
	if r, _ := do(t, c, "POST", srv.URL+"/api/user_rules/quick", `{"host":"tracker.example","action":"allow"}`); r.StatusCode != http.StatusOK {
		t.Fatal("quick allow")
	}
	if got := a.Config().UserRules; len(got) != 1 || got[0] != "@@||tracker.example^" {
		t.Errorf("rules after block then allow: %q", got)
	}
	if r, _ := do(t, c, "POST", srv.URL+"/api/user_rules/quick", `{"host":"bad host^","action":"block"}`); r.StatusCode != http.StatusBadRequest {
		t.Error("bad host accepted")
	}
}

func TestStatsAndQuerylogEndpoints(t *testing.T) {
	srv, a := newServer(t)
	c := http.DefaultClient
	now := time.Now()
	for i, act := range []string{"pass", "block", "pass"} {
		a.Record(querylog.Entry{Time: now.Add(time.Duration(i) * time.Second), Host: "h.example", ClientIP: "192.168.1.10", Action: act})
	}
	if _, v := do(t, c, "GET", srv.URL+"/api/stats", ""); v["total"] != 3.0 || v["blocked"] != 1.0 || v["interval"] != "7d" {
		t.Errorf("stats: %v", v)
	}

	// Cursor paging through the query log.
	resp, err := http.Get(srv.URL + "/api/querylog?limit=2")
	if err != nil {
		t.Fatal(err)
	}
	var page querylogPage
	json.NewDecoder(resp.Body).Decode(&page)
	resp.Body.Close()
	if len(page.Entries) != 2 || !page.More || page.NextBefore == nil {
		t.Fatalf("first page: %+v", page)
	}
	resp, _ = http.Get(srv.URL + "/api/querylog?limit=2&before=" + url.QueryEscape(page.NextBefore.Format(time.RFC3339Nano)))
	var next querylogPage
	json.NewDecoder(resp.Body).Decode(&next)
	resp.Body.Close()
	if len(next.Entries) != 1 || next.Entries[0].Action != "pass" || next.More {
		t.Errorf("second page: %+v", next)
	}

	// Retention settings round-trip and validation.
	_, s := do(t, c, "GET", srv.URL+"/api/settings", "")
	s["querylog_interval"], s["stats_interval"] = "30d", "24h"
	body, _ := json.Marshal(s)
	if r, v := do(t, c, "PUT", srv.URL+"/api/settings", string(body)); r.StatusCode != http.StatusOK {
		t.Fatalf("settings: %v", v)
	}
	if cfg := a.Config(); time.Duration(cfg.QueryLog.Interval) != 30*24*time.Hour || time.Duration(cfg.Stats.Interval) != 24*time.Hour {
		t.Errorf("retention not applied: %s %s", cfg.QueryLog.Interval, cfg.Stats.Interval)
	}
	s["stats_interval"] = "0"
	body, _ = json.Marshal(s)
	if r, _ := do(t, c, "PUT", srv.URL+"/api/settings", string(body)); r.StatusCode != http.StatusBadRequest {
		t.Error("statistics retention 0 accepted")
	}

	if r, _ := do(t, c, "POST", srv.URL+"/api/stats/reset", `{}`); r.StatusCode != http.StatusOK {
		t.Fatal("reset")
	}
	if _, v := do(t, c, "GET", srv.URL+"/api/stats", ""); v["total"] != 0.0 {
		t.Errorf("after reset: %v", v["total"])
	}
	if r, _ := do(t, c, "POST", srv.URL+"/api/querylog/clear", `{}`); r.StatusCode != http.StatusOK {
		t.Fatal("clear")
	}
	if len(a.Log.Find(querylog.Query{}).Entries) != 0 {
		t.Error("query log not cleared")
	}
}

func TestClientsLiveAddressesAndSuggestions(t *testing.T) {
	dir := t.TempDir()
	hostmap := filepath.Join(dir, "hostmap.conf")
	// Console moved to .67 by DHCP; the laptop has an IPv4 and an IPv6 address.
	err := os.WriteFile(hostmap, []byte(`host_map 192.168.1.67 02:00:00:00:ab:43 0 UGxheXN0YXRpb241X0xBTg
host_map 192.168.1.10 02:00:00:00:00:0a 0 TGVub3Zv
host_map fd12::5 02:00:00:00:00:0a 0 TGVub3Zv
`), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.DataDir, cfg.Hostmap, cfg.Filters = dir, hostmap, nil
	cfg.Clients = []config.Client{
		{Name: "playstation5_lan", IDs: []string{"192.168.1.11"}},
		{Name: "lenovo", IDs: []string{"02:00:00:00:00:0a"}},
	}
	a, err := app.New(filepath.Join(dir, "c.yaml"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(a, "test").Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/clients")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got struct {
		Clients []clientView `json:"clients"`
		Known   []deviceView `json:"known"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	ps, lenovo := got.Clients[0], got.Clients[1]
	if !ps.IPOnly || len(ps.Suggestions) != 1 || ps.Suggestions[0].MAC != "02:00:00:00:ab:43" || !ps.Suggestions[0].Strong {
		t.Errorf("console: %+v", ps)
	}
	if lenovo.IPOnly || len(lenovo.Suggestions) != 0 || len(lenovo.Addresses) != 2 || lenovo.Addresses[0] != "192.168.1.10" {
		t.Errorf("lenovo: %+v", lenovo)
	}
	for _, d := range got.Known {
		if d.MAC == "02:00:00:00:ab:43" && d.Client != "" {
			t.Errorf("console must not be attributed via the stale IP: %+v", d)
		}
		if d.MAC == "02:00:00:00:00:0a" && d.Client != "lenovo" {
			t.Errorf("lenovo device: %+v", d)
		}
	}
}

func TestStaticUI(t *testing.T) {
	srv, _ := newServer(t)
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Errorf("index: %d %v", resp.StatusCode, resp.Header)
	}
}
