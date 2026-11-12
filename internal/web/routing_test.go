package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QChiba/kdnsfilter/internal/app"
	"github.com/QChiba/kdnsfilter/internal/config"
)

func TestRoutingEndpoints(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir, cfg.Hostmap, cfg.Filters = dir, "", nil
	cfg.NFQueue.ManageFirewall = false // no iptables in tests
	a, err := app.New(filepath.Join(dir, "c.yaml"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(a, "test").Handler())
	defer srv.Close()
	c := srv.Client()

	_, v := do(t, c, "GET", srv.URL+"/api/routing", "")
	if v["enabled"] != false || len(v["lists"].([]any)) != 0 || v["min_timeout"] != "3h" {
		t.Fatalf("initial %v", v)
	}
	resp, _ := do(t, c, "PUT", srv.URL+"/api/routing/lists/bypass", // chains are set in the YAML; the UI never sends them

		`{"domains":["YouTube.com","*.googlevideo.com","","!music.youtube.com"],"chain":"MY_PROXY"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create list: %d", resp.StatusCode)
	}
	if resp, v := do(t, c, "PUT", srv.URL+"/api/routing", `{"enabled":true,"min_timeout":"6h"}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("enable: %d %v", resp.StatusCode, v)
	}
	_, v = do(t, c, "GET", srv.URL+"/api/routing", "")
	lists := v["lists"].([]any)
	l := lists[0].(map[string]any)
	if v["enabled"] != true || v["min_timeout"] != "6h" || len(lists) != 1 || l["set4"] != "kdf_bypass4" || l["chain"] != "MY_PROXY" {
		t.Fatalf("after enable %v", v)
	}
	if d := l["domains"].([]any); len(d) != 3 || d[0] != "googlevideo.com" || d[1] != "!music.youtube.com" || d[2] != "youtube.com" {
		t.Errorf("domains not normalized and sorted: %v", d)
	}
	if v["min_timeout_s"] != float64(6*3600) {
		t.Errorf("min_timeout_s %v", v["min_timeout_s"])
	}

	resp, err = c.Get(srv.URL + "/api/routing/lists/bypass/export")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") ||
		!strings.Contains(resp.Header.Get("Content-Disposition"), `filename="kdnsfilter-bypass-`) ||
		len(lines) != 4 || !strings.HasPrefix(lines[0], "# kdnsfilter routing list bypass, 3 domains") ||
		lines[1] != "googlevideo.com" || lines[3] != "youtube.com" {
		t.Errorf("export %d %v:\n%s", resp.StatusCode, resp.Header, body)
	}
	if resp, _ := do(t, c, "GET", srv.URL+"/api/routing/lists/nope/export", ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("export of a missing list: %d", resp.StatusCode)
	}
	_, v = do(t, c, "GET", srv.URL+"/api/check?host=rr1.googlevideo.com", "")
	if v["route"] != "bypass" {
		t.Errorf("check %v", v)
	}
	_, v = do(t, c, "GET", srv.URL+"/api/check?host=music.youtube.com", "")
	if v["route"] != "" {
		t.Errorf("exception routed: %v", v)
	}

	if resp, _ := do(t, c, "PUT", srv.URL+"/api/routing/lists/bypass", `{"domains":["not a domain"]}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad domain accepted: %d", resp.StatusCode)
	}
	if resp, _ := do(t, c, "PUT", srv.URL+"/api/routing", `{"enabled":true,"min_timeout":"5s"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("short lifetime accepted: %d", resp.StatusCode)
	}
	if got := a.Config().Routing.Lists[0].Domains; len(got) != 3 {
		t.Errorf("rejected change applied: %v", got)
	}
}
