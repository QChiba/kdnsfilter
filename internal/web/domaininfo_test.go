package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QChiba/kdnsfilter/internal/config"
)

func TestDomainInfoProxy(t *testing.T) {
	srv, a := newServer(t)
	c := http.DefaultClient

	// Not configured: the popover shows nothing.
	if r, v := do(t, c, "GET", srv.URL+"/api/domaininfo?host=a.example", ""); r.StatusCode != http.StatusOK || v["enabled"] != false {
		t.Fatalf("unconfigured: %d %v", r.StatusCode, v)
	}

	var gotQuery string
	di := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"host": "api.oneme.ru", "domain": "oneme.ru", "company": {"name": "VK"}}`))
	}))
	defer di.Close()
	if err := a.Update(func(c *config.Config) error { c.DomainInfo = di.URL; return nil }); err != nil {
		t.Fatal(err)
	}
	r, v := do(t, c, "GET", srv.URL+"/api/domaininfo?host=api.oneme.ru&page=0", "")
	if r.StatusCode != http.StatusOK || v["enabled"] != true || v["company"].(map[string]any)["name"] != "VK" {
		t.Fatalf("proxied: %d %v", r.StatusCode, v)
	}
	if gotQuery != "host=api.oneme.ru&page=0" {
		t.Errorf("service got %q", gotQuery)
	}
	if v["editor"] != di.URL+"/?host=api.oneme.ru" {
		t.Errorf("editor link %v", v["editor"])
	}

	// The service is down: an error the popover can show, not a hang.
	di.Close()
	if r, _ := do(t, c, "GET", srv.URL+"/api/domaininfo?host=api.oneme.ru", ""); r.StatusCode != http.StatusBadRequest {
		t.Errorf("service down: %d", r.StatusCode)
	}
}

func TestDomainInfoURLValidation(t *testing.T) {
	for u, ok := range map[string]bool{
		"": true, "http://192.168.1.5:8080": true, "https://info.lan": true,
		"192.168.1.5:8080": false, "ftp://x": false, "http://x/api": false,
	} {
		c := config.Default()
		c.DomainInfo = u
		err := c.Validate()
		if got := err == nil || !strings.Contains(err.Error(), "domain_info"); got != ok {
			t.Errorf("%q: valid=%v, want %v (%v)", u, got, ok, err)
		}
	}
}
