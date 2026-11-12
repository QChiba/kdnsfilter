package filtering

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// embeddedServices is AdGuard's HostlistsRegistry services.json with icons
// stripped, used until a fresher copy is downloaded.
//
//go:embed services.json
var embeddedServices []byte

type Service struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Group string   `json:"group"`
	Rules []string `json:"rules"`
}

type Catalog struct {
	Services []Service
	byID     map[string]*Service
}

// ParseCatalog parses services.json (icons, if present, are ignored).
func ParseCatalog(b []byte) (*Catalog, error) {
	var raw struct {
		Services []Service `json:"blocked_services"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("parse services: %w", err)
	}
	if len(raw.Services) == 0 {
		return nil, fmt.Errorf("parse services: no services")
	}
	sort.Slice(raw.Services, func(i, j int) bool { return raw.Services[i].Name < raw.Services[j].Name })
	c := &Catalog{Services: raw.Services, byID: make(map[string]*Service, len(raw.Services))}
	for i := range c.Services {
		c.byID[c.Services[i].ID] = &c.Services[i]
	}
	return c, nil
}

// LoadCatalog reads the cached catalog at path, falling back to the
// embedded copy.
func LoadCatalog(path string) *Catalog {
	if b, err := os.ReadFile(path); err == nil {
		if c, err := ParseCatalog(b); err == nil {
			return c
		}
	}
	c, err := ParseCatalog(embeddedServices)
	if err != nil {
		panic(err) // embedded data is validated by tests
	}
	return c
}

// Get returns the service with the given id.
func (c *Catalog) Get(id string) (*Service, bool) {
	s, ok := c.byID[id]
	return s, ok
}

// Strip re-encodes a downloaded services.json without icons for caching.
func Strip(b []byte) ([]byte, error) {
	c, err := ParseCatalog(b)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Services []Service `json:"blocked_services"`
	}{c.Services})
}
