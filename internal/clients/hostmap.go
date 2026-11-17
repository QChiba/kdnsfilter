// Package clients maps client addresses to MACs and host names using the
// host map that Keenetic writes for its DNS proxy (/var/ndnproxyhostmap.conf).
package clients

import (
	"bufio"
	"encoding/base64"
	"io"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type Host struct {
	IP   netip.Addr `json:"ip"`
	MAC  string     `json:"mac"`
	Name string     `json:"name"`
}

// HostMap is safe for concurrent use; it re-reads the file when it changes,
// checking at most every refreshEvery.
type HostMap struct {
	path         string
	refreshEvery time.Duration

	mu      sync.RWMutex
	byIP    map[netip.Addr]Host
	modTime time.Time
	checked time.Time
}

// Device is one MAC with every address Keenetic currently maps to it.
type Device struct {
	MAC  string       `json:"mac"`
	Name string       `json:"name"`
	IPs  []netip.Addr `json:"ips"` // IPv4 first, then IPv6, each sorted
}

// NewHostMap reads Keenetic's host map. DHCP leases change, so the file is
// re-checked every 10 s.
func NewHostMap(path string) *HostMap {
	return &HostMap{path: path, refreshEvery: 10 * time.Second, byIP: map[netip.Addr]Host{}}
}

// Lookup returns what Keenetic knows about ip.
func (m *HostMap) Lookup(ip netip.Addr) (Host, bool) {
	m.refresh()
	m.mu.RLock()
	defer m.mu.RUnlock()
	h, ok := m.byIP[ip.Unmap()]
	return h, ok
}

// Devices groups the host map by MAC.
func (m *HostMap) Devices() []Device {
	m.refresh()
	m.mu.RLock()
	defer m.mu.RUnlock()
	return devices(m.byIP)
}

func devices(byIP map[netip.Addr]Host) []Device {
	byMAC := map[string]*Device{}
	for _, h := range byIP {
		d := byMAC[h.MAC]
		if d == nil {
			d = &Device{MAC: h.MAC}
			byMAC[h.MAC] = d
		}
		if d.Name == "" {
			d.Name = h.Name
		}
		d.IPs = append(d.IPs, h.IP)
	}
	out := make([]Device, 0, len(byMAC))
	for _, d := range byMAC {
		sort.Slice(d.IPs, func(i, j int) bool {
			a, b := d.IPs[i], d.IPs[j]
			if a.Is4() != b.Is4() {
				return a.Is4()
			}
			return a.Less(b)
		})
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return firstIP(out[i]).Less(firstIP(out[j])) })
	return out
}

func firstIP(d Device) netip.Addr {
	if len(d.IPs) == 0 {
		return netip.Addr{}
	}
	return d.IPs[0]
}

func (m *HostMap) refresh() {
	if m.path == "" {
		return
	}
	m.mu.RLock()
	fresh := time.Since(m.checked) < m.refreshEvery
	m.mu.RUnlock()
	if fresh {
		return
	}
	st, err := os.Stat(m.path)
	if err != nil {
		// Don't retry sooner than refreshEvery even on errors.
		m.mu.Lock()
		m.checked = time.Now()
		m.mu.Unlock()
		return
	}
	// Read and parse without holding the write lock: Lookup runs on the DNS
	// reply path and must never wait for a file read.
	var parsed map[netip.Addr]Host
	var modTime time.Time
	if !st.ModTime().Equal(m.modTime) {
		f, err := os.Open(m.path)
		if err == nil {
			parsed = Parse(f)
			f.Close()
			modTime = st.ModTime()
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checked = time.Now()
	if parsed != nil {
		m.byIP = parsed
		m.modTime = modTime
	}
}

// Parse reads lines like
//
//	host_map 192.168.1.5 02:00:00:00:00:05 0 U3lub2xvZ3lfTEFOMQ
//
// where the last field is the base64 of the URL-encoded host name.
func Parse(r io.Reader) map[netip.Addr]Host {
	out := map[netip.Addr]Host{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || f[0] != "host_map" {
			continue
		}
		ip, err := netip.ParseAddr(f[1])
		if err != nil {
			continue
		}
		h := Host{IP: ip, MAC: strings.ToLower(f[2])}
		if len(f) >= 5 {
			h.Name = decodeName(f[4])
		}
		out[ip] = h
	}
	return out
}

func decodeName(s string) string {
	b, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return ""
	}
	if n, err := url.PathUnescape(string(b)); err == nil {
		return n
	}
	return string(b)
}
