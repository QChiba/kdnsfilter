package clients

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestParse(t *testing.T) {
	// Lines in the format of a Keenetic host map.
	in := `host_hash_seed = MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAw
host_map 192.168.1.5 02:00:00:00:00:05 0 UHJpbnRlcl9MQU4x
host_map 192.168.1.3 02:00:00:00:00:03 0 S2VlbmV0aWMlMjBCdWRkeSUyMDYlMjBTRSUyMDEwMCUyQSUyQSUyQTIwMA
host_map fd12:3456:789a::ff:fe00:3 02:00:00:00:00:03 0 S2VlbmV0aWMlMjBCdWRkeSUyMDYlMjBTRSUyMDEwMCUyQSUyQSUyQTIwMA
host_map 192.168.1.212 02:00:00:00:00:d4 0 U09OT0ZGJTIwJUQwJTlBJUQxJTgzJUQxJTg1JUQwJUJEJUQxJThG
garbage
`
	m := Parse(strings.NewReader(in))
	if len(m) != 4 {
		t.Fatalf("got %d entries", len(m))
	}
	for ip, want := range map[string]string{
		"192.168.1.5":               "Printer_LAN1",
		"192.168.1.3":               "Keenetic Buddy 6 SE 100***200",
		"fd12:3456:789a::ff:fe00:3": "Keenetic Buddy 6 SE 100***200",
		"192.168.1.212":             "SONOFF Кухня",
	} {
		if got := m[netip.MustParseAddr(ip)].Name; got != want {
			t.Errorf("%s: %q, want %q", ip, got, want)
		}
	}
	if m[netip.MustParseAddr("192.168.1.5")].MAC != "02:00:00:00:00:05" {
		t.Error("mac")
	}
}

func TestConcurrentHostMapRefresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	ip := netip.MustParseAddr("192.0.2.10")
	const mac = "02:00:00:00:00:10"
	if err := os.WriteFile(path, []byte("host_map 192.0.2.10 "+mac+" 0 aG9zdA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewHostMap(path)
	m.refreshEvery = 0
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			for range 10 {
				m.Lookup(ip)
				m.Devices()
			}
		})
	}
	wg.Wait()
	if host, ok := m.Lookup(ip); !ok || host.MAC != mac {
		t.Fatalf("host after refresh: %+v, found %v", host, ok)
	}
}
