package clients

import (
	"net/netip"
	"strings"
	"testing"
)

// Devices and stale AdGuard client IPs as a Keenetic host map lists them.
func realDevices(t *testing.T) []Device {
	t.Helper()
	in := `host_map 192.168.1.67 02:00:00:00:ab:43 0 UGxheXN0YXRpb241X0xBTg
host_map 192.168.1.65 02:00:00:00:00:41 0 U0xHLVcwOSUyMC0lMjBBbGljZSUyMHRhYmxldA
host_map 192.168.1.240 02:00:00:00:00:f0 0 U0xHLVcwOSUyMC0lMjBCb2IlMjB0YWJsZXQ
host_map 192.168.1.10 02:00:00:00:00:0a 0 TGVub3Zv
host_map fd12:3456:789a:0:e94c:35f2:3136:43cc 02:00:00:00:00:0a 0 TGVub3Zv
host_map 192.168.1.11 aa:aa:aa:aa:aa:aa 0 VFYtU3RhdGlvbiUyMGtpdGNoZW4
host_map 192.168.1.3 02:00:00:00:00:03 0 S2VlbmV0aWMlMjBCdWRkeSUyMDYlMjBTRSUyMDEwMCUyQSUyQSUyQTIwMA
`
	return devices(Parse(strings.NewReader(in)))
}

func TestDevicesGroupsByMAC(t *testing.T) {
	devs := realDevices(t)
	for _, d := range devs {
		if d.MAC == "02:00:00:00:00:0a" {
			if len(d.IPs) != 2 || !d.IPs[0].Is4() || d.Name != "Lenovo" {
				t.Errorf("lenovo: %+v", d)
			}
			return
		}
	}
	t.Fatal("lenovo not found")
}

func TestSuggest(t *testing.T) {
	devs := realDevices(t)
	ip := netip.MustParseAddr
	for _, tc := range []struct {
		client  string
		ips     []netip.Addr
		wantMAC string
		strong  bool
	}{
		// Stale IP 192.168.1.11 now belongs to a TV; the name still finds the console.
		{"playstation5_lan", []netip.Addr{ip("192.168.1.11")}, "02:00:00:00:ab:43", true},
		{"lenovo", []netip.Addr{ip("192.168.1.10")}, "02:00:00:00:00:0a", true},
		{"buddy6se", []netip.Addr{ip("192.168.1.3")}, "02:00:00:00:00:03", true},
		// Name inside a device name, or only a shared word: suggested, but
		// not strong enough for "bind all".
		{"Alice", []netip.Addr{ip("192.168.1.13")}, "02:00:00:00:00:41", false},
		{"bob-samsung", []netip.Addr{ip("192.168.1.16")}, "02:00:00:00:00:f0", false},
	} {
		got := Suggest(tc.client, tc.ips, devs, nil)
		if len(got) == 0 || got[0].MAC != tc.wantMAC || got[0].Strong != tc.strong {
			t.Errorf("%s: %+v", tc.client, got)
		}
	}

	// A clear match comes alone, without weaker alternatives.
	if got := Suggest("lenovo", nil, append(devs, Device{MAC: "00:00:00:00:00:02", Name: "lenovo-laptop"}), nil); len(got) != 1 {
		t.Errorf("strong match should be the only suggestion: %+v", got)
	}
	if got := Suggest("asus", []netip.Addr{ip("192.168.1.4")}, devs, nil); len(got) != 0 {
		t.Errorf("asus has no matching device: %+v", got)
	}
	taken := map[string]bool{"02:00:00:00:ab:43": true}
	if got := Suggest("playstation5_lan", nil, devs, taken); len(got) != 0 {
		t.Errorf("taken MAC suggested: %+v", got)
	}
}
