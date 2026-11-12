package ipset

import (
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestKernel talks to the real kernel; it needs CAP_NET_ADMIN and the ipset
// tool (to check the result), so it only runs with KDF_IPSET_TEST=1, e.g. in
// a throwaway container: docker run --cap-add NET_ADMIN ...
func TestKernel(t *testing.T) {
	if os.Getenv("KDF_IPSET_TEST") != "1" {
		t.Skip("set KDF_IPSET_TEST=1 to run against the kernel")
	}
	list := func(set string) string {
		out, err := exec.Command("ipset", "list", set).CombinedOutput()
		if err != nil {
			t.Fatalf("ipset list %s: %v: %s", set, err, out)
		}
		return string(out)
	}
	c, err := Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	t.Cleanup(func() {
		exec.Command("ipset", "destroy", "kdf_t4").Run()
		exec.Command("ipset", "destroy", "kdf_t6").Run()
	})

	if err := c.Create("kdf_t4", false, time.Hour, 65536); err != nil {
		t.Fatal(err)
	}
	if err := c.Create("kdf_t4", false, 2*time.Hour, 65536); err != nil {
		t.Errorf("re-create (other timeout) must keep the set: %v", err)
	}
	if err := c.Create("kdf_t6", true, time.Hour, 65536); err != nil {
		t.Fatal(err)
	}
	if out := list("kdf_t4"); !strings.Contains(out, "Type: hash:ip") || !strings.Contains(out, "family inet ") ||
		!strings.Contains(out, "timeout 3600") || !strings.Contains(out, "maxelem 65536") {
		t.Errorf("header:\n%s", out)
	}
	if out := list("kdf_t6"); !strings.Contains(out, "family inet6") {
		t.Errorf("v6 header:\n%s", out)
	}

	v4, v6 := netip.MustParseAddr("142.250.1.1"), netip.MustParseAddr("2a00:1450::1")
	if err := c.Add("kdf_t4", v4, 120*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := c.Add("kdf_t4", v4, 600*time.Second); err != nil {
		t.Errorf("re-add must refresh, got %v", err)
	}
	if err := c.Add("kdf_t6", v6, 0); err != nil { // the set's default timeout
		t.Fatal(err)
	}
	if out := list("kdf_t4"); !strings.Contains(out, "142.250.1.1 timeout 59") && !strings.Contains(out, "142.250.1.1 timeout 600") {
		t.Errorf("v4 entry not refreshed to 600 s:\n%s", out)
	}
	if out := list("kdf_t6"); !strings.Contains(out, "2a00:1450::1 timeout 3") {
		t.Errorf("v6 entry:\n%s", out)
	}
	if err := c.Add("kdf_t4", v6, time.Minute); err == nil {
		t.Error("IPv6 address accepted by an IPv4 set")
	}
	if err := c.Del("kdf_t4", v4); err != nil {
		t.Fatal(err)
	}
	if err := c.Del("kdf_t4", v4); err != nil {
		t.Errorf("deleting a missing entry: %v", err)
	}
	if out := list("kdf_t4"); strings.Contains(out, "142.250.1.1") {
		t.Errorf("not deleted:\n%s", out)
	}
	if err := c.Flush("kdf_t6"); err != nil {
		t.Fatal(err)
	}
	if out := list("kdf_t6"); strings.Contains(out, "2a00:1450::1") {
		t.Errorf("not flushed:\n%s", out)
	}
	if err := c.Add("kdf_missing", v4, time.Minute); err == nil {
		t.Error("add to a missing set succeeded")
	}
}
