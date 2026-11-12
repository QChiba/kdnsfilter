package clients

import (
	"net/netip"
	"sort"
	"strings"
	"unicode"
)

// Suggestion proposes binding a client configured by IP to a Keenetic device
// by MAC, so the client keeps working when DHCP hands out another address.
type Suggestion struct {
	MAC     string   `json:"mac"`
	Name    string   `json:"name"`
	IPs     []string `json:"ips"`
	Reasons []string `json:"reasons"`
	Score   int      `json:"score"`
	// Strong means a clear, unambiguous match, offered for "bind all".
	Strong bool `json:"strong"`
}

// genericTokens don't identify a device on their own.
var genericTokens = map[string]bool{"lan": true, "wifi": true, "wlan": true, "eth": true}

// Suggest ranks devices for a client. Devices whose MAC is in taken (already
// bound to some client) are skipped. At most three suggestions are returned.
func Suggest(clientName string, clientIPs []netip.Addr, devs []Device, taken map[string]bool) []Suggestion {
	cn := normalize(clientName)
	ctok := tokens(clientName)
	var out []Suggestion
	for _, d := range devs {
		if taken[d.MAC] {
			continue
		}
		s := Suggestion{MAC: d.MAC, Name: d.Name}
		for _, ip := range d.IPs {
			s.IPs = append(s.IPs, ip.String())
		}
		dn := normalize(d.Name)
		switch {
		case cn != "" && cn == dn:
			s.Score += 4
			s.Reasons = append(s.Reasons, "same name")
		case len(cn) >= 3 && len(dn) >= 3 && (strings.Contains(dn, cn) || strings.Contains(cn, dn)):
			s.Score += 3
			s.Reasons = append(s.Reasons, "similar name")
		default:
			for t := range tokens(d.Name) {
				if ctok[t] {
					s.Score++
					s.Reasons = append(s.Reasons, "name shares “"+t+"”")
				}
			}
		}
		for _, ip := range clientIPs {
			for _, dip := range d.IPs {
				if ip == dip {
					s.Score += 2
					s.Reasons = append(s.Reasons, "has "+ip.String()+" now")
				}
			}
		}
		if s.Score > 0 {
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	// Strong needs the same name, or a similar name plus the client's current
	// address: a person's name inside a device name ("Alice" in "Alice
	// tablet") alone is weak, people have several devices.
	if len(out) > 0 && out[0].Score >= 4 && (len(out) == 1 || out[1].Score < out[0].Score) {
		out[0].Strong = true
		return out[:1] // weaker alternatives are just noise next to a clear match
	}
	if len(out) > 3 {
		out = out[:3]
	}
	return out
}

// normalize keeps lower-case letters and digits: "Playstation5_LAN" -> "playstation5lan".
func normalize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func tokens(s string) map[string]bool {
	out := map[string]bool{}
	for _, t := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		if len([]rune(t)) >= 3 && !genericTokens[t] {
			out[t] = true
		}
	}
	return out
}
