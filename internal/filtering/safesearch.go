package filtering

import (
	"net/netip"
	"strings"

	"github.com/QChiba/kdnsfilter/internal/config"
)

// SafeTarget is where a search engine's hostname is rewritten to: either a
// CNAME to the engine's safe host or a fixed address. Mirrors AdGuard Home's
// safe search rules.
type SafeTarget struct {
	Engine string
	CNAME  string
	IP     netip.Addr
}

var (
	youtubeHosts = set("www.youtube.com", "m.youtube.com", "youtubei.googleapis.com",
		"youtube.googleapis.com", "www.youtube-nocookie.com")
	bingHosts       = set("www.bing.com", "edgeservices.bing.com")
	duckduckgoHosts = set("duckduckgo.com", "start.duckduckgo.com", "www.duckduckgo.com")
	yandexSafeIP    = netip.MustParseAddr("213.180.193.56")
)

func set(s ...string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return m
}

// safeSearch returns the rewrite for host if it's a search engine enabled in ss.
// host must be lower case without the trailing dot.
func safeSearch(host string, ss config.SafeSearch) (SafeTarget, bool) {
	if !ss.Enabled {
		return SafeTarget{}, false
	}
	switch {
	case ss.Google && isGoogleSearch(host):
		return SafeTarget{Engine: "google", CNAME: "forcesafesearch.google.com"}, true
	case ss.YouTube && youtubeHosts[host]:
		return SafeTarget{Engine: "youtube", CNAME: "restrictmoderate.youtube.com"}, true
	case ss.Bing && bingHosts[host]:
		return SafeTarget{Engine: "bing", CNAME: "strict.bing.com"}, true
	case ss.DuckDuckGo && duckduckgoHosts[host]:
		return SafeTarget{Engine: "duckduckgo", CNAME: "safe.duckduckgo.com"}, true
	case ss.Yandex && isYandexSearch(host):
		return SafeTarget{Engine: "yandex", IP: yandexSafeIP}, true
	case ss.Pixabay && host == "pixabay.com":
		return SafeTarget{Engine: "pixabay", CNAME: "safesearch.pixabay.com"}, true
	case ss.Ecosia && host == "www.ecosia.org":
		return SafeTarget{Engine: "ecosia", CNAME: "strict-safe-search.ecosia.org"}, true
	}
	return SafeTarget{}, false
}

// isGoogleSearch matches www.google.<tld>, www.google.co.<cc> and
// www.google.com.<cc>.
func isGoogleSearch(host string) bool {
	tld, ok := strings.CutPrefix(host, "www.google.")
	if !ok {
		return false
	}
	if rest, ok := strings.CutPrefix(tld, "co."); ok {
		return isLabel(rest, 2)
	}
	if rest, ok := strings.CutPrefix(tld, "com."); ok {
		return isLabel(rest, 2)
	}
	return tld == "com" || tld == "cat" || isLabel(tld, 2)
}

// isYandexSearch matches www.yandex.<suffix>, www.ya.ru and www.яндекс.рф.
func isYandexSearch(host string) bool {
	if host == "www.ya.ru" || host == "www.xn--d1acpjx3f.xn--p1ai" {
		return true
	}
	suffix, ok := strings.CutPrefix(host, "www.yandex.")
	if !ok {
		return false
	}
	for _, l := range strings.Split(suffix, ".") {
		if l == "" || len(l) > 3 || !isLabel(l, len(l)) {
			return false
		}
	}
	return true
}

func isLabel(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}
