package filtering

import (
	"net/netip"
	"strings"

	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"

	"github.com/QChiba/kdnsfilter/internal/config"
)

// Rewritten says how to answer a rewritten query. A non-zero RCode answers
// with that code. Otherwise the reply is the CNAME chain from the queried
// name followed by Addrs (of the queried family), plus the addresses of
// Resolve when set: a CNAME target no rewrite covers, looked up upstream.
// An empty reply is NOERROR with no records, so a rewritten name can't leak
// its real addresses through other record types (e.g. HTTPS address hints).
type Rewritten struct {
	RCode   int          `json:"rcode,omitempty"`
	CNAMEs  []string     `json:"cnames,omitempty"`
	Addrs   []netip.Addr `json:"addrs,omitempty"`
	Resolve string       `json:"resolve,omitempty"`
}

// maxCNAMEChain bounds rewrite chains (a → b → c ...); loops stop there.
const maxCNAMEChain = 8

// rewriteSet is all enabled answers for one domain pattern.
type rewriteSet struct {
	text           string // "media.home → 192.168.1.5, AAAA" for the log
	a, aaaa        []netip.Addr
	cname          string
	keepA, keepAAA bool
}

// rewriteTable matches names against the configured rewrites: an exact
// name wins over wildcards, and a longer wildcard over a shorter one.
type rewriteTable struct {
	exact map[string]*rewriteSet
	wild  map[string]*rewriteSet // key ".example.com" for "*.example.com"
}

func buildRewrites(rws []config.Rewrite) *rewriteTable {
	t := &rewriteTable{exact: map[string]*rewriteSet{}, wild: map[string]*rewriteSet{}}
	for _, r := range rws {
		if !r.Enabled {
			continue
		}
		m, key := t.exact, r.Domain
		if strings.HasPrefix(key, "*.") {
			m, key = t.wild, key[1:]
		}
		s := m[key]
		if s == nil {
			s = &rewriteSet{text: r.Domain + " →"}
			m[key] = s
		} else {
			s.text += ","
		}
		s.text += " " + r.Answer
		switch r.Kind() {
		case config.RewriteKeep:
			if r.Answer == "A" {
				s.keepA = true
			} else {
				s.keepAAA = true
			}
		case config.RewriteIP:
			ip := netip.MustParseAddr(r.Answer).Unmap()
			if ip.Is4() {
				s.a = append(s.a, ip)
			} else {
				s.aaaa = append(s.aaaa, ip)
			}
		default:
			s.cname = r.Answer
		}
	}
	return t
}

func (t *rewriteTable) match(host string) *rewriteSet {
	if s := t.exact[host]; s != nil {
		return s
	}
	for suffix := host; ; {
		i := strings.IndexByte(suffix, '.')
		if i < 0 {
			return nil
		}
		suffix = suffix[i:]
		if s := t.wild[suffix]; s != nil {
			return s
		}
		suffix = suffix[1:]
	}
}

// answer returns the rewrite of host for qtype and the matched rewrite's
// text. ok is false when no rewrite applies, including a kept type ("A" or
// "AAAA" answer) asked directly, which then goes through normal filtering.
func (t *rewriteTable) answer(host string, qtype uint16) (r Rewritten, text string, ok bool) {
	s := t.match(host)
	if s == nil {
		return r, "", false
	}
	text = s.text
	name := host
	for s.cname != "" {
		r.CNAMEs = append(r.CNAMEs, s.cname)
		name = s.cname
		next := t.match(name)
		if next == nil || len(r.CNAMEs) == maxCNAMEChain {
			if isAddrType(qtype) {
				r.Resolve = name
			}
			return r, text, true
		}
		s = next
	}
	keep, addrs := s.keepA, s.a
	if qtype == dns.TypeAAAA {
		keep, addrs = s.keepAAA, s.aaaa
	}
	switch {
	case !isAddrType(qtype):
	case keep && len(r.CNAMEs) == 0:
		return Rewritten{}, "", false
	case keep:
		r.Resolve = name
	default:
		r.Addrs = addrs
	}
	return r, text, true
}

func isAddrType(qtype uint16) bool { return qtype == dns.TypeA || qtype == dns.TypeAAAA }

// ruleRewrite turns matched $dnsrewrite rules into an answer for qtype. It
// supports response codes, CNAMEs and A/AAAA values; other record types
// answer with an empty NOERROR. It returns the first rule for the log.
func ruleRewrite(nrs []*rules.NetworkRule, qtype uint16) (Rewritten, *rules.NetworkRule) {
	var r Rewritten
	for _, nr := range nrs {
		dr := nr.DNSRewrite
		switch {
		case dr.NewCNAME != "":
			r = Rewritten{CNAMEs: []string{strings.TrimSuffix(strings.ToLower(dr.NewCNAME), ".")}}
			if isAddrType(qtype) {
				r.Resolve = r.CNAMEs[0]
			}
			return r, nr
		case dr.RCode != dns.RcodeSuccess:
			return Rewritten{RCode: dr.RCode}, nr
		case dr.RRType == qtype && isAddrType(qtype):
			if ip, ok := dr.Value.(netip.Addr); ok {
				r.Addrs = append(r.Addrs, ip)
			}
		}
	}
	return r, nrs[0]
}
