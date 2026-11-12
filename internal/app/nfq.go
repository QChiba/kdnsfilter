package app

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"time"

	"github.com/florianl/go-nfqueue/v2"
	"github.com/mdlayher/netlink"
	"github.com/miekg/dns"

	"github.com/QChiba/kdnsfilter/internal/config"
	"github.com/QChiba/kdnsfilter/internal/dnspkt"
	"github.com/QChiba/kdnsfilter/internal/filtering"
	"github.com/QChiba/kdnsfilter/internal/querylog"
)

// RunQueue reads DNS replies from the NFQUEUE until ctx is cancelled.
// Packets the filter can't handle are always accepted unchanged.
func (a *App) RunQueue(ctx context.Context, queue uint16) error {
	nf, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      queue,
		MaxPacketLen: 0xffff,
		MaxQueueLen:  1024,
		Copymode:     nfqueue.NfQnlCopyPacket,
		Flags:        nfqueue.NfQaCfgFlagFailOpen,
		WriteTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		return fmt.Errorf("open nfqueue %d: %w", queue, err)
	}
	defer nf.Close()
	if err := nf.SetOption(netlink.NoENOBUFS, true); err != nil {
		log.Printf("nfqueue: set NoENOBUFS: %v", err)
	}

	handle := func(attr nfqueue.Attribute) int {
		id := *attr.PacketID
		var out []byte
		if attr.Payload != nil {
			var e *querylog.Entry
			out, e = a.process(*attr.Payload, time.Now())
			if e != nil {
				a.Record(*e)
			}
		}
		var verr error
		if out != nil {
			verr = nf.SetVerdictModPacket(id, nfqueue.NfAccept, out)
		} else {
			verr = nf.SetVerdict(id, nfqueue.NfAccept)
		}
		if verr != nil {
			log.Printf("nfqueue verdict: %v", verr)
		}
		return 0
	}
	onErr := func(err error) int {
		if ctx.Err() == nil {
			log.Printf("nfqueue: %v", err)
		}
		return 0
	}
	if err := nf.RegisterWithErrorFunc(ctx, handle, onErr); err != nil {
		return fmt.Errorf("register nfqueue: %w", err)
	}
	<-ctx.Done()
	return nil
}

// process inspects one IP packet. It returns the replacement packet (nil to
// pass it unchanged) and a log entry (nil if the packet isn't a DNS reply).
func (a *App) process(raw []byte, now time.Time) ([]byte, *querylog.Entry) {
	start := time.Now()
	p, err := dnspkt.Parse(raw)
	if err != nil {
		return nil, nil
	}
	var m dns.Msg
	if m.Unpack(p.Payload) != nil || !m.Response || m.Opcode != dns.OpcodeQuery || len(m.Question) != 1 {
		return nil, nil
	}
	q := m.Question[0]
	host := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	h, _ := a.Hosts.Lookup(p.Dst)
	req := filtering.Request{Host: host, QType: q.Qtype, ClientIP: p.Dst, ClientMAC: h.MAC}

	f := a.Filter()
	res := f.Check(req, now)
	var cname string
	if res.Action == filtering.Pass && res.Reason == "" {
		for _, rr := range m.Answer {
			c, ok := rr.(*dns.CNAME)
			if !ok {
				continue
			}
			t := strings.TrimSuffix(strings.ToLower(c.Target), ".")
			creq := req
			creq.Host = t
			if r := f.CheckCNAME(creq, now); r.Action == filtering.Block {
				res, cname = r, t
				break
			}
		}
	}

	e := &querylog.Entry{
		Time:       now,
		ClientIP:   p.Dst.String(),
		ClientName: res.ClientName,
		Host:       host,
		QType:      dns.TypeToString[q.Qtype],
		Action:     res.Action.String(),
		Reason:     res.Reason,
		Rule:       res.Rule,
		ListID:     res.ListID,
		Service:    res.Service,
		CNAME:      cname,
	}
	if e.ClientName == "" {
		e.ClientName = h.Name
	}

	final := &m
	switch res.Action {
	case filtering.Block:
		mode := f.BlockingMode
		if res.Reason == filtering.ReasonDoHCanary {
			mode = config.BlockNXDomain // a null IP still counts as "use DoH"
		}
		final = blockedReply(&m, mode, f.BlockedTTL)
	case filtering.Rewrite:
		if rw := res.Rewrite; rw != nil {
			addrs := rw.Addrs
			if rw.Resolve != "" {
				more, err := a.safe.lookup(rw.Resolve, q.Qtype)
				if err != nil {
					log.Printf("rewrite %s: %v", host, err)
					e.Action, e.Reason = filtering.Pass.String(), "rewrite_error"
					break
				}
				addrs = append(append([]netip.Addr(nil), addrs...), more...)
			}
			final = rewriteReply(&m, rw, addrs, f.BlockedTTL)
			break
		}
		addrs, err := a.safe.addrs(res.Safe, q.Qtype)
		if err != nil {
			log.Printf("safe search %s: %v", host, err)
			e.Action, e.Reason = filtering.Pass.String(), "safe_search_error"
			break
		}
		final = safeReply(&m, res.Safe, addrs, uint32(safeMinTTL/time.Second))
	}
	// Route before the verdict: the client gets the addresses only after
	// they are in the sets.
	if e.Action != filtering.Block.String() && final.Rcode == dns.RcodeSuccess {
		rt := a.Routing.Route(host, final.Answer, now)
		e.Route, e.RouteEntry, e.RouteVia = rt.List, rt.Entry, rt.Via
	}
	e.Rcode = dns.RcodeToString[final.Rcode]
	e.Answers = summarize(final.Answer)

	var out []byte
	if final != &m {
		b, err := final.Pack()
		if err != nil {
			log.Printf("pack reply for %s: %v", host, err)
			e.Action, e.Reason = filtering.Pass.String(), "pack_error"
		} else {
			out = p.WithPayload(b)
		}
	}
	e.ElapsedUS = time.Since(start).Microseconds()
	return out, e
}

func summarize(rrs []dns.RR) []string {
	var out []string
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.A:
			out = append(out, v.A.String())
		case *dns.AAAA:
			out = append(out, v.AAAA.String())
		case *dns.CNAME:
			out = append(out, "CNAME "+strings.TrimSuffix(v.Target, "."))
		case *dns.HTTPS:
			out = append(out, "HTTPS")
		}
		if len(out) == 8 {
			out = append(out, "…")
			break
		}
	}
	return out
}
