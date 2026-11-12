package app

import (
	"net/netip"

	"github.com/QChiba/kdnsfilter/internal/filtering"
)

func filteringReq(host string) filtering.Request {
	return filtering.Request{Host: host, ClientIP: netip.MustParseAddr("192.168.1.50")}
}
