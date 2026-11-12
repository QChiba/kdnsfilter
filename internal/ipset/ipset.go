// Package ipset manages hash:ip sets with per-entry timeouts over the
// kernel's ipset netlink protocol (what the ipset tool speaks), so adding an
// address costs one netlink round trip instead of a process.
package ipset

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/mdlayher/netlink"
)

// Protocol constants from linux/netfilter/ipset/ip_set.h.
const (
	netlinkNetfilter = 12 // NETLINK_NETFILTER
	subsysIPSet      = 6  // NFNL_SUBSYS_IPSET
	protocolVersion  = 6  // IPSET_PROTOCOL (Linux 4.9); newer kernels still accept it

	cmdCreate = 2
	cmdFlush  = 4
	cmdAdd    = 9
	cmdDel    = 10

	attrProtocol = 1
	attrSetName  = 2
	attrTypeName = 3
	attrRevision = 4
	attrFamily   = 5
	attrFlags    = 6
	attrData     = 7

	attrIP       = 1 // nested: attrIPv4 / attrIPv6
	attrTimeout  = 6
	attrHashSize = 18
	attrMaxElem  = 19
	attrIPv4     = 1
	attrIPv6     = 2

	flagExist = 1 << 0 // IPSET_FLAG_EXIST: no error if the entry/set exists

	nlaNetByteOrder = 1 << 14 // NLA_F_NET_BYTEORDER

	nfprotoIPv4 = 2
	nfprotoIPv6 = 10
)

// Kernel error codes (IPSET_ERR_*), returned as errnos.
const (
	errFindType     syscall.Errno = 4098 // no such set type/revision
	errExistSetname syscall.Errno = 4101 // a different set with this name exists
	errExist        syscall.Errno = 4103 // element exists (without flagExist) / missing on del
	errHashFull     syscall.Errno = 4352 // IPSET_ERR_HASH_FULL
)

// ErrHashFull reports a set at its maxelem.
var ErrHashFull = errors.New("ipset is full")

// MaxTimeout is the kernel's limit for a timeout (UINT_MAX/1000 seconds).
const MaxTimeout = 2147483 * time.Second

// Conn is a netlink connection for ipset commands; it is safe for
// concurrent use.
type Conn struct {
	mu sync.Mutex
	c  *netlink.Conn
}

func Dial() (*Conn, error) {
	c, err := netlink.Dial(netlinkNetfilter, nil)
	if err != nil {
		return nil, fmt.Errorf("ipset: %w", err)
	}
	return &Conn{c: c}, nil
}

func (c *Conn) Close() error { return c.c.Close() }

// Create makes a hash:ip set (IPv6 if v6) whose entries expire after
// timeout unless added with their own. An existing set of that name is
// kept as is, even if created with other parameters.
func (c *Conn) Create(name string, v6 bool, timeout time.Duration, maxElem uint32) error {
	family := uint8(nfprotoIPv4)
	if v6 {
		family = nfprotoIPv6
	}
	err := c.do(cmdCreate, family, func(ae *netlink.AttributeEncoder) {
		ae.String(attrSetName, name)
		ae.String(attrTypeName, "hash:ip")
		ae.Uint8(attrRevision, 0) // timeouts exist since revision 0
		ae.Uint8(attrFamily, family)
		ae.Nested(attrData, func(d *netlink.AttributeEncoder) error {
			d.Uint32(attrTimeout|nlaNetByteOrder, seconds(timeout))
			d.Uint32(attrHashSize|nlaNetByteOrder, 1024)
			d.Uint32(attrMaxElem|nlaNetByteOrder, maxElem)
			return nil
		})
	}, flagExist)
	if errors.Is(err, errExistSetname) || errors.Is(err, syscall.EEXIST) {
		return nil
	}
	return err
}

// Add adds addr to the set or, if present, resets its timeout.
func (c *Conn) Add(set string, addr netip.Addr, timeout time.Duration) error {
	return c.elem(cmdAdd, set, addr, timeout, flagExist)
}

// Del removes addr; a missing address is not an error.
func (c *Conn) Del(set string, addr netip.Addr) error {
	err := c.elem(cmdDel, set, addr, 0, flagExist)
	if errors.Is(err, errExist) {
		return nil
	}
	return err
}

// Flush empties the set.
func (c *Conn) Flush(set string) error {
	return c.do(cmdFlush, nfprotoIPv4, func(ae *netlink.AttributeEncoder) {
		ae.String(attrSetName, set)
	}, 0)
}

func (c *Conn) elem(cmd uint8, set string, addr netip.Addr, timeout time.Duration, flags uint32) error {
	addr = addr.Unmap()
	family := uint8(nfprotoIPv4)
	if addr.Is6() {
		family = nfprotoIPv6
	}
	err := c.do(cmd, family, func(ae *netlink.AttributeEncoder) {
		ae.String(attrSetName, set)
		ae.Nested(attrData, func(d *netlink.AttributeEncoder) error {
			d.Nested(attrIP, func(ip *netlink.AttributeEncoder) error {
				if addr.Is4() {
					a := addr.As4()
					ip.Bytes(attrIPv4|nlaNetByteOrder, a[:])
				} else {
					a := addr.As16()
					ip.Bytes(attrIPv6|nlaNetByteOrder, a[:])
				}
				return nil
			})
			if timeout > 0 {
				d.Uint32(attrTimeout|nlaNetByteOrder, seconds(timeout))
			}
			return nil
		})
	}, flags)
	if errors.Is(err, errHashFull) {
		return ErrHashFull
	}
	return err
}

// do sends one ipset command and waits for the kernel's acknowledgement.
func (c *Conn) do(cmd, family uint8, attrs func(*netlink.AttributeEncoder), flags uint32) error {
	ae := netlink.NewAttributeEncoder()
	ae.ByteOrder = binary.BigEndian // only attributes flagged net byte order are multi-byte
	ae.Uint8(attrProtocol, protocolVersion)
	attrs(ae)
	if flags != 0 {
		ae.Uint32(attrFlags|nlaNetByteOrder, flags)
	}
	b, err := ae.Encode()
	if err != nil {
		return err
	}
	// nfgenmsg: family, version (NFNETLINK_V0), resource id
	data := append([]byte{family, 0, 0, 0}, b...)
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err = c.c.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(subsysIPSet<<8 | uint16(cmd)),
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: data,
	})
	if err != nil {
		return fmt.Errorf("ipset %s: %w", cmdName(cmd), err)
	}
	return nil
}

func cmdName(cmd uint8) string {
	switch cmd {
	case cmdCreate:
		return "create"
	case cmdFlush:
		return "flush"
	case cmdAdd:
		return "add"
	case cmdDel:
		return "del"
	}
	return fmt.Sprint(cmd)
}

func seconds(d time.Duration) uint32 {
	return uint32(min(max(d, time.Second), MaxTimeout) / time.Second)
}
