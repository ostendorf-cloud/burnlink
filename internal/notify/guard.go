// Copyright 2026 Simon Ostendorf
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"errors"
	"net/netip"
	"syscall"
)

// ErrBlocked is the one error for a destination the guard refuses: a scheme,
// a port or an address class an untrusted destination may not have. It is
// never retried.
var ErrBlocked = errors.New("notify: destination not allowed")

// allowedPort is the only port a webhook may use. A sender supplied port
// would turn this service into a port scanner of every public host.
const allowedPort = 443

// blockedV4 lists the IPv4 special purpose blocks of the IANA registry that
// are not globally reachable, plus the ranges a sender must not reach. Any
// other IPv4 address is public.
var blockedV4 = mustPrefixes(
	"0.0.0.0/8",       // this network, includes the unspecified address
	"10.0.0.0/8",      // private
	"100.64.0.0/10",   // carrier grade NAT
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link local, includes the cloud metadata address
	"172.16.0.0/12",   // private
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // documentation (TEST-NET-1)
	"192.88.99.0/24",  // deprecated 6to4 relay anycast
	"192.168.0.0/16",  // private
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // documentation (TEST-NET-2)
	"203.0.113.0/24",  // documentation (TEST-NET-3)
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved, includes the broadcast address
)

// globalV6 is the only IPv6 block checked for destinations: global unicast.
// Everything outside it, loopback, link local, unique local, multicast, the
// IPv4 embedding NAT64 ranges and the rest, is refused without a list.
var globalV6 = netip.MustParsePrefix("2000::/3")

// blockedV6 lists what inside globalV6 is still not a public destination.
var blockedV6 = mustPrefixes(
	"2001::/23",     // IETF protocol assignments, includes Teredo
	"2001:db8::/32", // documentation
	"2002::/16",     // 6to4, embeds an IPv4 address
	"3fff::/20",     // documentation
)

func mustPrefixes(list ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(list))
	for i, s := range list {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// CheckAddr reports ErrBlocked for an address that is not a public unicast
// address. An IPv4 mapped IPv6 address is judged as the IPv4 address it
// carries, so ::ffff:127.0.0.1 is loopback. An address with a zone is
// refused.
func CheckAddr(addr netip.Addr) error {
	if !addr.IsValid() || addr.Zone() != "" {
		return ErrBlocked
	}
	addr = addr.Unmap()
	if addr.Is4() {
		for _, p := range blockedV4 {
			if p.Contains(addr) {
				return ErrBlocked
			}
		}
		return nil
	}
	if !globalV6.Contains(addr) {
		return ErrBlocked
	}
	for _, p := range blockedV6 {
		if p.Contains(addr) {
			return ErrBlocked
		}
	}
	return nil
}

// guardControl is the net.Dialer Control hook. It runs for every address the
// dialer is about to connect to, after name resolution and before the
// connection, so a name that resolves to a private address, and a name that
// changes its answer between a check and the connect, are both refused at
// the moment that matters.
func guardControl(network, address string, _ syscall.RawConn) error {
	if network != "tcp4" && network != "tcp6" {
		return ErrBlocked
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil || ap.Port() != allowedPort {
		return ErrBlocked
	}
	return CheckAddr(ap.Addr())
}
