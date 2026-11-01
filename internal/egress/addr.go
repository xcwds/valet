package egress

import "net/netip"

// nonPublic are ranges a tunnel must never reach even when the name is
// allowed: so an allowlisted name pointed at Valet's admin port, the LAN or
// a cloud metadata endpoint gets nowhere. netip's predicates cover
// loopback, RFC 1918 and fc00::/7 (IsPrivate), link-local (which holds
// 169.254.169.254) and multicast; these are the rest.
var nonPublic = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8",       // "this network"
		"100.64.0.0/10",   // carrier-grade NAT, often internal
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // documentation
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // documentation
		"203.0.113.0/24",  // documentation
		"240.0.0.0/4",     // reserved, and broadcast
		"64:ff9b::/96",    // NAT64: embeds an IPv4 address of any kind
		"64:ff9b:1::/48",  // local-use NAT64
		"100::/64",        // discard
		"2001::/32",       // Teredo: embeds an IPv4 address
		"2001:db8::/32",   // documentation
		"2002::/16",       // 6to4: embeds an IPv4 address
		"fec0::/10",       // deprecated site-local
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// public reports whether a tunnel may connect to a.
func public(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() ||
		a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}
