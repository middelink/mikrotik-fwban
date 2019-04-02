package main

import (
	"log"
	"net"
	"strconv"
	"strings"
)

// parseCIDR parses s as a CIDR notation IP address and mask,
// like "192.168.100.1/24" or "2001:DB8::/48", as defined in
// RFC 4632 and RFC 4291.
//
// It returns the network implied by the IP and mask.
// For example, ParseCIDR("192.168.100.1/16") returns
// the IP address 192.168.100.0 and the mask 255.255.255.0.
func parseCIDR(s string, verbose bool) *net.IPNet {
	//log.Printf("s: %#v\n", s)
	i := strings.Index(s, "/")
	if i < 0 {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil
		}
		iplen := net.IPv4len
		if len(ip.To4()) == 0 {
			iplen = net.IPv6len
		}
		m := net.CIDRMask(8*iplen, 8*iplen)
		return &net.IPNet{IP: ip, Mask: m}
	}
	addr, mask := s[:i], s[i+1:]
	iplen := net.IPv4len
	ip := net.ParseIP(addr)
	if ip.To4() == nil {
		iplen = net.IPv6len
	}
	n, err := strconv.Atoi(mask)
	if ip == nil || err != nil || n < 0 || n > 8*iplen {
		return nil
	}
	m := net.CIDRMask(n, 8*iplen)
	if verbose && !ip.Mask(m).Equal(ip) {
		log.Printf("WARNING: prefix/ip %s has hostbits set\n", s)
	}
	return &net.IPNet{IP: ip.Mask(m), Mask: m}
}
