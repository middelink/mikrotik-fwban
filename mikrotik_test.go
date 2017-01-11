package main

import (
	"testing"
)

func TestParseCIDR(t *testing.T) {
	testdata := []struct {
		expectOk bool
		str      string
		expect   string
	}{
		{true, "192.168.10.0", "192.168.10.0/32"},
		{true, "192.168.10.0/32", "192.168.10.0/32"},
		{true, "192.168.10.5/24", "192.168.10.0/24"},
		{true, "192.168.10.0/0", "0.0.0.0/0"},
		{false, "256.168.10.0/32", ""},
		{false, "192.168.10.0/33", ""},
		{false, "192.168.10.20.1", ""},
		{false, "192.168.10.20.1/24", ""},
		{false, "192.168.10", ""},
		{false, "192.168.10/24", ""},
		{false, "not_an_ip", ""},
		{false, "not_an_ip/32", ""},
		{true, "fe80:0123:4567::1234:5678:abce:f123/128", "fe80:123:4567:0:1234:5678:abce:f123/128"},
		{true, "fe80:0123:4567::1234:5678:abce:f123/64", "fe80:123:4567::/64"},
		{false, "fe80:g123::/64", ""},
		{false, "fe80:0123:4567:abcd:1234:5678:abce:f123:6545/64", ""},
		{false, "fe80:0123:4567::1234:5678:abce:f123/129", ""},
	}
	for _, d := range testdata {
		ip := parseCIDR(d.str)
		//t.Logf("ok=%v, str=%v, ip=%v", d.expectOk, d.str, ip)
		if ip == nil {
			if d.expectOk {
				t.Fatalf("parseCIDR(%q) failed, got nil, expected %q", d.str, d.expect)
			}
			continue
		} else if !d.expectOk {
			t.Fatalf("parseCIDR(%q) failed, got %q, expected nil", d.str, d.expect)
			continue
		}
		if ip.String() != d.expect {
			t.Fatalf("parseCIDR(%q) failed, got %q, expected %q", d.str, ip.String(), d.expect)
			continue
		}
	}
}
