package main

import (
	"testing"
	"time"
)

func TestDecodeTimes(t *testing.T) {
	cases := []struct {
		succeed bool
		in      string
		expect  time.Duration
	}{
		{true, "1s", time.Second},
		{true, "3m", 3 * time.Minute},
		{true, "5h", 5 * time.Hour},
		{true, "5h3m", 5*time.Hour + 3*time.Minute},
		{true, "5h3m40s", 5*time.Hour + 3*time.Minute + 40*time.Second},
		{false, "10d", 0},
		{false, "10", 0},
	}
	for _, c := range cases {
		var dur Duration
		err := dur.UnmarshalText([]byte(c.in))
		if (err == nil && time.Duration(dur) == c.expect) != c.succeed {
			t.Errorf("Unmarshal(%q) == %q, want %q", c.in, dur, c.expect)
		}
		if c.succeed {
			out, err := dur.MarshalText()
			if err != nil {
				t.Error(err)
			}
			if string(out) != c.in {
				t.Errorf("Marshal(%q) == %q, want %q", dur, out, c.expect)
			}
		}
	}
}

func TestStringify(t *testing.T) {
	cases := []struct {
		succeed bool
		in      time.Duration
		expect  string
	}{
		{true, time.Second, "1s"},
		{true, 3 * time.Minute, "3m0s"},
		{true, 5*time.Hour + 4*time.Minute + 3*time.Second, "5h4m3s"},
		{false, 0, "10d"},
		{false, 0, "10"},
	}
	for _, c := range cases {
		got := Duration(c.in).String()
		if (got == c.expect) != c.succeed {
			t.Errorf("String(%q) == %q, want %q", c.in, got, c.expect)
		}
	}
}
