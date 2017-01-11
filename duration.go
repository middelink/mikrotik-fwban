package main

import (
	"strings"
	"time"
)

// Duration is my own wrapper around time.Duration as that
// does not seem to have UnmarshalText, making it unable to
// read from an xml file.
type Duration time.Duration

// UnmarshalText parses a given text into a duration.
func (d *Duration) UnmarshalText(data []byte) (err error) {
	// Fractional seconds are handled implicitly by Parse.
	var dd time.Duration
	dd, err = time.ParseDuration(string(data))
	*d = Duration(dd)
	return
}

func (d Duration) MarshalText() (text []byte, err error) {
	// We could have simply done
	//  return []byte(d.String()), nil
	// but my OCD kicked in and it needs pretty output.
	res := d.String()
	sec := time.Duration(d).Nanoseconds() / 1e9
	if sec%60 == 0 {
		res = strings.TrimSuffix(res, "0s")
		if sec/60%60 == 0 {
			res = strings.TrimSuffix(res, "0m")
		}
	}
	return []byte(res), nil
}

func (d Duration) String() string {
	return time.Duration(d).String()
}
