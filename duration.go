package main

import (
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
func (d Duration) String() string {
	return time.Duration(d).String()
}
