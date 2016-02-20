package main

import (
	"time"
)

// Why, oh why does time.Duration not have a UnmarshalText?
type Duration time.Duration

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
