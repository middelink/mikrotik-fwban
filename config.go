package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"regexp"
	"strings"
	"time"

	"gopkg.in/gcfg.v1"
)

// ConfigMikrotik is the internal representation of a Mikrotik object,
// initialized from the configfile.
// Note that missing elements are inititalized to a sensible default.
type ConfigMikrotik struct {
	Disabled  bool
	UseTLS    bool
	Address   string
	User      string
	Passwd    string
	BanList   string
	Whitelist []string `json:",omitempty"`
	Blacklist []string `json:",omitempty"`
}

// Config is the internal representation of the config file, read during
// startup of the program.
// Note that missing elements are inititalized to a sensible default.
type Config struct {
	Settings struct {
		BlockTime  Duration
		AutoDelete bool
		Verbose    bool
		Port       uint16
	}
	RegExps struct {
		RE      []string `json:",omitempty"`
		Test_RE []string `json:",omitempty"`
	}
	re       []regexps
	Mikrotik map[string]*ConfigMikrotik `json:",omitempty"`
}

type regexps struct {
	RE      *regexp.Regexp
	IPIndex int
}

func (c *Config) mergeFlags(port uint16, blocktime Duration, autodelete, verbose bool) {
	// Commandline flags override the config, but only when set
	if blocktime != 0 {
		c.Settings.BlockTime = blocktime
	}
	if autodelete {
		c.Settings.AutoDelete = autodelete
	}
	if verbose {
		c.Settings.Verbose = verbose
	}
	if port != 0 {
		c.Settings.Port = port
	}
}

func (c *Config) setupDefaults() error {
	if c.Settings.BlockTime == 0 {
		c.Settings.BlockTime = Duration(24 * time.Hour)
	}
	// Make sure we have a initial regex to start out with.
	if len(c.RegExps.RE) == 0 {
		return fmt.Errorf("need at least one valid regexp")
	}

	var hasValid bool
	for k, v := range c.Mikrotik {
		if v.Disabled {
			continue
		}
		if v.Address == "" {
			return fmt.Errorf("%s: address is a required field", k)
		}
		if v.User == "" {
			return fmt.Errorf("%s: user is a required field", k)
		}
		if v.Passwd == "" {
			return fmt.Errorf("%s: passwd is a required field", k)
		}
		// Add port 8728/8729 if it was not included
		_, _, err := net.SplitHostPort(v.Address)
		if err != nil {
			// For anything else than missing port, bail.
			if !strings.Contains(err.Error(), "missing port in address") {
				return fmt.Errorf("%s: malformed address: %v", k, err)
			}
			if v.UseTLS {
				v.Address = net.JoinHostPort(v.Address, "8729")
			} else {
				v.Address = net.JoinHostPort(v.Address, "8728")
			}
		}
		// set default managed addresslist name
		if v.BanList == "" {
			v.BanList = "blacklist"
		}
		hasValid = true
	}
	if !hasValid {
		return fmt.Errorf("need at least one valid Mikrotik configuration")
	}
	return nil
}

func (c *Config) setupREs() error {
	for _, v := range c.RegExps.RE {
		re, err := regexp.Compile(v)
		if err != nil {
			return err
		}
		index := -1
		for i, v := range re.SubexpNames() {
			if v == "IP" {
				index = i
				break
			}
		}
		c.re = append(c.re, regexps{re, index})
		if index < 0 {
			return fmt.Errorf("missing named group `IP` in regexp %q", v)
		}
	}

	for _, v := range c.RegExps.Test_RE {
		found := false
		for _, re := range c.re {
			if res := re.RE.FindStringSubmatch(v); len(res) > 0 {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("test_re failed to match any re %q", v)
		}
	}

	return nil
}

func newConfigString(data string, port uint16, blocktime Duration, autodelete, verbose bool) (Config, error) {
	var cfg Config
	err := gcfg.ReadStringInto(&cfg, data)
	if err != nil {
		return Config{}, err
	}
	cfg.mergeFlags(port, blocktime, autodelete, verbose)
	if err = cfg.setupDefaults(); err != nil {
		return Config{}, err
	}
	if err = cfg.setupREs(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func newConfigFile(path string, port uint16, blocktime Duration, autodelete, verbose bool) (Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return newConfigString(string(data), port, blocktime, autodelete, verbose)
}
