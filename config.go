package main

import (
	"flag"
	"log"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"gopkg.in/gcfg.v1"
)

// ConfigMikrotik is the internal representation of a Mikrotik object,
// initialized from the configfile.
// Note that missing elements are inititalized to a sensible default.
type ConfigMikrotik struct {
	Disabled  bool
	Address   string
	User      string
	Passwd    string
	BanList   string
	Whitelist []string
	Blacklist []string
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
	Mikrotik map[string]*ConfigMikrotik
}

var (
	progname = path.Base(os.Args[0])

	blocktime  = flag.Duration("blocktime", 7*24*time.Hour, "Set the life time for dynamically managed entries.")
	filename   = flag.String("filename", "/etc/mikrotik-fwban.cfg", "Path of the configuration file to read.")
	port       = flag.Uint("port", 10514, "UDP port we listen on for syslog formatted messages.")
	autodelete = flag.Bool("autodelete", true, "Autodelete entries when they expire. Aka, don't trust Mikrotik to do it for us.")
	verbose    = flag.Bool("verbose", false, "Be more verbose in our logging.")
	debug      = flag.Bool("debug", false, "Be absolutely staggering in our logging.")

	cfg Config
)

func hasFlag(s string) bool {
	var res bool
	flag.Visit(func(f *flag.Flag) {
		if s == f.Name {
			res = true
		}
	})
	return res
}

func configParse() {
	flag.Parse()

	err := gcfg.ReadFileInto(&cfg, *filename)
	if err != nil {
		log.Fatal(err)
	}
	// Flags override the config file
	if hasFlag("blocktime") {
		cfg.Settings.BlockTime = Duration(*blocktime)
	}
	if hasFlag("activedelete") {
		cfg.Settings.AutoDelete = *autodelete
	}
	if hasFlag("verbose") {
		cfg.Settings.Verbose = *verbose
	}
	if hasFlag("port") {
		cfg.Settings.Port = uint16(*port)
	}
	if cfg.Settings.BlockTime == 0 {
		log.Fatal("Blocktime needs to be non-zero.")
	}

	for _, v := range cfg.Mikrotik {
		if v.Disabled {
			continue
		}
		// Add port 8728 if it was not included
		_, _, err := net.SplitHostPort(v.Address)
		if err != nil {
			// For anything else than missing port, bail.
			if !strings.HasPrefix(err.Error(), "missing port in address") {
				continue
			}
			v.Address = net.JoinHostPort(v.Address, "8728")
		}
		// set default managed addresslist name
		if v.BanList == "" {
			v.BanList = "blacklist"
		}
	}
}
