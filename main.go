// Copyright 2016 Pauline Middelink. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be
// found in the LICENSE file.

// Command mikrotik-fwban acts as a syslog receiver and tries to extract an
// IP address out of the messages received. It then adds the IPs to the
// banlist on the configured Mikrotiks. In essence it is a Fail2Ban done the
// lazy way. Since it leverages the filtering mechanisms of rsyslog to do the
// pre-filtering, it should be able to handle large sets of publicly
// accessible machines (famous last words, I know).
//
// It handles both IPv4 and IPv6 addresses and banlists.
//
// It can handle multiple Mikrotiks, keeping the banned IPs in their
// respective banlists in sync.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/gops/agent"
	"github.com/howeyc/fsnotify"
	"github.com/jeromer/syslogparser"
	"github.com/jeromer/syslogparser/rfc3164"
	"github.com/jeromer/syslogparser/rfc5424"
)

var (
	filename      = flag.String("filename", "/etc/mikrotik-fwban.cfg", "Path of the configuration file to read.")
	port          = flag.Uint("port", 0, "UDP port we listen on for syslog formatted messages.")
	autodelete    = flag.Bool("autodelete", false, "Autodelete entries when they expire. Aka, don't trust Mikrotik to do it for us.")
	blocktime     = flag.Duration("blocktime", 0, "Set the life time for dynamically managed entries.")
	debug         = flag.Bool("debug", false, "Be absolutely staggering in our logging.")
	verbose       = flag.Bool("verbose", false, "Be more verbose in our logging.")
	configchanged = flag.Bool("configchange", false, "Exit process when config file changes.")

	cfg Config
)

func setFlags(flags ...string) error {
	if len(flags) != 0 {
		// Some complicated shit to reset the flags to their default values.
		// Make sure not to touch the test.* flags as that will inhibit any profiling.
		flag.VisitAll(func(flg *flag.Flag) {
			if !strings.HasPrefix(flg.Name, "test.") {
				flg.Value.Set(flg.DefValue)
			}
		})
		return flag.CommandLine.Parse(flags)
	}
	return flag.CommandLine.Parse(os.Args[1:])
}

func main() {
	setFlags()
	var err error
	cfg, err = newConfigFile(*filename, uint16(*port), Duration(*blocktime), *autodelete, *verbose)
	if err != nil {
		log.Fatal(err)
	}

	// Start the gops diagnostic agent.
	if err := agent.Listen(agent.Options{}); err != nil {
		log.Fatal(err)
	}

	if *configchanged {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			for {
				select {
				case <-watcher.Event:
					os.Exit(0)
				case <-watcher.Error:
					os.Exit(1)
				}
			}
		}()
		if err = watcher.Watch(*filename); err != nil {
			log.Fatal(err)
		}
	}

	// Open connections to each mikrotik and build a list of the unique
	// IPs they all have.
	var mts []*Mikrotik
	mergeIP := make(map[string]BlackIP)
	for k, v := range cfg.Mikrotik {
		if v.Disabled {
			log.Printf("%s: definition disabled, skipping\n", k)
			continue
		}
		mt, err := NewMikrotik(k, v)
		//mt, err := NewMikrotik(k, v.Address, v.User, v.Passwd, v.BanList, v.Whitelist, v.Blacklist)
		if err != nil {
			log.Fatalln(err)
		}
		defer mt.Close()
		for _, ip := range mt.GetIPs() {
			if _, ok := mergeIP[ip.Net.String()]; !ok {
				mergeIP[ip.Net.String()] = ip
			}
		}
		mts = append(mts, mt)
	}

	// Distribute the missing dynamic IPs to the mikrotiks.
	for _, mt := range mts {
		ips := mt.GetIPs()
		for k, ip := range mergeIP {
			found := false
			for _, ip2 := range ips {
				if k == ip2.Net.String() {
					found = true
					break
				}
			}
			if !found {
				mt.AddIP(ip.Net, Duration(ip.Dead.Sub(time.Now())), "")
			}
		}
	}

	sigs := make(chan os.Signal, 1)
	go func() {
		for range sigs {
			log.Printf("Got signal, dumping dynlists")
			for _, mt := range mts {
				for i, ip := range mt.GetIPs() {
					log.Printf("%s(%d): %s\n", mt.Name, i, ip)
				}
			}
		}
	}()
	signal.Notify(sigs, syscall.SIGUSR1)

	// Start listening to the socket for syslog messages.
	listener, err := net.ListenPacket("udp", fmt.Sprintf(":%d", cfg.Settings.Port))
	if err != nil {
		log.Fatalln(err)
	}
	pkt := make([]byte, 4096)
	for {
		n, _, err := listener.ReadFrom(pkt)
		if err != nil {
			log.Fatalln(err)
		}

		var parser syslogparser.LogParser
		parser = rfc3164.NewParser(pkt[:n])
		msg := "content"
		if err = parser.Parse(); err != nil {
			parser = rfc5424.NewParser(pkt[:n])
			if err = parser.Parse(); err != nil {
				log.Println(err)
				continue
			}
			msg = "message"
		}
		logparts := parser.Dump()
		for _, re := range cfg.re {
			if res := re.RE.FindStringSubmatch(logparts[msg].(string)); len(res) > 0 {
				if *debug {
					log.Printf("MATCH!!! %s\n", string(pkt[:n]))
					log.Printf("%#v\n", res[1:])
				}
				if ip := parseCIDR(res[re.IPIndex]); ip != nil {
					for _, mt := range mts {
						if err = mt.AddIP(*ip, cfg.Settings.BlockTime, logparts[msg].(string)); err != nil {
							log.Fatalln(err)
							continue
						}
					}
				}
				break
			}
		}
	}
}
