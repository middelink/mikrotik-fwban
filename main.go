// Copyright 2016 Pauline Middelink. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be
// found in the LICENSE file.

// Command mikrotik-fwban acts as a syslog receiver and tries to extract an
// IP address out of the messages received. It then adds the IPs to the
// banlist on the configured Mikrotiks. In essence it is a Fail2Ban done the
// lazy way. Since it leverages the filtering mechanisms of rsyslog to do the
// pre-filtering, it should be able to handle large sets of publicly
// accessable machines (famous last words, I know).
//
// It handles both IPv4 and IPv6 addresses and banlists.
//
// It can handle multiple Mikrotiks, keeping the banned IPs in their
// respective banlists in sync.
package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/jeromer/syslogparser"
	"github.com/jeromer/syslogparser/rfc3164"
	"github.com/jeromer/syslogparser/rfc5424"
)

var ()

func main() {
	configParse()

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
		for k, ip := range mergeIP {
			found := false
			for _, ip2 := range mt.GetIPs() {
				if k == ip2.Net.String() {
					found = true
					break
				}
			}
			if !found {
				mt.AddIP(ip.Net, Duration(ip.Dead.Sub(time.Now())))
			}
		}
	}

	// Start listening to the socket for syslog messages.
	listener, err := net.ListenPacket("udp", fmt.Sprintf("[::]:%d", cfg.Settings.Port))
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
		err = parser.Parse()
		if err != nil {
			parser = rfc5424.NewParser(pkt[:n])
			err = parser.Parse()
			if err != nil {
				log.Println(err)
				continue
			}
			msg = "message"
		}
		logparts := parser.Dump()
		for _, rev := range cfg.GetRE() {
			if res := rev.RE.FindStringSubmatch(logparts[msg].(string)); len(res) > 0 {
				if *debug {
					log.Printf("MATCH!!! %s\n", string(pkt[:n]))
					log.Printf("%#v\n", res[1:])
				}
				ip := parseCIDR(res[rev.IPIndex])
				if ip != nil {
					for _, mt := range mts {
						err = mt.AddIP(*ip, cfg.Settings.BlockTime)
						if err != nil {
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
