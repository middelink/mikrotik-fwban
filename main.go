package main

import (
	"fmt"
	"log"
	"net"
	"regexp"
	"time"

	"github.com/jeromer/syslogparser"
	"github.com/jeromer/syslogparser/rfc3164"
	"github.com/jeromer/syslogparser/rfc5424"
)

var (
	// Failed password for root from 60.173.26.187 port 8962 ssh2
	// Failed password for invalid user admin from 117.255.228.117 port 56975 ssh2
	regSSH = regexp.MustCompile(`Failed password for(?: invalid user)? (\S+) from (\S+) port \d+ ssh2`)

	// Registration from '"1001" <sip:1001@[82.197.195.165:5060]:5060>' failed for '195.154.185.244:5060' - Wrong password
	// Registration from '\"1001\" <sip:1001@[82.197.195.165:5060]:5060>' failed for '195.154.185.244:5081' - Wrong password
	regSIP = regexp.MustCompile(`Registration from '(.*)' failed for '([0-9.]+):\d+' - Wrong password`)
)

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
		//mt, err := NewMikrotik(k, v.Address, v.User, v.Passwd, v.ListName, v.Whitelist, v.Blacklist)
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
		if res := regSSH.FindStringSubmatch(logparts[msg].(string)); len(res) > 0 {
			if *debug {
				log.Printf("MATCH!!! %s\n", string(pkt[:n]))
				log.Printf("%#v\n", res[1:])
			}
			ip := parseCIDR(res[2])
			if ip != nil {
				for _, mt := range mts {
					err = mt.AddIP(*ip, cfg.Settings.BlockTime)
					if err != nil {
						log.Fatalln(err)
						continue
					}
				}
			}
		} else if res := regSIP.FindStringSubmatch(logparts[msg].(string)); len(res) > 0 {
			if *debug {
				log.Printf("MATCH!!! %s\n", string(pkt[:n]))
				log.Printf("%#v\n", res[1:])
			}
			ip := parseCIDR(res[2])
			if ip != nil {
				for _, mt := range mts {
					err = mt.AddIP(*ip, cfg.Settings.BlockTime)
					if err != nil {
						log.Fatalln(err)
						continue
					}
				}
			}
		}
	}
}
