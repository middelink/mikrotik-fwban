package main

import (
	"fmt"
	"log"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	ros "github.com/Netwurx/routeros-api-go"
)

var (
	// 28w4d23h59m56s
	regTimeout = regexp.MustCompile(`(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?`)
)

// ParseCIDR parses s as a CIDR notation IP address and mask,
// like "192.168.100.1/24" or "2001:DB8::/48", as defined in
// RFC 4632 and RFC 4291.
//
// It returns the network implied by the IP and mask.
// For example, ParseCIDR("192.168.100.1/16") returns
// the IP address 192.168.100.0 and the mask 255.255.255.0.
func parseCIDR(s string) *net.IPNet {
	//log.Printf("s: %#v\n", s)
	i := strings.Index(s, "/")
	if i < 0 {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil
		}
		iplen := net.IPv4len
		if len(ip.To4()) == 0 {
			iplen = net.IPv6len
		}
		m := net.CIDRMask(8*iplen, 8*iplen)
		return &net.IPNet{IP: ip, Mask: m}
	}
	addr, mask := s[:i], s[i+1:]
	iplen := net.IPv4len
	ip := net.ParseIP(addr)
	if ip.To4() == nil {
		iplen = net.IPv6len
	}
	n, err := strconv.Atoi(mask)
	if ip == nil || err != nil || n < 0 || n > 8*iplen {
		return nil
	}
	m := net.CIDRMask(n, 8*iplen)
	if cfg.Settings.Verbose && !ip.Mask(m).Equal(ip) {
		log.Printf("WARNING: prefix/ip %s has hostbits set\n", s)
	}
	return &net.IPNet{IP: ip.Mask(m), Mask: m}
}

// BlackIP is a structure holding a single IP (Prefix really). It contains
// a timeout value, where IsZero means it has no timeout, aka a permanent
// entry. ID is used to store the row identifier Mikrotik gives us when
// reading the IP. It will contain ".gcfg" for config based entries.
type BlackIP struct {
	Net  net.IPNet
	Dead time.Time
	ID   string
}

func (b BlackIP) String() string {
	return fmt.Sprintf("{%s, %q, %q}", b.Net.String(), b.Dead, b.ID)
}

// ByAge implements sort.Interface for []Person based on
// the Age field.
type ByAge []BlackIP

func (a ByAge) Len() int           { return len(a) }
func (a ByAge) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByAge) Less(i, j int) bool { return a[i].Dead.Before(a[j].Dead) }

// Mikrotik contains the internal state of a Mikrotik object, configuration
// details but also the API connection to the Mikrotik. It acts as a cache
// between the rest of the program and the Mikrotik.
type Mikrotik struct {
	client *ros.Client

	Name string

	Address string
	User    string
	Passwd  string

	hasData chan struct{}
	banlist string

	sync.RWMutex
	dynlist   []BlackIP
	blacklist []BlackIP
	whitelist []BlackIP
}

// NewMikrotik returns an initialized Mikrotik object.
func NewMikrotik(name string, c *ConfigMikrotik) (*Mikrotik, error) {
	if *debug {
		log.Printf("NewMikrotik(name=%s, %#v)\n", name, c)
	} else if cfg.Settings.Verbose {
		log.Printf("NewMikrotik(name=%s)\n", name)
	}
	mt := &Mikrotik{
		Name:    name,
		Address: c.Address,
		User:    c.User,
		Passwd:  c.Passwd,
		banlist: c.BanList,
	}
	// Open the connection
	var err error
	mt.client, err = ros.New(mt.Address)
	if err != nil {
		return nil, err
	}
	err = mt.client.Connect(mt.User, mt.Passwd)
	if err != nil {
		return nil, err
	}
	if cfg.Settings.AutoDelete {
		mt.hasData = make(chan struct{})
	}

	// Setup the whitelist
	for _, v := range c.Whitelist {
		if strings.HasPrefix(v, "@") {
			if v[1:] == mt.banlist {
				log.Printf("%s: Skipping the managed blacklist %s", mt.Name, v)
			} else {
				mt.whitelist = append(mt.whitelist, mt.getAddresslist(v[1:])...)
			}
		} else {
			ip := parseCIDR(v)
			if ip == nil {
				log.Fatalf("%s: Unable to parse whitelist prefix/ip %s", mt.Name, v)
			}
			mt.whitelist = append(mt.whitelist, BlackIP{*ip, time.Time{}, ".gcfg"})
		}
	}
	// Fill the blacklist, aka permanent blacklist members.
	for _, v := range c.Blacklist {
		if strings.HasPrefix(v, "@") {
			if v[1:] == mt.banlist {
				log.Printf("%s: Skipping the managed blacklist %s", mt.Name, v)
			} else {
				mt.blacklist = append(mt.blacklist, mt.getAddresslist(v[1:])...)
			}
		} else {
			ip := parseCIDR(v)
			if ip == nil {
				log.Fatalf("%s: Unable to parse blacklist prefix/ip %s", mt.Name, v)
			}
			mt.blacklist = append(mt.blacklist, BlackIP{*ip, time.Time{}, ".gcfg"})
		}
	}

	// Fetch and split the managed blacklist in permanent and dynamic members
	blackmap := make(map[string]*BlackIP)
	for _, v := range mt.blacklist {
		blackmap[v.Net.String()] = &v
	}

	// Check if the whitelist entries are not in the permanent blacklist
	for _, v := range mt.whitelist {
		if _, ok := blackmap[v.Net.String()]; ok {
			log.Fatalf("%s: Conflicting whitelist/blacklist entry %s", mt.Name, v.Net.String())
		}
	}

	// Now check every entry from the managed dynlist
addresslist:
	for _, v := range mt.getAddresslist(mt.banlist) {
		for _, w := range mt.whitelist {
			if w.Net.Contains(v.Net.IP) {
				// Whitelisted entries should never be on the dynlist
				log.Printf("%s(%s): Deleting whitelisted entry", mt.Name, mt.banlist)
				err = mt.DelIP(v)
				if err != nil {
					log.Fatalln(mt.Name, err)
				}
				delete(blackmap, v.Net.String())
				continue addresslist
			}
		}
		if v.Dead.IsZero() {
			// Permanent entry, must (literally) exist in blacklist
			if _, ok := blackmap[v.Net.String()]; ok {
				// In blacklist, mark as found
				delete(blackmap, v.Net.String())
			} else {
				// Not in permanent blacklist, but permanent.
				// Remove immediately.
				log.Printf("%s: Deleting unwanted permanent blacklist entry", mt.Name)
				err = mt.DelIP(v)
				if err != nil {
					log.Fatalln(mt.Name, err)
				}
			}
		} else {
			// Temporary entry, must not exist in permanent blacklist
			if _, ok := blackmap[v.Net.String()]; ok {
				// Oops, in permanent blacklist, remove it as
				// it will be added back later as a permanent entry.
				log.Println("Deleting unwanted dynamic blacklist entry")
				err = mt.DelIP(v)
				if err != nil {
					log.Fatalln(mt.Name, err)
				}
			} else {
				// Dynamic entry
				mt.dynlist = append(mt.dynlist, v)
			}
		}
	}
	// Add the missing permanent blacklist entries
	for _, v := range blackmap {
		err := mt.AddIP(v.Net, 0)
		if err != nil {
			log.Fatalln(err)
		}
	}

	if cfg.Settings.AutoDelete {
		// Start a go function to monitor the dynlist for entries to delete.
		// It effectively implements a priority queue on the Dead time.
		// From now on we need locking if we mess with the dynlist.
		go func(mt *Mikrotik) {
			var oldest time.Time
			var oldestEntry *BlackIP
			for {
				mt.RLock()
				if len(mt.dynlist) != 0 {
					oldest = mt.dynlist[0].Dead
					oldestEntry = &mt.dynlist[0]
				} else {
					if cfg.Settings.Verbose {
						log.Printf("%s: No dynlist entries found to expire, retry in an hour", mt.Name)
					}
					oldest = time.Now().Add(time.Hour)
					oldestEntry = nil
				}
				mt.RUnlock()
				if *debug {
					log.Printf("%s: next event: %v", mt.Name, oldest)
				}
				select {
				case <-mt.hasData:
					if *debug {
						log.Printf("%s: Received indication new data is here", mt.Name)
					}
					break
				case <-time.After(oldest.Sub(time.Now())):
					if oldestEntry != nil {
						if *debug {
							log.Printf("%s: Deleting old dynlist entry", mt.Name)
						}
						err = mt.DelIP(*oldestEntry)
						if err != nil {
							log.Fatalln(mt.Name, err)
						}
						mt.Lock()
						mt.dynlist = mt.dynlist[1:]
						mt.Unlock()
					}
				}
			}
		}(mt)
	}
	return mt, nil
}

func (mt *Mikrotik) toDuration(mapname string, dict map[string]string) time.Time {
	if dynamic, ok := dict["dynamic"]; ok && dynamic == "true" {
		if timeout, ok := dict["timeout"]; ok {
			res := regTimeout.FindStringSubmatch(timeout)
			var duration time.Duration
			if res[1] != "" {
				weeks, _ := strconv.Atoi(res[1])
				duration += time.Duration(weeks) * 7 * 24 * time.Hour
			}
			if res[2] != "" {
				days, _ := strconv.Atoi(res[2])
				duration += time.Duration(days) * 24 * time.Hour
			}
			if res[3] != "" {
				hours, _ := strconv.Atoi(res[3])
				duration += time.Duration(hours) * time.Hour
			}
			if res[4] != "" {
				minutes, _ := strconv.Atoi(res[4])
				duration += time.Duration(minutes) * time.Minute
			}
			if res[5] != "" {
				seconds, _ := strconv.Atoi(res[5])
				duration += time.Duration(seconds) * time.Second
			}
			if *debug {
				log.Printf("%s(%s): dynamic entry, address=%s, timeout=%s, duration=%s\n", mt.Name, mapname, dict["address"], timeout, duration)
			}
			return time.Now().Add(duration)
		}
		panic(fmt.Sprintf("%s(%s): dynamic entry without timeout??", mt.Name, mapname))
	}
	if *debug {
		log.Printf("%s(%s): static entry, address=%s\n", mt.Name, mapname, dict["address"])
	}
	return time.Time{} // permanent entry
}

func (mt *Mikrotik) getAddresslist(mapname string) []BlackIP {
	var ips []BlackIP

	q := ros.Query{
		Pairs: []ros.Pair{{"list", mapname, ""}},
	}
	reply, err := mt.client.Query("/ip/firewall/address-list/getall", q)
	if err != nil {
		log.Fatalln(err)
	}
	for _, v := range reply.SubPairs {
		ip := parseCIDR(v["address"])
		if ip != nil {
			duration := mt.toDuration(mapname, v)
			ips = append(ips, BlackIP{*ip, duration, v[".id"]})
		}
	}
	reply, err = mt.client.Query("/ipv6/firewall/address-list/getall", q)
	if err != nil {
		log.Fatalln(err)
	}
	for _, v := range reply.SubPairs {
		ip := parseCIDR(v["address"])
		if ip != nil {
			duration := mt.toDuration(mapname, v)
			ips = append(ips, BlackIP{*ip, duration, v[".id"]})
		}
	}
	sort.Sort(ByAge(ips))
	if *debug {
		log.Printf("%s: getAddresslist(%s)=%v", mt.Name, mapname, ips)
	} else if cfg.Settings.Verbose {
		log.Printf("%s: getAddresslist(%s)", mt.Name, mapname)
	}
	return ips
}

// DelIP removed an ip address from the Mikrotik.
func (mt *Mikrotik) DelIP(ip BlackIP) error {
	if *debug || cfg.Settings.Verbose {
		defer log.Printf("%s: DelIP(%s)", mt.Name, ip.String())
	}
	args := []ros.Pair{{".id", ip.ID, ""}}
	var err error
	if ip.Net.IP.To4() != nil {
		_, err = mt.client.Call("/ip/firewall/address-list/remove", args)
	} else {
		_, err = mt.client.Call("/ipv6/firewall/address-list/remove", args)
	}
	if err != nil {
		return err
	}

	return nil
}

// AddIP will add the given ip address to the Mikrotik, when duration is 0,
// the entry is seen as permanent and the white and blacklist are not checked
// for duplicates. Conflicts on those lists are checked when the configuration
// is read. It protects against double adding, as that will make the Mikrotik
// spit out an error which in the current implementation leads to a program
// restart. For all timeouts != 0, the index returned over the Mikrotik
// connection is stored, together with the IP itself, in the dynlist entry.
func (mt *Mikrotik) AddIP(ip net.IPNet, duration Duration) error {
	if *debug || cfg.Settings.Verbose {
		defer log.Printf("%s: AddIP(%s/%v)", mt.Name, ip.String(), duration)
	}

	// For permanent members skip the built-in white/blacklist checking
	if duration != 0 {
		// Check if it is on the whitelist
		for _, v := range mt.whitelist {
			if v.Net.Contains(ip.IP) {
				log.Printf("%s: %v is on the admin whitelist, skipped", mt.Name, ip.IP)
				return nil
			}
		}
		// Check if it is on the permanent blacklist
		for _, v := range mt.blacklist {
			if v.Net.Contains(ip.IP) {
				log.Printf("%s: %v is on the admin blacklist, skipped", mt.Name, ip.IP)
				return nil
			}
		}
		for _, v := range mt.dynlist {
			if v.Net.Contains(ip.IP) {
				log.Printf("%s: %v is on the dynamic blacklist, skipped", mt.Name, ip.IP)
				return nil
			}
		}
	}

	// Do the physical interaction with the MT
	args := []ros.Pair{
		*ros.NewPair("address", ip.String()),
		*ros.NewPair("list", mt.banlist),
	}
	if duration != 0 {
		args = append(args, *ros.NewPair("timeout", duration.String()))
	}
	var err error
	var reply ros.Reply
	if ip.IP.To4() != nil {
		reply, err = mt.client.Call("/ip/firewall/address-list/add", args)
	} else {
		reply, err = mt.client.Call("/ipv6/firewall/address-list/add", args)
	}
	if err != nil {
		return err
	}
	var id string
	if id, err = reply.GetPairVal("message"); err == nil {
		return fmt.Errorf(id)
	}
	if id, err = reply.GetPairVal("ret"); err != nil {
		return err
	}

	// Add the entry to the dynlist if it has a timeout
	if duration != 0 {
		mt.Lock()
		defer mt.Unlock()
		mt.dynlist = append(mt.dynlist, BlackIP{ip, time.Now().Add(time.Duration(duration)), id})
		sort.Sort(ByAge(mt.dynlist))
		if cfg.Settings.AutoDelete {
			mt.hasData <- struct{}{}
		}
	}
	return nil
}

// Close closes the session with the mikrotik.
func (mt *Mikrotik) Close() {
	mt.client.Close()
}

// GetIPs returns the current list of blacklisted IPs.
func (mt *Mikrotik) GetIPs() (r []BlackIP) {
	return mt.dynlist
}
