package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	ros "github.com/go-routeros/routeros/v3"
)

var (
	// 28w4d23h59m56s
	regTimeout = regexp.MustCompile(`(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?`)
)

// ByAge implements sort.Interface for []Person based on
// the Age field.
type ByAge []BlackIP

func (a ByAge) Len() int           { return len(a) }
func (a ByAge) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByAge) Less(i, j int) bool { return a[i].Dead.Before(a[j].Dead) }

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
	return fmt.Sprintf("{%s, %q, %q}", b.Net.String(), b.Dead.Format(time.RFC3339), b.ID)
}

// Mikrotik contains the internal state of a Mikrotik object, configuration
// details but also the API connection to the Mikrotik. It acts as a cache
// between the rest of the program and the Mikrotik.
type Mikrotik struct {
	conn   net.Conn
	client *ros.Client
	lock   sync.Mutex // protect AddIP/DelIP racing against AutoDelete.

	Name string

	Address string
	User    string
	Passwd  string

	hasData chan struct{}
	banlist string

	sync.RWMutex // Protect maps.
	dynlist      []BlackIP
	blacklist    []BlackIP
	whitelist    []BlackIP
}

// Setup a deadline on the connection to the Mikrotik. It returns a cancel
// function, resetting the idle deadline on the connection.
func (mt *Mikrotik) startDeadline(duration time.Duration) func() {
	_ = mt.conn.SetDeadline(time.Now().Add(duration))
	return func() { _ = mt.conn.SetDeadline(time.Time{}) }
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
	// Open the connection, use our own code for this, as we need
	// access to it for setting deadlines.
	var err error
	dialer := new(net.Dialer)
	dialer.Timeout = time.Minute
	if c.UseTLS {
		mt.conn, err = tls.DialWithDialer(dialer, "tcp", mt.Address, nil)
	} else {
		mt.conn, err = dialer.Dial("tcp", mt.Address)
	}
	if err != nil {
		return nil, err
	}
	mt.client, err = ros.NewClient(mt.conn)
	if err != nil {
		mt.conn.Close()
		return nil, err
	}

	cancel := mt.startDeadline(5 * time.Second)
	err = mt.client.Login(mt.User, mt.Passwd)
	cancel()
	if err != nil {
		mt.client.Close()
		return nil, err
	}

	if err := mt.populateBanlist(c.Whitelist, c.Blacklist); err != nil {
		mt.client.Close()
		return nil, err
	}

	if cfg.Settings.AutoDelete {
		// Start a go routine to monitor the dynlist for entries to delete.
		// It effectively implements a priority queue on the Dead time.
		// From now on we need locking if we mess with the dynlist.
		mt.hasData = make(chan struct{})
		go mt.autoDelete()
	}
	return mt, nil
}

func (mt *Mikrotik) populateBanlist(whitelist, blacklist []string) error {
	// Setup the whitelist.
	for _, v := range whitelist {
		if strings.HasPrefix(v, "@") {
			if v[1:] == mt.banlist {
				log.Printf("%s: Skipping the managed blacklist %s", mt.Name, v)
			} else {
				mt.whitelist = append(mt.whitelist, mt.getAddresslist(v[1:])...)
			}
		} else if ip := parseCIDR(v, cfg.Settings.Verbose); ip != nil {
			mt.whitelist = append(mt.whitelist, BlackIP{*ip, time.Time{}, ".gcfg"})
		} else {
			return fmt.Errorf("%s: Unable to parse whitelist prefix/ip %s", mt.Name, v)
		}
	}
	// Fill the blacklist, aka permanent blacklist members.
	for _, v := range blacklist {
		if strings.HasPrefix(v, "@") {
			if v[1:] == mt.banlist {
				log.Printf("%s: Skipping the managed blacklist %s", mt.Name, v)
			} else {
				mt.blacklist = append(mt.blacklist, mt.getAddresslist(v[1:])...)
			}
		} else if ip := parseCIDR(v, cfg.Settings.Verbose); ip != nil {
			mt.blacklist = append(mt.blacklist, BlackIP{*ip, time.Time{}, ".gcfg"})
		} else {
			return fmt.Errorf("%s: Unable to parse blacklist prefix/ip %s", mt.Name, v)
		}
	}

	// Create a map and prefill it with the permanent blacklist.
	blackmap := make(map[string]*BlackIP)
	for i, v := range mt.blacklist {
		blackmap[v.Net.String()] = &mt.blacklist[i]
	}

	// Check if the whitelist entries are not on the permanent blacklist.
	for _, v := range mt.whitelist {
		if _, ok := blackmap[v.Net.String()]; ok {
			return fmt.Errorf("%s: Conflicting whitelist/blacklist entry %s", mt.Name, v.Net.String())
		}
	}

	// Now check every entry from the managed dynlist.
addresslist:
	for _, v := range mt.getAddresslist(mt.banlist) {
		// Whitelisted entries should never be on the banlist.
		for _, w := range mt.whitelist {
			if w.Net.Contains(v.Net.IP) {
				log.Printf("%s(%s): Deleting whitelisted entry %s", mt.Name, mt.banlist, v.Net.String())
				if err := mt.DelIP(v); err != nil {
					return err
				}
				// No use checking the rest, it's dead Jim.
				continue addresslist
			}
		}
		if v.Dead.IsZero() {
			// Permanent entry, must (literally) exist in permanent blacklist.
			if _, ok := blackmap[v.Net.String()]; ok {
				// In blacklist, mark as found.
				delete(blackmap, v.Net.String())
			} else {
				// Remove this permanent entry as it is not on permanent blacklist.
				log.Printf("%s: Deleting unwanted permanent blacklist entry %s", mt.Name, v.Net.String())
				if err := mt.DelIP(v); err != nil {
					return err
				}
			}
		} else {
			// Dynamic entry, not expected to exist in permanent blacklist.
			if _, ok := blackmap[v.Net.String()]; ok {
				// Remove this dynamic entry as it is on the permanent blacklist.
				// It will be added back later as a permanent entry.
				log.Printf("%s: Deleting unwanted dynamic blacklist entry %s", mt.Name, v.Net.String())
				if err := mt.DelIP(v); err != nil {
					return err
				}
			} else {
				// Dynamic entry. All good.
				mt.dynlist = append(mt.dynlist, v)
			}
		}
	}
	// Add the remaining (missing) permanent blacklist entries.
	for _, v := range blackmap {
		if err := mt.AddIP(v.Net, 0, ""); err != nil {
			return err
		}
	}

	return nil
}

func (mt *Mikrotik) autoDelete() {
	var oldest time.Time
	var oldestEntry *BlackIP
	for {
		mt.RLock()
		if len(mt.dynlist) != 0 {
			oldest = mt.dynlist[0].Dead
			oldestEntry = &mt.dynlist[0]
		} else {
			if *debug {
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
		case _, more := <-mt.hasData:
			if !more {
				if *debug {
					log.Printf("%s: Got close, stopping AutoDelete goroutine", mt.Name)
				}
				return
			}
			if *debug {
				log.Printf("%s: Received new data indication", mt.Name)
			}
			break
		case <-time.After(time.Until(oldest)):
			if oldestEntry != nil {
				if *debug {
					log.Printf("%s: Deleting oldest dynlist entry", mt.Name)
				}
				if err := mt.DelIP(*oldestEntry); err != nil {
					log.Fatalln(mt.Name, err)
				}
			}
		}
	}
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
	return time.Time{} // permanent entry.
}

func (mt *Mikrotik) getAddresslist(mapname string) []BlackIP {
	var ips []BlackIP

	cancel := mt.startDeadline(5 * time.Second)
	list := fmt.Sprintf("?list=%s", mapname)
	reply, err := mt.client.Run("/ip/firewall/address-list/getall", list)
	cancel()
	if err != nil {
		log.Fatalln(err)
	}
	for _, re := range reply.Re {
		ip := parseCIDR(re.Map["address"], cfg.Settings.Verbose)
		if ip != nil {
			duration := mt.toDuration(mapname, re.Map)
			ips = append(ips, BlackIP{*ip, duration, re.Map[".id"]})
		}
	}
	cancel = mt.startDeadline(5 * time.Second)
	reply, err = mt.client.Run("/ipv6/firewall/address-list/getall", list)
	cancel()
	if err != nil {
		log.Fatalln(err)
	}
	for _, re := range reply.Re {
		ip := parseCIDR(re.Map["address"], cfg.Settings.Verbose)
		if ip != nil {
			duration := mt.toDuration(mapname, re.Map)
			ips = append(ips, BlackIP{*ip, duration, re.Map[".id"]})
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
		defer log.Printf("%s: DelIP(%s) finished", mt.Name, ip.String())
	}
	// Protect against racing DelIP/AddIPs.
	mt.lock.Lock()
	defer mt.lock.Unlock()

	if *debug || cfg.Settings.Verbose {
		log.Printf("%s: DelIP(%s) started", mt.Name, ip.String())
	}
	selector := fmt.Sprintf("=.id=%s", ip.ID)
	var err error
	cancel := mt.startDeadline(5 * time.Second)
	if ip.Net.IP.To4() != nil {
		_, err = mt.client.Run("/ip/firewall/address-list/remove", selector)
	} else {
		_, err = mt.client.Run("/ipv6/firewall/address-list/remove", selector)
	}
	cancel()
	if err == nil && cfg.Settings.AutoDelete {
		mt.Lock()
		// We expect to be called with the oldest entry. Delete that.
		if mt.dynlist[0].ID == ip.ID {
			mt.dynlist = mt.dynlist[1:]
		}
		mt.Unlock()
	}
	return err
}

// AddIP will add the given ip address to the Mikrotik, when duration is 0,
// the entry is seen as permanent and the white and blacklist are not checked
// for duplicates. Conflicts on those lists are checked when the configuration
// is read. It protects against double adding, as that will make the Mikrotik
// spit out an error which in the current implementation leads to a program
// restart. For all timeouts != 0, the index returned over the Mikrotik
// connection is stored, together with the IP itself, in the dynlist entry.
func (mt *Mikrotik) AddIP(ip net.IPNet, duration Duration, comment string) error {
	if *debug || cfg.Settings.Verbose {
		defer log.Printf("%s: AddIP(%s/%v) finished", mt.Name, ip.String(), duration)
	}
	// Protect against racing DelIP/AddIPs.
	mt.lock.Lock()
	defer mt.lock.Unlock()

	if *debug || cfg.Settings.Verbose {
		log.Printf("%s: AddIP(%s/%v) started", mt.Name, ip.String(), duration)
	}
	// For permanent members skip the built-in white/blacklist checking.
	if duration != 0 {
		// Check if it is on the whitelist
		for _, v := range mt.whitelist {
			if v.Net.Contains(ip.IP) {
				log.Printf("%s: AddIP(%v) is on the admin whitelist, skipped", mt.Name, ip.IP)
				return nil
			}
		}
		// Check if it is on the permanent blacklist.
		for _, v := range mt.blacklist {
			if v.Net.Contains(ip.IP) {
				log.Printf("%s: AddIP(%v) is on the admin blacklist, skipped", mt.Name, ip.IP)
				return nil
			}
		}
		mt.RLock()
		for _, v := range mt.dynlist {
			if v.Net.Contains(ip.IP) {
				mt.RUnlock()
				log.Printf("%s: AddIP(%v) is already on the dynamic blacklist, skipped", mt.Name, ip.IP)
				return nil
			}
		}
		mt.RUnlock()
	}

	// Do the physical interaction with the MT.
	args := []string{
		"/ip/firewall/address-list/add",
		fmt.Sprintf("=address=%s", ip.String()),
		fmt.Sprintf("=list=%s", mt.banlist),
	}
	if ip.IP.To4() == nil {
		args[0] = "/ipv6/firewall/address-list/add"
	}
	if duration != 0 {
		args = append(args, fmt.Sprintf("=timeout=%s", duration))
	}
	if comment != "" {
		args = append(args, fmt.Sprintf("=comment=%s", comment))
	}
	cancel := mt.startDeadline(5 * time.Second)
	var err error
	var reply *ros.Reply
	reply, err = mt.client.RunArgs(args)
	cancel()
	if err != nil {
		if strings.Contains(err.Error(), "already have") {
			return nil
		}
		return fmt.Errorf("addip=%v", err)
	}
	var (
		id string
		ok bool
	)
	if id, ok = reply.Done.Map["ret"]; !ok {
		return fmt.Errorf("missing `ret`")
	}

	// Add the entry to the dynlist if it has a timeout.
	if duration != 0 && cfg.Settings.AutoDelete {
		mt.Lock()
		mt.dynlist = append(mt.dynlist, BlackIP{ip, time.Now().Add(time.Duration(duration)), id})
		sort.Sort(ByAge(mt.dynlist))
		mt.Unlock()
		// Tell auto deleter new data has arrived.
		select {
		case mt.hasData <- struct{}{}:
		default:
			log.Printf("hasData full, deadlock?")
		}
	}
	return nil
}

// Close closes the session with the mikrotik.
func (mt *Mikrotik) Close() {
	close(mt.hasData)
	mt.client.Close()
}

// GetIPs returns the current list of blacklisted IPs.
func (mt *Mikrotik) GetIPs() (r []BlackIP) {
	mt.RLock()
	defer mt.RUnlock()
	return append([]BlackIP(nil), mt.dynlist...)
}
