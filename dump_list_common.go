//go:build !windows

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

func DumpDynList(mts []*Mikrotik) {
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
}
