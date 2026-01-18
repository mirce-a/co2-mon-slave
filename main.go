package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/grandcat/zeroconf"
)

func main() {
	// 1. Define the service
	// Parameters: Instance Name, Service Type, Domain, Port, TXT Records, Interface
	server, err := zeroconf.Register(
		"Slave-Sensor-01",   // Unique instance name
		"_co2-monitor._tcp", // Service type
		"local.",            // Domain
		8080,                // The port your Go API runs on
		[]string{"version=1.0", "room=greenhouse-1"},
		nil,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer server.Shutdown()

	log.Println("Slave is broadcasting mDNS...")

	// Keep the program running until interrupted
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}
