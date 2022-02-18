//go:build linux
// +build linux

package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"flag"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	// "github.com/cilium/ebpf/ringbuf"
	"errors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  -cflags "-O2  -g -Wall -Werror -I./headers"  bpf tcp_data.c

var (
	connectionsCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "connections",
		Help: "Count of connections",
	})
)

// Length of struct event_t sent from kernelspace.
var eventLength = 12

type Event struct {
	SPort uint16
	DPort uint16
	SAddr uint32
	DAddr uint32
}

// UnmarshalBinary unmarshals a ringbuf record into an Event.
func (e *Event) UnmarshalBinary(b []byte) error {
	if len(b) != eventLength {
		return fmt.Errorf("unexpected event length %d", len(b))
	}

	e.SPort = binary.BigEndian.Uint16(b[0:2])
	e.DPort = binary.BigEndian.Uint16(b[2:4])

	e.SAddr = binary.BigEndian.Uint32(b[4:8])
	e.DAddr = binary.BigEndian.Uint32(b[8:12])

	return nil
}

type ScanData struct {
	Event    Event
	ScanTime time.Time
}

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}

func main() {
	var ifaceName string
	flag.StringVar(&ifaceName, "iface", "eth0", "Interface name to attach XDP program")
	flag.Parse()

	if ifaceName == "" {
		log.Fatal("Missing required param iface")
		os.Exit(1)
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	ifaces, err := net.Interfaces()
	if err != nil {
		log.Print(fmt.Errorf("Unable to get list of interfaces: %+v\n", err.Error()))
		return
	}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	var xdpIface net.Interface
	var foundIface bool
	for _, iface := range ifaces {
		if iface.Name == ifaceName {
			xdpIface = iface
			foundIface = true
		}
	}
	if !foundIface {
		log.Fatalf("Unable to find given interface")
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpSampleProg,
		Interface: xdpIface.Index,
	})
	defer l.Close()
	if err != nil {
		log.Fatalf("attaching xdp: %s", err)
	}

	// Open a perf event reader from userspace on the PERF_EVENT_ARRAY map
	// described in the eBPF C program.
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	go func() {
		// Wait for a signal and close the perf reader,
		// which will interrupt rd.Read() and make the program exit.
		<-stopper
		log.Println("Received signal, exiting program..")

		if err := rd.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}
	}()

	go func() {
		r := mux.NewRouter()
		srv := &http.Server{
			Addr:         ":8081",
			WriteTimeout: time.Second * 15,
			ReadTimeout:  time.Second * 15,
			IdleTimeout:  time.Second * 60,
			Handler:      r,
		}

		r.Handle("/metrics", promhttp.Handler())
		fmt.Println("Server listen on :8081")
		if err != nil {
			log.Println(err)
		}
		if err := srv.ListenAndServe(); err != nil {
			panic(err)
		}
	}()
	log.Printf("Listening for events..")

	var event Event
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("reading from perf event reader: %s", err)
			continue
		}

		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		err = event.UnmarshalBinary(record.RawSample)
		if err != nil {
			log.Println("parse error", err)
		}

		log.Printf("New connection: %s:%d -> %s:%d \n", intToIP(event.SAddr).String(), event.SPort, intToIP(event.DAddr).String(), event.DPort)
	}

}
