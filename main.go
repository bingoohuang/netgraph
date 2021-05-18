package main

import (
	"fmt"
	"github.com/ga0/netgraph/pkg/httpstream"
	"github.com/google/gopacket"
	"os"
)

type Arg struct {
	Input        string `flag:"i" val:"any" usage:"Device to capture, or pcap filename to open"`
	Bpf          string `flag:"bpf" val:"tcp and dst port 80" usage:"Set berkeley packet filter"`
	OutHTTP      string `flag:"o" val:"" usage:"Write HTTP request/response to file/log, :replay suffix to create replay-able http file"`
	OutPcap      string `flag:"o.pcap" val:"" usage:"Write captured packet to a pcap file"`
	ReplayAddr   string `flag:"replay" val:"" usage:"Replay HTTP requests to the address, eg 127.0.0.1:5004"`
	ReplayMethod string `flag:"replay.method" val:"" usage:"Replay if HTTP request method matches, empty for ANY, eg POST,GET"`
	WebPort      int    `flag:"p"  val:"0" usage:"Web server port. 0 for no web server"`
	EventSize    int    `flag:"event.size" val:"1024" usage:"Event channel size"`
	SnapLen      int    `flag:"snap.len" val:"65535" usage:"Snap length (max bytes per packet to capture)"`
	SaveEvent    bool   `flag:"s" val:"false" usage:"Save HTTP event in server"`
	Version      bool   `flag:"v" val:"false" usage:"Show version"`
}

func (a Arg) ShowVersion() {
	if a.Version {
		fmt.Println("netgraph v1.0.1 2021-05-18 17:44:42")
		os.Exit(0)
	}
}

func (a Arg) NewPacketSource() (*gopacket.PacketSource, error) {
	return httpstream.NewPacketSource(a.Input, a.Bpf, a.SnapLen)
}

func main() {
	var a Arg
	httpstream.ParseFlags(&a)
	a.ShowVersion()

	source, err := a.NewPacketSource()
	if err != nil {
		panic(err)
	}

	eventChan := make(chan interface{}, a.EventSize)
	go httpstream.Run(source, a.OutPcap, eventChan, a.SnapLen)

	a.createHandlers().Run(eventChan)
}

func (a Arg) createHandlers() (hs httpstream.EventHandlers) {
	if a.WebPort > 0 {
		hs = append(hs, NewNGServer(fmt.Sprintf(":%d", a.WebPort), a.SaveEvent))
	}

	if a.OutHTTP != "" {
		hs = append(hs, httpstream.NewEventPrinter(a.OutHTTP))
	}

	if a.ReplayAddr != "" {
		hs = append(hs, httpstream.NewEventReplay(a.ReplayAddr, a.ReplayMethod))
	}

	return hs
}
