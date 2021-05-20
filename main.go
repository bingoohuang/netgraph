package main

import (
	"fmt"

	"github.com/bingoohuang/gg/pkg/flagparse"
	"github.com/ga0/netgraph/pkg/httpstream"
	"github.com/google/gopacket"
)

// Arg arguments.
type Arg struct {
	Input        string   `flag:"i" val:"any" usage:"Device to capture, or pcap filename to open"`
	InputRequest bool     `flag:"i.request" val:"true" usage:"Only capture HTTP requests"`
	InputMethod  string   `flag:"i.method" val:"" usage:"Only capture HTTP methods, empty for ANY, multiple separated by comma, eg POST"`
	Bpf          string   `flag:"bpf" val:"tcp and dst port 80" usage:"Set berkeley packet filter"`
	Outs         []string `flag:"o" val:"" usage:"Outputs HTTP request/response, :\n stdout to print to stdout,\n stdlog to log,\nxx.http to create replay-able http file, \nxx.pcap to write captured packets as a pcap file, \nxx.json to create replay-able json file"`
	ReplayAddr   string   `flag:"replay" val:"" usage:"Replay HTTP requests to the address, eg 127.0.0.1:5004"`
	ReplayMethod string   `flag:"replay.method" val:"" usage:"Replay if HTTP request method matches, empty for ANY, eg POST,GET"`
	WebPort      int      `flag:"p"  val:"0" usage:"Web server port. 0 for no web server"`
	EventSize    int      `flag:"event.size" val:"1024" usage:"Event channel size"`
	SnapLen      int      `flag:"snap.len" val:"65535" usage:"Snap length (max bytes per packet to capture)"`
	SaveEvent    bool     `flag:"s" val:"false" usage:"Save HTTP event in server"`
	Version      bool     `flag:"v" val:"false" usage:"Show version"`
}

// VersionInfo gives the version information.
func (a Arg) VersionInfo() string { return " v1.0.2 2021-05-19 22:35:41" }

// NewPacketSource creates new packet source.
func (a Arg) NewPacketSource() (*gopacket.PacketSource, error) {
	return httpstream.NewPacketSource(a.Input, a.Bpf, a.SnapLen)
}

func main() {
	var a Arg
	flagparse.Parse(&a)

	source, err := a.NewPacketSource()
	if err != nil {
		panic(err)
	}

	eventChan := make(chan interface{}, a.EventSize)

	go httpstream.Run(source, httpstream.SuffixPcap.Find(a.Outs), eventChan, a.SnapLen, a.InputRequest, a.InputMethod)

	a.createHandlers().Run(eventChan)
}

func (a Arg) createHandlers() (hs httpstream.EventHandlers) {
	if a.WebPort > 0 {
		hs = append(hs, NewNGServer(fmt.Sprintf(":%d", a.WebPort), a.SaveEvent))
	}

	if v := httpstream.SuffixStdLog.Find(a.Outs); v != "" {
		hs = append(hs, httpstream.NewEventLog())
	}
	if v := httpstream.SuffixStdout.Find(a.Outs); v != "" {
		hs = append(hs, httpstream.NewEventStdout())
	}
	if v := httpstream.SuffixJson.Find(a.Outs); v != "" {
		hs = append(hs, httpstream.NewEventJson(v))
	}
	if v := httpstream.SuffixLog.Find(a.Outs); v != "" {
		hs = append(hs, httpstream.NewEventLogFile(v))
	}
	if v := httpstream.SuffixHttp.Find(a.Outs); v != "" {
		hs = append(hs, httpstream.NewEventHttp(v))
	}

	if a.ReplayAddr != "" {
		hs = append(hs, httpstream.NewEventReplay(a.ReplayAddr, a.ReplayMethod))
	}

	return hs
}
