package main

import (
	"flag"
	"fmt"
	"github.com/ga0/netgraph/pkg/httpstream"
	"os"
)

func main() {
	f := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	input := f.String("i", "any", "Device to capture, or pcap filename to open")
	bpf := f.String("bpf", "tcp and dst port 80", "Set berkeley packet filter")
	outHTTP := f.String("o", "", "Write HTTP request/response to file/log, :replay suffix to create replay-able http file")
	outPcap := f.String("o.pcap", "", "Write captured packet to a pcap file")
	replay := f.String("replay", "", "Replay HTTP requests to the address, eg 127.0.0.1:5004")
	replayMethod := f.String("replay.method", "", "Replay if HTTP request method matches, empty for ANY, eg POST,GET")
	port := f.Int("p", 0, "Web server port. 0 for no  web server.")
	eventSize := f.Int("event.size", 1024, "Event channel size.")
	snapLen := f.Int("snap.len", 65535, "Snap length (max bytes per packet to capture).")
	saveEvent := f.Bool("s", false, "Save HTTP event in server")
	verbose := f.Bool("v", false, "Show version")
	_ = f.Parse(os.Args[1:])

	if *verbose {
		fmt.Printf("netgraph v1.0.0 2021-05-18 15:34:10")
		os.Exit(0)
	}

	source, err := httpstream.NewPacketSource(*input, *bpf, *snapLen)
	if err != nil {
		panic(err)
	}

	eventChan := make(chan interface{}, *eventSize)
	go httpstream.Run(source, *outPcap, eventChan, *snapLen)

	handlers := initEventHandlers(*port, *outHTTP, *replay, *replayMethod, *saveEvent)
	runEventHandler(handlers, eventChan)
}

func initEventHandlers(bindingPort int, outputHTTPFile, outReplay, replayMethod string, saveEvent bool) (handlers []httpstream.EventHandler) {
	if bindingPort > 0 {
		addr := fmt.Sprintf(":%d", bindingPort)
		handlers = append(handlers, NewNGServer(addr, saveEvent))
	}

	if outputHTTPFile != "" {
		handlers = append(handlers, httpstream.NewEventPrinter(outputHTTPFile))
	}

	if outReplay != "" {
		handlers = append(handlers, httpstream.NewEventReplay(outReplay, replayMethod))
	}

	return handlers
}

func runEventHandler(handlers []httpstream.EventHandler, eventChan <-chan interface{}) {
	for e := range eventChan {
		for _, h := range handlers {
			h.PushEvent(e)
		}
	}

	for _, h := range handlers {
		h.Wait()
	}
}
