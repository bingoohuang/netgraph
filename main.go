package main

import (
	"flag"
	"fmt"
	"github.com/ga0/netgraph/pkg/httpstream"
	"io/ioutil"
	"log"
)

var device = flag.String("i", "", "Device to capture, auto select one if no device provided, or pcap filename to open")
var bpf = flag.String("bpf", "tcp port 80", "Set berkeley packet filter")

var outputHTTP = flag.String("o", "", "Write HTTP request/response to file")
var outputPcap = flag.String("o.pcap", "", "Write captured packet to a pcap file")

var bindingPort = flag.Int("p", 9000, "Web server port. If the port is set to '0', the server will not run.")
var saveEvent = flag.Bool("s", false, "Save HTTP event in server")

var verbose = flag.Bool("v", true, "Show more message")

func init() {
	flag.Parse()

	if !*verbose {
		log.SetOutput(ioutil.Discard)
	}
}

func main() {
	source, err := httpstream.NewPacketSource(*device, *bpf)
	if err != nil {
		panic(err)
	}

	eventChan := make(chan interface{}, 1024)
	go httpstream.Run(source, *outputPcap, eventChan)

	handlers := initEventHandlers(*bindingPort, *outputHTTP)
	runEventHandler(handlers, eventChan)
}

func initEventHandlers(bindingPort int, outputHTTPFile string) (handlers []httpstream.EventHandler) {
	if bindingPort > 0 {
		addr := fmt.Sprintf(":%d", bindingPort)
		handlers = append(handlers, NewNGServer(addr, *saveEvent))
	}

	if outputHTTPFile != "" {
		handlers = append(handlers, httpstream.NewEventPrinter(outputHTTPFile))
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
