package main

import (
	"flag"
	"fmt"
	"github.com/ga0/netgraph/pkg/httpstream"
	"io/ioutil"
	"log"
)

func main() {
	input := flag.String("i", "any", "Device to capture, or pcap filename to open")
	bpf := flag.String("bpf", "tcp port 80", "Set berkeley packet filter")
	outHTTP := flag.String("o", "", "Write HTTP request/response to file")
	outPcap := flag.String("o.pcap", "", "Write captured packet to a pcap file")
	port := flag.Int("p", 9000, "Web server port. If the port is set to '0', the server will not run.")
	saveEvent := flag.Bool("s", false, "Save HTTP event in server")
	verbose := flag.Bool("v", true, "Show more message")

	flag.Parse()

	if !*verbose {
		log.SetOutput(ioutil.Discard)
	}

	source, err := httpstream.NewPacketSource(*input, *bpf)
	if err != nil {
		panic(err)
	}

	eventChan := make(chan interface{}, 1024)
	go httpstream.Run(source, *outPcap, eventChan)

	handlers := initEventHandlers(*port, *outHTTP, *saveEvent)
	runEventHandler(handlers, eventChan)
}

func initEventHandlers(bindingPort int, outputHTTPFile string, saveEvent bool) (handlers []httpstream.EventHandler) {
	if bindingPort > 0 {
		addr := fmt.Sprintf(":%d", bindingPort)
		handlers = append(handlers, NewNGServer(addr, saveEvent))
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
