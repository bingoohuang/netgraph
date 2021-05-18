package main

import (
	"flag"
	"fmt"
	"github.com/ga0/netgraph/pkg/httpstream"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	f := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	input := f.String("i", "any", "Device to capture, or pcap filename to open")
	bpf := f.String("bpf", "tcp port 80", "Set berkeley packet filter")
	outHTTP := f.String("o", "", "Write HTTP request/response to file, with :replay suffix to create a http file that can be replayed")
	outPcap := f.String("o.pcap", "", "Write captured packet to a pcap file")
	port := f.Int("p", 0, "Web server port. 0 for no  web server.")
	saveEvent := f.Bool("s", false, "Save HTTP event in server")
	verbose := f.Bool("v", true, "Show more message")
	_ = f.Parse(os.Args[1:])

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
