package httpstream

import (
	"fmt"
	"github.com/bingoohuang/gg/pkg/rest"
	"log"
	"net/http"
	"strings"
)

// EventReplay replay HTTP events.
type EventReplay struct {
	Addr        string
	MethodAllow func(method string) bool
}

// NewEventReplay creates EventReplay.
func NewEventReplay(addr string, method string) *EventReplay {
	r := &EventReplay{Addr: addr}

	if method == "" {
		r.MethodAllow = func(string) bool { return true }
	} else {
		mm := make(map[string]bool)
		for _, m := range strings.Split(method, ",") {
			m = strings.ToUpper(strings.TrimSpace(m))
			if m != "" {
				mm[m] = true
			}
		}
		r.MethodAllow = func(m string) bool { return mm[m] }
	}

	return r
}

// PushEvent implements the function of interface EventHandler.
func (p *EventReplay) PushEvent(e interface{}) {
	switch v := e.(type) {
	case RequestEvent:
		p.replay(v)
	case ResponseEvent:
		// bypass
	default:
		log.Printf("Unknown event: %v", e)
	}
}

// Wait implements the function of interface EventHandler.
func (p *EventReplay) Wait() {}

const XHttpCapRelay = "X-Httpcap-Replay"

func (p *EventReplay) replay(v RequestEvent) {
	if !p.MethodAllow(v.Method) {
		log.Printf("Replay ignored, %s %s method not allowed", v.Method, v.URI)
		return
	}

	if v.Header.Get(XHttpCapRelay) == "true" {
		log.Printf("Replay ignored, %s %s %s = true", v.Method, v.URI, XHttpCapRelay)
		return
	}

	u := Fulfil(fmt.Sprintf("%s%s", p.Addr, v.URI))

	v.Header.Add(XHttpCapRelay, "true")
	for _, n := range []string{"User-Agent", "Host", "Connection", "Transfer-Encoding", "Content-Length"} {
		v.Header.Del(n)
	}
	r, err := rest.Rest{Method: v.Method, Addr: u, Headers: ConvertHeaders(v.Header), Body: v.Body}.Do()
	if err != nil {
		log.Printf("E! Replay %s %s error:%v", v.Method, u, err)
	} else {
		log.Printf("Replay %s %s status %d", v.Method, u, r.Status)
	}
}

func ConvertHeaders(header http.Header) map[string]string {
	m := make(map[string]string)

	for k := range header {
		m[k] = header.Get(k)
	}

	return m
}
