package httpstream

import (
	"io"
	"log"
	"os"
	"strings"
)

// EventPrinter print HTTP events to file or stdout.
type EventPrinter struct {
	file   *os.File
	replay bool
}

const replayTag = ":replay"

// NewEventPrinter creates EventPrinter.
func NewEventPrinter(name string) *EventPrinter {
	replay := strings.HasSuffix(name, replayTag)
	if replay {
		name = name[:len(name)-len(replayTag)]
	}
	if name == "stdout" {
		return &EventPrinter{file: os.Stdout, replay: replay}
	}

	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		log.Fatalln("Cannot open file ", name)
	}

	return &EventPrinter{file: f, replay: replay}
}

// PushEvent implements the function of interface EventHandler.
func (p *EventPrinter) PushEvent(e interface{}) {
	switch v := e.(type) {
	case RequestEvent:
		_, _ = WriteRequestTo(p.replay, v, p.file)
	case ResponseEvent:
		_, _ = WriteResponseTo(p.replay, v, p.file)

	default:
		log.Printf("Unknown event: %v", e)
	}
}

// Wait implements the function of interface EventHandler.
func (p *EventPrinter) Wait() {}

func WriteRequestTo(replay bool, r RequestEvent, out io.Writer) (n int64, err error) {
	if replay {
		n += fp(out, "###\r\n%s %s\r\n", r.Method, r.URI)
		for _, h := range r.Headers {
			switch h.Name {
			case "User-Agent", "Host", "Connection", "Transfer-Encoding":
			default:
				n += fp(out, "%s: %s\r\n", h.Name, h.Value)
			}
		}
		n += fp(out, "\r\n")
		if len(r.Body) > 0 {
			n += fp(out, "%s\r\n", r.Body)
			n += fp(out, "\r\n")
		}

		return n, nil
	}

	return r.WriteTo(out)
}

func WriteResponseTo(replay bool, r ResponseEvent, out io.Writer) (n int64, err error) {
	if replay {
		return 0, nil
	}

	return r.WriteTo(out)
}
