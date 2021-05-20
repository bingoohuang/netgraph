package httpstream

import (
	"io"
	"log"
	"os"
	"strings"
)

type (
	OutSuffix   string
	OutSuffixes []OutSuffix
)

const (
	SuffixStdout OutSuffix = "stdout"
	SuffixStdLog OutSuffix = "log"
	SuffixHttp   OutSuffix = ".http"
	SuffixPcap   OutSuffix = ".pcap"
	SuffixLog    OutSuffix = ".log"
	SuffixJson   OutSuffix = ".json"
)

func (o OutSuffix) Find(ss []string) string {
	for _, s := range ss {
		so := string(o)
		if so == s || strings.HasSuffix(s, so) {
			return s
		}
	}

	return ""
}

// EventPrinter print HTTP events to writer or stdout.
type EventPrinter struct {
	writer io.WriteCloser
	replay bool
}

type LogWriter struct{}

func (l LogWriter) Write(p []byte) (n int, err error) {
	log.Printf("{PRE}Request %s", p)
	return 0, nil
}

func (l LogWriter) Close() error { return nil }

func NewEventStdout() *EventPrinter {
	return &EventPrinter{writer: os.Stdout, replay: false}
}

func NewEventLogFile(name string) *EventPrinter {
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o755)
	if err != nil {
		log.Fatalln("Cannot open writer ", name)
	}
	return &EventPrinter{writer: f, replay: false}
}

func NewEventLog() *EventPrinter {
	return &EventPrinter{writer: &LogWriter{}, replay: false}
}

func NewEventHttp(name string) *EventPrinter {
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o755)
	if err != nil {
		log.Fatalln("Cannot open writer ", name)
	}
	return &EventPrinter{writer: f, replay: true}
}

// PushEvent implements the function of interface EventHandler.
func (p *EventPrinter) PushEvent(e interface{}) {
	switch v := e.(type) {
	case RequestEvent:
		_, _ = WriteRequestTo(p.replay, v, p.writer)
	case ResponseEvent:
		_, _ = WriteResponseTo(p.replay, v, p.writer)

	default:
		log.Printf("Unknown event: %v", e)
	}
}

// Wait implements the function of interface EventHandler.
func (p *EventPrinter) Wait() { _ = p.writer.Close() }

func WriteRequestTo(replay bool, r RequestEvent, out io.Writer) (n int64, err error) {
	if replay {
		n += fp(out, "###\r\n%s %s\r\n", r.Method, r.URI)
		for h := range r.Header {
			switch h {
			case "User-Agent", "Host", "Connection", "Transfer-Encoding":
			default:
				n += fp(out, "%s: %s\r\n", h, r.Header.Get(h))
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
