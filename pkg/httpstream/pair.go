package httpstream

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// EventHandler handle HTTP events.
type EventHandler interface {
	PushEvent(interface{})
	Wait()
}

type EventHandlers []EventHandler

func (handlers EventHandlers) Run(eventChan <-chan interface{}) {
	for e := range eventChan {
		for _, h := range handlers {
			h.PushEvent(e)
		}
	}

	for _, h := range handlers {
		h.Wait()
	}
}

// Header is HTTP header key-value pair.
type Header struct {
	Name  string
	Value string
}

// Event is HTTP request or response.
type Event struct {
	Type       string
	Start, End time.Time
	StreamSeq  uint
	ID         int
	ClientAddr string
	ServerAddr string
	Header     http.Header
	Body       []byte
}

// RequestEvent is HTTP request.
type RequestEvent struct {
	Event
	Method  string
	URI     string
	Version string
}

// ResponseEvent is HTTP response.
type ResponseEvent struct {
	Event
	Version string
	Code    string
	Reason  string
}

// pair is Bi-direction HTTP stream pair.
type pair struct {
	connSeq   uint
	eventChan chan<- interface{}

	method, clientAddr, serverAddr string

	idChan       chan int
	id           int
	onlyRequests bool
}

func newPair(seq uint, eventChan chan<- interface{}, onlyRequests bool) *pair {
	return &pair{connSeq: seq, eventChan: eventChan, idChan: make(chan int, 10000), onlyRequests: onlyRequests}
}

func (p *pair) run(wg *sync.WaitGroup, stream *httpStream, methodAllowed func(string) bool) {
	defer wg.Done()
	defer close(stream.reader.stopCh)

	dir := DirectionUnknown
	for {
		if err := p.handleTransaction(&dir, stream, methodAllowed); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				log.Printf("EOF %s", stream.key.String())
			} else {
				log.Printf("E! %s, error: %v", stream.key.String(), err)
			}
			return
		}
	}
}

func (p *pair) handleRequestTransaction(method, uri, version string, s *httpStream, methodAllowed func(string) bool) error {
	reqStart := s.reader.lastSeen
	reqHeader, err := s.parseHeader()
	if err != nil {
		return err
	}

	p.clientAddr = s.key.net.Src().String() + ":" + s.key.tcp.Src().String()
	p.serverAddr = s.key.net.Dst().String() + ":" + s.key.tcp.Dst().String()

	reqBody, err := s.parseBody(method, reqHeader, true)
	if err != nil {
		return err
	}

	p.method = method
	p.id++
	TryPut(p.idChan, p.id)

	if !methodAllowed(method) {
		return nil
	}

	p.eventChan <- RequestEvent{
		Method:  method,
		URI:     uri,
		Version: version,

		Event: Event{
			ClientAddr: p.clientAddr,
			ServerAddr: p.serverAddr,
			Type:       "HTTPRequest",
			StreamSeq:  p.connSeq,
			Start:      reqStart,
			End:        s.reader.lastSeen,
			ID:         p.id,
			Header:     reqHeader,
			Body:       reqBody,
		},
	}

	return nil
}

func (p *pair) handleTransaction(dir *Direction, stream *httpStream, methodAllowed func(string) bool) error {
	direction, p1, p2, p3, err := stream.parseFirstLine(*dir)
	if err != nil {
		return err
	}
	*dir = direction

	if direction == DirectionRequest {
		return p.handleRequestTransaction(p1, p2, p3, stream, methodAllowed)
	} else {
		return p.handleResponseTransaction(p1, p2, p3, stream)
	}
}

func (p *pair) handleResponseTransaction(respVersion, code, reason string, stream *httpStream) error {
	respStart := stream.reader.lastSeen
	respHeader, err := stream.parseHeader()
	if err != nil {
		return err
	}
	respBody, err := stream.parseBody(p.method, respHeader, false)
	if err != nil {
		return err
	}

	if p.onlyRequests {
		return nil
	}

	p.eventChan <- ResponseEvent{
		Version: respVersion,
		Code:    code,
		Reason:  reason,

		Event: Event{
			Type:       "HTTPResponse",
			StreamSeq:  p.connSeq,
			Start:      respStart,
			End:        stream.reader.lastSeen,
			ID:         TryGet(p.idChan),
			ClientAddr: p.clientAddr,
			ServerAddr: p.serverAddr,
			Header:     respHeader,
			Body:       respBody,
		},
	}

	return nil
}

var fp = func(w io.Writer, format string, a ...interface{}) int64 {
	n, _ := fmt.Fprintf(w, format, a...)
	return int64(n)
}

const layout = "2006-01-02 15:04:05.000"

func (r RequestEvent) WriteTo(out io.Writer) (n int64, err error) {
	var b bytes.Buffer
	b.WriteString(fmt.Sprintf("#%d [%s] Request %s->%s\r\n", r.StreamSeq,
		r.Start.Format(layout), r.ClientAddr, r.ServerAddr))
	b.WriteString(fmt.Sprintf("%s %s %s\r\n", r.Method, r.URI, r.Version))
	r.writeHeader(&b)
	r.writeBody(&b)
	return b.WriteTo(out)
}

func (r ResponseEvent) WriteTo(out io.Writer) (n int64, err error) {
	var b bytes.Buffer
	b.WriteString(fmt.Sprintf("#%d [%s] Response %s<-%s\r\n", r.StreamSeq,
		r.Start.Format(layout), r.ClientAddr, r.ServerAddr))
	b.WriteString(fmt.Sprintf("%s %s %s\r\n", r.Version, r.Code, r.Reason))
	r.writeHeader(&b)
	r.writeBody(&b)
	return b.WriteTo(out)
}

func (r Event) writeHeader(b *bytes.Buffer) {
	for h := range r.Header {
		b.WriteString(fmt.Sprintf("%s: %s\r\n", h, r.Header.Get(h)))
	}
}

func (r Event) writeBody(b *bytes.Buffer) {
	if len(r.Body) > 0 {
		b.WriteString(fmt.Sprintf("\r\ncontent(%d)", len(r.Body)))
		b.WriteString(fmt.Sprintf("%s", r.Body))
	}
	b.WriteString("\r\n\r\n")
}
