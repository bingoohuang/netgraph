package httpstream

import (
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"
)

// EventHandler handle HTTP events.
type EventHandler interface {
	PushEvent(interface{})
	Wait()
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
	Headers    []Header
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

	idChan chan int
	id     int
}

func newPair(seq uint, eventChan chan<- interface{}) *pair {
	return &pair{connSeq: seq, eventChan: eventChan, idChan: make(chan int, 10000)}
}

func (p *pair) run(wg *sync.WaitGroup, stream *httpStream) {
	defer wg.Done()
	defer close(stream.reader.stopCh)

	dir := DirectionUnknown
	for {
		err := p.handleTransaction(&dir, stream)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			log.Printf("EOF %s", stream.key.String())
			return // We must read until we see an EOF... very important!
		} else if err != nil {
			log.Printf("E! Reading stream %s, error: %v", stream.key.String(), err)
			continue
		}
	}
}

func (p *pair) handleRequestTransaction(method, uri, version string, s *httpStream) error {
	reqStart := s.reader.lastSeen
	reqHeaders, err := s.parseHeaders()
	if err != nil {
		return err
	}

	p.clientAddr = s.key.net.Src().String() + ":" + s.key.tcp.Src().String()
	p.serverAddr = s.key.net.Dst().String() + ":" + s.key.tcp.Dst().String()

	reqBody, err := s.parseBody(method, reqHeaders, true)
	if err != nil {
		return err
	}

	p.method = method
	p.id++
	TryPut(p.idChan, p.id)
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
			Headers:    reqHeaders,
			Body:       reqBody,
		},
	}
	return nil
}

func TryGetValue(c chan int) int {
	v, _ := TryGet(c)
	return v
}

func TryGet(c chan int) (int, bool) {
	select {
	case v := <-c:
		return v, true
	default:
		return 0, false
	}
}

func TryPut(c chan int, v int) bool {
	select {
	case c <- v:
		return true
	default:
		return false
	}
}

func (p *pair) handleTransaction(dir *Direction, stream *httpStream) error {
	direction, p1, p2, p3, err := stream.parseFirstLine(*dir)
	if err != nil {
		return err
	}
	*dir = direction

	if direction == DirectionRequest {
		return p.handleRequestTransaction(p1, p2, p3, stream)
	}

	return p.handleResponseTransaction(p1, p2, p3, stream)
}

func (p *pair) handleResponseTransaction(respVersion, code, reason string, stream *httpStream) error {
	respStart := stream.reader.lastSeen
	respHeaders, err := stream.parseHeaders()
	if err != nil {
		return err
	}
	respBody, err := stream.parseBody(p.method, respHeaders, false)
	if err != nil {
		return err
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
			ID:         TryGetValue(p.idChan),
			ClientAddr: p.clientAddr,
			ServerAddr: p.serverAddr,
			Headers:    respHeaders,
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
	n += fp(out, "#%d [%s] Request %s->%s\r\n", r.StreamSeq, r.Start.Format(layout), r.ClientAddr, r.ServerAddr)
	n += fp(out, "%s %s %s\r\n", r.Method, r.URI, r.Version)
	n = r.writeHeader(out, n)
	return r.writeBody(out, n)
}

func (r ResponseEvent) WriteTo(out io.Writer) (n int64, err error) {
	n += fp(out, "#%d [%s] Response %s<-%s\r\n", r.StreamSeq, r.Start.Format(layout), r.ClientAddr, r.ServerAddr)
	n += fp(out, "%s %s %s\r\n", r.Version, r.Code, r.Reason)
	n = r.writeHeader(out, n)
	return r.writeBody(out, n)
}

func (r Event) writeHeader(out io.Writer, n int64) int64 {
	for _, h := range r.Headers {
		n += fp(out, "%s: %s\r\n", h.Name, h.Value)
	}
	return n
}

func (r Event) writeBody(out io.Writer, n int64) (int64, error) {
	n += fp(out, "\r\ncontent(%d)", len(r.Body))
	if len(r.Body) > 0 {
		n += fp(out, "%s", r.Body)
	}
	n += fp(out, "\r\n\r\n")
	return n, nil
}
