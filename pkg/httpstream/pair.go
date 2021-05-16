package httpstream

import (
	"errors"
	"fmt"
	"io"
	"log"
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
}

// RequestEvent is HTTP request.
type RequestEvent struct {
	Event
	ClientAddr string
	ServerAddr string
	Method     string
	URI        string
	Version    string
	Headers    []Header
	Body       []byte
}

// ResponseEvent is HTTP response.
type ResponseEvent struct {
	Event
	ClientAddr string
	ServerAddr string
	Version    string
	Code       int
	Reason     string
	Headers    []Header
	Body       []byte
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

func (p *pair) runRsp(stream *httpStream) {
	defer close(stream.reader.stopCh)

	for {
		err := p.handleResponseTransaction(stream)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			log.Printf("EOF %s", stream.key.String())
			return // We must read until we see an EOF... very important!
		} else if err != nil {
			log.Printf("E! Reading stream %s, error: %v", stream.key.String(), err)
			continue
		}
	}
}
func (p *pair) runReq(stream *httpStream) {
	defer close(stream.reader.stopCh)

	for {
		err := p.handleRequestTransaction(stream)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			log.Printf("EOF %s", stream.key.String())
			return // We must read until we see an EOF... very important!
		} else if err != nil {
			log.Printf("E! Reading stream %s, error: %v", stream.key.String(), err)
			continue
		}

	}
}

func (p *pair) handleRequestTransaction(s *httpStream) error {
	method, uri, version, _ := s.parseRequestLine()
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
	p.idChan <- p.id
	p.eventChan <- RequestEvent{
		ClientAddr: p.clientAddr,
		ServerAddr: p.serverAddr,
		Method:     method,
		URI:        uri,
		Version:    version,
		Headers:    reqHeaders,
		Body:       reqBody,
		Event: Event{
			Type:      "HTTPRequest",
			StreamSeq: p.connSeq,
			Start:     reqStart,
			End:       s.reader.lastSeen,
			ID:        p.id,
		},
	}
	return nil
}

func (p *pair) handleResponseTransaction(stream *httpStream) error {
	respVersion, code, reason, err := stream.parseResponseLine()
	if err != nil {
		return err
	}

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
		ClientAddr: p.clientAddr,
		ServerAddr: p.serverAddr,
		Version:    respVersion,
		Code:       code,
		Reason:     reason,
		Headers:    respHeaders,
		Body:       respBody,
		Event: Event{
			Type:      "HTTPResponse",
			StreamSeq: p.connSeq,
			Start:     respStart,
			End:       stream.reader.lastSeen,
			ID:        <-p.idChan,
		},
	}

	return nil
}

var fp = func(w io.Writer, format string, a ...interface{}) int64 {
	n, _ := fmt.Fprintf(w, format, a...)
	return int64(n)
}

func (r RequestEvent) WriteTo(out io.Writer) (n int64, err error) {
	n += fp(out, "[%s] #%d Request %s->%s\r\n",
		r.Start.Format("2006-01-02 15:04:05.000"), r.StreamSeq, r.ClientAddr, r.ServerAddr)
	n += fp(out, "%s %s %s\r\n", r.Method, r.URI, r.Version)
	for _, h := range r.Headers {
		n += fp(out, "%s: %s\r\n", h.Name, h.Value)
	}

	n += fp(out, "\r\ncontent(%d)", len(r.Body))
	if len(r.Body) > 0 {
		n += fp(out, "%s", r.Body)
	}
	n += fp(out, "\r\n\r\n")
	return n, nil
}

func (r ResponseEvent) WriteTo(out io.Writer) (n int64, err error) {
	n += fp(out, "[%s] #%d Response %s<-%s\r\n",
		r.Start.Format("2006-01-02 15:04:05.000"), r.StreamSeq, r.ClientAddr, r.ServerAddr)
	n += fp(out, "%s %d %s\r\n", r.Version, r.Code, r.Reason)
	for _, h := range r.Headers {
		n += fp(out, "%s: %s\r\n", h.Name, h.Value)
	}

	n += fp(out, "\r\ncontent(%d)", len(r.Body))
	if len(r.Body) > 0 {
		n += fp(out, "%s", r.Body)
	}
	n += fp(out, "\r\n\r\n")
	return n, nil
}
