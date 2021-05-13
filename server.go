package main

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"sync"

	"golang.org/x/net/websocket"
)

// NewNGServer creates HttpcapServer.
func NewNGServer(addr string, saveEvent bool) *HttpcapServer {
	s := &HttpcapServer{
		addr:            addr,
		connectedClient: make(map[*websocket.Conn]*WsClient),
		saveEvent:       saveEvent,
	}
	s.serve()

	return s
}

//go:embed assets
var assetsFS embed.FS

// Serve the web page.
func (s *HttpcapServer) serve() {
	assets, _ := fs.Sub(assetsFS, "assets")
	http.Handle("/data", websocket.Handler(s.websocketHandler))
	http.Handle("/", http.FileServer(http.FS(assets)))
	s.wg.Add(1)
	go s.listenAndServe()
}

// HttpcapServer is a http server which push captured Event to the front end
type HttpcapServer struct {
	addr string

	connectedClient      map[*websocket.Conn]*WsClient
	connectedClientMutex sync.Mutex

	eventBuffer []interface{}
	saveEvent   bool
	wg          sync.WaitGroup
}

func (s *HttpcapServer) websocketHandler(ws *websocket.Conn) {
	c := NewWsClient(ws, s)

	s.connectedClientMutex.Lock()
	s.connectedClient[ws] = c
	s.connectedClientMutex.Unlock()

	go c.transmitEvents()

	c.recvAndProcessCommand()
	c.close()

	s.connectedClientMutex.Lock()
	delete(s.connectedClient, ws)
	s.connectedClientMutex.Unlock()
}

// PushEvent dispatches the event received from ngnet to all clients connected with websocket.
func (s *HttpcapServer) PushEvent(e interface{}) {
	if s.saveEvent {
		s.eventBuffer = append(s.eventBuffer, e)
	}
	s.connectedClientMutex.Lock()
	for _, c := range s.connectedClient {
		c.eventChan <- e
	}
	s.connectedClientMutex.Unlock()
}

// Wait waits for serving
func (s *HttpcapServer) Wait() { s.wg.Wait() }

/*
   If the flag '-s' is set and the browser sent a 'sync' command,
   the HttpcapServer will push all the http message buffered in eventBuffer to
   the client.
*/
func (s *HttpcapServer) sync(c *WsClient) {
	for _, ev := range s.eventBuffer {
		c.eventChan <- ev
	}
}

func (s *HttpcapServer) listenAndServe() {
	defer s.wg.Done()
	err := http.ListenAndServe(s.addr, nil)
	if err != nil {
		log.Fatalln(err)
	}
}
