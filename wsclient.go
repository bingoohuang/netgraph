package main

import (
	"encoding/json"
	"golang.org/x/net/websocket"
)

// NewWsClient creates WsClient
func NewWsClient(ws *websocket.Conn, server *HttpcapServer) *WsClient {
	c := new(WsClient)
	c.server = server
	c.ws = ws
	c.eventChan = make(chan interface{}, 16)
	return c
}

// WsClient is the websocket client
type WsClient struct {
	eventChan chan interface{}
	server    *HttpcapServer
	ws        *websocket.Conn
}

func (c *WsClient) recvAndProcessCommand() {
	for {
		var msg string
		err := websocket.Message.Receive(c.ws, &msg)
		if err != nil {
			return
		}
		if msg == "sync" {
			c.server.sync(c)
		}
	}
}

func (c *WsClient) transmitEvents() {
	for ev := range c.eventChan {
		if jso, err := json.Marshal(ev); err == nil {
			websocket.Message.Send(c.ws, string(jso))
		}
	}
}

func (c *WsClient) close() { close(c.eventChan) }
