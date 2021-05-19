package httpstream

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// EventJson records HTTP events as JSON.
type EventJson struct {
	filename string
	Ch       chan RequestEvent
	StopCh   chan struct{}
}

// NewEventJson creates EventReplay.
func NewEventJson(filename string) *EventJson {
	e := &EventJson{filename: filename, Ch: make(chan RequestEvent, 1000), StopCh: make(chan struct{})}
	go e.loop()
	return e
}

func (p *EventJson) loop() {
	batchNum := 1000
	seq := 0
	f := createFile(p.filename, &seq)
	tick := time.NewTicker(1 * time.Hour)
	defer tick.Stop()

	count := 0
	for {
		select {
		case v := <-p.Ch:
			data := createJSON(v)
			_, _ = f.WriteString(data)
			_, _ = f.Write([]byte("\n"))
			count++
			if count >= batchNum {
				count = 0
				_ = f.Close()
				f = createFile(p.filename, &seq)
			}
		case <-tick.C:
			if count > 0 {
				count = 0
				_ = f.Close()
				f = createFile(p.filename, &seq)
			}
		case <-p.StopCh:
			_ = f.Close()
			p.StopCh <- struct{}{}
			return
		}
	}
}

func createFile(baseFileName string, seq *int) *os.File {
	*seq++
	fn := createFileName(baseFileName, seq, `200601021504`)
	f, err := os.OpenFile(fn, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0755)
	if err != nil {
		log.Fatalln("Cannot open writer ", fn)
	}
	return f
}

func createFileName(baseFileName string, seq *int, timeLayout string) string {
	for {
		hour := time.Now().Format(timeLayout)
		fn := fmt.Sprintf("%s.%s.%04d", baseFileName, hour, *seq)
		if _, err := os.Stat(fn); os.IsNotExist(err) {
			return fn
		}

		*seq++
	}
}

// PushEvent implements the function of interface EventHandler.
func (p *EventJson) PushEvent(e interface{}) {
	switch v := e.(type) {
	case RequestEvent:
		p.Ch <- v
	default:
		// bypass
	}
}

// Wait implements the function of interface EventHandler.
func (p *EventJson) Wait() {
	p.StopCh <- struct{}{}
	<-p.StopCh
}

type RequestRecord struct {
	Method string            `json:"method"`
	Uri    string            `json:"uri"`
	Header map[string]string `json:"header"`
	Body   string            `json:"body"`
}

func createJSON(v RequestEvent) string {
	for _, n := range []string{"User-Agent", "Host", "Connection", "Transfer-Encoding", "Content-Length"} {
		v.Header.Del(n)
	}
	r := RequestRecord{Method: v.Method, Uri: v.URI, Header: ConvertHeaders(v.Header), Body: string(v.Body)}
	data, _ := json.Marshal(r)
	return UnescapeUnicodeCharactersInJSON(string(data))
}

func UnescapeUnicodeCharactersInJSON(_jsonRaw string) string {
	str, err := strconv.Unquote(strings.Replace(strconv.Quote(_jsonRaw), `\\u`, `\u`, -1))
	if err != nil {
		return _jsonRaw
	}
	return str
}
