package httpstream

import (
	"io"
	"log"
	"os"
)

// EventPrinter print HTTP events to file or stdout.
type EventPrinter struct {
	file *os.File
}

// NewEventPrinter creates EventPrinter.
func NewEventPrinter(name string) *EventPrinter {
	if name == "stdout" {
		return &EventPrinter{file: os.Stdout}
	}

	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		log.Fatalln("Cannot open file ", name)
	}

	return &EventPrinter{file: f}
}

// PushEvent implements the function of interface EventHandler.
func (p *EventPrinter) PushEvent(e interface{}) {
	if v, ok := e.(io.WriterTo); ok {
		_, _ = v.WriteTo(p.file)
	} else {
		log.Printf("Unknown event: %v", e)
	}
}

// Wait implements the function of interface EventHandler.
func (p *EventPrinter) Wait() {}
