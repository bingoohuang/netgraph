package httpstream

import (
	"bytes"
	"io"
	"time"
)

// DataBlock is copied from tcpassembly.Reassembly.
type DataBlock struct {
	Bytes []byte
	Seen  time.Time
}

// NewDataBlock create a new DataBlock.
func NewDataBlock(bytes []byte, seen time.Time) *DataBlock {
	b := &DataBlock{
		Bytes: make([]byte, len(bytes)),
		Seen:  seen,
	}
	copy(b.Bytes, bytes[:])
	return b
}

// Reader read data from tcp stream.
type Reader struct {
	src      chan *DataBlock
	stopCh   chan interface{}
	buffer   *bytes.Buffer
	lastSeen time.Time
}

// NewReader create a new Reader.
func NewReader() *Reader {
	r := new(Reader)
	r.stopCh = make(chan interface{})
	r.buffer = bytes.NewBuffer([]byte(""))
	r.src = make(chan *DataBlock, 32)
	return r
}

func (s *Reader) fillBuffer() error {
	if dataBlock, ok := <-s.src; ok {
		s.buffer.Write(dataBlock.Bytes)
		s.lastSeen = dataBlock.Seen
		return nil
	}
	return io.EOF
}

// ReadUntil read bytes until delim.
func (s *Reader) ReadUntil(delim []byte) ([]byte, error) {
	var p int
	for {
		if p = bytes.Index(s.buffer.Bytes(), delim); p == -1 {
			if err := s.fillBuffer(); err != nil {
				return nil, err
			}
		} else {
			break
		}
	}
	return s.buffer.Next(p + len(delim)), nil
}

// Next read n bytes from stream.
func (s *Reader) Next(n int) ([]byte, error) {
	for s.buffer.Len() < n {
		if err := s.fillBuffer(); err != nil {
			return nil, err
		}
	}
	dst := make([]byte, n)
	copy(dst, s.buffer.Next(n))
	return dst, nil
}
